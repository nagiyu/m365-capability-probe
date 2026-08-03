using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Reads one and the same file twice in a single run - once as the app, once as a person - and puts
/// the two answers side by side.
/// <para>
/// Both legs walk the same three calls: resolve the site by path, resolve the item by path inside that
/// site, then ask for the item's permission list by ID. The site is resolved first on purpose: Graph's
/// path addressing uses a single colon segment, and a URL that chains two of them is rejected outright,
/// so each path lookup is turned into an ID before the next call is built.
/// </para>
/// <para>
/// Running both legs in one execution is also on purpose. Two separate runs would leave the reader
/// unable to say whether the two halves describe the same moment.
/// </para>
/// </summary>
public sealed class AccessProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    private sealed record CallRecord(string Mode, string Step, HttpObservation Observation);

    private sealed record ModeRun
    {
        public required ProbeMode Mode { get; init; }
        public required TokenResult Token { get; init; }
        public HttpObservation? Site { get; init; }
        public HttpObservation? Item { get; init; }
        public HttpObservation? Permissions { get; init; }
        public string? SiteId { get; init; }
        public string? ItemId { get; init; }
        public int? PermissionEntryCount { get; init; }
        public IReadOnlyList<string> PrincipalKinds { get; init; } = [];
        public long ElapsedMs { get; init; }
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("access");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["client"] = options.ClientId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["file"] = options.FilePath;
        report.Subject["sign-in"] = options.DelegatedUserHint;

        var calls = new List<CallRecord>();

        console.WriteLine("Reading the file as the application (client credentials)...");
        var appOnlyToken = await new AppOnlyTokenSource(options).GetTokenAsync(ProbeAudience.Graph, cancellationToken);
        var appOnlyRun = await WalkAsync(ProbeMode.AppOnly, appOnlyToken, calls, cancellationToken);

        console.WriteLine("Reading the same file on behalf of a signed-in person (device code)...");
        var delegatedSource = new DelegatedTokenSource(options, console);
        var delegatedToken = await delegatedSource.SignInAsync(cancellationToken);
        var delegatedRun = await WalkAsync(ProbeMode.Delegated, delegatedToken, calls, cancellationToken);

        report.Add(BuildComparison(appOnlyRun, delegatedRun));
        report.Add(BuildCallTable(calls));

        foreach (var run in new[] { appOnlyRun, delegatedRun })
        {
            report.Add(TokenObservation(run));
            report.Add(SiteObservation(run));
            report.Add(ItemObservation(run));
            report.Add(PermissionsObservation(run));
        }

        report.Add(ContrastObservation(appOnlyRun, delegatedRun));

        report.Finish();
        return report;
    }

    private async Task<ModeRun> WalkAsync(
        ProbeMode mode,
        TokenResult token,
        List<CallRecord> calls,
        CancellationToken cancellationToken)
    {
        var run = new ModeRun { Mode = mode, Token = token };
        if (!token.Succeeded || token.AccessToken is null)
        {
            return run;
        }

        var accessToken = token.AccessToken;
        var elapsed = 0L;

        // 1. Path -> site ID. One colon segment only: /sites/{host}:{server-relative-path}
        // A host with no path below it is the tenant root site and takes no colon segment at all.
        var relativePath = options.SiteServerRelativePath;
        var siteUrl = string.IsNullOrEmpty(relativePath)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relativePath)}";
        var site = await http.GetAsync(siteUrl, accessToken, cancellationToken);
        calls.Add(new CallRecord(mode.Display(), "resolve site", site));
        elapsed += site.ElapsedMs;
        run = run with { Site = site, ElapsedMs = elapsed };

        var siteId = ReadStringProperty(site, "id");
        if (!site.IsSuccess || siteId is null)
        {
            return run;
        }

        run = run with { SiteId = siteId };

        // 2. Path -> item ID, now under an ID-addressed site so no second colon segment appears.
        var itemUrl = $"{GraphBase}/sites/{siteId}/drive/root:{EscapePath(options.FilePath)}";
        var item = await http.GetAsync(itemUrl, accessToken, cancellationToken);
        calls.Add(new CallRecord(mode.Display(), "resolve item", item));
        elapsed += item.ElapsedMs;
        run = run with { Item = item, ElapsedMs = elapsed };

        var itemId = ReadStringProperty(item, "id");
        if (!item.IsSuccess || itemId is null)
        {
            return run;
        }

        run = run with { ItemId = itemId };

        // 3. The measurement of interest: who can see the item's permission list at all.
        var permissionsUrl = $"{GraphBase}/sites/{siteId}/drive/items/{itemId}/permissions";
        var permissions = await http.GetAsync(permissionsUrl, accessToken, cancellationToken);
        calls.Add(new CallRecord(mode.Display(), "read permissions", permissions));
        elapsed += permissions.ElapsedMs;

        var (count, kinds) = SummarisePermissions(permissions);

        return run with
        {
            Permissions = permissions,
            PermissionEntryCount = count,
            PrincipalKinds = kinds,
            ElapsedMs = elapsed,
        };
    }

    /// <summary>Escapes each segment but keeps the separators, so '/Shared Documents/x.docx' stays a path.</summary>
    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/').Select(Uri.EscapeDataString));

    private static string? ReadStringProperty(HttpObservation observation, string propertyName)
    {
        if (!observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Counts the permission entries and names the kinds of principal that appear in them.
    /// A refused response yields no count at all rather than a zero - "we were not allowed to look"
    /// and "we looked and there was nothing" are different observations.
    /// </summary>
    private static (int? Count, IReadOnlyList<string> Kinds) SummarisePermissions(HttpObservation observation)
    {
        if (!observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return (null, []);
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            if (!document.RootElement.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
            {
                return (null, []);
            }

            var kinds = new SortedSet<string>(StringComparer.Ordinal);
            var count = 0;

            foreach (var entry in value.EnumerateArray())
            {
                count++;

                CollectIdentitySetKinds(entry, "grantedToV2", kinds);
                CollectIdentitySetKinds(entry, "grantedTo", kinds);
                CollectIdentityListKinds(entry, "grantedToIdentitiesV2", kinds);
                CollectIdentityListKinds(entry, "grantedToIdentities", kinds);

                if (entry.TryGetProperty("link", out var link) && link.ValueKind == JsonValueKind.Object)
                {
                    var scope = link.TryGetProperty("scope", out var s) ? s.GetString() : null;
                    kinds.Add(scope is null ? "link" : $"link:{scope}");
                }

                if (entry.TryGetProperty("invitation", out var invitation) && invitation.ValueKind == JsonValueKind.Object)
                {
                    kinds.Add("invitation");
                }
            }

            return (count, kinds.ToList());
        }
        catch (JsonException)
        {
            return (null, []);
        }
    }

    private static void CollectIdentitySetKinds(JsonElement entry, string propertyName, SortedSet<string> kinds)
    {
        if (entry.TryGetProperty(propertyName, out var identitySet) && identitySet.ValueKind == JsonValueKind.Object)
        {
            foreach (var kind in identitySet.EnumerateObject())
            {
                if (kind.Value.ValueKind == JsonValueKind.Object)
                {
                    kinds.Add(kind.Name);
                }
            }
        }
    }

    private static void CollectIdentityListKinds(JsonElement entry, string propertyName, SortedSet<string> kinds)
    {
        if (entry.TryGetProperty(propertyName, out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var identitySet in list.EnumerateArray())
            {
                foreach (var kind in identitySet.EnumerateObject())
                {
                    if (kind.Value.ValueKind == JsonValueKind.Object)
                    {
                        kinds.Add(kind.Name);
                    }
                }
            }
        }
    }

    private static ProbeTable BuildComparison(ModeRun appOnly, ModeRun delegatedRun)
    {
        var rows = new[] { appOnly, delegatedRun }
            .Select(run => (IReadOnlyList<string?>)new[]
            {
                run.Mode.Display(),
                Status(run.Site),
                Status(run.Item),
                Status(run.Permissions),
                run.PermissionEntryCount?.ToString() ?? "-",
                run.PrincipalKinds.Count == 0 ? "-" : string.Join(", ", run.PrincipalKinds),
                run.ElapsedMs.ToString(),
            })
            .ToList();

        return new ProbeTable(
            "The same file, read two ways",
            ["mode", "site", "item", "permissions", "entries", "principal kinds", "ms"],
            rows);
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<CallRecord> calls)
    {
        var rows = calls
            .Select(c => (IReadOnlyList<string?>)new[]
            {
                c.Mode,
                c.Step,
                c.Observation.Method,
                c.Observation.Url,
                c.Observation.StatusText,
                c.Observation.ElapsedMs.ToString(),
                ErrorCodeOf(c.Observation),
            })
            .ToList();

        return new ProbeTable(
            "Calls issued (every one carried 'Authorization: Bearer <token>' and 'Accept: application/json')",
            ["mode", "step", "method", "url", "status", "ms", "graph error code"],
            rows);
    }

    private static string Status(HttpObservation? observation) => observation is null ? "NotRun" : observation.StatusText;

    /// <summary>Graph puts its own code in the body; that code says more than the HTTP status alone.</summary>
    private static string ErrorCodeOf(HttpObservation observation)
    {
        if (observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return "";
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.TryGetProperty("error", out var error) &&
                   error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String
                ? code.GetString() ?? ""
                : "";
        }
        catch (JsonException)
        {
            return "";
        }
    }

    private static Observation TokenObservation(ModeRun run)
    {
        var claim = $"{run.Mode.Display()}: a Graph token can be acquired for the file read";
        if (run.Token.Succeeded)
        {
            // The delegated token is the device code sign-in, so most of its elapsed time is a person
            // reading a screen. Reporting it next to service timings without saying so invites the
            // reading that Entra took a minute and a half to answer.
            var timing = run.Mode == ProbeMode.Delegated
                ? $"{run.Token.ElapsedMs} ms, including the wait for the person to sign in"
                : $"{run.Token.ElapsedMs} ms";

            return new Observation(claim, $"token issued ({timing})", Verdict.Ok)
            {
                Details = Details(
                    run,
                    ("elapsedMs", run.Token.ElapsedMs.ToString()),
                    ("elapsedIncludesSignIn", run.Mode == ProbeMode.Delegated ? "true" : "false")),
            };
        }

        return new Observation(claim, $"refused with {run.Token.ErrorCode}", Verdict.Failed)
        {
            Details = Details(run, ("errorCode", run.Token.ErrorCode), ("errorDetail", run.Token.ErrorDetail)),
        };
    }

    private static Observation SiteObservation(ModeRun run)
    {
        var claim = $"{run.Mode.Display()}: the site resolves from its URL to a site ID";
        if (run.Site is null)
        {
            return Observation.NotRun(claim, "no Graph token was issued for this mode");
        }

        return new Observation(
            claim,
            run.SiteId is null ? $"{run.Site.StatusText} {ErrorCodeOf(run.Site)}".Trim() : $"{run.Site.StatusText}, id resolved",
            run.SiteId is null ? Verdict.Failed : Verdict.Ok)
        {
            Details = Details(run, ("url", run.Site.Url), ("status", run.Site.StatusText), ("elapsedMs", run.Site.ElapsedMs.ToString())),
        };
    }

    private static Observation ItemObservation(ModeRun run)
    {
        var claim = $"{run.Mode.Display()}: the file resolves from its path to an item ID";
        if (run.Item is null)
        {
            return Observation.NotRun(claim, "the site was never resolved, so no item lookup was built");
        }

        return new Observation(
            claim,
            run.ItemId is null ? $"{run.Item.StatusText} {ErrorCodeOf(run.Item)}".Trim() : $"{run.Item.StatusText}, id resolved",
            run.ItemId is null ? Verdict.Failed : Verdict.Ok)
        {
            Details = Details(run, ("url", run.Item.Url), ("status", run.Item.StatusText), ("elapsedMs", run.Item.ElapsedMs.ToString())),
        };
    }

    /// <summary>
    /// The delegated leg is claimed not to learn who has access: the signed-in person is a visitor on
    /// the site, and an item's permission entries are not a visitor's to see.
    /// <para>
    /// The claim is about what is revealed, not about the HTTP status, because Graph does not refuse
    /// this call. It answers 200 with an empty collection - the entries are filtered to what the caller
    /// may see, and a caller who may see none is told "success, nothing here". So a 403 and a 200 with
    /// zero entries both satisfy the claim, and neither is a fault to be cleared by granting more.
    /// </para>
    /// </summary>
    private static Observation PermissionsObservation(ModeRun run)
    {
        var expectsSuccess = run.Mode == ProbeMode.AppOnly;
        var claim = expectsSuccess
            ? $"{run.Mode.Display()}: the file's permission list is readable"
            : $"{run.Mode.Display()}: the permission list does not reveal the file's permission entries";

        if (run.Permissions is null)
        {
            return Observation.NotRun(claim, "the item was never resolved, so the permission list was never requested");
        }

        var observed = run.Permissions.IsSuccess
            ? $"{run.Permissions.StatusText}, {run.PermissionEntryCount} entries, principals: " +
              (run.PrincipalKinds.Count == 0 ? "none" : string.Join(", ", run.PrincipalKinds))
            : $"{run.Permissions.StatusText} {ErrorCodeOf(run.Permissions)}".Trim();

        if (!expectsSuccess && run.Permissions.IsSuccess && run.PermissionEntryCount == 0)
        {
            observed += " - Graph answered success with an empty list rather than refusing";
        }

        var held = expectsSuccess
            ? run.Permissions.IsSuccess
            : !run.Permissions.IsSuccess || run.PermissionEntryCount is null or 0;

        return new Observation(claim, observed, held ? Verdict.Ok : Verdict.Failed)
        {
            Details = Details(
                run,
                ("url", run.Permissions.Url),
                ("status", run.Permissions.StatusText),
                ("graphErrorCode", ErrorCodeOf(run.Permissions)),
                ("entryCount", run.PermissionEntryCount?.ToString()),
                ("principalKinds", string.Join(", ", run.PrincipalKinds)),
                ("elapsedMs", run.Permissions.ElapsedMs.ToString())),
        };
    }

    /// <summary>The headline: the two identities did not see the same thing at the same moment.</summary>
    private static Observation ContrastObservation(ModeRun appOnly, ModeRun delegatedRun)
    {
        const string Claim = "app-only and delegated do not see the same permission surface for this file";

        if (appOnly.Permissions is null && delegatedRun.Permissions is null)
        {
            return Observation.NotRun(Claim, "neither mode reached the permission list");
        }

        var appStatus = Status(appOnly.Permissions);
        var delegatedStatus = Status(delegatedRun.Permissions);
        var differs = appStatus != delegatedStatus ||
                      appOnly.PermissionEntryCount != delegatedRun.PermissionEntryCount;

        var observed =
            $"app-only {appStatus} / entries {appOnly.PermissionEntryCount?.ToString() ?? "-"}; " +
            $"delegated {delegatedStatus} / entries {delegatedRun.PermissionEntryCount?.ToString() ?? "-"}";

        // Same status, different contents. Worth saying out loud: a caller seeing only the delegated
        // half has no way to tell this file's sharing from a file that is not shared with anyone.
        if (appStatus == delegatedStatus &&
            appOnly.PermissionEntryCount != delegatedRun.PermissionEntryCount)
        {
            observed += " - identical status, different contents: the status alone cannot tell a filtered list from an empty one";
        }

        return new Observation(Claim, observed, differs ? Verdict.Ok : Verdict.Failed)
        {
            Details = new Dictionary<string, string?>
            {
                ["appOnlyStatus"] = appStatus,
                ["delegatedStatus"] = delegatedStatus,
                ["appOnlyEntryCount"] = appOnly.PermissionEntryCount?.ToString(),
                ["delegatedEntryCount"] = delegatedRun.PermissionEntryCount?.ToString(),
            },
        };
    }

    private static IReadOnlyDictionary<string, string?> Details(ModeRun run, params (string Key, string? Value)[] extra)
    {
        var details = new Dictionary<string, string?> { ["mode"] = run.Mode.Display() };
        foreach (var (key, value) in extra)
        {
            details[key] = value;
        }

        return details;
    }
}
