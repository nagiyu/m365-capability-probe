using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Reads the same set of files twice over in a single run - once as the app, once as a person - and
/// puts the two answers side by side, file by file.
/// <para>
/// Each leg walks the same calls: resolve the site by path, then for every file resolve the item by
/// path inside that site and ask for the item's permission list by ID. Path lookups are turned into
/// IDs before the next call is built, because Graph's path addressing uses a single colon segment and
/// a URL that chains two of them is rejected outright.
/// </para>
/// <para>
/// Both identities are established before any file is read, and every file is then read by both in
/// immediate succession. That ordering is the point: a difference between the two answers for one file
/// has to be about the identity, and the narrower the gap in time, the less room there is for "something
/// changed in between" as an explanation. It also means one device code sign-in for the whole set
/// rather than one per file.
/// </para>
/// <para>
/// Two of the four things this measures cannot be read from one identity alone. A permission list that
/// comes back empty and a file that comes back 404 both look like facts about the file; only the other
/// identity's answer at the same moment shows them to be facts about the caller.
/// </para>
/// <para>
/// The app is read once here, with its shared secret, and not a second time with its certificate. That
/// is a choice, not an omission: this subcommand asks what an identity can see, and how the app proved
/// itself to Entra is a question about the token, not about the file. <c>auth</c> and <c>sharepoint</c>
/// carry both proofs; running a third leg over every file would double the calls to ask a question
/// those two already answer.
/// </para>
/// </summary>
public sealed class AccessProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    private sealed record CallRecord(string Mode, string File, string Step, HttpObservation Observation);

    /// <summary>An identity, and how far it got before any file was looked at.</summary>
    private sealed record Identity
    {
        public required ProbeMode Mode { get; init; }
        public required TokenResult Token { get; init; }
        public HttpObservation? Site { get; init; }
        public string? SiteId { get; init; }

        /// <summary>Why no file could be read as this identity, or null if files were readable.</summary>
        public string? Blocked { get; init; }
    }

    /// <summary>One file, as seen by one identity.</summary>
    private sealed record FileRun
    {
        public required string File { get; init; }
        public required ProbeMode Mode { get; init; }
        public HttpObservation? Item { get; init; }
        public HttpObservation? Permissions { get; init; }
        public string? ItemId { get; init; }
        public int? PermissionEntryCount { get; init; }
        public IReadOnlyList<string> PrincipalKinds { get; init; } = [];
        public long ElapsedMs { get; init; }

        /// <summary>Set when the identity never got far enough for this file to be requested at all.</summary>
        public string? Blocked { get; init; }
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("access");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["client"] = options.ClientId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["files"] = string.Join(", ", options.Files);
        report.Subject["hint"] = options.DelegatedUserHint;

        var calls = new List<CallRecord>();

        // Both identities first, then the files. One sign-in for the whole set.
        console.WriteLine("Establishing the application identity (client credentials)...");
        var appOnlyToken = await AppOnlyTokenSource.WithSecret(options).GetTokenAsync(ProbeAudience.Graph, cancellationToken);

        console.WriteLine("Establishing the delegated identity (device code)...");
        var delegatedSource = new DelegatedTokenSource(options, console);
        var delegatedToken = await delegatedSource.SignInAsync(cancellationToken);

        // Who actually signed in, not who was configured to. The delegated half of every number below
        // is a statement about that account, so a report that names the hint instead is asserting
        // something it never measured.
        report.Subject["signed in"] = delegatedSource.SignedInAs ?? "(nobody - sign-in did not complete)";

        if (!delegatedSource.IsSignedIn)
        {
            report.MarkIncomplete(
                "the device code was printed but the sign-in was never completed, so the delegated half " +
                "is empty for want of an identity rather than for want of an answer");
        }

        var appOnly = await ResolveIdentityAsync(ProbeMode.AppOnly, appOnlyToken, calls, cancellationToken);
        var delegated = await ResolveIdentityAsync(ProbeMode.Delegated, delegatedToken, calls, cancellationToken);

        var runs = new List<FileRun>();
        foreach (var file in options.Files)
        {
            console.WriteLine($"Reading {file} as both identities...");
            runs.Add(await ReadFileAsync(appOnly, file, calls, cancellationToken));
            runs.Add(await ReadFileAsync(delegated, file, calls, cancellationToken));
        }

        report.Add(BuildIdentityTable(appOnly, delegated));
        report.Add(BuildFileTable(runs));
        report.Add(BuildCallTable(calls));

        foreach (var identity in new[] { appOnly, delegated })
        {
            report.Add(TokenObservation(identity));
            report.Add(SiteObservation(identity));
        }

        foreach (var run in runs)
        {
            report.Add(ItemObservation(run));
            report.Add(PermissionsObservation(run));
        }

        foreach (var file in options.Files)
        {
            report.Add(ContrastObservation(
                file,
                runs.Single(r => r.File == file && r.Mode == ProbeMode.AppOnly),
                runs.Single(r => r.File == file && r.Mode == ProbeMode.Delegated)));
        }

        report.Finish();
        return report;
    }

    /// <summary>Turns a token into a usable site ID, once per identity rather than once per file.</summary>
    private async Task<Identity> ResolveIdentityAsync(
        ProbeMode mode,
        TokenResult token,
        List<CallRecord> calls,
        CancellationToken cancellationToken)
    {
        var identity = new Identity { Mode = mode, Token = token };
        if (!token.Succeeded || token.AccessToken is null)
        {
            return identity with { Blocked = "no Graph token was issued for this mode" };
        }

        // One colon segment only: /sites/{host}:{server-relative-path}. A host with no path below it
        // is the tenant root site and takes no colon segment at all.
        var relativePath = options.SiteServerRelativePath;
        var url = string.IsNullOrEmpty(relativePath)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relativePath)}";

        var site = await http.GetAsync(url, token.AccessToken, cancellationToken);
        calls.Add(new CallRecord(mode.Display(), "-", "resolve site", site));

        var siteId = ReadStringProperty(site, "id");
        return identity with
        {
            Site = site,
            SiteId = siteId,
            Blocked = siteId is null ? "the site was never resolved, so no item lookup could be built" : null,
        };
    }

    private async Task<FileRun> ReadFileAsync(
        Identity identity,
        string file,
        List<CallRecord> calls,
        CancellationToken cancellationToken)
    {
        var run = new FileRun { File = file, Mode = identity.Mode };
        if (identity.Blocked is not null || identity.SiteId is null || identity.Token.AccessToken is null)
        {
            return run with { Blocked = identity.Blocked ?? "this identity could not be established" };
        }

        var accessToken = identity.Token.AccessToken;
        var elapsed = 0L;

        // Path -> item ID, under an ID-addressed site so no second colon segment appears.
        var itemUrl = $"{GraphBase}/sites/{identity.SiteId}/drive/root:{EscapePath(file)}";
        var item = await http.GetAsync(itemUrl, accessToken, cancellationToken);
        calls.Add(new CallRecord(identity.Mode.Display(), file, "resolve item", item));
        elapsed += item.ElapsedMs;
        run = run with { Item = item, ElapsedMs = elapsed };

        var itemId = ReadStringProperty(item, "id");
        if (itemId is null)
        {
            return run;
        }

        run = run with { ItemId = itemId };

        var permissionsUrl = $"{GraphBase}/sites/{identity.SiteId}/drive/items/{itemId}/permissions";
        var permissions = await http.GetAsync(permissionsUrl, accessToken, cancellationToken);
        calls.Add(new CallRecord(identity.Mode.Display(), file, "read permissions", permissions));
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

    /// <summary>Escapes each segment but keeps the separators, so '/my drafts/q3.docx' stays a path.</summary>
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

    private static ProbeTable BuildIdentityTable(Identity appOnly, Identity delegatedRun)
    {
        var rows = new[] { appOnly, delegatedRun }
            .Select(i => (IReadOnlyList<string?>)new[]
            {
                i.Mode.Display(),
                i.Token.StateText,
                Status(i.Site),
                i.SiteId is null ? "-" : "resolved",
                i.Site is null ? "" : i.Site.ElapsedMs.ToString(),
            })
            .ToList();

        return new ProbeTable(
            "Identities (established once, then used for every file below)",
            ["mode", "graph token", "site", "site id", "ms"],
            rows);
    }

    private static ProbeTable BuildFileTable(IReadOnlyList<FileRun> runs)
    {
        var rows = runs
            .Select(r => (IReadOnlyList<string?>)new[]
            {
                r.File,
                r.Mode.Display(),
                r.Blocked is not null ? "NotRun" : Status(r.Item),
                r.Blocked is not null ? "NotRun" : Status(r.Permissions),
                r.PermissionEntryCount?.ToString() ?? "-",
                r.PrincipalKinds.Count == 0 ? "-" : string.Join(", ", r.PrincipalKinds),
                r.ElapsedMs.ToString(),
            })
            .ToList();

        return new ProbeTable(
            "The same files, read two ways",
            ["file", "mode", "item", "permissions", "entries", "principal kinds", "ms"],
            rows);
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<CallRecord> calls)
    {
        var rows = calls
            .Select(c => (IReadOnlyList<string?>)new[]
            {
                c.Mode,
                c.File,
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
            ["mode", "file", "step", "method", "url", "status", "ms", "graph error code"],
            rows);
    }

    private static string Status(HttpObservation? observation) => observation is null ? "NotRun" : observation.StatusText;

    /// <summary>
    /// The headers actually sent, as recorded per call. Stating them once in a table heading would be a
    /// claim about the calls; this is the record of each one, and it is what makes a call reproducible
    /// by hand. The bearer value is not among them - only its length, so a reader can see a token was
    /// there without the report becoming something that must be handled carefully.
    /// </summary>
    private static string HeadersOf(HttpObservation observation) => string.Join(" | ", observation.RequestHeaders);

    /// <summary>The response headers that carry a reason. Graph uses these for refusals too.</summary>
    private static string ResponseHeadersOf(HttpObservation observation) =>
        string.Join(" | ", observation.ResponseHeaders.Select(h => $"{h.Key}: {h.Value}"));

    /// <summary>Graph puts its own code in the body; that code says more than the HTTP status alone.</summary>
    private static string ErrorCodeOf(HttpObservation observation) => ApiError.Code(observation);

    private static Observation TokenObservation(Identity identity)
    {
        var subject = $"{identity.Mode.Display()}: the Graph token";
        if (!identity.Token.Succeeded)
        {
            return Observation.Measured(subject, $"refused with {identity.Token.ErrorCode}") with
            {
                Details = Details(
                    identity.Mode,
                    ("errorCode", identity.Token.ErrorCode),
                    ("errorDetail", identity.Token.ErrorDetail)),
            };
        }

        // The delegated token is the device code sign-in, so most of its elapsed time is a person
        // reading a screen. Reporting it next to service timings without saying so invites the
        // reading that Entra took a minute and a half to answer.
        var timing = identity.Mode == ProbeMode.Delegated
            ? $"{identity.Token.ElapsedMs} ms, including the wait for the person to sign in"
            : $"{identity.Token.ElapsedMs} ms";

        return Observation.Measured(subject, $"issued ({timing})") with
        {
            Details = Details(
                identity.Mode,
                ("elapsedMs", identity.Token.ElapsedMs.ToString()),
                ("elapsedIncludesSignIn", identity.Mode == ProbeMode.Delegated ? "true" : "false"),
                ("signedInAs", identity.Token.Claims?.SignedInAs)),
        };
    }

    private static Observation SiteObservation(Identity identity)
    {
        var subject = $"{identity.Mode.Display()}: resolving the site URL to a site ID";
        if (identity.Site is null)
        {
            return Observation.NotRun(subject, "no Graph token was issued for this mode");
        }

        return Observation.Measured(
            subject,
            identity.SiteId is null
                ? $"{identity.Site.StatusText} {ErrorCodeOf(identity.Site)}".Trim()
                : $"{identity.Site.StatusText}, id resolved") with
        {
            Details = Details(
                identity.Mode,
                ("url", identity.Site.Url),
                ("requestHeaders", HeadersOf(identity.Site)),
                ("responseHeaders", ResponseHeadersOf(identity.Site)),
                ("status", identity.Site.StatusText),
                ("graphErrorCode", ErrorCodeOf(identity.Site)),
                ("elapsedMs", identity.Site.ElapsedMs.ToString())),
        };
    }

    /// <summary>
    /// Resolving the path to an item ID. Worth watching in its own right: an item the caller may not
    /// see comes back as a not-found rather than a refusal, which is the same answer a mistyped path
    /// gets. The URL and the Graph error code are both recorded so the two can still be told apart.
    /// </summary>
    private static Observation ItemObservation(FileRun run)
    {
        var subject = $"{run.File} / {run.Mode.Display()}: resolving the path to an item ID";
        if (run.Blocked is not null)
        {
            return Observation.NotRun(subject, run.Blocked);
        }

        if (run.Item is null)
        {
            return Observation.NotRun(subject, "the item lookup was never issued");
        }

        return Observation.Measured(
            subject,
            run.ItemId is null
                ? $"{run.Item.StatusText} {ErrorCodeOf(run.Item)}".Trim()
                : $"{run.Item.StatusText}, id resolved") with
        {
            Details = Details(
                run.Mode,
                ("file", run.File),
                ("url", run.Item.Url),
                ("requestHeaders", HeadersOf(run.Item)),
                ("responseHeaders", ResponseHeadersOf(run.Item)),
                ("status", run.Item.StatusText),
                ("graphErrorCode", ErrorCodeOf(run.Item)),
                ("elapsedMs", run.Item.ElapsedMs.ToString())),
        };
    }

    /// <summary>
    /// How much of an item's permission list this caller gets to see.
    /// <para>
    /// Graph does not refuse a caller who may see none of it. It answers 200 with an empty collection -
    /// the entries are filtered to what the caller may see. So the count matters independently of the
    /// status, and the two are recorded separately.
    /// </para>
    /// </summary>
    private static Observation PermissionsObservation(FileRun run)
    {
        var subject = $"{run.File} / {run.Mode.Display()}: the permission list";

        if (run.Blocked is not null)
        {
            return Observation.NotRun(subject, run.Blocked);
        }

        if (run.Permissions is null)
        {
            return Observation.NotRun(subject, "the item was never resolved, so the permission list was never requested");
        }

        var observed = run.Permissions.IsSuccess
            ? $"{run.Permissions.StatusText}, {run.PermissionEntryCount} entries, principals: " +
              (run.PrincipalKinds.Count == 0 ? "none" : string.Join(", ", run.PrincipalKinds))
            : $"{run.Permissions.StatusText} {ErrorCodeOf(run.Permissions)}".Trim();

        if (run.Permissions.IsSuccess && run.PermissionEntryCount == 0)
        {
            observed += " - an empty list, not a refusal";
        }

        return Observation.Measured(subject, observed) with
        {
            Details = Details(
                run.Mode,
                ("file", run.File),
                ("url", run.Permissions.Url),
                ("requestHeaders", HeadersOf(run.Permissions)),
                ("responseHeaders", ResponseHeadersOf(run.Permissions)),
                ("status", run.Permissions.StatusText),
                ("graphErrorCode", ErrorCodeOf(run.Permissions)),
                ("entryCount", run.PermissionEntryCount?.ToString()),
                ("principalKinds", string.Join(", ", run.PrincipalKinds)),
                ("elapsedMs", run.Permissions.ElapsedMs.ToString())),
        };
    }

    /// <summary>The two identities, set side by side, at the same moment, on the same file.</summary>
    private static Observation ContrastObservation(string file, FileRun appOnly, FileRun delegatedRun)
    {
        var subject = $"{file}: app-only vs delegated";

        if (appOnly.Blocked is not null && delegatedRun.Blocked is not null)
        {
            return Observation.NotRun(subject, "neither identity could be established");
        }

        var appItem = appOnly.Blocked is not null ? "NotRun" : Status(appOnly.Item);
        var delegatedItem = delegatedRun.Blocked is not null ? "NotRun" : Status(delegatedRun.Item);
        var appPermissions = appOnly.Blocked is not null ? "NotRun" : Status(appOnly.Permissions);
        var delegatedPermissions = delegatedRun.Blocked is not null ? "NotRun" : Status(delegatedRun.Permissions);

        // The whole point of this row has to survive a terminal column. Written short enough to read
        // at a glance, with the long form kept alongside it for whoever reads the JSON.
        var note = (appOnly.ItemId, delegatedRun.ItemId, delegatedRun.Item?.StatusCode) switch
        {
            (not null, null, 404) => "exists, but not to this caller",

            _ when appPermissions == delegatedPermissions &&
                   appOnly.PermissionEntryCount != delegatedRun.PermissionEntryCount =>
                "filtered, not empty",

            _ => null,
        };

        var explanation = note switch
        {
            "exists, but not to this caller" =>
                "the file exists and app-only reads it; the delegated caller is told it does not exist, " +
                "which is the same answer a mistyped path gets",

            "filtered, not empty" =>
                "identical status, different contents: the status alone cannot tell a list filtered down " +
                "to nothing from a file that is shared with nobody",

            _ => null,
        };

        var observed =
            $"app-only {Side(appOnly, appItem, appPermissions)}; " +
            $"delegated {Side(delegatedRun, delegatedItem, delegatedPermissions)}" +
            (note is null ? "" : $" - {note}");

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["file"] = file,
                ["appOnlyItemStatus"] = appItem,
                ["delegatedItemStatus"] = delegatedItem,
                ["appOnlyPermissionsStatus"] = appPermissions,
                ["delegatedPermissionsStatus"] = delegatedPermissions,
                ["appOnlyEntryCount"] = appOnly.PermissionEntryCount?.ToString(),
                ["delegatedEntryCount"] = delegatedRun.PermissionEntryCount?.ToString(),
                ["note"] = explanation,
            },
        };
    }

    /// <summary>One identity's answer for one file, compressed: how far it got, and how much it saw.</summary>
    private static string Side(FileRun run, string itemStatus, string permissionsStatus) =>
        run.ItemId is null
            ? itemStatus
            : $"{permissionsStatus}/{run.PermissionEntryCount?.ToString() ?? "-"}";

    private static IReadOnlyDictionary<string, string?> Details(ProbeMode mode, params (string Key, string? Value)[] extra)
    {
        var details = new Dictionary<string, string?> { ["mode"] = mode.Display() };
        foreach (var (key, value) in extra)
        {
            details[key] = value;
        }

        return details;
    }
}
