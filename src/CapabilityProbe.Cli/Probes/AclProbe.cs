using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Asks whether a page of items' access control lists can be fetched in one call instead of one call
/// per item, and what that costs.
/// <para>
/// <c>access</c> reads permissions the only way it is sure of: resolve an item, then ask that item for
/// its permission collection. That is one call per file, so reading a whole library means a call for
/// every file in it. Whether there is a cheaper route is a different question, and it had not been
/// asked. If one of these works, "read every file's ACL, every time" stops being a thing you only do
/// to a handful of files.
/// </para>
/// <para>
/// Three candidate routes, none of them known to work here:
/// Graph's <c>children</c> collection with <c>$expand=permissions</c>, Graph's <c>delta</c> with the
/// same expansion, and SharePoint's list items with <c>$expand=RoleAssignments</c>. Each is measured
/// against the one-at-a-time baseline in the same run, by the same identities, against the same
/// library.
/// </para>
/// <para>
/// Cost is not the only axis, and on its own it is the misleading one. A call that returns in a
/// quarter of the time because it quietly returned a quarter of the answer is a worse route, not a
/// better one, so every route also reports how many items came back, how many carried an ACL at all,
/// whether more pages were waiting, and - for the two Graph routes, which return the same objects the
/// baseline does - whether each item's ACL matches what reading it alone produced.
/// </para>
/// <para>
/// The SharePoint route is reported beside the others and never compared for equality with them. A
/// role assignment and a Graph permission entry are different objects describing overlapping facts;
/// treating a difference between their counts as a disagreement would be this tool asserting the two
/// models line up, which it has not measured.
/// </para>
/// </summary>
public sealed class AclProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string SharePointAccept = "application/json;odata=nometadata";

    private const string Baseline = "one at a time (children + N x permissions)";
    private const string ChildrenExpand = "Graph children?$expand=permissions";
    private const string DeltaExpand = "Graph delta?$expand=permissions";
    private const string SharePointExpand = "SP items?$expand=RoleAssignments";

    private const string RootChildren = "the root folder's children";
    private const string WholeDrive = "every item in the drive, at any depth";
    private const string WholeList = "every item in the library list, at any depth";

    /// <summary>One route as one identity found it.</summary>
    private sealed record RouteResult
    {
        public required string Route { get; init; }
        public required ProbeMode Mode { get; init; }

        /// <summary>Why this route produced nothing, or null if it ran.</summary>
        public string? Blocked { get; init; }

        public int Calls { get; init; }
        public long ElapsedMs { get; init; }
        public int? Items { get; init; }

        /// <summary>How many of those items came back carrying an ACL. Below <see cref="Items"/> means
        /// the expansion was accepted for some items and not others, or ignored entirely.</summary>
        public int? WithAcl { get; init; }

        public int? Entries { get; init; }
        public bool? MorePages { get; init; }

        /// <summary>Item ID to the shape of its ACL, for checking one route against another.</summary>
        public IReadOnlyDictionary<string, string> PerItem { get; init; } =
            new Dictionary<string, string>();

        /// <summary>What the last call answered, when the route did not get what it asked for.</summary>
        public string? Refusal { get; init; }

        /// <summary>
        /// What this route walks. The routes do not all enumerate the same set - one folder's children
        /// is not the whole library - so two of them returning different item counts is not a
        /// disagreement, and a report that showed only the counts would invite reading it as one.
        /// </summary>
        public required string Enumerates { get; init; }

        /// <summary>
        /// One line per item, so a count can be checked rather than taken on trust. Names are the
        /// file names the service returned; the members of an ACL are still only counted.
        /// </summary>
        public IReadOnlyList<string> Breakdown { get; init; } = [];

        public bool Ran => Blocked is null;
    }

    private sealed class Leg
    {
        public required ProbeMode Mode { get; init; }
        public required TokenResult GraphToken { get; init; }
        public required TokenResult SharePointToken { get; init; }
        public string? SiteId { get; set; }
        public string? Blocked { get; set; }
        public List<RouteResult> Routes { get; } = [];
        public List<HttpObservation> Calls { get; } = [];

        public RouteResult? Find(string route) => Routes.FirstOrDefault(r => r.Route == route);
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("acl");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["client"] = options.ClientId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["hint"] = options.DelegatedUserHint;

        console.WriteLine("Establishing the application identity (client credentials, shared secret)...");
        var secret = AppOnlyTokenSource.WithSecret(options);

        var certificate = AppOnlyTokenSource.WithCertificate(options);
        console.WriteLine(certificate.IsUnavailable
            ? $"Skipping the certificate identity: {certificate.Identity}"
            : "Establishing the application identity (client credentials, certificate)...");

        report.Subject["secret"] = secret.Identity;
        report.Subject["cert"] = certificate.Identity;

        var legs = new List<Leg>
        {
            new()
            {
                Mode = ProbeMode.AppOnly,
                GraphToken = await secret.GetTokenAsync(ProbeAudience.Graph, cancellationToken),
                SharePointToken = await secret.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken),
            },
            new()
            {
                Mode = ProbeMode.AppOnlyCertificate,
                GraphToken = await certificate.GetTokenAsync(ProbeAudience.Graph, cancellationToken),
                SharePointToken = await certificate.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken),
            },
        };

        var delegatedSource = new DelegatedTokenSource(options, console);
        console.WriteLine(delegatedSource.Enabled
            ? "Establishing the delegated identity (device code)..."
            : $"Not establishing a delegated identity: Identities is '{ProbeOptions.AppOnlyIdentities}'.");
        var signIn = await delegatedSource.SignInAsync(cancellationToken);

        report.Subject["signed in"] = delegatedSource.SignedInSummary;

        if (delegatedSource.IncompleteReason is { } incomplete)
        {
            report.MarkIncomplete(incomplete);
        }

        legs.Add(new Leg
        {
            Mode = ProbeMode.Delegated,
            GraphToken = signIn.Succeeded ? await delegatedSource.GetTokenAsync(ProbeAudience.Graph, cancellationToken) : signIn,
            SharePointToken = signIn.Succeeded
                ? await delegatedSource.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken)
                : signIn with { Audience = ProbeAudience.SharePoint },
        });

        foreach (var leg in legs)
        {
            console.WriteLine($"Measuring the routes as {leg.Mode.Display()}...");
            await ResolveSiteAsync(leg, cancellationToken);

            leg.Routes.Add(await BaselineAsync(leg, cancellationToken));
            leg.Routes.Add(await GraphBulkAsync(leg, ChildrenExpand, "/drive/root/children?$expand=permissions", RootChildren, cancellationToken));
            leg.Routes.Add(await GraphBulkAsync(leg, DeltaExpand, "/drive/root/delta?$expand=permissions", WholeDrive, cancellationToken));
            leg.Routes.Add(await SharePointBulkAsync(leg, cancellationToken));
        }

        report.Add(BuildCostTable(legs));
        report.Add(BuildAgreementTable(legs));
        report.Add(BuildCallTable(legs));

        foreach (var leg in legs)
        {
            foreach (var route in leg.Routes)
            {
                report.Add(RouteObservation(leg, route));
            }

            report.Add(VerdictObservation(leg));
        }

        report.Finish();
        return report;
    }

    private async Task ResolveSiteAsync(Leg leg, CancellationToken cancellationToken)
    {
        if (!leg.GraphToken.Succeeded || leg.GraphToken.AccessToken is null)
        {
            leg.Blocked = leg.GraphToken.Requested
                ? $"no Graph token was issued for this mode: {leg.GraphToken.ErrorCode}"
                : $"this identity never asked for a token: {leg.GraphToken.ErrorDetail}";
            return;
        }

        var relativePath = options.SiteServerRelativePath;
        var url = string.IsNullOrEmpty(relativePath)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relativePath)}";

        // Outside every route's cost. Both the baseline and the bulk routes need it, so counting it
        // against either would flatter the comparison rather than measure it.
        var site = await http.GetAsync(url, leg.GraphToken.AccessToken, cancellationToken);
        leg.Calls.Add(site);

        leg.SiteId = ReadString(site, "id");
        if (leg.SiteId is null)
        {
            leg.Blocked = $"the site was never resolved ({site.StatusText}), so no route could be built";
        }
    }

    /// <summary>
    /// What <c>access</c> already does, done to a page rather than to a named list of files: list the
    /// folder, then ask each item for its permissions. This is the thing the other routes have to beat,
    /// and the thing their answers are checked against.
    /// </summary>
    private async Task<RouteResult> BaselineAsync(Leg leg, CancellationToken cancellationToken)
    {
        if (leg.Blocked is not null || leg.SiteId is null || leg.GraphToken.AccessToken is null)
        {
            return Blocked(Baseline, RootChildren, leg);
        }

        var token = leg.GraphToken.AccessToken;
        var children = await http.GetAsync($"{GraphBase}/sites/{leg.SiteId}/drive/root/children", token, cancellationToken);
        leg.Calls.Add(children);

        var page = AclResponses.GraphPage(children);
        if (page is null)
        {
            return new RouteResult
            {
                Route = Baseline,
                Mode = leg.Mode,
                Enumerates = RootChildren,
                Calls = 1,
                ElapsedMs = children.ElapsedMs,
                Refusal = Describe(children),
            };
        }

        var calls = 1;
        var elapsed = children.ElapsedMs;
        var perItem = new Dictionary<string, string>(StringComparer.Ordinal);
        var breakdown = new List<string>();
        var entries = 0;
        var withAcl = 0;

        foreach (var item in page.Items)
        {
            var permissions = await http.GetAsync(
                $"{GraphBase}/sites/{leg.SiteId}/drive/items/{item.Id}/permissions", token, cancellationToken);
            leg.Calls.Add(permissions);
            calls++;
            elapsed += permissions.ElapsedMs;

            var acl = AclResponses.Permissions(permissions);
            if (acl is null)
            {
                perItem[item.Id] = $"unread ({permissions.StatusText})";
                breakdown.Add($"{item.Name ?? item.Id}: unread ({permissions.StatusText})");
                continue;
            }

            withAcl++;
            entries += acl.Count;
            perItem[item.Id] = acl.Fingerprint;
            breakdown.Add($"{item.Name ?? item.Id}: {acl.Fingerprint}");
        }

        return new RouteResult
        {
            Route = Baseline,
            Mode = leg.Mode,
            Enumerates = RootChildren,
            Calls = calls,
            ElapsedMs = elapsed,
            Items = page.Items.Count,
            WithAcl = withAcl,
            Entries = entries,
            MorePages = page.MorePages,
            PerItem = perItem,
            Breakdown = breakdown,
        };
    }

    private async Task<RouteResult> GraphBulkAsync(
        Leg leg, string route, string path, string enumerates, CancellationToken cancellationToken)
    {
        if (leg.Blocked is not null || leg.SiteId is null || leg.GraphToken.AccessToken is null)
        {
            return Blocked(route, enumerates, leg);
        }

        var observation = await http.GetAsync(
            $"{GraphBase}/sites/{leg.SiteId}{path}", leg.GraphToken.AccessToken, cancellationToken);
        leg.Calls.Add(observation);

        var page = AclResponses.GraphPage(observation);
        if (page is null)
        {
            return new RouteResult
            {
                Route = route,
                Mode = leg.Mode,
                Enumerates = enumerates,
                Calls = 1,
                ElapsedMs = observation.ElapsedMs,
                Refusal = Describe(observation),
            };
        }

        return new RouteResult
        {
            Route = route,
            Mode = leg.Mode,
            Enumerates = enumerates,
            Calls = 1,
            ElapsedMs = observation.ElapsedMs,
            Items = page.Items.Count,
            WithAcl = page.Expanded,
            Entries = page.TotalEntries,
            MorePages = page.MorePages,
            PerItem = page.Items
                .Where(i => i.Permissions is not null)
                .ToDictionary(i => i.Id, i => i.Permissions!.Fingerprint, StringComparer.Ordinal),
            Breakdown = Describe(page),
        };
    }

    /// <summary>
    /// The SharePoint route. It needs the library's server-relative path, which comes from Graph's
    /// answer for the same drive - so the two APIs are pointed at the same library rather than at
    /// whatever each of them would have picked. That discovery call is counted, because a route that
    /// cannot be built without a second API is more expensive than one that can.
    /// </summary>
    private async Task<RouteResult> SharePointBulkAsync(Leg leg, CancellationToken cancellationToken)
    {
        if (leg.Blocked is not null || leg.SiteId is null || leg.GraphToken.AccessToken is null)
        {
            return Blocked(SharePointExpand, WholeList, leg);
        }

        if (!leg.SharePointToken.Succeeded || leg.SharePointToken.AccessToken is null)
        {
            return new RouteResult
            {
                Route = SharePointExpand,
                Mode = leg.Mode,
                Enumerates = WholeList,
                Blocked = leg.SharePointToken.Requested
                    ? $"no SharePoint token was issued for this mode: {leg.SharePointToken.ErrorCode}"
                    : $"this identity never asked for a SharePoint token: {leg.SharePointToken.ErrorDetail}",
            };
        }

        var drive = await http.GetAsync(
            $"{GraphBase}/sites/{leg.SiteId}/drive", leg.GraphToken.AccessToken, cancellationToken);
        leg.Calls.Add(drive);

        var libraryPath = AclResponses.DriveServerRelativePath(drive);
        if (libraryPath is null)
        {
            return new RouteResult
            {
                Route = SharePointExpand,
                Mode = leg.Mode,
                Enumerates = WholeList,
                Calls = 1,
                ElapsedMs = drive.ElapsedMs,
                Refusal = $"the library path was never discovered ({Describe(drive)})",
            };
        }

        var url = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')" +
                  "/items?$expand=RoleAssignments&$top=100";

        var items = await http.GetAsync(url, leg.SharePointToken.AccessToken, cancellationToken, SharePointAccept);
        leg.Calls.Add(items);

        var page = AclResponses.SharePointPage(items);
        if (page is null)
        {
            return new RouteResult
            {
                Route = SharePointExpand,
                Mode = leg.Mode,
                Enumerates = WholeList,
                Calls = 2,
                ElapsedMs = drive.ElapsedMs + items.ElapsedMs,
                Refusal = Describe(items),
            };
        }

        return new RouteResult
        {
            Route = SharePointExpand,
            Mode = leg.Mode,
            Enumerates = WholeList,
            Calls = 2,
            ElapsedMs = drive.ElapsedMs + items.ElapsedMs,
            Items = page.Items.Count,
            WithAcl = page.Expanded,
            Entries = page.TotalEntries,
            MorePages = page.MorePages,
            Breakdown = Describe(page),
        };
    }

    /// <summary>
    /// One line per item: what it is called, and how big its ACL was. It is the difference between a
    /// route that returned five items and a route that returned four being inspectable rather than
    /// argued about.
    /// </summary>
    private static IReadOnlyList<string> Describe(AclResponses.Page page) =>
        page.Items
            .Select(i => $"{i.Name ?? i.Id}: {i.Permissions?.Fingerprint ?? "(no acl)"}")
            .ToList();

    private static RouteResult Blocked(string route, string enumerates, Leg leg) =>
        new()
        {
            Route = route,
            Mode = leg.Mode,
            Enumerates = enumerates,
            Blocked = leg.Blocked ?? "this identity could not be established",
        };

    /// <summary>
    /// Why a route produced no page. A refusal and a success whose body could not be read are
    /// different things and used to print the same way - the second one arrived as
    /// "200 OK: &lt;some diagnostic header&gt;", which reads like the service said no.
    /// </summary>
    private static string Describe(HttpObservation observation)
    {
        if (observation.IsSuccess)
        {
            return observation.BodyTruncated
                ? $"{observation.StatusText}, but the probe cut the body short before it could be read"
                : $"{observation.StatusText}, but the body held no collection this could read";
        }

        var code = ApiError.Code(observation);
        var message = code.Length > 0 ? code : observation.RefusalDiagnostic ?? "no reason given";
        return $"{observation.StatusText}: {message}";
    }

    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/').Select(Uri.EscapeDataString));

    private static string? ReadString(HttpObservation observation, string propertyName)
    {
        if (!observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.TryGetProperty(propertyName, out var value) &&
                   value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static ProbeTable BuildCostTable(IReadOnlyList<Leg> legs)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var leg in legs)
        {
            foreach (var route in leg.Routes)
            {
                rows.Add(new[]
                {
                    route.Route,
                    route.Enumerates,
                    leg.Mode.Display(),
                    route.Ran ? route.Calls.ToString() : "-",
                    route.Ran ? route.ElapsedMs.ToString() : "-",
                    route.Items?.ToString() ?? "-",
                    route.WithAcl?.ToString() ?? "-",
                    route.Entries?.ToString() ?? "-",
                    route.MorePages switch { true => "yes", false => "no", null => "-" },
                    route.Blocked ?? route.Refusal ?? "",
                });
            }
        }

        return new ProbeTable(
            "What each route cost (site resolution is excluded - every route needs it)",
            ["route", "walks", "mode", "calls", "ms", "items", "with acl", "acl entries", "more pages", "why not"],
            rows);
    }

    /// <summary>
    /// Whether a bulk answer says the same thing as reading the items one at a time.
    /// <para>
    /// Cheaper is only better if it is also the same. The comparison is by item ID and by the shape of
    /// each ACL - how many entries and what kinds of principal - so it catches a route that returns
    /// fewer items, or the same items with a thinner ACL, without either report naming anybody.
    /// </para>
    /// <para>
    /// The SharePoint route is absent from this table on purpose. It returns role assignments, which
    /// are not the objects the baseline counted, and its list item IDs are not the drive item IDs the
    /// baseline keyed on. There is nothing here it could be lined up against without an assumption.
    /// </para>
    /// </summary>
    private static ProbeTable BuildAgreementTable(IReadOnlyList<Leg> legs)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var leg in legs)
        {
            var baseline = leg.Find(Baseline);

            foreach (var route in new[] { ChildrenExpand, DeltaExpand })
            {
                var candidate = leg.Find(route);
                if (baseline is null || candidate is null || !baseline.Ran || !candidate.Ran)
                {
                    rows.Add(new[] { route, leg.Mode.Display(), "NotRun", "-", "-", "-", "-" });
                    continue;
                }

                var same = baseline.PerItem.Count(p =>
                    candidate.PerItem.TryGetValue(p.Key, out var other) && other == p.Value);
                var differ = baseline.PerItem.Count(p =>
                    candidate.PerItem.TryGetValue(p.Key, out var other) && other != p.Value);
                var onlyBaseline = baseline.PerItem.Keys.Count(k => !candidate.PerItem.ContainsKey(k));
                var onlyCandidate = candidate.PerItem.Keys.Count(k => !baseline.PerItem.ContainsKey(k));

                // Nothing on either side is not agreement. Two routes that both produced no ACL at
                // all would otherwise be reported as saying the same thing, which they are - and it
                // is the least informative true statement available.
                var verdict = (baseline.PerItem.Count, candidate.PerItem.Count) switch
                {
                    (0, 0) => "nothing to compare - neither produced an ACL",
                    (0, _) => "nothing to compare - one at a time produced no ACL",
                    (_, 0) => "nothing to compare - the bulk route produced no ACL",
                    _ when differ == 0 && onlyBaseline == 0 => "identical",
                    _ => "differs",
                };

                rows.Add(new[]
                {
                    route,
                    leg.Mode.Display(),
                    verdict,
                    same.ToString(),
                    differ.ToString(),
                    onlyBaseline.ToString(),
                    onlyCandidate.ToString(),
                });
            }
        }

        return new ProbeTable(
            "Do the bulk answers match reading one at a time (by item id, entry count and principal kinds)",
            ["route", "mode", "verdict of the comparison", "same", "different", "only one-at-a-time", "only bulk"],
            rows);
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<Leg> legs)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var leg in legs)
        {
            foreach (var call in leg.Calls)
            {
                rows.Add(new[]
                {
                    leg.Mode.Display(),
                    call.Method,
                    call.Url,
                    call.StatusText,
                    call.ElapsedMs.ToString(),
                    ApiError.Code(call),
                });
            }
        }

        return new ProbeTable(
            "Calls issued (each carried 'Authorization: Bearer <token>'; Accept differs per API, see details)",
            ["mode", "method", "url", "status", "ms", "error code"],
            rows);
    }

    private static Observation RouteObservation(Leg leg, RouteResult route)
    {
        var subject = $"{route.Route} / {leg.Mode.Display()}";

        if (!route.Ran)
        {
            return Observation.NotRun(subject, route.Blocked!);
        }

        var observed = route.Items is null
            ? $"no page came back - {route.Refusal ?? "the answer could not be read"} " +
              $"({route.Calls} calls, {route.ElapsedMs} ms)"
            : $"{route.Items} items, {route.WithAcl} of them carrying an ACL, {route.Entries} entries " +
              $"in {route.Calls} calls / {route.ElapsedMs} ms" +
              (route.MorePages == true ? " - more pages were waiting" : "");

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["route"] = route.Route,
                ["mode"] = leg.Mode.Display(),
                ["calls"] = route.Calls.ToString(),
                ["elapsedMs"] = route.ElapsedMs.ToString(),
                ["items"] = route.Items?.ToString(),
                ["itemsWithAcl"] = route.WithAcl?.ToString(),
                ["aclEntries"] = route.Entries?.ToString(),
                ["morePages"] = route.MorePages?.ToString(),
                ["enumerates"] = route.Enumerates,
                ["breakdown"] = route.Breakdown.Count == 0 ? null : string.Join(" | ", route.Breakdown),
                ["refusal"] = route.Refusal,
                ["perItem"] = route.PerItem.Count == 0
                    ? null
                    : string.Join(" | ", route.PerItem.OrderBy(p => p.Key, StringComparer.Ordinal)
                        .Select(p => $"{p.Key}={p.Value}")),
            },
        };
    }

    /// <summary>
    /// The one line this subcommand exists to produce: for this identity, what reading every item's
    /// ACL costs each way, per item. Stated as a rate because that is the number that decides whether
    /// doing it to a whole library is reasonable - a route that halves the calls on four files halves
    /// them on four thousand.
    /// </summary>
    private static Observation VerdictObservation(Leg leg)
    {
        var subject = $"{leg.Mode.Display()}: what reading every item's ACL costs";
        var baseline = leg.Find(Baseline);

        if (baseline is null || !baseline.Ran || baseline.Items is null)
        {
            return Observation.NotRun(subject, leg.Blocked ?? "the one-at-a-time baseline never produced a page");
        }

        var usable = leg.Routes
            .Where(r => r.Route != Baseline && r.Ran && r.Items is > 0 && r.WithAcl > 0)
            .ToList();

        var observed = usable.Count == 0
            ? $"one at a time: {baseline.Calls} calls for {baseline.Items} items " +
              $"({baseline.ElapsedMs} ms); no bulk route returned an ACL"
            : $"one at a time: {baseline.Calls} calls / {baseline.ElapsedMs} ms; " +
              string.Join("; ", usable.Select(r =>
                  $"{Short(r.Route)}: {r.Calls} calls / {r.ElapsedMs} ms"));

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["mode"] = leg.Mode.Display(),
                ["items"] = baseline.Items.ToString(),
                ["baselineCalls"] = baseline.Calls.ToString(),
                ["baselineCallsPerItem"] = Rate(baseline.Calls, baseline.Items.Value),
                ["baselineMs"] = baseline.ElapsedMs.ToString(),
                ["note"] = usable.Count == 0
                    ? "every bulk route either refused or returned items without an ACL, so reading each " +
                      "item on its own is the only route measured to work for this identity"
                    : "the bulk routes answered in a fixed number of calls regardless of how many items " +
                      "the page held; see the agreement table for whether they answered the same thing",
            }.Concat(usable.SelectMany(r => new Dictionary<string, string?>
            {
                [$"{Short(r.Route)}Calls"] = r.Calls.ToString(),
                [$"{Short(r.Route)}CallsPerItem"] = Rate(r.Calls, r.Items!.Value),
                [$"{Short(r.Route)}Ms"] = r.ElapsedMs.ToString(),
            })).ToDictionary(p => p.Key, p => p.Value),
        };
    }

    private static string Rate(int calls, int items) =>
        items == 0 ? "-" : (calls / (double)items).ToString("0.00");

    private static string Short(string route) => route switch
    {
        ChildrenExpand => "children",
        DeltaExpand => "delta",
        SharePointExpand => "spItems",
        _ => route,
    };
}
