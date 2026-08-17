using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Whether an app-only call to <c>driveItem/permissions</c> is being shown everything.
/// <para>
/// Graph documents the collection as filtered by who is asking: the item's owner is shown every
/// grant, anyone else only the grants that apply to them. It does not say which of the two an
/// app-only caller is, and <c>200 OK</c> looks the same either way - so a count cannot answer it and
/// a second reading of the same item is required.
/// </para>
/// <para>
/// The request this was built for asked for that second reading to be the owner's own delegated
/// session, on the strength of the documentation's claim about owners. That is not reachable in this
/// tenant: security defaults refuse the device code flow with <c>AADSTS530035</c> (finding 7, and it
/// still refuses - measured again on two accounts). So the comparison is made against SharePoint's
/// own role assignments instead, read with the certificate identity that finding 8 measured getting
/// through.
/// </para>
/// <para>
/// That substitution changes what can be claimed, and the change is in the report rather than left
/// for a reader to notice. The documented baseline rests on believing what the documentation says
/// about owners; this one rests on reading what the list actually carries. It is a different
/// question - "is Graph showing everything SharePoint holds" rather than "is app-only owner-equivalent"
/// - and arguably the sturdier one, but it is not the question that was asked.
/// </para>
/// </summary>
public sealed class PermissionsProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    private const string SharePointAccept = "application/json;odata=nometadata";

    /// <summary>
    /// The same projection <c>inventory</c> uses, so the two subcommands read one shape of answer.
    /// A difference between them would then be about the items and not about two copies of an idea.
    /// </summary>
    private const string SharingQuery =
        "$select=Id,FileLeafRef,FileRef,HasUniqueRoleAssignments" +
        "&$expand=RoleAssignments/Member,RoleAssignments/RoleDefinitionBindings";

    private sealed record Target
    {
        public required string Path { get; init; }

        /// <summary>
        /// True for the library root rather than a file in it. The root is where a grant is placed
        /// when it is meant to reach everything inheriting, so what sits there is what every
        /// inheriting file's Limited Access rows are an echo of - which makes it worth reading whole
        /// rather than inferring from the files.
        /// </summary>
        public bool IsRoot { get; init; }

        public string? ItemId { get; set; }
        public string? ListItemId { get; set; }
        public string? Name { get; set; }
        public string? PlacedBy { get; set; }
        public bool? UniqueRoleAssignments { get; set; }

        /// <summary>Why this file has no rows, when it has none. Never left to be inferred.</summary>
        public string? Unreadable { get; set; }

        public List<GrantParty> Graph { get; } = [];
        public List<GrantParty> SharePoint { get; } = [];

        public string? GraphRefusal { get; set; }
        public string? SharePointRefusal { get; set; }
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("permissions");
        var app = options.InventoryApp;

        report.Subject["tenant"] = options.TenantId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["speaking as"] = app.Label;
        report.Subject["comparing"] = "Graph driveItem/permissions against SharePoint's role assignments, " +
                                      "both app-only, in one run";
        report.Subject["not comparing"] = "the item owner's own delegated reading - security defaults " +
                                          "refuse the device code flow in this tenant (finding 7)";

        var source = AppOnlyTokenSource.WithCertificate(options, app);
        if (source.IsUnavailable)
        {
            console.WriteLine($"No certificate for {app.Label}: {source.Identity}. Falling back to the secret.");
            source = AppOnlyTokenSource.WithSecret(options, app);
        }

        report.Subject["proof of identity"] = source.Identity;

        var caller = new ThrottleAwareCaller(http);
        var calls = new List<HttpObservation>();

        var graph = await source.GetTokenAsync(ProbeAudience.Graph, cancellationToken);
        var sharePoint = await source.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken);

        report.Subject["Graph token"] = Describe(graph);
        report.Subject["SharePoint token"] = Describe(sharePoint);

        if (!graph.Succeeded || graph.AccessToken is null)
        {
            report.MarkIncomplete($"no Graph token: {graph.ErrorCode}");
            report.Add(Observation.NotRun("both readings", $"no Graph token was issued: {graph.ErrorDetail}"));
            report.Finish();
            return report;
        }

        console.WriteLine("Resolving the site and the library...");
        var site = await caller.GetAsync(SiteUrl(), graph.AccessToken, cancellationToken);
        calls.Add(site);

        var siteId = ReadString(site, "id");
        if (siteId is null)
        {
            report.MarkIncomplete("the site was never resolved");
            report.Add(Observation.NotRun("both readings", $"the site was never resolved ({site.StatusText})"));
            report.Add(BuildCallTable(calls));
            report.Finish();
            return report;
        }

        var drive = await caller.GetAsync($"{GraphBase}/sites/{siteId}/drive", graph.AccessToken, cancellationToken);
        calls.Add(drive);

        var driveId = ReadString(drive, "id");
        var libraryPath = AclResponses.DriveServerRelativePath(drive);

        var targets = options.Files.Select(p => new Target { Path = p }).ToList();
        targets.Add(new Target { Path = "(the library root)", IsRoot = true });

        foreach (var target in targets)
        {
            console.WriteLine($"Reading {target.Path}...");
            await ReadGraphAsync(caller, driveId, target, graph.AccessToken, calls, report, cancellationToken);

            if (target.IsRoot)
            {
                // Deliberately one-sided. The baseline this run compares against is a file's role
                // assignments, and the list's own are a different collection with a different shape -
                // reading them here would put two unlike things in one column and call it agreement.
                target.SharePointRefusal =
                    "not read - the root's SharePoint counterpart is the list's own role assignments, " +
                    "which is a different collection from a file's and is not what this run compares";
                continue;
            }

            await ReadSharePointAsync(caller, libraryPath, target, sharePoint, calls, cancellationToken);
        }

        report.Subject["throttling"] = caller.Record.Summary;

        report.Add(BuildFileTable(targets));
        report.Add(BuildSideTable("What Graph returned, app-only", targets, t => t.Graph));
        report.Add(BuildSideTable("What SharePoint's role assignments hold", targets, t => t.SharePoint));
        report.Add(BuildSubtraction(targets));
        report.Add(BuildUnjoinable(targets));
        report.Add(BuildCallTable(calls));

        foreach (var target in targets)
        {
            report.Add(FileObservation(target));
        }

        report.Add(LimitedAccessObservation(targets));
        report.Add(FullnessObservation(targets));
        report.Add(KindObservation(targets));
        report.Add(BaselineObservation());
        report.Finish();
        return report;
    }

    private async Task ReadGraphAsync(
        ThrottleAwareCaller caller,
        string? driveId,
        Target target,
        string token,
        List<HttpObservation> calls,
        ProbeReport report,
        CancellationToken cancellationToken)
    {
        if (driveId is null)
        {
            target.Unreadable = "the drive was never resolved, so no item could be addressed";
            return;
        }

        var address = target.IsRoot
            ? $"{GraphBase}/drives/{driveId}/root?$select=id,name,createdBy,sharepointIds"
            : $"{GraphBase}/drives/{driveId}/root:/" +
              string.Join('/', target.Path.TrimStart('/').Split('/').Select(Uri.EscapeDataString)) +
              "?$select=id,name,createdBy,sharepointIds";

        var item = await caller.GetAsync(address, token, cancellationToken);
        calls.Add(item);

        var root = Root(item);
        if (root is null)
        {
            target.Unreadable = $"the item was never resolved ({item.StatusText})";
            return;
        }

        target.ItemId = Text(root.Value, "id");
        target.Name = Text(root.Value, "name");
        target.PlacedBy = PlacedBy(root.Value);
        target.ListItemId = root.Value.TryGetProperty("sharepointIds", out var ids) &&
                            ids.ValueKind == JsonValueKind.Object
            ? Text(ids, "listItemId")
            : null;

        if (target.ItemId is null)
        {
            target.Unreadable = "the item resolved but carried no id";
            return;
        }

        var permissions = await caller.GetAsync(
            $"{GraphBase}/drives/{driveId}/items/{target.ItemId}/permissions", token, cancellationToken);
        calls.Add(permissions);

        var body = Root(permissions);
        if (body is null || !body.Value.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            target.GraphRefusal = string.IsNullOrWhiteSpace(permissions.Body)
                ? $"{permissions.StatusText}, no body"
                : permissions.Body;
            return;
        }

        target.Graph.AddRange(GrantParty.FromGraph(value));

        // Every entry, whole. The request asks whether anything besides `roles` marks a grant as
        // Limited Access - and "nothing does" is only sayable from the entry as it arrived, not from
        // the fields this tool happens to read. A key nobody looked for is not a key that is absent.
        var index = 0;
        foreach (var entry in value.EnumerateArray())
        {
            index++;
            report.Quote($"Graph /permissions on {target.Path}, entry {index} of {value.GetArrayLength()}",
                Indent(entry));
        }

        if (value.GetArrayLength() == 0)
        {
            report.Quote($"Graph /permissions on {target.Path}",
                "200 OK, and the collection was empty. No entry to quote");
        }
    }

    /// <summary>One permission entry as it arrived, indented so a reader can see where it ends.</summary>
    private static string Indent(JsonElement entry) =>
        string.Join("\n", JsonSerializer
            .Serialize(entry, new JsonSerializerOptions { WriteIndented = true })
            .Split('\n')
            .Select(line => $"  {line.TrimEnd()}"));

    /// <summary>
    /// The same item read the other way. Asked for through the collection with a filter rather than
    /// by addressing the item directly, so the body has the shape <see cref="InventorySharing"/>
    /// already reads - the parsing that produced findings 15 and 16 is reused rather than rewritten
    /// for one caller.
    /// </summary>
    private async Task ReadSharePointAsync(
        ThrottleAwareCaller caller,
        string? libraryPath,
        Target target,
        TokenResult sharePoint,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        if (!sharePoint.Succeeded || sharePoint.AccessToken is null)
        {
            target.SharePointRefusal = $"no SharePoint token was issued: {sharePoint.ErrorCode}";
            return;
        }

        if (libraryPath is null)
        {
            target.SharePointRefusal = "the library path was never discovered";
            return;
        }

        if (target.ListItemId is null)
        {
            target.SharePointRefusal = "Graph returned no sharepointIds.listItemId, so the two APIs " +
                                       "could not be pointed at the same item";
            return;
        }

        var url = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')" +
                  $"/items?{SharingQuery}&$filter=Id eq {Uri.EscapeDataString(target.ListItemId)}";

        var observation = await caller.GetAsync(url, sharePoint.AccessToken, cancellationToken, SharePointAccept);
        calls.Add(observation);

        var page = InventorySharing.ReadPage(observation);
        if (page is null)
        {
            target.SharePointRefusal = string.IsNullOrWhiteSpace(observation.Body)
                ? $"{observation.StatusText}, no body"
                : observation.Body;
            return;
        }

        if (page.Items == 0)
        {
            target.SharePointRefusal = "the filter matched no list item";
            return;
        }

        target.UniqueRoleAssignments = page.Grants.Select(g => g.HasUniqueRoleAssignments).FirstOrDefault();
        target.SharePoint.AddRange(GrantParty.FromSharePoint(page.Grants));
    }

    private static ProbeTable BuildFileTable(IReadOnlyList<Target> targets) =>
        new("The files, and whether both readings were obtained",
            ["path", "list item", "placed by", "unique permissions", "Graph", "SharePoint"],
            targets.Select(t => (IReadOnlyList<string?>)new[]
            {
                t.Path,
                t.ListItemId ?? "-",
                t.PlacedBy ?? "-",
                t.UniqueRoleAssignments switch { true => "yes", false => "no (inherited)", null => "-" },
                t.Unreadable is not null ? $"not read - {t.Unreadable}"
                    : t.GraphRefusal is not null ? "refused - see below"
                    : $"{t.Graph.Count} entries",
                t.SharePointRefusal is not null ? "not read - see below" : $"{t.SharePoint.Count} assignments",
            }).ToList());

    private static ProbeTable BuildSideTable(
        string title,
        IReadOnlyList<Target> targets,
        Func<Target, IReadOnlyList<GrantParty>> pick)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var target in targets)
        {
            var parties = pick(target);
            if (parties.Count == 0)
            {
                rows.Add([target.Path, "(nothing was read)", "-", "-", "-"]);
                continue;
            }

            foreach (var party in parties)
            {
                rows.Add([target.Path, party.Kind, party.Name, party.Detail, party.KeyList]);
            }
        }

        return new ProbeTable(title, ["path", "kind", "principal", "grant", "keys"],
            rows.Count == 0 ? [["(no files were read)", "-", "-", "-", "-"]] : rows);
    }

    /// <summary>
    /// The comparison itself. One row per grant on either side, with the side it appeared on - the
    /// same subtraction shape <c>delta</c> uses, and for the same reason: a difference that has to be
    /// found by reading two lists is a difference a reader can miss.
    /// </summary>
    private static ProbeTable BuildSubtraction(IReadOnlyList<Target> targets)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var target in targets)
        {
            foreach (var party in target.Graph.Where(p => p.CanJoin))
            {
                var other = party.PartyIn(target.SharePoint);
                var match = party.MatchIn(target.SharePoint);
                rows.Add([
                    target.Path, party.Kind, party.Name, "yes",
                    match is null ? "no" : "yes",
                    $"{party.Detail} | {other?.Detail ?? "-"}",
                    match ?? "(no key in common)",
                    match is null ? "only Graph" : "both",
                ]);
            }

            foreach (var party in target.SharePoint.Where(p => p.CanJoin))
            {
                if (party.MatchIn(target.Graph) is not null)
                {
                    continue;
                }

                rows.Add([
                    target.Path, party.Kind, party.Name, "no", "yes",
                    $"- | {party.Detail}",
                    "(no key in common)", "only SharePoint",
                ]);
            }
        }

        return new ProbeTable(
            "The subtraction - grants naming a directory principal, on both sides",
            ["path", "kind", "principal", "in Graph", "in SharePoint", "grant (Graph | SharePoint)",
             "matched on", "side"],
            rows.Count == 0 ? [["(nothing could be joined)", "-", "-", "-", "-", "-", "-", "-"]] : rows);
    }

    /// <summary>
    /// What the subtraction had to leave out, and why. Sharing links land here by design: both APIs
    /// report them and neither offers the other's identifier, so they are counted per side and the
    /// report says the identities were not joined rather than pretending they were.
    /// </summary>
    private static ProbeTable BuildUnjoinable(IReadOnlyList<Target> targets)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var target in targets)
        {
            foreach (var (side, party) in target.Graph.Select(p => ("Graph", p))
                         .Concat(target.SharePoint.Select(p => ("SharePoint", p))))
            {
                if (party.CanJoin)
                {
                    continue;
                }

                rows.Add([target.Path, side, party.Kind, party.Name, party.Detail, party.KeyBasis]);
            }

            if (target.GraphRefusal is not null)
            {
                rows.Add([target.Path, "Graph", "(nothing was read)", "-", "-", target.GraphRefusal]);
            }

            if (target.SharePointRefusal is not null)
            {
                rows.Add([target.Path, "SharePoint", "(nothing was read)", "-", "-", target.SharePointRefusal]);
            }
        }

        return new ProbeTable(
            "What the subtraction left out, and why",
            ["path", "side", "kind", "principal", "grant", "why"],
            rows.Count == 0 ? [["(every row on both sides carried a key)", "-", "-", "-", "-", "-"]] : rows);
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)new[]
            {
                c.Method, c.Url, c.StatusText, c.ElapsedMs.ToString(), ApiError.Code(c),
            }).ToList());

    private static Observation FileObservation(Target target)
    {
        if (target.Unreadable is not null)
        {
            return Observation.NotRun(target.Path, target.Unreadable);
        }

        var graphJoinable = target.Graph.Count(p => p.CanJoin);
        var sharePointJoinable = target.SharePoint.Count(p => p.CanJoin);
        var onlyInSharePoint = target.SharePoint.Where(p => p.CanJoin && p.MatchIn(target.Graph) is null).ToList();
        var onlySharePoint = onlyInSharePoint.Count;
        var conveyingNone = onlyInSharePoint.Count(p => p.ConveysAccess == false);
        var onlyGraph = target.Graph.Count(p => p.CanJoin && p.MatchIn(target.SharePoint) is null);

        // The subtraction leads, the inventory follows: this cell is clipped to the column width, and
        // what a reader needs is the difference and whether it conveys anything, not the totals.
        var observed = target.GraphRefusal is not null || target.SharePointRefusal is not null
            ? "one of the two readings did not arrive, so this file was not compared"
            : $"{onlyGraph} only in Graph, {onlySharePoint} only in SharePoint" +
              (conveyingNone == 0 ? string.Empty : $" ({conveyingNone} conveying none)") +
              $"; {target.Graph.Count} Graph entries ({graphJoinable} joinable), " +
              $"{target.SharePoint.Count} SharePoint assignments ({sharePointJoinable} joinable)";

        return Observation.Measured(target.Path, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["listItemId"] = target.ListItemId,
                ["placedBy"] = target.PlacedBy,
                ["uniqueRoleAssignments"] = target.UniqueRoleAssignments?.ToString(),
                ["graphEntries"] = target.Graph.Count.ToString(),
                ["sharePointAssignments"] = target.SharePoint.Count.ToString(),
                ["graphRefusal"] = target.GraphRefusal,
                ["sharePointRefusal"] = target.SharePointRefusal,
            },
        };
    }

    /// <summary>
    /// What Graph says about the principals SharePoint marks as conveying nothing.
    /// <para>
    /// Graph reduces a role to <c>owner</c> / <c>read</c> / <c>write</c>, and Limited Access is none
    /// of those three - so either the principal does not appear, in which case Graph has dropped a row
    /// that grants nothing and no harm follows, or it appears as one of the three and the distinction
    /// finding 15 rests on is gone with nothing in the reply to rebuild it from. Which of those two it
    /// is decides whether an ACL can be read from Graph at all, so it is answered here rather than
    /// left to be worked out from the tables.
    /// </para>
    /// </summary>
    private static Observation LimitedAccessObservation(IReadOnlyList<Target> targets)
    {
        var pairs = targets
            .Where(t => t.SharePointRefusal is null && t.GraphRefusal is null)
            .SelectMany(t => t.SharePoint
                .Where(p => p.CanJoin && p.ConveysAccess == false)
                .Select(p => (t.Path, Party: p, InGraph: p.PartyIn(t.Graph))))
            .ToList();

        if (pairs.Count == 0)
        {
            return Observation.NotRun("what Graph says about a Limited Access holder",
                "no file in this run had a grant SharePoint marks as conveying nothing, so there was " +
                "nothing to look up. The roles are in the SharePoint table above");
        }

        // Both halves as counts, and the counts first. The previous shape put the deciding comparison
        // in a clause at the end of the sentence, and run 122 clipped it at the column width - the
        // third time in this repository that a finding's deciding fact was written past the clip.
        var readable = targets.Where(t => t.GraphRefusal is null && t.SharePointRefusal is null).ToList();

        var lines = pairs
            .Select(p => p.Party)
            .DistinctBy(party => party.Name, StringComparer.Ordinal)
            .Select(party =>
            {
                var held = readable
                    .SelectMany(t => t.SharePoint
                        .Where(sp => sp.CanJoin && sp.Keys.Any(k =>
                            party.Keys.Contains(k, StringComparer.OrdinalIgnoreCase)))
                        .Select(sp => (t, sp)))
                    .ToList();

                var limited = held.Where(x => x.sp.ConveysAccess == false).ToList();
                var conveying = held.Where(x => x.sp.ConveysAccess != false).ToList();

                var limitedShown = limited.Count(x => party.PartyIn(x.t.Graph) is not null);
                var conveyingShown = conveying.Count(x => party.PartyIn(x.t.Graph) is not null);

                return $"{party.Name}: Graph shows {limitedShown}/{limited.Count} Limited Access, " +
                       $"{conveyingShown}/{conveying.Count} conveying";
            })
            .ToList();

        var observed = string.Join("; ", lines);

        return Observation.Measured("what Graph says about a Limited Access holder", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["howLimitedAccessWasIdentified"] = "SharePoint's own permission mask, through " +
                                                    "InventorySharing.Role.Reaches - the same reading " +
                                                    "findings 15 and 71 were measured with",
                ["entriesQuotedWhole"] = "every Graph permission entry is quoted above as it arrived, " +
                                         "so 'nothing else marks it' can be checked rather than taken " +
                                         "from the columns this tool chose to read",
                ["howToReadTheTwoCounts"] = "the second count is the control. A principal Graph never " +
                                            "shows would give 0 on both, and would say nothing about " +
                                            "Limited Access; one shown where the grant conveys access " +
                                            "and not where it does not is the distinction being lost " +
                                            "on purpose. A zero denominator means this run had no such " +
                                            "file and the control is missing, not passed",
            },
        };
    }

    /// <summary>
    /// The question, answered in the only direction this shape can answer it: whether anything the
    /// list carries is missing from Graph's reply.
    /// </summary>
    private static Observation FullnessObservation(IReadOnlyList<Target> targets)
    {
        var compared = targets.Where(t => t.Unreadable is null && t.GraphRefusal is null && t.SharePointRefusal is null).ToList();
        if (compared.Count == 0)
        {
            return Observation.NotRun(
                "is app-only being shown everything",
                "no file produced both readings, so there was nothing to subtract");
        }

        var missing = compared
            .SelectMany(t => t.SharePoint.Where(p => p.CanJoin && p.MatchIn(t.Graph) is null).Select(p => (t.Path, p)))
            .ToList();

        var extra = compared
            .SelectMany(t => t.Graph.Where(p => p.CanJoin && p.MatchIn(t.SharePoint) is null).Select(p => (t.Path, p)))
            .ToList();

        // Run 106 put "4 grant(s) ... are in SharePoint and not in Graph" here and I read it as Graph
        // hiding four people; run 109 showed all four were 制限付きアクセス, which conveys nothing
        // (finding 15). The console clips this cell at its column width, so it is not enough for the
        // capability to be somewhere in the sentence - the deciding number goes first, before any
        // clip can reach it.
        var withAccess = missing.Where(m => m.p.ConveysAccess != false).ToList();
        var withoutAccess = missing.Count - withAccess.Count;

        var observed = missing.Count == 0 && extra.Count == 0
            ? $"across {compared.Count} file(s), every grant naming a directory principal appeared on " +
              "both sides - app-only Graph is not dropping any of them"
            : $"{withAccess.Count} grant(s) that convey access are in SharePoint and not in Graph" +
              (withoutAccess == 0
                  ? string.Empty
                  : $" ({withoutAccess} more are there and convey none - 制限付きアクセス, finding 15)") +
              $"; {extra.Count} in Graph and not in SharePoint; {compared.Count} file(s) compared";

        return Observation.Measured("is app-only being shown everything", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["filesCompared"] = compared.Count.ToString(),
                ["onlyInSharePoint"] = missing.Count == 0
                    ? "(none)"
                    : string.Join("; ", missing.Select(m => $"{m.Path}: {m.p.Kind} {m.p.Name} - {m.p.Detail}")),
                ["onlyInSharePointConveyingAccess"] = withAccess.Count == 0
                    ? "(none)"
                    : string.Join("; ", withAccess.Select(m => $"{m.Path}: {m.p.Kind} {m.p.Name} - {m.p.Detail}")),
                ["onlyInGraph"] = extra.Count == 0
                    ? "(none)"
                    : string.Join("; ", extra.Select(e => $"{e.Path}: {e.p.Kind} {e.p.Name}")),
                ["note"] = "rows only one of the two APIs models are excluded from this count and " +
                           "listed in the table below with the reason: sharing links (Graph returns " +
                           "them as 'link' entries, SharePoint as backing groups, and the two cannot " +
                           "be joined) and SharePoint's own Limited Access bookkeeping groups. Run 99 " +
                           "counted seven of those as missing from Graph, which was wrong - none of " +
                           "them is a grant Graph failed to return",
            },
        };
    }

    /// <summary>
    /// Which kinds of grant fall out, which is the half of the request that survives the substituted
    /// baseline unchanged. Counted per side rather than subtracted, because a kind present on both
    /// sides in different numbers is the interesting case and a set difference would hide it.
    /// </summary>
    private static Observation KindObservation(IReadOnlyList<Target> targets)
    {
        string Count(Func<Target, IReadOnlyList<GrantParty>> pick, Func<GrantParty, bool> match) =>
            targets.Sum(t => pick(t).Count(match)).ToString();

        var graphLinks = Count(t => t.Graph, p => p.Kind == "sharing link");
        var sharePointLinks = Count(t => t.SharePoint, p => p.Kind.Contains("sharing link", StringComparison.OrdinalIgnoreCase));

        return Observation.Measured(
            "which kinds appear on each side",
            $"links: {graphLinks} in Graph, {sharePointLinks} in SharePoint (not joined by identity); " +
            $"Graph entries naming a directory principal: {Count(t => t.Graph, p => p.CanJoin)}; " +
            $"SharePoint assignments naming one: {Count(t => t.SharePoint, p => p.CanJoin)}") with
        {
            Details = new Dictionary<string, string?>
            {
                ["note"] = "a count of links matching on both sides is not a claim that they are the " +
                           "same links. Finding 16 measured the two APIs describing one link in " +
                           "different vocabularies, and nothing here resolves that",
            },
        };
    }

    /// <summary>
    /// What this run is not. Printed as a measurement of its own because the request asked for a
    /// different baseline, and a report that quietly answered a nearby question would be the failure
    /// this repository keeps recording.
    /// </summary>
    private static Observation BaselineObservation() =>
        Observation.Measured(
            "what this shape can and cannot claim",
            "the baseline here is SharePoint's role assignments, not the item owner's own reading. " +
            "So this can say whether Graph is dropping grants the list holds - it cannot say whether " +
            "app-only is owner-equivalent in the documentation's terms, because no owner was asked") with
        {
            Details = new Dictionary<string, string?>
            {
                ["why"] = "the owner's leg needs a delegated sign-in, and security defaults refuse the " +
                          "device code flow in this tenant with AADSTS530035 - measured on two " +
                          "different accounts, twelve days after finding 7 first recorded it",
                ["theOtherMissingLeg"] = "a non-owner delegated reading, which the request wanted as a " +
                                         "positive control that filtering happens at all. Finding 3 " +
                                         "already holds one - a viewer was answered 200 with 0 entries - " +
                                         "but it was measured before the flow was blocked and cannot be retaken",
            },
        };

    private static string Describe(TokenResult token) =>
        !token.Succeeded
            ? $"none - {token.ErrorCode}: {token.ErrorDetail}"
            : token.Claims?.GrantSummary() ?? "issued, but its claims could not be read";

    private string SiteUrl()
    {
        var relative = options.SiteServerRelativePath;
        return string.IsNullOrEmpty(relative)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:" +
              string.Join('/', relative.Split('/').Select(Uri.EscapeDataString));
    }

    private static string? PlacedBy(JsonElement item) =>
        item.TryGetProperty("createdBy", out var by) && by.ValueKind == JsonValueKind.Object &&
        by.TryGetProperty("user", out var user) && user.ValueKind == JsonValueKind.Object
            ? Text(user, "displayName") ?? Text(user, "email")
            : null;

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? ReadString(HttpObservation observation, string property)
    {
        var root = Root(observation);
        return root is null ? null : Text(root.Value, property);
    }

    private static JsonElement? Root(HttpObservation observation)
    {
        if (string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
