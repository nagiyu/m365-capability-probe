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

        foreach (var target in targets)
        {
            console.WriteLine($"Reading {target.Path}...");
            await ReadGraphAsync(caller, driveId, target, graph.AccessToken, calls, cancellationToken);
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
        CancellationToken cancellationToken)
    {
        if (driveId is null)
        {
            target.Unreadable = "the drive was never resolved, so no item could be addressed";
            return;
        }

        var encoded = string.Join('/', target.Path.TrimStart('/').Split('/').Select(Uri.EscapeDataString));
        var item = await caller.GetAsync(
            $"{GraphBase}/drives/{driveId}/root:/{encoded}?$select=id,name,createdBy,sharepointIds",
            token,
            cancellationToken);
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
    }

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
                var match = party.MatchIn(target.SharePoint);
                rows.Add([
                    target.Path, party.Kind, party.Name, "yes",
                    match is null ? "no" : "yes",
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
                    "(no key in common)", "only SharePoint",
                ]);
            }
        }

        return new ProbeTable(
            "The subtraction - grants naming a directory principal, on both sides",
            ["path", "kind", "principal", "in Graph", "in SharePoint", "matched on", "side"],
            rows.Count == 0 ? [["(nothing could be joined)", "-", "-", "-", "-", "-", "-"]] : rows);
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
        var onlySharePoint = target.SharePoint.Count(p => p.CanJoin && p.MatchIn(target.Graph) is null);
        var onlyGraph = target.Graph.Count(p => p.CanJoin && p.MatchIn(target.SharePoint) is null);

        var observed = target.GraphRefusal is not null || target.SharePointRefusal is not null
            ? "one of the two readings did not arrive, so this file was not compared"
            : $"{target.Graph.Count} Graph entries ({graphJoinable} joinable), " +
              $"{target.SharePoint.Count} SharePoint assignments ({sharePointJoinable} joinable); " +
              $"{onlyGraph} only in Graph, {onlySharePoint} only in SharePoint";

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

        var observed = missing.Count == 0 && extra.Count == 0
            ? $"across {compared.Count} file(s), every grant naming a directory principal appeared on " +
              "both sides - app-only Graph is not dropping any of them"
            : $"across {compared.Count} file(s), {missing.Count} grant(s) naming a directory principal are " +
              $"in SharePoint and not in Graph, and {extra.Count} are in Graph and not in SharePoint";

        return Observation.Measured("is app-only being shown everything", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["filesCompared"] = compared.Count.ToString(),
                ["onlyInSharePoint"] = missing.Count == 0
                    ? "(none)"
                    : string.Join("; ", missing.Select(m => $"{m.Path}: {m.p.Kind} {m.p.Name}")),
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
