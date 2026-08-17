using System.Text;
using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Whether <c>MetaInfo</c> can ride along in a bulk listing, rather than costing one call per file.
/// <para>
/// Finding 23 established that a document's label GUID is in <c>MetaInfo</c> even when the file never
/// promoted, and that it is read out of the file rather than replayed from a cache. That makes the
/// column a candidate for answering "what label is on this?" for a whole library at once - which
/// today takes a listing and then one call per file that the listing could not decide.
/// </para>
/// <para>
/// Whether it can is not something to reason about. <c>$select</c> in this tenant has already refused
/// a column that <c>/fields</c> lists, so a refusal here is an ordinary outcome and not a surprise;
/// what would make it unreadable is a refusal with nothing said about which name was wrong. So the
/// two candidate routes are measured beside a listing that asks for neither, and beside four
/// controls: the promoted column, two misspellings of <c>MetaInfo</c>, and a name invented for this
/// run. The controls are what tell "this column is special" apart from "any unknown name is refused
/// the same way" - which the candidates alone cannot.
/// </para>
/// <para>
/// The expansion route is walked twice, once with no projection and once with the projection naming
/// it: with a <c>$select</c> present, OData is entitled to drop an expansion the projection does not
/// mention, and an empty answer that was really a question never asked would read here as "the route
/// does not work in bulk".
/// </para>
/// <para>
/// The same question is then put to Graph, whose <c>fields</c> is the same idea as SharePoint's
/// <c>FieldValuesAsText</c>. The reason is not tidiness: SharePoint REST publishes no per-call cost
/// and carries a limit of its own, while Graph publishes a table - so the same answer from Graph is
/// an answer whose cost can be worked out before the run rather than after it. Two columns are at
/// stake, <c>MetaInfo</c> and <c>HasUniqueRoleAssignments</c>, and they are reported separately
/// because one arriving is not the other arriving. The untrimmed Graph leg has its whole bag quoted
/// for every file followed: what is not there cannot be named, and a name nobody knows cannot be
/// searched for.
/// </para>
/// </summary>
public sealed class MetaInfoProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    private const string SharePointAccept = "application/json;odata=nometadata";

    /// <summary>
    /// What every leg asks for regardless, so the difference between legs is only the ride-along.
    /// <c>FileRef</c> is here because it is how a row is matched to a configured path.
    /// </summary>
    private const string Base = "$select=Id,FileLeafRef,FileRef";

    /// <summary>
    /// A name nothing should recognise. Without it, a refusal naming <c>MetaInfo</c> reads as "this
    /// column is withheld" when it may only be "this is what an unknown column gets".
    /// </summary>
    private const string InventedColumn = "NoSuchColumn_e3f1";

    /// <summary>Which API a leg speaks to. The two are compared, so neither may be assumed.</summary>
    private enum Api
    {
        SharePoint,
        Graph,
    }

    private sealed record Leg(string Name, string Query, string Why)
    {
        /// <summary>
        /// False for the routes the request is actually about. A control that answers is
        /// interesting; a control that is refused is the yardstick the candidates are read against.
        /// </summary>
        public bool IsControl { get; init; }

        public Api Api { get; init; } = Api.SharePoint;

        /// <summary>
        /// Where this API puts a row's field values. SharePoint expands them under
        /// <c>FieldValuesAsText</c>; Graph calls the same idea <c>fields</c>. The name is data rather
        /// than a branch so that a leg reading the wrong bag is a wrong constant and not a wrong path.
        /// </summary>
        public string Bag => Api == Api.Graph ? "fields" : "FieldValuesAsText";

        /// <summary>
        /// True where the leg asks for the bag without trimming it, which is the only kind of leg that
        /// can answer "what is in there" rather than "is this one thing in there". Those get the whole
        /// bag quoted: a name nobody knows cannot be searched for.
        /// </summary>
        public bool QuoteTheBag { get; init; }
    }

    private static readonly Leg[] Legs =
    [
        new("nothing extra", Base,
            "the baseline - what a listing costs when it asks for neither route"),

        new("$select=MetaInfo", $"{Base},MetaInfo",
            "the column named directly, which is the cheap answer if it is allowed"),

        // No $select at all, which is what the per-file call sends. With one, OData is entitled to
        // drop an expansion the projection does not name, and a leg that came back empty for that
        // reason would read as "this route does not work in bulk" when it had not been asked.
        new("$expand only, no $select", "$expand=FieldValuesAsText",
            "exactly what the per-file call sends - promotion reads MetaInfo out of this"),

        new("$expand named in $select too", $"{Base},FieldValuesAsText&$expand=FieldValuesAsText",
            "the same expansion with the projection naming it, which is what OData asks for. " +
            "Whether the leg above needs this is part of what is being measured"),

        new("both routes at once", $"{Base},MetaInfo,FieldValuesAsText&$expand=FieldValuesAsText",
            "whether asking both ways changes either answer, and what asking twice costs"),

        // Run 115 split the two expansion legs cleanly - naming FieldValuesAsText in $select carried
        // MetaInfo and omitting it did not - which leaves it open which half of that did the work.
        new("$select names it, no $expand", $"{Base},FieldValuesAsText",
            "the projection naming the expansion without asking for the expansion. Run 115 left it " +
            "undecided whether $select or $expand was what made the difference"),

        new("$select=OData__IpLabelId", $"{Base},OData__IpLabelId",
            "the promoted column, under the prefix SharePoint REST gives names starting with '_'. " +
            "Not the request's question - it is here because if it rides along too, the listing " +
            "decides promoted-or-not without a second call either")
            { IsControl = true },

        new("$select=Metainfo (case)", $"{Base},Metainfo",
            "the same name with different casing - does the route care?")
            { IsControl = true },

        new("$select=vti_metainfo", $"{Base},vti_metainfo",
            "the name the property bag uses internally, rather than the column's")
            { IsControl = true },

        new($"$select={InventedColumn}", $"{Base},{InventedColumn}",
            "invented for this run - nothing should recognise it. what an unknown column is told")
            { IsControl = true },

        // Graph. The reason to ask is not that it would be tidier: SharePoint REST publishes no
        // per-call cost and carries its own separate limit, and Graph publishes a table. The same
        // answer from Graph is an answer whose cost can be worked out in advance.
        new("Graph: $expand=fields", "$expand=fields",
            "the whole bag, untrimmed - the only leg that can say what is in there rather than " +
            "whether one named thing is. The bag is quoted whole for each file followed")
            { Api = Api.Graph, QuoteTheBag = true },

        new("Graph: fields($select=the two)",
            $"$expand=fields($select={WantedColumns})",
            "the two columns named. Whether naming is allowed here is a different question from " +
            "whether the values are there")
            { Api = Api.Graph },

        new("Graph: fields($select=the two + an invented name)",
            $"$expand=fields($select={WantedColumns},{InventedColumn})",
            "the same list with one name nothing should recognise mixed in. If this is refused and " +
            "the leg above is not, the refusal is about the name; if both are refused the same way, " +
            "the message says nothing (finding 24's fifteenth)")
            { Api = Api.Graph, IsControl = true },

        new($"Graph: fields($select={InventedColumn})",
            $"$expand=fields($select={InventedColumn})",
            "the invented name on its own, so a refusal has nothing real beside it to be about")
            { Api = Api.Graph, IsControl = true },
    ];

    /// <summary>
    /// The two columns the enumeration currently takes from SharePoint REST: the label GUID's carrier
    /// (finding 24) and whether the item breaks inheritance.
    /// </summary>
    private const string WantedColumns = "MetaInfo,HasUniqueRoleAssignments";

    /// <summary>One file the request is about, and what each leg managed to say about it.</summary>
    private sealed record Tracked(string Path)
    {
        public string? Expected { get; set; }

        /// <summary>
        /// The list item id, resolved through Graph before any leg runs.
        /// <para>
        /// Runs 115 and 116 matched rows on <c>FileRef</c> and <c>FileLeafRef</c>, and the leg that
        /// sends no <c>$select</c> came back with neither - so all four files read as "not in this
        /// leg's rows" and the leg looked like it had carried nothing. It may have carried everything.
        /// A key that is itself part of what the leg varies cannot be the key: this one is asked for
        /// once, from a different API, and holds still while the projections change.
        /// </para>
        /// </summary>
        public string? ListItemId { get; set; }

        /// <summary>Why this file has no id, when it has none. Never left to be inferred.</summary>
        public string? Unresolved { get; set; }

        /// <summary>Keyed by leg name. Absent means that leg produced no row for this file at all.</summary>
        public Dictionary<string, Reading> Readings { get; } = [];
    }

    private sealed record Reading(string From, string? MetaInfo, string? PromotedColumn)
    {
        public IReadOnlyList<SharePointMetaInfo.Label> Labels { get; init; } = [];

        /// <summary>The inheritance flag, the other column the enumeration takes from REST today.</summary>
        public string? Unique { get; init; }

        /// <summary>
        /// Every key the row's bag arrived with. The request asked for this rather than for a lookup:
        /// a name nobody knows cannot be searched for, so the bag is enumerated instead of queried.
        /// </summary>
        public IReadOnlyList<string> BagKeys { get; init; } = [];

        public string LabelText => Labels.Count == 0
            ? "(no label in it)"
            : string.Join(", ", Labels.Select(l => l.Id));
    }

    private sealed record Cost
    {
        public int Pages { get; set; }
        public int Items { get; set; }
        public long Bytes { get; set; }
        public long Ms { get; set; }
        public bool Truncated { get; set; }
        public string? Refusal { get; set; }
        public string? StoppedAt { get; set; }
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("metainfo");
        var app = options.InventoryApp;

        report.Subject["tenant"] = options.TenantId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["speaking as"] = app.Label;
        report.Subject["asking"] = "whether MetaInfo arrives in a bulk listing of the library's items, " +
                                   "and what it costs when it does";
        report.Subject["files followed"] = string.Join(", ", options.Files);
        report.Subject["matched on"] = "the list item id, resolved through Graph before any leg runs - " +
                                       "a key none of the projections under test can remove";

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
            report.Add(Observation.NotRun("every leg", $"no Graph token was issued: {graph.ErrorDetail}"));
            report.Finish();
            return report;
        }

        if (sharePoint.AccessToken is null)
        {
            report.MarkIncomplete($"no SharePoint token: {sharePoint.ErrorCode}");
            report.Add(Observation.NotRun("every leg",
                $"no SharePoint token was issued: {sharePoint.ErrorDetail}. Every leg here is a " +
                "SharePoint REST call, so none of them could be issued"));
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
            report.Add(Observation.NotRun("every leg", $"the site was never resolved ({site.StatusText})"));
            report.Add(BuildCallTable(calls));
            report.Finish();
            return report;
        }

        var drive = await caller.GetAsync($"{GraphBase}/sites/{siteId}/drive", graph.AccessToken, cancellationToken);
        calls.Add(drive);

        var libraryPath = AclResponses.DriveServerRelativePath(drive);
        if (libraryPath is null)
        {
            report.MarkIncomplete("the library's path was never resolved");
            report.Add(Observation.NotRun("every leg",
                $"the drive did not say where it lives ({drive.StatusText}), so GetList had nothing to name"));
            report.Add(BuildCallTable(calls));
            report.Finish();
            return report;
        }

        report.Subject["library"] = libraryPath;

        var tracked = options.Files
            .Select(p => new Tracked(p) { Expected = $"{libraryPath}/{p.TrimStart('/')}" })
            .ToList();

        var driveId = ReadString(drive, "id");

        foreach (var file in tracked)
        {
            await ResolveAsync(caller, driveId, file, graph.AccessToken, calls, cancellationToken);
        }

        // The same library, addressed as a list. Asked for through the drive rather than by matching a
        // name: a library's list has a display name that a tenant may translate, and the two halves of
        // this run have to be the same library or the comparison is between two libraries.
        var list = driveId is null
            ? null
            : await caller.GetAsync($"{GraphBase}/drives/{driveId}/list?$select=id,name",
                graph.AccessToken, cancellationToken);

        if (list is not null)
        {
            calls.Add(list);
        }

        var listId = list is null ? null : ReadString(list, "id");
        report.Subject["list, through Graph"] = listId ?? "never resolved - the Graph legs cannot run";

        var costs = new Dictionary<string, Cost>(StringComparer.Ordinal);

        foreach (var leg in Legs)
        {
            console.WriteLine($"Listing with {leg.Name}...");
            costs[leg.Name] = await WalkAsync(
                caller, libraryPath, siteId, listId, leg, tracked,
                leg.Api == Api.Graph ? graph.AccessToken : sharePoint.AccessToken,
                calls, report, cancellationToken);
        }

        report.Subject["throttling"] = caller.Record.Summary;
        report.Subject["paging"] = options.RequestedPageSize is { } size
            ? $"$top={size}, at most {options.PagesToFollow} page(s) per leg"
            : $"the service's own page size, at most {options.PagesToFollow} page(s) per leg";

        report.Add(BuildCostTable(costs));
        report.Add(BuildReadingTable(tracked));
        report.Add(BuildCallTable(calls));

        foreach (var leg in Legs)
        {
            report.Add(LegObservation(leg, costs[leg.Name], tracked));
        }

        report.Add(RideAlongObservation(costs, tracked));
        report.Add(GraphObservation(costs, tracked));
        report.Add(CostObservation(costs));
        report.Add(ClaimObservation(tracked));
        report.Finish();
        return report;
    }

    /// <summary>
    /// The list item id for one configured file, asked of Graph rather than of the listing. Asking
    /// the listing would mean the key depends on the projection, which is the very thing the legs
    /// vary - and runs 115 and 116 lost a whole leg to exactly that.
    /// </summary>
    private async Task ResolveAsync(
        ThrottleAwareCaller caller,
        string? driveId,
        Tracked file,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        if (driveId is null)
        {
            file.Unresolved = "the drive was never resolved, so no item could be addressed";
            return;
        }

        var encoded = string.Join('/', file.Path.TrimStart('/').Split('/').Select(Uri.EscapeDataString));
        var item = await caller.GetAsync(
            $"{GraphBase}/drives/{driveId}/root:/{encoded}?$select=id,name,sharepointIds",
            token,
            cancellationToken);
        calls.Add(item);

        var root = Root(item);
        if (root is null)
        {
            file.Unresolved = $"the item was never resolved ({item.StatusText})";
            return;
        }

        file.ListItemId = root.Value.TryGetProperty("sharepointIds", out var ids) &&
                          ids.ValueKind == JsonValueKind.Object
            ? Text(ids, "listItemId")
            : null;

        if (file.ListItemId is null)
        {
            file.Unresolved = "the item resolved but carried no sharepointIds.listItemId";
        }
    }

    /// <summary>
    /// One leg, followed across pages. The page count is part of the measurement rather than an
    /// implementation detail: finding 8 measured a bulk route costing one call per page, so "one call
    /// instead of one per file" is only true if the pages are counted too.
    /// </summary>
    private async Task<Cost> WalkAsync(
        ThrottleAwareCaller caller,
        string libraryPath,
        string siteId,
        string? listId,
        Leg leg,
        IReadOnlyList<Tracked> tracked,
        string token,
        List<HttpObservation> calls,
        ProbeReport report,
        CancellationToken cancellationToken)
    {
        var cost = new Cost();

        if (leg.Api == Api.Graph && listId is null)
        {
            cost.Refusal = "the list was never resolved through Graph, so this leg was never issued";
            return cost;
        }

        var top = options.RequestedPageSize is { } size ? $"&$top={size}" : string.Empty;
        var next = leg.Api == Api.Graph
            ? $"{GraphBase}/sites/{siteId}/lists/{listId}/items?{leg.Query}{top}"
            : $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')" +
              $"/items?{leg.Query}{top}";

        while (next is not null && cost.Pages < options.PagesToFollow)
        {
            var observation = leg.Api == Api.Graph
                ? await caller.GetAsync(next, token, cancellationToken)
                : await caller.GetAsync(next, token, cancellationToken, SharePointAccept);
            calls.Add(observation);

            cost.Pages++;
            cost.Ms += observation.ElapsedMs;
            cost.Bytes += Encoding.UTF8.GetByteCount(observation.Body);
            cost.Truncated |= observation.BodyTruncated;

            var root = Root(observation);
            if (root is null)
            {
                // The body is the whole point of a refusal here - which column name it objects to is
                // what separates "this column is withheld" from "this name is not a column". A cell
                // clips, so it is quoted whole as well as summarised.
                cost.Refusal = string.IsNullOrWhiteSpace(observation.Body)
                    ? $"{observation.StatusText}, no body"
                    : observation.StatusText;

                report.Quote(
                    $"{leg.Name} - what came back on page {cost.Pages}",
                    string.IsNullOrWhiteSpace(observation.Body)
                        ? $"{observation.StatusText}, and the body was empty"
                        : $"{observation.StatusText}\n{observation.Body}");

                return cost;
            }

            if (!root.Value.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
            {
                cost.Refusal = "the reply parsed but carried no 'value' array";
                report.Quote($"{leg.Name} - a reply with no value array", observation.Body);
                return cost;
            }

            foreach (var entry in value.EnumerateArray())
            {
                cost.Items++;
                Record(leg, entry, tracked, report);
            }

            next = Link(root.Value, "odata.nextLink") ?? Link(root.Value, "@odata.nextLink");
        }

        if (next is not null)
        {
            // Reaching the limit is reported as reaching the limit. A run that stopped early and said
            // nothing would read as a library that ends here.
            cost.StoppedAt = $"the page limit ({options.PagesToFollow}) was reached with more to follow";
        }

        return cost;
    }

    /// <summary>
    /// What one listed row said about one of the configured files. Both places <c>MetaInfo</c> has
    /// been seen arriving are read, and which one answered is kept - the same care the per-file call
    /// takes, for the same reason: run 77 dropped the expansion believing it did nothing and lost the
    /// value entirely.
    /// </summary>
    private static void Record(Leg leg, JsonElement entry, IReadOnlyList<Tracked> tracked, ProbeReport report)
    {
        var fileRef = Text(entry, "FileRef");
        var leaf = Text(entry, "FileLeafRef");

        // Graph spells the same id lower-case and as a string; SharePoint sends a number. Both are
        // read rather than one being assumed, because the two APIs are what this run compares.
        var id = entry.TryGetProperty("Id", out var idValue) && idValue.ValueKind == JsonValueKind.Number
            ? idValue.GetInt32().ToString()
            : Text(entry, "Id") ?? Text(entry, "id");

        // Id first, because it is the one key no projection here removes. The path forms stay as a
        // fallback for a file Graph could not resolve an id for.
        var match = tracked.FirstOrDefault(t =>
            (id is not null && t.ListItemId is not null && string.Equals(id, t.ListItemId, StringComparison.Ordinal)) ||
            (fileRef is not null && string.Equals(fileRef, t.Expected, StringComparison.OrdinalIgnoreCase)) ||
            (leaf is not null && string.Equals(leaf, Leaf(t.Path), StringComparison.OrdinalIgnoreCase)));

        if (match is null)
        {
            return;
        }

        // The bag this API puts field values in - FieldValuesAsText for SharePoint, fields for Graph.
        var expanded = entry.TryGetProperty(leg.Bag, out var text) && text.ValueKind == JsonValueKind.Object
            ? text
            : default;

        var fromItem = Text(entry, "MetaInfo");
        var fromExpansion = expanded.ValueKind == JsonValueKind.Object ? Text(expanded, "MetaInfo") : null;

        var metaInfo = fromItem ?? fromExpansion;

        // Run 115 reported "neither place carried it" for the leg that asked for the expansion without
        // naming it, and that one phrase covers two different services: one that did not expand at
        // all, and one that expanded and left MetaInfo out of what it expanded. Reading the first as
        // the second is how a route gets written off for something it was never asked.
        var bagKeys = expanded.ValueKind == JsonValueKind.Object
            ? expanded.EnumerateObject().Select(p => p.Name).ToList()
            : [];

        var from = (fromItem, fromExpansion) switch
        {
            (not null, not null) => $"both the item and {leg.Bag}",
            (not null, null) => "the item itself",
            (null, not null) => leg.Bag,
            _ when expanded.ValueKind == JsonValueKind.Object =>
                $"{leg.Bag} arrived with {bagKeys.Count} key(s) and MetaInfo was not among them",
            _ => $"no MetaInfo, and no {leg.Bag} on the row either",
        };

        // Both spellings, because absence claimed from one spelling is not absence. The prefixed form
        // is what SharePoint REST gives an internal name starting with '_'; the bare form is what the
        // text bag has been seen using.
        var promoted = First(entry, expanded, "OData__IpLabelId") ?? First(entry, expanded, "_IpLabelId");

        // The inheritance flag arrives as a bare true/false rather than as text, so it is read as a
        // value rather than through the string reader every other column here uses.
        var unique = Flag(entry, "HasUniqueRoleAssignments") ??
                     (expanded.ValueKind == JsonValueKind.Object
                         ? Flag(expanded, "HasUniqueRoleAssignments")
                         : null);

        match.Readings[leg.Name] = new Reading(from, metaInfo, promoted)
        {
            Labels = metaInfo is null ? [] : SharePointMetaInfo.Labels(SharePointMetaInfo.Parse(metaInfo)),
            Unique = unique,
            BagKeys = bagKeys,
        };

        // The request asked to see the bag rather than to search it - "a name I do not know cannot be
        // looked for". Quoted whole, because this is exactly the text a cell would clip.
        if (leg.QuoteTheBag && expanded.ValueKind == JsonValueKind.Object)
        {
            report.Quote(
                $"{leg.Name} - the whole bag for {match.Path}, {bagKeys.Count} key(s)",
                string.Join("\n", expanded.EnumerateObject().Select(p =>
                    $"  {p.Name}: {Summarise(p.Value)}")));
        }
    }

    /// <summary>A boolean column, as text, without turning "absent" into "false".</summary>
    private static string? Flag(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean().ToString().ToLowerInvariant()
            : Text(element, property);

    /// <summary>
    /// One bag entry, short enough to read. MetaInfo is thousands of characters and would bury the
    /// other forty keys, which are the reason the bag is being printed at all.
    /// </summary>
    private static string Summarise(JsonElement value)
    {
        var raw = value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : value.GetRawText();
        return raw.Length <= 200 ? raw : $"{raw[..200]}... ({raw.Length} characters in all)";
    }

    private static ProbeTable BuildCostTable(IReadOnlyDictionary<string, Cost> costs)
    {
        var rows = Legs.Select(leg =>
        {
            var cost = costs[leg.Name];
            return (IReadOnlyList<string?>)
            [
                leg.Name,
                leg.Api == Api.Graph ? "Graph" : "SharePoint",
                leg.IsControl ? "control" : "asked about",
                cost.Pages.ToString(),
                cost.Refusal is null ? cost.Items.ToString() : "-",
                cost.Bytes.ToString() + (cost.Truncated ? " (the probe cut a body short)" : string.Empty),
                cost.Ms.ToString(),
                cost.Refusal ?? cost.StoppedAt ?? "200 OK",
                leg.Why,
            ];
        }).ToList();

        return new ProbeTable(
            "What each listing cost, and whether it was allowed",
            ["leg", "api", "kind", "pages", "items", "bytes", "ms", "outcome", "why this leg is here"],
            rows);
    }

    /// <summary>
    /// The rows the request is actually about: for each configured file, what each leg managed to say.
    /// Flat rather than a file-by-leg grid, because the values are long enough that a grid would clip
    /// the label GUID - which is the one value this whole run exists to read.
    /// </summary>
    private static ProbeTable BuildReadingTable(IReadOnlyList<Tracked> tracked)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var file in tracked)
        {
            foreach (var leg in Legs)
            {
                if (!file.Readings.TryGetValue(leg.Name, out var reading))
                {
                    // Distinguished from "this leg carried nothing": if the file has no id, the probe
                    // had nothing to recognise it by, which is a fact about the probe.
                    rows.Add([
                        file.Path,
                        leg.Name,
                        file.ListItemId is null
                            ? $"not looked for - {file.Unresolved ?? "no list item id"}"
                            : "the file was not among this leg's rows",
                        "-", "-", "-", "-", "-",
                    ]);
                    continue;
                }

                rows.Add([
                    file.Path,
                    leg.Name,
                    reading.MetaInfo is null ? "no" : "yes",
                    reading.From,
                    reading.LabelText,
                    reading.Unique ?? "(not on this row)",
                    reading.PromotedColumn ?? "(not on this row)",
                    reading.BagKeys.Count == 0 ? "(no bag)" : reading.BagKeys.Count.ToString(),
                ]);
            }
        }

        return new ProbeTable(
            "What each leg said about each file it was asked about",
            ["file", "leg", "MetaInfo arrived", "from where", "label GUID in it",
             "HasUniqueRoleAssignments", "_IpLabelId", "keys in the bag"],
            rows.Count == 0 ? [["(no file was configured)", "-", "-", "-", "-", "-", "-", "-"]] : rows);
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)new[]
            {
                c.Method, c.Url, c.StatusText, c.ElapsedMs.ToString(), ApiError.Code(c),
            }).ToList());

    private static Observation LegObservation(Leg leg, Cost cost, IReadOnlyList<Tracked> tracked)
    {
        var answered = tracked.Count(t => t.Readings.TryGetValue(leg.Name, out var r) && r.Labels.Count > 0);

        var observed = cost.Refusal is not null
            ? $"refused - {cost.Refusal}. The body is quoted whole above"
            : $"{answered} of {tracked.Count} file(s) gave a label GUID; {cost.Items} item(s) over " +
              $"{cost.Pages} page(s), {cost.Bytes} bytes, {cost.Ms} ms";

        return Observation.Measured(leg.Name, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["query"] = leg.Query,
                ["kind"] = leg.IsControl ? "control" : "asked about",
                ["why"] = leg.Why,
                ["stoppedEarly"] = cost.StoppedAt,
                ["bodyTruncatedByTheProbe"] = cost.Truncated ? "yes" : "no",
            },
        };
    }

    /// <summary>
    /// The request's question, answered with the deciding number first. The console clips this cell at
    /// its column width, and run 106 was misread because the deciding fact sat past the clip.
    /// </summary>
    private static Observation RideAlongObservation(
        IReadOnlyDictionary<string, Cost> costs,
        IReadOnlyList<Tracked> tracked)
    {
        var candidates = Legs
            .Where(l => l.Api == Api.SharePoint && !l.IsControl && costs[l.Name].Refusal is null)
            .ToList();

        if (tracked.Count == 0)
        {
            return Observation.NotRun("can the label ride along in one listing",
                "no file was configured, so no row was followed");
        }

        var best = candidates
            .Select(l => (Leg: l, Read: tracked.Count(t => t.Readings.TryGetValue(l.Name, out var r) && r.Labels.Count > 0)))
            .OrderByDescending(x => x.Read)
            .FirstOrDefault();

        if (best.Leg is null)
        {
            return Observation.Measured("can the label ride along in one listing",
                $"no - both routes were refused, across {tracked.Count} file(s) asked about. " +
                "The refusals are quoted whole above, and the controls say whether the refusal is " +
                "about this column or about any unknown name");
        }

        return Observation.Measured("can the label ride along in one listing",
            $"{best.Read} of {tracked.Count} file(s) gave a label GUID from one listing, best via " +
            $"'{best.Leg.Name}'; the per-file call is needed for the remaining {tracked.Count - best.Read}");
    }

    /// <summary>
    /// Whether the enumeration can move to Graph, which is the question this run was extended for.
    /// The two columns are named separately: one of them arriving is not the other one arriving, and
    /// a single yes/no would hide which half is missing.
    /// </summary>
    private static Observation GraphObservation(
        IReadOnlyDictionary<string, Cost> costs,
        IReadOnlyList<Tracked> tracked)
    {
        var whole = Legs.First(l => l.Api == Api.Graph && l.QuoteTheBag);
        var cost = costs[whole.Name];

        if (cost.Refusal is not null)
        {
            return Observation.Measured("can the enumeration move to Graph",
                $"the untrimmed Graph leg was refused - {cost.Refusal}. The body is quoted whole above");
        }

        if (tracked.Count == 0)
        {
            return Observation.NotRun("can the enumeration move to Graph",
                "no file was configured, so no row was followed");
        }

        var withLabel = tracked.Count(t => t.Readings.TryGetValue(whole.Name, out var r) && r.Labels.Count > 0);
        var withFlag = tracked.Count(t => t.Readings.TryGetValue(whole.Name, out var r) && r.Unique is not null);
        var keys = tracked
            .Select(t => t.Readings.TryGetValue(whole.Name, out var r) ? r.BagKeys.Count : 0)
            .DefaultIfEmpty(0)
            .Max();

        var baseline = costs[Legs[0].Name];

        return Observation.Measured("can the enumeration move to Graph",
            $"MetaInfo: {withLabel} of {tracked.Count}; HasUniqueRoleAssignments: {withFlag} of " +
            $"{tracked.Count}; the bag held up to {keys} key(s) and is quoted whole above; " +
            $"{cost.Bytes} bytes over {cost.Pages} page(s) against SharePoint's {baseline.Bytes} " +
            $"over {baseline.Pages}") with
        {
            Details = new Dictionary<string, string?>
            {
                ["whyItMatters"] = "SharePoint REST publishes no per-call cost and carries a separate " +
                                   "limit; Graph publishes a table. The same answer from Graph is one " +
                                   "whose cost can be worked out before the run rather than after",
                ["notMeasured"] = "the published costs themselves. This run measured what arrives, " +
                                  "not what either service charges for it",
            },
        };
    }

    private static Observation CostObservation(IReadOnlyDictionary<string, Cost> costs)
    {
        var baseline = costs[Legs[0].Name];

        var lines = Legs.Skip(1)
            .Where(l => costs[l.Name].Refusal is null)
            .Select(l =>
            {
                var cost = costs[l.Name];
                var bytes = baseline.Bytes == 0 ? "n/a" : $"x{(double)cost.Bytes / baseline.Bytes:0.0}";
                return $"{l.Name}: {bytes} the bytes, {cost.Ms} ms against {baseline.Ms} ms";
            })
            .ToList();

        return Observation.Measured("what the ride-along costs",
            lines.Count == 0
                ? "nothing to compare - every leg past the baseline was refused"
                : string.Join("; ", lines)) with
        {
            Details = new Dictionary<string, string?>
            {
                ["baselineBytes"] = baseline.Bytes.ToString(),
                ["baselineMs"] = baseline.Ms.ToString(),
                ["baselinePages"] = baseline.Pages.ToString(),
                ["note"] = "one run each, from a GitHub-hosted runner. The byte counts are exact and " +
                           "the millisecond counts are not - they carry the network between this " +
                           "runner and the tenant, which is not the same network twice",
            },
        };
    }

    private static Observation ClaimObservation(IReadOnlyList<Tracked> tracked) =>
        Observation.Measured("what this shape can and cannot claim",
            "it can say whether one listing carries the label for these files in this library. It " +
            "cannot say the same for a library with more items than the page limit followed here, " +
            $"and it says nothing about whether the {tracked.Count} file(s) followed are representative " +
            "- they were chosen because they differ in whether they promoted");

    private static string Leaf(string path) => path.TrimEnd('/').Split('/').Last();

    /// <summary>The named value from the row or from its expanded text values, whichever has it.</summary>
    private static string? First(JsonElement entry, JsonElement expanded, string property) =>
        Text(entry, property) ??
        (expanded.ValueKind == JsonValueKind.Object ? Text(expanded, property) : null);

    private string SiteUrl()
    {
        var relative = options.SiteServerRelativePath;
        return string.IsNullOrEmpty(relative)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:" +
              string.Join('/', relative.Split('/').Select(Uri.EscapeDataString));
    }

    private static string? Link(JsonElement root, string property) =>
        root.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static JsonElement? Root(HttpObservation? observation)
    {
        if (observation is null || !observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(observation.Body).RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? ReadString(HttpObservation observation, string property) =>
        Root(observation) is { } root ? Text(root, property) : null;

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string Describe(TokenResult token) =>
        !token.Succeeded
            ? $"none - {token.ErrorCode}: {token.ErrorDetail}"
            : token.Claims?.GrantSummary() ?? "issued, but its claims could not be read";
}
