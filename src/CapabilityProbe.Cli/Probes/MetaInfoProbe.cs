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

    private sealed record Leg(string Name, string Query, string Why)
    {
        /// <summary>
        /// False for the routes the request is actually about. A control that answers is
        /// interesting; a control that is refused is the yardstick the candidates are read against.
        /// </summary>
        public bool IsControl { get; init; }
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
    ];

    /// <summary>One file the request is about, and what each leg managed to say about it.</summary>
    private sealed record Tracked(string Path)
    {
        public string? Expected { get; set; }

        /// <summary>Keyed by leg name. Absent means that leg produced no row for this file at all.</summary>
        public Dictionary<string, Reading> Readings { get; } = [];
    }

    private sealed record Reading(string From, string? MetaInfo, string? PromotedColumn)
    {
        public IReadOnlyList<SharePointMetaInfo.Label> Labels { get; init; } = [];

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

        var costs = new Dictionary<string, Cost>(StringComparer.Ordinal);

        foreach (var leg in Legs)
        {
            console.WriteLine($"Listing with {leg.Name}...");
            costs[leg.Name] = await WalkAsync(
                caller, libraryPath, leg, tracked, sharePoint.AccessToken, calls, report, cancellationToken);
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
        report.Add(CostObservation(costs));
        report.Add(ClaimObservation(tracked));
        report.Finish();
        return report;
    }

    /// <summary>
    /// One leg, followed across pages. The page count is part of the measurement rather than an
    /// implementation detail: finding 8 measured a bulk route costing one call per page, so "one call
    /// instead of one per file" is only true if the pages are counted too.
    /// </summary>
    private async Task<Cost> WalkAsync(
        ThrottleAwareCaller caller,
        string libraryPath,
        Leg leg,
        IReadOnlyList<Tracked> tracked,
        string token,
        List<HttpObservation> calls,
        ProbeReport report,
        CancellationToken cancellationToken)
    {
        var cost = new Cost();

        var top = options.RequestedPageSize is { } size ? $"&$top={size}" : string.Empty;
        var next = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')" +
                   $"/items?{leg.Query}{top}";

        while (next is not null && cost.Pages < options.PagesToFollow)
        {
            var observation = await caller.GetAsync(next, token, cancellationToken, SharePointAccept);
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
                Record(leg, entry, tracked);
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
    private static void Record(Leg leg, JsonElement entry, IReadOnlyList<Tracked> tracked)
    {
        var fileRef = Text(entry, "FileRef");
        var leaf = Text(entry, "FileLeafRef");

        var match = tracked.FirstOrDefault(t =>
            (fileRef is not null && string.Equals(fileRef, t.Expected, StringComparison.OrdinalIgnoreCase)) ||
            (leaf is not null && string.Equals(leaf, Leaf(t.Path), StringComparison.OrdinalIgnoreCase)));

        if (match is null)
        {
            return;
        }

        var expanded = entry.TryGetProperty("FieldValuesAsText", out var text) &&
                       text.ValueKind == JsonValueKind.Object
            ? text
            : default;

        var fromItem = Text(entry, "MetaInfo");
        var fromExpansion = expanded.ValueKind == JsonValueKind.Object ? Text(expanded, "MetaInfo") : null;

        var metaInfo = fromItem ?? fromExpansion;
        var from = (fromItem, fromExpansion) switch
        {
            (not null, not null) => "both the item and FieldValuesAsText",
            (not null, null) => "the item itself",
            (null, not null) => "FieldValuesAsText",
            _ => "neither place carried it",
        };

        var promoted = Text(entry, "OData__IpLabelId") ??
                       (expanded.ValueKind == JsonValueKind.Object ? Text(expanded, "OData__IpLabelId") : null);

        match.Readings[leg.Name] = new Reading(from, metaInfo, promoted)
        {
            Labels = metaInfo is null ? [] : SharePointMetaInfo.Labels(SharePointMetaInfo.Parse(metaInfo)),
        };
    }

    private static ProbeTable BuildCostTable(IReadOnlyDictionary<string, Cost> costs)
    {
        var rows = Legs.Select(leg =>
        {
            var cost = costs[leg.Name];
            return (IReadOnlyList<string?>)
            [
                leg.Name,
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
            ["leg", "kind", "pages", "items", "bytes", "ms", "outcome", "why this leg is here"],
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
                    rows.Add([file.Path, leg.Name, "the file was not in this leg's rows", "-", "-", "-"]);
                    continue;
                }

                rows.Add([
                    file.Path,
                    leg.Name,
                    reading.MetaInfo is null ? "no" : "yes",
                    reading.From,
                    reading.LabelText,
                    reading.PromotedColumn ?? "(the column was not on this row)",
                ]);
            }
        }

        return new ProbeTable(
            "What each leg said about each file it was asked about",
            ["file", "leg", "MetaInfo arrived", "from where", "label GUID in it", "_IpLabelId"],
            rows.Count == 0 ? [["(no file was configured)", "-", "-", "-", "-", "-"]] : rows);
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
        var candidates = Legs.Where(l => !l.IsControl && costs[l.Name].Refusal is null).ToList();

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
