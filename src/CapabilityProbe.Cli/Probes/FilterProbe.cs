using System.Text;
using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Whether the listing route will filter on a hidden column, not merely return it.
/// <para>
/// Finding 30 put ten hidden columns in <c>ViewFields</c> and eight came back. That answered half the
/// question. A column arriving in every row and a column the server will narrow the result set by are
/// different capabilities: the first costs a whole library's worth of rows, the second is what makes
/// a survey affordable.
/// </para>
/// <para>
/// Four calls, one library, one run. Two of them are the request - unfiltered and filtered - and two
/// are controls, because the pair on its own cannot tell "the filter was honoured" from "the filter
/// was ignored and everything matched anyway".
/// </para>
/// </summary>
public sealed class FilterProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string SharePointAccept = "application/json;odata=nometadata";

    /// <summary>The column the request names. Not swept: this run is about one column by name.</summary>
    private const string Column = "_IpLabelId";

    /// <summary>
    /// A file name nothing in the library can have, for the leg that must come back empty.
    /// <para>
    /// Without it, an unfiltered count and a filtered count that agree mean either "every row matched"
    /// or "the Where was never applied", and those are opposite answers. A predicate that cannot match
    /// separates them: if it still returns every row, filtering is not happening at all.
    /// </para>
    /// </summary>
    private const string ImpossibleName = "__probe-no-such-file-xyzzy__";

    /// <summary>Rows per page for the two legs that are not about paging.</summary>
    private const int DefaultRowLimit = 100;

    /// <summary>
    /// Rows per page for the leg that is about paging. Small enough that a library of twenty-odd rows
    /// has to offer a continuation to answer at all - which is the half of paging that lives in this
    /// tool rather than in the service.
    /// </summary>
    private const int SmallRowLimit = 2;

    private sealed record Leg(string Name, string? Where, int RowLimit, string Asks);

    private sealed class Result
    {
        public required Leg Leg { get; init; }
        public string? Status { get; set; }
        public string? ErrorCode { get; set; }
        public int Pages { get; set; }
        public int Rows { get; set; }

        /// <summary>True when any page offered a continuation, whether or not this run followed it.</summary>
        public bool ContinuationOffered { get; set; }

        /// <summary>True when this run stopped with a continuation still outstanding.</summary>
        public bool MoreWaiting { get; set; }

        /// <summary>The named specimens this leg returned a row for.</summary>
        public HashSet<string> Named { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Named specimens whose cell in the filtered column was not empty.</summary>
        public HashSet<string> WithValue { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string Describe => Status is null
            ? "not asked"
            : $"{Status}, {Rows} row(s) over {Pages} page(s)" +
              (ContinuationOffered ? ", continuation offered" : ", no continuation") +
              (MoreWaiting ? " - stopped at the page limit with more waiting" : string.Empty);
    }

    private sealed class Library
    {
        public required string Title { get; init; }
        public string? Path { get; set; }
        public string? Unresolved { get; set; }
        public string? FieldsStatus { get; set; }

        /// <summary>Whether the list defines the column at all, read before anything is filtered on it.</summary>
        public bool ColumnDefined { get; set; }
        public string? ColumnType { get; set; }

        public List<Result> Results { get; } = [];
        public List<string> Specimens { get; } = [];
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("filter");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["column"] = Column;
        report.Subject["asking"] =
            $"whether RenderListDataAsStream will narrow a result set by {Column}, which finding 30 " +
            "showed it will return. Returning a column and filtering on it are different capabilities";
        report.Subject["impossible predicate"] = ImpossibleName;
        report.Subject["values"] =
            "not recorded. Whether a cell was empty is the measurement; what was in it is a label " +
            "identifier";

        var calls = new List<HttpObservation>();
        var caller = new ThrottleAwareCaller(http);

        var app = options.InventoryApp;
        var source = AppOnlyTokenSource.WithCertificate(options, app);
        if (source.IsUnavailable)
        {
            console.WriteLine($"No certificate for {app.Label}: {source.Identity}. Falling back to the secret.");
            source = AppOnlyTokenSource.WithSecret(options, app);
        }

        report.Subject["speaking as"] = source.Identity;

        var graph = await source.GetTokenAsync(ProbeAudience.Graph, cancellationToken);
        var sharePoint = await source.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken);

        if (graph.AccessToken is null || sharePoint.AccessToken is null)
        {
            report.MarkIncomplete(
                $"a token was refused (Graph: {Describe(graph)}; SharePoint: {Describe(sharePoint)}), " +
                "so nothing below was ever addressed");
            report.Finish();
            return report;
        }

        var siteId = await SiteAsync(caller, graph.AccessToken, calls, cancellationToken);
        if (siteId is null)
        {
            report.MarkIncomplete("the site was never resolved, so no library could be named");
            report.Add(CallTable(calls));
            report.Finish();
            return report;
        }

        var drives = await DrivesAsync(caller, siteId, graph.AccessToken, calls, cancellationToken);
        var libraries = Wanted(drives);

        var legs = Legs();
        report.Subject["legs"] = string.Join("; ", legs.Select(l => $"{l.Name}: {l.Asks}"));

        foreach (var library in libraries.Where(l => l.Path is not null))
        {
            await ColumnAsync(caller, library, sharePoint.AccessToken, calls, cancellationToken);

            foreach (var leg in legs)
            {
                console.WriteLine($"{leg.Name} over {library.Title}...");
                var result = await AskAsync(caller, library, leg, sharePoint.AccessToken, calls, report, cancellationToken);
                library.Results.Add(result);
            }
        }

        report.Add(LibraryTable(libraries));
        report.Add(LegTable(libraries));
        report.Add(SpecimenTable(libraries));
        report.Add(CallTable(calls));

        foreach (var observation in Observations(libraries))
        {
            report.Add(observation);
        }

        report.Subject["throttling"] = caller.Record.Summary;
        report.Finish();
        return report;
    }

    /// <summary>
    /// The four calls, in the order they are made. The two controls are not optional extras: the pair
    /// they qualify is unreadable without them.
    /// </summary>
    private static Leg[] Legs() =>
    [
        new("no condition", null, DefaultRowLimit,
            "how many rows the library returns when nothing is asked of it"),

        new($"{Column} IsNotNull", $"<Where><IsNotNull><FieldRef Name='{Column}' /></IsNotNull></Where>",
            DefaultRowLimit,
            "the request: does the server narrow the set by a hidden column"),

        new("a predicate that cannot match",
            "<Where><Eq><FieldRef Name='FileLeafRef' />" +
            $"<Value Type='Text'>{ImpossibleName}</Value></Eq></Where>",
            DefaultRowLimit,
            "the control: if this still returns every row, no Where is being applied at all, and the " +
            "leg above agreeing with the unfiltered count would have meant nothing"),

        new($"{Column} IsNotNull, RowLimit {SmallRowLimit}",
            $"<Where><IsNotNull><FieldRef Name='{Column}' /></IsNotNull></Where>",
            SmallRowLimit,
            "whether a continuation is actually offered when the limit bites"),
    ];

    // ---- the call --------------------------------------------------------------------------------

    private async Task<Result> AskAsync(
        ThrottleAwareCaller caller,
        Library library,
        Leg leg,
        string token,
        List<HttpObservation> calls,
        ProbeReport report,
        CancellationToken cancellationToken)
    {
        var result = new Result { Leg = leg };

        var view = ViewXml(leg);
        report.Quote($"{library.Title} - {leg.Name} - the ViewXml sent", view);

        var body = JsonSerializer.Serialize(new
        {
            parameters = new { RenderOptions = 2, ViewXml = view },
        });

        var url = $"{ListUrl(library)}/RenderListDataAsStream";
        string? next = url;

        while (next is not null && result.Pages < options.PagesToFollow)
        {
            var observation = await caller.PostAsync(next, token, cancellationToken, body);
            calls.Add(observation);

            result.Pages++;
            result.Status ??= observation.StatusText;
            result.ErrorCode ??= NullIfEmpty(ApiError.Code(observation));

            var root = Root(observation);
            if (root is null || !root.Value.TryGetProperty("Row", out var rows) ||
                rows.ValueKind != JsonValueKind.Array)
            {
                // A leg that comes back empty is the one this run most needs to read correctly, and a
                // status alone will not do it: "the filter matched nothing" and "the Where was thrown
                // out" can both arrive as a short answer. The body is the only thing that separates
                // them, so it is quoted whole rather than summarised into a cell.
                result.Status = observation.StatusText;
                report.Quote(
                    $"{library.Title} - {leg.Name} - what came back on page {result.Pages}",
                    string.IsNullOrWhiteSpace(observation.Body)
                        ? $"{observation.StatusText}, and the body was empty"
                        : $"{observation.StatusText}\n{observation.Body}");
                return result;
            }

            foreach (var row in rows.EnumerateArray())
            {
                result.Rows++;

                var leaf = Text(row, "FileLeafRef");
                if (leaf is null || !library.Specimens.Contains(leaf, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                result.Named.Add(leaf);

                if (row.TryGetProperty(Column, out var cell) && HasValue(cell))
                {
                    result.WithValue.Add(leaf);
                }
            }

            var href = Text(root, "NextHref");
            if (string.IsNullOrEmpty(href))
            {
                next = null;
            }
            else
            {
                result.ContinuationOffered = true;
                next = url + href;
            }
        }

        result.MoreWaiting = next is not null;
        return result;
    }

    /// <summary>
    /// The view. CAML wants Query before ViewFields before RowLimit, and the only thing that varies
    /// between legs is the Where and the limit - so a difference between legs cannot be a difference
    /// of projection.
    /// </summary>
    private static string ViewXml(Leg leg)
    {
        var view = new StringBuilder("<View>");

        if (leg.Where is not null)
        {
            view.Append("<Query>").Append(leg.Where).Append("</Query>");
        }

        view.Append("<ViewFields>")
            .Append("<FieldRef Name='FileLeafRef' />")
            .Append("<FieldRef Name='FileRef' />")
            .Append($"<FieldRef Name='{Column}' />")
            .Append("</ViewFields>")
            .Append($"<RowLimit Paged=\"TRUE\">{leg.RowLimit}</RowLimit>")
            .Append("</View>");

        return view.ToString();
    }

    // ---- resolving --------------------------------------------------------------------------------

    private async Task<string?> SiteAsync(
        ThrottleAwareCaller caller,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var relative = options.SiteServerRelativePath;
        var url = string.IsNullOrEmpty(relative)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relative)}";

        var observation = await caller.GetAsync(url, token, cancellationToken);
        calls.Add(observation);

        return Text(Root(observation), "id");
    }

    private async Task<List<(string Title, string Path)>> DrivesAsync(
        ThrottleAwareCaller caller,
        string siteId,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var observation = await caller.GetAsync(
            $"{GraphBase}/sites/{siteId}/drives?$select=id,name,webUrl", token, cancellationToken);
        calls.Add(observation);

        var drives = new List<(string Title, string Path)>();
        var root = Root(observation);

        if (root is not null && root.Value.TryGetProperty("value", out var value) &&
            value.ValueKind == JsonValueKind.Array)
        {
            foreach (var drive in value.EnumerateArray())
            {
                var name = Text(drive, "name");
                var path = ServerRelative(Text(drive, "webUrl"));

                if (name is not null && path is not null)
                {
                    drives.Add((name, Uri.UnescapeDataString(path)));
                }
            }
        }

        return drives;
    }

    private List<Library> Wanted(IReadOnlyList<(string Title, string Path)> drives)
    {
        var libraries = new List<Library>();

        foreach (var group in options.FileTargets.GroupBy(t => t.Library ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            var wanted = group.Key;
            var library = new Library { Title = wanted.Length == 0 ? "(the default library)" : wanted };

            var match = wanted.Length == 0
                ? drives.FirstOrDefault()
                : drives.FirstOrDefault(d =>
                    string.Equals(d.Title, wanted, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(d.Path.Split('/').Last(), wanted, StringComparison.OrdinalIgnoreCase));

            if (match.Path is null)
            {
                library.Unresolved = wanted.Length == 0
                    ? "the site listed no library at all"
                    : $"no library on this site is titled '{wanted}'";
            }
            else
            {
                library.Path = match.Path;
            }

            foreach (var (_, path) in group)
            {
                library.Specimens.Add(path.TrimStart('/').Split('/').Last());
            }

            libraries.Add(library);
        }

        return libraries;
    }

    /// <summary>
    /// Whether the list defines the column, asked before anything is filtered on it.
    /// <para>
    /// A filter on a name the list does not have and a filter the server declines to apply are
    /// different findings, and the second one is only interesting once the first is ruled out.
    /// </para>
    /// </summary>
    private async Task ColumnAsync(
        ThrottleAwareCaller caller,
        Library library,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{ListUrl(library)}/fields?$select=InternalName,TypeAsString,Hidden,Indexed";

        var observation = await caller.GetAsync(url, token, cancellationToken, SharePointAccept);
        calls.Add(observation);
        library.FieldsStatus = observation.StatusText;

        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var field in value.EnumerateArray())
        {
            if (!string.Equals(Text(field, "InternalName"), Column, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            library.ColumnDefined = true;
            library.ColumnType = Text(field, "TypeAsString") ?? "(no type)";

            if (field.TryGetProperty("Indexed", out var indexed))
            {
                library.ColumnType += indexed.ValueKind == JsonValueKind.True
                    ? ", indexed"
                    : ", not indexed";
            }

            return;
        }
    }

    // ---- tables -----------------------------------------------------------------------------------

    private string ListUrl(Library library) =>
        $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(library.Path!)}')";

    private static ProbeTable LibraryTable(IReadOnlyList<Library> libraries) =>
        new("The library, and whether it defines the column being filtered on",
            ["library", "path", "/fields", $"{Column} defined", "type"],
            libraries.Select(l => (IReadOnlyList<string?>)
            [
                l.Title,
                l.Path ?? l.Unresolved ?? "(unresolved)",
                l.FieldsStatus ?? "not asked",
                l.ColumnDefined ? "yes" : "no",
                l.ColumnType ?? "-",
            ]).ToList());

    private static ProbeTable LegTable(IReadOnlyList<Library> libraries) =>
        new("Each call, against the same library in one run. Only the Where and the RowLimit differ",
            ["leg", "status", "error code", "rows", "pages", "continuation"],
            libraries.SelectMany(l => l.Results.Select(r => (IReadOnlyList<string?>)
            [
                r.Leg.Name,
                r.Status ?? "not asked",
                r.ErrorCode,
                r.Rows.ToString(),
                r.Pages.ToString(),
                r.ContinuationOffered ? (r.MoreWaiting ? "offered, more waiting" : "offered") : "none",
            ])).ToList());

    private static ProbeTable SpecimenTable(IReadOnlyList<Library> libraries)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var library in libraries)
        {
            foreach (var specimen in library.Specimens)
            {
                var cells = new List<string?> { specimen };

                foreach (var result in library.Results)
                {
                    cells.Add(result.Status is null
                        ? "not asked"
                        : result.Named.Contains(specimen)
                            ? result.WithValue.Contains(specimen) ? "row, value" : "row, empty"
                            : "no row");
                }

                rows.Add(cells);
            }
        }

        var header = new List<string> { "file" };
        header.AddRange(libraries.SelectMany(l => l.Results).Select(r => r.Leg.Name).Distinct());

        return new ProbeTable(
            $"Each named specimen, per call. 'value' means the {Column} cell was not empty - never " +
            "what was in it",
            header,
            rows);
    }

    private static ProbeTable CallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)
                [c.Method, c.Url, c.StatusText, c.ElapsedMs.ToString(), ApiError.Code(c)]).ToList());

    // ---- observations -----------------------------------------------------------------------------

    private static IEnumerable<Observation> Observations(IReadOnlyList<Library> libraries)
    {
        foreach (var library in libraries)
        {
            if (library.Path is null)
            {
                yield return Observation.NotRun(library.Title, library.Unresolved ?? "never resolved");
                continue;
            }

            var plain = library.Results.FirstOrDefault(r => r.Leg.Where is null);
            var filtered = library.Results.FirstOrDefault(r =>
                r.Leg.Where is not null && r.Leg.RowLimit == DefaultRowLimit &&
                r.Leg.Name.StartsWith(Column, StringComparison.Ordinal));
            var impossible = library.Results.FirstOrDefault(r => r.Leg.Name.StartsWith("a predicate", StringComparison.Ordinal));
            var paged = library.Results.FirstOrDefault(r => r.Leg.RowLimit == SmallRowLimit);

            if (plain is null || filtered is null || impossible is null)
            {
                yield return Observation.NotRun(library.Title, "not every leg was issued");
                continue;
            }

            // The control decides how the pair may be read at all, so it is stated before the pair.
            var filteringHappens = impossible.Status is not null && impossible.Status.StartsWith("200") &&
                                   impossible.Rows < plain.Rows;

            yield return Observation.Measured(
                $"{library.Title} - is any Where being applied",
                $"{impossible.Rows} row(s) for a predicate that cannot match, against {plain.Rows} " +
                $"unfiltered - {(filteringHappens ? "filtering happens" : "no narrowing observed")}")
                with
            {
                Details = new Dictionary<string, string?>
                {
                    ["impossible predicate"] = impossible.Describe,
                    ["no condition"] = plain.Describe,
                    ["why this comes first"] =
                        "if a predicate that cannot match still returns every row, the filtered leg " +
                        "agreeing with the unfiltered count says nothing about the column",
                },
            };

            var narrowed = filtered.Status is not null && filtered.Status.StartsWith("200") &&
                           filtered.Rows < plain.Rows;

            yield return Observation.Measured(
                $"{library.Title} - filtering on {Column}",
                $"{filtered.Rows} row(s) filtered against {plain.Rows} unfiltered; " +
                $"{filtered.Named.Count} of {library.Specimens.Count} named specimen(s) came back, " +
                $"{plain.WithValue.Count} carry a value")
                with
            {
                Details = new Dictionary<string, string?>
                {
                    ["filtered"] = filtered.Describe,
                    ["unfiltered"] = plain.Describe,
                    ["named specimens returned when filtered"] = Join(filtered.Named),
                    ["named specimens with a value when unfiltered"] = Join(plain.WithValue),
                    ["the two agree"] =
                        filtered.Named.SetEquals(plain.WithValue) ? "yes" : "no",
                    ["reading"] = filteringHappens
                        ? narrowed
                            ? "the server narrowed the set by this column"
                            : "a Where is applied in general, and this one did not narrow"
                        : "no narrowing was observed anywhere, so this leg says nothing about the column",
                    ["column defined"] = library.ColumnDefined ? library.ColumnType : "no",
                },
            };

            if (paged is not null)
            {
                yield return Observation.Measured(
                    $"{library.Title} - continuation at RowLimit {SmallRowLimit}",
                    $"{paged.Pages} page(s), {paged.Rows} row(s), " +
                    $"{(paged.ContinuationOffered ? "a continuation was offered" : "no continuation was offered")}")
                    with
                {
                    Details = new Dictionary<string, string?>
                    {
                        ["walk"] = paged.Describe,
                        ["against the same filter at the larger limit"] = filtered.Describe,
                        ["note"] = "row counts agreeing across the two limits is what says the " +
                                   "continuation was followed rather than the answer being cut short",
                    },
                };
            }
        }
    }

    // ---- helpers ----------------------------------------------------------------------------------

    private static string Join(IEnumerable<string> names)
    {
        var list = names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        return list.Count == 0 ? "(none)" : string.Join(", ", list);
    }

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static bool HasValue(JsonElement cell) => cell.ValueKind switch
    {
        JsonValueKind.Null or JsonValueKind.Undefined => false,
        JsonValueKind.String => !string.IsNullOrEmpty(cell.GetString()),
        JsonValueKind.Array => cell.GetArrayLength() > 0,
        JsonValueKind.Object => cell.EnumerateObject().Any(),
        _ => true,
    };

    private static string Describe(TokenResult token) =>
        token.Succeeded ? "held" : token.ErrorCode ?? "refused, no code";

    private static string? ServerRelative(string? webUrl) =>
        Uri.TryCreate(webUrl, UriKind.Absolute, out var uri) ? uri.AbsolutePath : null;

    private static JsonElement? Root(HttpObservation? observation)
    {
        if (observation is null || string.IsNullOrWhiteSpace(observation.Body))
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

    private static string? Text(JsonElement? element, string property) =>
        element is { } value ? Text(value, property) : null;

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/').Select(Uri.EscapeDataString));
}
