using System.Text;
using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Whether a label can be read from a listing when the label never reached the list's columns.
/// <para>
/// Two findings meet on this question and point opposite ways. Finding 24 read the label out of
/// <c>MetaInfo</c> for four files including the two that never promoted - the document's own property
/// bag does not care what the list knows. Finding 30 read eight protection columns out of
/// <c>RenderListDataAsStream</c> - but every value in them was a promoted value, and the file that
/// had not promoted carried the same three columns as the file with no label at all.
/// </para>
/// <para>
/// So: is the listing route tied to promotion, or is there a column in it that reads the file? One
/// column standing up on an unpromoted specimen settles it in favour of the listing. None standing up
/// settles it the other way - the document has to be opened, one file at a time - and that is an
/// answer too.
/// </para>
/// <para>
/// Both routes are walked over the same specimens in one run, so the difference between them cannot
/// be a difference of moment, of library or of caller. Every key that came back is written down whole
/// rather than only the ones that carried something: a column nobody knew to look for cannot be found
/// by looking for it.
/// </para>
/// </summary>
public sealed class UnpromotedProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string SharePointAccept = "application/json;odata=nometadata";

    /// <summary>The sweep from finding 30, unchanged so the two runs name the same columns.</summary>
    private static readonly string[] Needles =
        ["IpLabel", "Sensitivity", "Rms", "MSIP", "Encrypt", "Protect", "Classif"];

    /// <summary>
    /// Columns the needles do not catch and this run has to look at anyway.
    /// <para>
    /// <c>_DisplayName</c> holds the promoted label's display name - findings 22 and 29 turn on it -
    /// and not one of the needles above appears in it. Run 133 swept ten columns and this was not
    /// among them; it showed up only because the whole bag was printed. That is the failure the
    /// request warned about in so many words: a column nobody knows the name of cannot be searched
    /// for.
    /// </para>
    /// </summary>
    private static readonly string[] AlsoNamed = ["_DisplayName"];

    /// <summary>The allow list from finding 30: a flag, a flag and a version number, and nothing else.</summary>
    private static readonly string[] ValuesRecorded =
        ["_HasEncryptedContent", "_HasUserDefinedProtection", "_IpLabelPromotionCtagVersion"];

    private const int MaxRecordedValue = 100;

    /// <summary>
    /// Rows per page. Deliberately not the whole library: the point of asking for a page is that the
    /// continuation has to work, and a limit never reached proves nothing about it.
    /// </summary>
    private const int DefaultRowLimit = 100;

    private sealed record Column(string InternalName, string Title, string Type, bool Hidden);

    /// <summary>What one route cost and whether it finished. A stop at the limit is not an ending.</summary>
    private sealed class Walk
    {
        public string? Status { get; set; }
        public int Pages { get; set; }
        public int Rows { get; set; }

        /// <summary>True when the route still had a continuation when this run stopped following.</summary>
        public bool MoreWaiting { get; set; }

        /// <summary>How many pages this run was willing to follow, so the limit is visible beside the count.</summary>
        public required int PageLimit { get; init; }

        public string Describe => Status is null
            ? "not asked"
            : $"{Status}, {Rows} row(s) over {Pages} page(s)" +
              (MoreWaiting ? $" - stopped at the {PageLimit} page limit with more waiting" : string.Empty);
    }

    /// <summary>One named specimen, as both routes answered about it.</summary>
    private sealed class Specimen
    {
        public required string Library { get; init; }
        public required string Path { get; init; }
        public string Leaf => Path.TrimStart('/').Split('/').Last();

        /// <summary>The full server-relative path this specimen means, once the library is known.</summary>
        public string? FileRef { get; set; }
        public string Extension => Path.Contains('.') ? Path[Path.LastIndexOf('.')..] : "(none)";

        /// <summary>
        /// How many items each route matched. More than one means the library holds another file of
        /// the same name somewhere else, and a specimen that absorbed it would be reporting two files
        /// as one - so it is counted rather than merged away.
        /// </summary>
        public int StreamMatches { get; set; }

        public int TextMatches { get; set; }

        /// <summary>Items sharing this leaf name anywhere in the library, however deep.</summary>
        public int LeafSeen { get; set; }

        /// <summary>Every key the listing returned for this row, whatever it held.</summary>
        public List<string> StreamKeys { get; } = [];

        /// <summary>Protection columns whose cell was not empty.</summary>
        public HashSet<string> StreamValues { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Every key in the listing whose cell was not empty, swept or not.
        /// <para>
        /// The narrow set above can only find columns somebody thought to name. This one cannot miss a
        /// column for being unnamed, which is the whole reason the request asked for the bag rather
        /// than for the columns that stood up.
        /// </para>
        /// </summary>
        public HashSet<string> AllValues { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Dictionary<string, string> Recorded { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Every key the FieldValuesAsText bag returned.</summary>
        public List<string> TextKeys { get; } = [];

        /// <summary>
        /// Who has the file checked out, straight from the list's own bag.
        /// <para>
        /// Leg 4 turns on a specimen being checked out, and "we checked it out" is something done in a
        /// browser rather than something this run can see. Reading it back means a leg measuring
        /// check-out cannot quietly be measuring a file that was checked in again.
        /// </para>
        /// </summary>
        public string? CheckoutUser { get; set; }

        public string? MetaInfo { get; set; }
        public IReadOnlyList<SharePointMetaInfo.Label> Labels { get; set; } = [];

        public bool FoundInStream { get; set; }
        public bool FoundInText { get; set; }

        /// <summary>True when the list's own label column carried something for this file.</summary>
        public bool Promoted => StreamValues.Contains("_IpLabelId");

        /// <summary>True when the document itself carries a label, whatever the list knows.</summary>
        public bool Labelled => Labels.Count > 0;
    }

    private sealed class Library
    {
        public required string Title { get; init; }
        public string? DriveId { get; set; }
        public string? Path { get; set; }
        public string? Unresolved { get; set; }
        public List<Column> Columns { get; } = [];
        public string? FieldsStatus { get; set; }
        public Walk Stream { get; set; } = null!;
        public Walk Text { get; set; } = null!;
        public List<Specimen> Specimens { get; } = [];
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("unpromoted");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["needles"] = string.Join(", ", Needles);
        report.Subject["values written down"] =
            $"{string.Join(", ", ValuesRecorded)} - and no others. Every other column is recorded as " +
            "whether a value arrived, never as what it was";
        report.Subject["matched on"] =
            "FileRef - the full server-relative path - asked for by name in both routes, so the key " +
            "is not part of what the two routes vary. Run 132 matched on FileLeafRef instead and one " +
            "specimen silently absorbed a second item of the same name from somewhere else in the " +
            "library; how many items share each leaf is now reported rather than merged";
        report.Subject["paging"] =
            $"RowLimit {options.RequestedPageSize ?? DefaultRowLimit} with Paged=TRUE, following at " +
            $"most {options.PagesToFollow} page(s). Without Paged the listing ends at the limit " +
            "without offering a continuation, and a short answer reads as a complete one";

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

        var (drives, driveTable) = await DrivesAsync(caller, siteId, graph.AccessToken, calls, cancellationToken);
        report.Add(driveTable);

        var libraries = Wanted(drives);

        foreach (var library in libraries)
        {
            if (library.Path is null)
            {
                continue;
            }

            console.WriteLine($"Sweeping {library.Title} for protection columns...");
            await SweepAsync(caller, library, sharePoint.AccessToken, calls, cancellationToken);

            console.WriteLine($"RenderListDataAsStream over {library.Title}...");
            await StreamAsync(caller, library, sharePoint.AccessToken, calls, cancellationToken);

            console.WriteLine($"FieldValuesAsText over {library.Title}...");
            await TextAsync(caller, library, sharePoint.AccessToken, calls, cancellationToken);
        }

        report.Add(LibraryTable(libraries));
        report.Add(ColumnTable(libraries));
        report.Add(SpecimenTable(libraries));
        report.Add(ValueTable(libraries));
        report.Add(CallTable(calls));

        foreach (var library in libraries)
        {
            foreach (var specimen in library.Specimens)
            {
                Quote(report, specimen);
            }
        }

        foreach (var observation in Observations(libraries))
        {
            report.Add(observation);
        }

        report.Subject["throttling"] = caller.Record.Summary;
        report.Finish();
        return report;
    }

    // ---- resolving ---------------------------------------------------------------------------

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

    /// <summary>
    /// Every library the site has, listed whether or not this run wants it.
    /// <para>
    /// A title that matches nothing is the likeliest way this run goes wrong, and it is the kind of
    /// wrong that looks like a refusal. Printing the actual titles means a reader can see that the
    /// library was never there rather than inferring it from an empty table.
    /// </para>
    /// </summary>
    private async Task<(List<(string Title, string Id, string Path)> Drives, ProbeTable Table)> DrivesAsync(
        ThrottleAwareCaller caller,
        string siteId,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var observation = await caller.GetAsync(
            $"{GraphBase}/sites/{siteId}/drives?$select=id,name,webUrl", token, cancellationToken);
        calls.Add(observation);

        var drives = new List<(string Title, string Id, string Path)>();
        var rows = new List<IReadOnlyList<string?>>();

        var root = Root(observation);
        if (root is not null && root.Value.TryGetProperty("value", out var value) &&
            value.ValueKind == JsonValueKind.Array)
        {
            foreach (var drive in value.EnumerateArray())
            {
                var name = Text(drive, "name");
                var id = Text(drive, "id");
                var path = ServerRelative(Text(drive, "webUrl"));

                if (name is null || id is null || path is null)
                {
                    continue;
                }

                drives.Add((name, id, path));
                rows.Add([name, path, Uri.UnescapeDataString(path).Split('/').Last()]);
            }
        }

        if (rows.Count == 0)
        {
            rows.Add(["(none listed)", observation.StatusText, ApiError.Code(observation)]);
        }

        return (drives, new ProbeTable(
            "Every document library this site has. A title that matches nothing is diagnosable here " +
            "rather than from an empty result",
            ["title", "server-relative path", "last path segment"],
            rows));
    }

    /// <summary>
    /// The libraries this run's specimens name, matched against the site's own titles.
    /// <para>
    /// A title matches either the drive's name or the last segment of its path, because those differ
    /// for the default library - Graph calls it Documents and the path says Shared Documents - and an
    /// operator has seen one of the two without knowing which.
    /// </para>
    /// </summary>
    private List<Library> Wanted(IReadOnlyList<(string Title, string Id, string Path)> drives)
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
                    string.Equals(Uri.UnescapeDataString(d.Path).Split('/').Last(), wanted, StringComparison.OrdinalIgnoreCase));

            if (match.Id is null)
            {
                library.Unresolved = wanted.Length == 0
                    ? "the site listed no library at all"
                    : $"no library on this site is titled '{wanted}'";
            }
            else
            {
                library.DriveId = match.Id;
                library.Path = Uri.UnescapeDataString(match.Path);
            }

            foreach (var (_, path) in group)
            {
                library.Specimens.Add(new Specimen
                {
                    Library = library.Title,
                    Path = path,
                    FileRef = library.Path is null
                        ? null
                        : $"{library.Path.TrimEnd('/')}/{path.TrimStart('/')}",
                });
            }

            libraries.Add(library);
        }

        return libraries;
    }

    // ---- the column sweep --------------------------------------------------------------------

    private async Task SweepAsync(
        ThrottleAwareCaller caller,
        Library library,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{ListUrl(library)}/fields?$select=InternalName,Title,TypeAsString,Hidden";

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
            var internalName = Text(field, "InternalName");
            var title = Text(field, "Title");

            if (internalName is null || !Matches(internalName, title))
            {
                continue;
            }

            library.Columns.Add(new Column(
                internalName,
                title ?? internalName,
                Text(field, "TypeAsString") ?? "(no type)",
                field.TryGetProperty("Hidden", out var hidden) && hidden.ValueKind == JsonValueKind.True));
        }
    }

    private static bool Matches(string internalName, string? title) =>
        AlsoNamed.Contains(internalName, StringComparer.OrdinalIgnoreCase) ||
        Needles.Any(needle =>
            internalName.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
            (title is not null && title.Contains(needle, StringComparison.OrdinalIgnoreCase)));

    // ---- route one: the listing ----------------------------------------------------------------

    /// <summary>
    /// <c>RenderListDataAsStream</c>, paged.
    /// <para>
    /// <c>Paged="TRUE"</c> is on the <c>RowLimit</c> rather than left off, because without it the view
    /// stops at the limit and offers no continuation - the listing simply ends, and a truncated answer
    /// is indistinguishable from a complete one. With it, <c>NextHref</c> arrives and can be followed
    /// or, when this run stops first, reported as still waiting.
    /// </para>
    /// </summary>
    private async Task StreamAsync(
        ThrottleAwareCaller caller,
        Library library,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var walk = new Walk { PageLimit = options.PagesToFollow };
        library.Stream = walk;

        var names = library.Columns.Select(c => c.InternalName)
            .Prepend("FileRef").Prepend("FileLeafRef").ToList();
        var body = Body(names);
        var url = $"{ListUrl(library)}/RenderListDataAsStream";
        string? next = url;

        while (next is not null && walk.Pages < options.PagesToFollow)
        {
            var observation = await caller.PostAsync(next, token, cancellationToken, body);
            calls.Add(observation);

            walk.Pages++;
            walk.Status ??= observation.StatusText;

            var root = Root(observation);
            if (root is null || !root.Value.TryGetProperty("Row", out var rows) ||
                rows.ValueKind != JsonValueKind.Array)
            {
                walk.Status = observation.StatusText;
                return;
            }

            foreach (var row in rows.EnumerateArray())
            {
                walk.Rows++;
                Absorb(library, row);
            }

            var href = Text(root, "NextHref");
            next = string.IsNullOrEmpty(href) ? null : url + href;
        }

        walk.MoreWaiting = next is not null;
    }

    private void Absorb(Library library, JsonElement row)
    {
        var leaf = Text(row, "FileLeafRef");
        if (leaf is null)
        {
            return;
        }

        foreach (var sharing in library.Specimens.Where(s =>
                     string.Equals(s.Leaf, leaf, StringComparison.OrdinalIgnoreCase)))
        {
            sharing.LeafSeen++;
        }

        var specimen = Match(library, Text(row, "FileRef"), leaf);
        if (specimen is null)
        {
            return;
        }

        specimen.StreamMatches++;
        specimen.FoundInStream = true;

        foreach (var property in row.EnumerateObject())
        {
            specimen.StreamKeys.Add(property.Name);

            if (HasValue(property.Value))
            {
                specimen.AllValues.Add(property.Name);
            }
        }

        foreach (var column in library.Columns)
        {
            if (!row.TryGetProperty(column.InternalName, out var cell) || !HasValue(cell))
            {
                continue;
            }

            specimen.StreamValues.Add(column.InternalName);

            if (ValuesRecorded.Contains(column.InternalName, StringComparer.OrdinalIgnoreCase))
            {
                specimen.Recorded[column.InternalName] = Short(cell);
            }
        }
    }

    /// <summary>
    /// The specimen a row belongs to, decided by the full path rather than by the file name.
    /// <para>
    /// A leaf name is not unique inside a library - a folder can hold another file called the same
    /// thing - and matching on one merges two files into one row of the report without saying so. Run
    /// 132 did exactly that: a specimen's property bag arrived twice, and only the key count gave it
    /// away. The path is what the operator named, so it is what the row is matched against.
    /// </para>
    /// <para>
    /// The leaf is still compared as a fallback, but only when no path came back at all - a row with
    /// no FileRef is a row this run cannot place, and guessing from the name is worse than saying so.
    /// </para>
    /// </summary>
    private static Specimen? Match(Library library, string? fileRef, string leaf)
    {
        if (fileRef is not null)
        {
            var decoded = Uri.UnescapeDataString(fileRef);

            return library.Specimens.FirstOrDefault(s =>
                s.FileRef is not null &&
                (string.Equals(s.FileRef, fileRef, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(s.FileRef, decoded, StringComparison.OrdinalIgnoreCase)));
        }

        return library.Specimens.FirstOrDefault(s =>
            string.Equals(s.Leaf, leaf, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The request body. The names are the only thing that varies between runs.</summary>
    private string Body(IEnumerable<string> fieldNames)
    {
        var view = new StringBuilder("<View><ViewFields>");

        foreach (var name in fieldNames)
        {
            view.Append("<FieldRef Name='").Append(Attribute(name)).Append("' />");
        }

        view.Append("</ViewFields><RowLimit Paged=\"TRUE\">")
            .Append(options.RequestedPageSize ?? DefaultRowLimit)
            .Append("</RowLimit></View>");

        return JsonSerializer.Serialize(new
        {
            parameters = new
            {
                RenderOptions = 2,
                ViewXml = view.ToString(),
            },
        });
    }

    // ---- route two: the document's own bag -----------------------------------------------------

    /// <summary>
    /// Finding 24's route: <c>$expand=FieldValuesAsText</c>, which carries <c>MetaInfo</c> and read the
    /// label off four files including the two the list never knew about.
    /// </summary>
    private async Task TextAsync(
        ThrottleAwareCaller caller,
        Library library,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var walk = new Walk { PageLimit = options.PagesToFollow };
        library.Text = walk;

        var top = options.RequestedPageSize is { } size ? $"&$top={size}" : $"&$top={DefaultRowLimit}";
        string? next = $"{ListUrl(library)}/items?$expand=FieldValuesAsText{top}";

        while (next is not null && walk.Pages < options.PagesToFollow)
        {
            var observation = await caller.GetAsync(next, token, cancellationToken, SharePointAccept);
            calls.Add(observation);

            walk.Pages++;
            walk.Status ??= observation.StatusText;

            var root = Root(observation);
            if (root is null || !root.Value.TryGetProperty("value", out var items) ||
                items.ValueKind != JsonValueKind.Array)
            {
                walk.Status = observation.StatusText;
                return;
            }

            foreach (var item in items.EnumerateArray())
            {
                walk.Rows++;

                if (!item.TryGetProperty("FieldValuesAsText", out var bag) ||
                    bag.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var leaf = Text(bag, "FileLeafRef");
                var specimen = leaf is null ? null : Match(library, Text(bag, "FileRef"), leaf);

                if (specimen is null)
                {
                    continue;
                }

                specimen.TextMatches++;
                specimen.FoundInText = true;
                specimen.TextKeys.AddRange(bag.EnumerateObject().Select(p => p.Name));
                specimen.CheckoutUser = Text(bag, "CheckoutUser");
                specimen.MetaInfo = Text(bag, "MetaInfo");
                specimen.Labels = SharePointMetaInfo.Labels(SharePointMetaInfo.Parse(specimen.MetaInfo));
            }

            next = Text(root, "odata.nextLink") ?? Text(root, "@odata.nextLink");
        }

        walk.MoreWaiting = next is not null;
    }

    // ---- tables ---------------------------------------------------------------------------------

    private string ListUrl(Library library) =>
        $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(library.Path!)}')";

    private static ProbeTable LibraryTable(IReadOnlyList<Library> libraries) =>
        new("Each library this run was pointed at, and how far each route got",
            ["library", "path", "/fields", "RenderListDataAsStream", "FieldValuesAsText"],
            libraries.Select(l => (IReadOnlyList<string?>)
            [
                l.Title,
                l.Path ?? l.Unresolved ?? "(unresolved)",
                l.FieldsStatus ?? "not asked",
                l.Stream?.Describe ?? "not asked",
                l.Text?.Describe ?? "not asked",
            ]).ToList());

    private static ProbeTable ColumnTable(IReadOnlyList<Library> libraries) =>
        new("The protection columns each library defines, swept rather than named in advance",
            ["library", "internal name", "type", "hidden"],
            libraries.SelectMany(l => l.Columns.Select(c => (IReadOnlyList<string?>)
                [l.Title, c.InternalName, c.Type, c.Hidden ? "yes" : "no"])).ToList());

    /// <summary>
    /// The answer, one row per specimen. Both routes side by side, with the two classifications the
    /// rest of the report turns on stated rather than left to the reader.
    /// </summary>
    private static ProbeTable SpecimenTable(IReadOnlyList<Library> libraries) =>
        new("Each specimen, on both routes. 'promoted' is whether the list's own label column carried " +
            "anything; 'label in the file' is what MetaInfo says, which does not depend on the list",
            ["file", "ext", "checked out", "promoted", "listing: columns with a value", "label in the file"],
            libraries.SelectMany(l => l.Specimens.Select(s => (IReadOnlyList<string?>)
            [
                s.Leaf,
                s.Extension,
                !s.FoundInText
                    ? "(no row)"
                    : string.IsNullOrEmpty(s.CheckoutUser) ? "no" : "yes",
                !s.FoundInStream ? "(row never returned)" : s.Promoted ? "yes" : "no",
                !s.FoundInStream
                    ? "-"
                    : $"{s.StreamValues.Count} of {l.Columns.Count}: {Join(s.StreamValues)}",
                !s.FoundInText
                    ? "(row never returned)"
                    : s.Labels.Count == 0
                        ? "no MSIP_Label entries"
                        : string.Join("; ", s.Labels.Select(x => x.Describe)),
            ])).ToList());

    private static ProbeTable ValueTable(IReadOnlyList<Library> libraries)
    {
        var header = new List<string> { "file", "library" };
        header.AddRange(ValuesRecorded);

        return new ProbeTable(
            "The three columns whose values this run writes down. Every other column is presence only",
            header,
            libraries.SelectMany(l => l.Specimens.Select(s => (IReadOnlyList<string?>)
                new List<string?> { s.Leaf, l.Title }
                    .Concat(ValuesRecorded.Select(n =>
                        s.Recorded.TryGetValue(n, out var v) ? v : "(no value)"))
                    .ToList())).ToList());
    }

    private static ProbeTable CallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)
                [c.Method, c.Url, c.StatusText, c.ElapsedMs.ToString(), ApiError.Code(c)]).ToList());

    /// <summary>
    /// Every key both routes returned, per specimen, whole.
    /// <para>
    /// Only the names. The values are file names, user names and label identifiers, and the request
    /// was for the bag rather than for what is in it: a column nobody knows the name of cannot be
    /// searched for, so it has to be enumerated.
    /// </para>
    /// </summary>
    private static void Quote(ProbeReport report, Specimen specimen)
    {
        Bag(report, specimen, "RenderListDataAsStream", specimen.StreamKeys, specimen.StreamMatches);
        Bag(report, specimen, "FieldValuesAsText", specimen.TextKeys, specimen.TextMatches);
    }

    /// <summary>
    /// One bag, quoted whole. The title carries the distinct count and how many rows contributed it:
    /// a raw total that is twice the distinct one is not a wide bag, it is two files.
    /// </summary>
    private static void Bag(ProbeReport report, Specimen specimen, string route, List<string> keys, int matches)
    {
        if (keys.Count == 0)
        {
            return;
        }

        var distinct = keys.Distinct(StringComparer.Ordinal).OrderBy(k => k, StringComparer.Ordinal).ToList();

        report.Quote(
            $"{specimen.Leaf} - every key {route} returned ({distinct.Count} distinct, from {matches} row(s))",
            string.Join("\n", distinct));
    }

    // ---- observations ---------------------------------------------------------------------------

    private static IEnumerable<Observation> Observations(IReadOnlyList<Library> libraries)
    {
        var all = libraries.SelectMany(l => l.Specimens).ToList();

        foreach (var library in libraries.Where(l => l.Path is null))
        {
            yield return Observation.NotRun(library.Title, library.Unresolved ?? "never resolved");
        }

        // The controls are picked by what was measured rather than by which file the operator meant:
        // a specimen carrying no label in its own bytes is the thing an unlabelled control is.
        var controls = all.Where(s => s.FoundInText && !s.Labelled).ToList();
        var everywhere = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var control in controls)
        {
            everywhere.UnionWith(control.AllValues);
        }

        foreach (var specimen in all)
        {
            if (!specimen.FoundInStream && !specimen.FoundInText)
            {
                yield return Observation.NotRun(specimen.Leaf, "neither route returned a row for it");
                continue;
            }

            // Counts first, and the deciding one first of those: a column that also stands up on a
            // file with no label is not reading the label, whatever its name promises.
            var telling = specimen.AllValues.Except(everywhere, StringComparer.OrdinalIgnoreCase).ToList();

            yield return Observation.Measured(
                specimen.Leaf,
                $"{telling.Count} key(s) stand up here and not on an unlabelled file, " +
                $"{specimen.AllValues.Count} of {specimen.StreamKeys.Distinct(StringComparer.Ordinal).Count()} " +
                $"stand up at all; MetaInfo: {(specimen.Labelled ? "label present" : "no label")}")
                with
            {
                Details = new Dictionary<string, string?>
                {
                    ["library"] = specimen.Library,
                    ["extension"] = specimen.Extension,
                    ["checked out"] = specimen.FoundInText
                        ? string.IsNullOrEmpty(specimen.CheckoutUser) ? "no" : "yes"
                        : "(no row)",
                    ["rows matched"] =
                        $"{specimen.StreamMatches} from the listing, {specimen.TextMatches} from the bag" +
                        (specimen.LeafSeen > specimen.StreamMatches
                            ? $"; {specimen.LeafSeen} item(s) in this library share the name"
                            : string.Empty),
                    ["promoted"] = specimen.FoundInStream ? specimen.Promoted ? "yes" : "no" : "(no row)",
                    ["labelled in its own bytes"] = specimen.FoundInText ? specimen.Labelled ? "yes" : "no" : "(no row)",
                    ["keys telling it from an unlabelled file"] = Join(telling),
                    ["swept columns with any value"] = Join(specimen.StreamValues),
                    ["label from MetaInfo"] = specimen.Labels.Count == 0
                        ? "(none)"
                        : string.Join("; ", specimen.Labels.Select(l => l.Describe)),
                    ["keys returned"] =
                        $"{specimen.StreamKeys.Distinct(StringComparer.Ordinal).Count()} from the listing, " +
                        $"{specimen.TextKeys.Distinct(StringComparer.Ordinal).Count()} from FieldValuesAsText",
                },
            };
        }

        // The question the run was built for, answered only from the specimens that can answer it.
        var subjects = all.Where(s => s.FoundInStream && s.FoundInText && s.Labelled && !s.Promoted).ToList();

        if (subjects.Count == 0)
        {
            yield return Observation.NotRun(
                "whether the listing can read a label that never promoted",
                $"{all.Count(s => s.Labelled)} labelled specimen(s), none of them unpromoted - " +
                "there was no case of the thing being asked about");
            yield break;
        }

        var stood = subjects
            .SelectMany(s => s.AllValues.Except(everywhere, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        yield return Observation.Measured(
            "whether the listing can read a label that never promoted",
            $"{stood.Count} key(s) stood up on {subjects.Count} unpromoted specimen(s), " +
            $"out of {subjects.Max(s => s.StreamKeys.Distinct(StringComparer.Ordinal).Count())} the " +
            $"listing returned; MetaInfo carried the label on {subjects.Count(s => s.Labelled)} of them")
            with
        {
            Details = new Dictionary<string, string?>
            {
                ["unpromoted specimens"] = Join(subjects.Select(s => s.Leaf)),
                ["unlabelled controls"] = controls.Count == 0
                    ? "(none - so 'stands up here and not there' had nothing to subtract)"
                    : Join(controls.Select(s => s.Leaf)),
                ["keys that stood up"] = Join(stood),
                ["keys discounted for standing up on an unlabelled file too"] = $"{everywhere.Count}",
                ["counted over"] = "every key the listing returned, not only the swept columns - a " +
                                   "column nobody knows the name of cannot be searched for",
                ["note"] = "one call sequence over both routes, so the difference between them is the " +
                           "route and not the moment",
            },
        };
    }

    // ---- helpers --------------------------------------------------------------------------------

    private static string Join(IEnumerable<string> names)
    {
        var list = names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        return list.Count == 0 ? "(none)" : string.Join(", ", list);
    }

    private static bool HasValue(JsonElement cell) => cell.ValueKind switch
    {
        JsonValueKind.Null or JsonValueKind.Undefined => false,
        JsonValueKind.String => !string.IsNullOrEmpty(cell.GetString()),
        JsonValueKind.Array => cell.GetArrayLength() > 0,
        JsonValueKind.Object => cell.EnumerateObject().Any(),
        _ => true,
    };

    private static string Short(JsonElement cell)
    {
        var text = cell.ValueKind == JsonValueKind.String
            ? cell.GetString() ?? string.Empty
            : cell.GetRawText();

        return text.Length <= MaxRecordedValue ? text : text[..MaxRecordedValue] + "...[truncated]";
    }

    private static string Attribute(string value) =>
        value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("'", "&apos;");

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
