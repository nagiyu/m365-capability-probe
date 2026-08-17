using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Why a label inside a document does not appear in the list's columns.
/// <para>
/// Finding 14 left this open. Three files were measured as encrypted - the licence issued, the owner
/// read, the content undecryptable - and SharePoint's <c>MetaInfo</c> carried their label GUIDs,
/// matching what the MIP SDK reported exactly. Every dedicated label column was empty anyway, and the
/// tenant's <c>EnableAIPIntegration</c> was <c>True</c>, so the setting was not the reason.
/// </para>
/// <para>
/// The question this answers is narrow on purpose: <em>does it happen to files made now, or only to
/// the ones already there?</em> Everything else - which of the documented causes it is - depends on
/// that answer, and asking it first costs one run.
/// </para>
/// <para>
/// So this takes several paths and reports them side by side in one run. That is the whole design.
/// Promotion is a background job, and measuring four files in four runs would put "did the job run
/// between them" into every comparison; measuring them in one call sequence takes time out of the
/// experiment and leaves only how each file was made.
/// </para>
/// </summary>
public sealed class PromotionProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string SharePointAccept = "application/json;odata=nometadata";

    private const string ItemSelect =
        "id,name,size,createdBy,lastModifiedBy,createdDateTime,lastModifiedDateTime," +
        "sensitivityLabel,sharepointIds,publication";

    /// <summary>
    /// Which of the list's columns this reports per file. Discovered from the list rather than
    /// written down here.
    /// <para>
    /// Naming them from memory is exactly how the earlier attempt went wrong: five rounds of guessing
    /// column names, two of which SharePoint refused to <c>$select</c> while <c>/fields</c> listed
    /// them plainly. The rule now is that a column appears in this report because the list said it
    /// exists.
    /// </para>
    /// </summary>
    private static bool IsInteresting(string internalName) =>
        internalName.Contains("IpLabel", StringComparison.OrdinalIgnoreCase) ||
        internalName.Contains("Sensitivity", StringComparison.OrdinalIgnoreCase) ||
        internalName.StartsWith("_dlc", StringComparison.OrdinalIgnoreCase) ||
        internalName.Equals("_DisplayName", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The three columns this reports on every file whether or not the list defines them.
    /// <para>
    /// Everything else in this report is discovered. These are named because the question is about
    /// them specifically, and because "the list has no such column" and "the column exists and is
    /// empty" are different answers that a discovered-only report would collapse into one silence.
    /// </para>
    /// </summary>
    private static readonly string[] NamedColumns = ["_IpLabelId", "_EffectiveIpLabelId", "_DisplayName"];

    private sealed record Column(string InternalName, string Title, string Type, bool Hidden);

    private sealed record Subject
    {
        public required string Path { get; init; }

        /// <summary>Why this file produced no row, when it produced none. Never left blank.</summary>
        public string? Unreadable { get; set; }

        public string? ItemId { get; set; }
        public string? ListItemId { get; set; }
        public long? Size { get; set; }

        /// <summary>
        /// The <c>publication</c> facet exactly as it arrived, or why it did not.
        /// <para>
        /// A run that compares "while the condition is on" against "after it was lifted" rests on
        /// somebody remembering which of the two a given run was. That is the one part of a
        /// measurement this repository has no business taking on trust, and for a checked-out file
        /// the service says so itself. Printed raw rather than reduced to a flag: whatever this
        /// facet carries is the answer, and a boolean derived here would be this tool's opinion.
        /// </para>
        /// </summary>
        public string? Publication { get; set; }

        /// <summary>Graph's listing answer, kept as it arrived including a bare false (finding 14).</summary>
        public bool? FacetProtectionEnabled { get; set; }
        public bool FacetPresent { get; set; }
        public string? FacetLabelId { get; set; }

        public string? ExtractStatus { get; set; }
        public string? ExtractCodes { get; set; }
        public bool? ExtractFoundLabels { get; set; }

        public IReadOnlyList<SharePointMetaInfo.Label> InFile { get; set; } = [];

        /// <summary>
        /// False when the list item came back without a <c>MetaInfo</c> value at all. Kept apart from
        /// an empty label list: "the document carries no label" and "nobody asked the document" would
        /// otherwise print the same, and this whole run turns on that distinction.
        /// </summary>
        public bool? MetaInfoRead { get; set; }

        /// <summary>Why <c>MetaInfo</c> is missing, when it is. Never left to be inferred from silence.</summary>
        public string? MetaInfoUnread { get; set; }

        /// <summary>Which half of the response carried <c>MetaInfo</c>, so the route stays visible.</summary>
        public string? MetaInfoFrom { get; set; }

        /// <summary>
        /// The property bag exactly as SharePoint wrote it.
        /// <para>
        /// This tool gathers six named fields out of it and drops the rest, which was fine while the
        /// question was "does the file carry a label". It is not fine once the question is who applied
        /// one: whichever entry would answer that is among the fields being discarded, and a parser
        /// that only keeps what it already knows about cannot surface a field nobody thought to name.
        /// So the whole bag is quoted, and the reading is offered beside it rather than instead of it.
        /// </para>
        /// </summary>
        public string? RawMetaInfo { get; set; }

        /// <summary>Every key Graph returned in the list item's field bag, in the order it sent them.</summary>
        public IReadOnlyList<string> FieldNames { get; set; } = [];

        /// <summary>Whether Graph returned the list item's field bag at all.</summary>
        public bool FieldsRead { get; set; }

        public string? FieldsUnread { get; set; }

        /// <summary>What came back when the missing columns were asked for by name, and what did not.</summary>
        public IReadOnlyList<string> NamedSelectAnswered { get; set; } = [];

        public string? NamedSelectRefused { get; set; }

        /// <summary>The interesting columns' values, by internal name. Absent keys never arrived.</summary>
        public Dictionary<string, string> Columns { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string? GraphCreatedBy { get; set; }

        /// <summary>
        /// Who wrote it last, which is not who uploaded it. Run 76 read these from SharePoint and got
        /// lookup ids - bare numbers where a report needs a person - so both now come from Graph,
        /// where they arrive as identities.
        /// </summary>
        public string? LastModifiedBy { get; set; }
        public string? Created { get; set; }
        public string? Modified { get; set; }

        /// <summary>The label id the file carries, when it carries exactly one.</summary>
        public string? CarriedLabelId => InFile.Count == 1 ? InFile[0].Id : null;

        /// <summary>
        /// The column that names the label the file carries, and what it holds. Named rather than
        /// counted: run 78 reported "a column names it" without saying which, and a verdict whose
        /// basis cannot be read is a verdict that has to be taken on trust.
        /// </summary>
        public KeyValuePair<string, string>? Match
        {
            get
            {
                var ids = InFile.Select(l => l.Id).ToList();
                foreach (var column in Columns)
                {
                    if (ids.Any(id => column.Value.Contains(id, StringComparison.OrdinalIgnoreCase)))
                    {
                        return column;
                    }
                }

                return null;
            }
        }

        /// <summary>
        /// Whether any of the list's label columns names the label the file carries.
        /// <para>
        /// Three answers, and the third is the point. <c>no</c> means the file has a label and the
        /// columns do not know it - the thing being investigated. <c>-</c> means the file carries no
        /// label, so there was never anything to promote, and counting that as a failure would put a
        /// healthy file in the same bucket as a broken one.
        /// </para>
        /// </summary>
        public string Promoted
        {
            get
            {
                if (Unreadable is not null)
                {
                    return "?";
                }

                // An unread property bag is not a file without a label. Run 77 printed "carries no
                // label" for four documents whose MetaInfo had simply not been fetched.
                if (MetaInfoRead is not true)
                {
                    return "?";
                }

                if (InFile.Count == 0)
                {
                    return "-";
                }

                // Run 76 printed "no" for four files whose columns had never been read, because the
                // comparison had nothing to compare against and an empty set matches nothing. A
                // verdict about a source this never saw is worse than no verdict.
                if (!FieldsRead)
                {
                    return "?";
                }

                return Match is null ? "no" : "yes";
            }
        }
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("promotion");
        var app = options.InventoryApp;

        report.Subject["tenant"] = options.TenantId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["speaking as"] = app.Label;

        // Certificate first for the same reason inventory does it: half of this runs through
        // SharePoint REST, which refuses a client secret outright (finding 5).
        var source = AppOnlyTokenSource.WithCertificate(options, app);
        if (source.IsUnavailable)
        {
            console.WriteLine($"No certificate for {app.Label}: {source.Identity}. Falling back to the secret.");
            source = AppOnlyTokenSource.WithSecret(options, app);
        }

        report.Subject["proof of identity"] = source.Identity;
        report.Subject["files asked about"] = string.Join(", ", options.Files);

        // Stamped once so every row is aged against the same instant. The brief asks for two runs an
        // hour apart with the gap written down; taking it from each file's own timestamp means the gap
        // is measured rather than remembered, and it is per file rather than per run - which matters,
        // because the files in one run were not all made at the same moment.
        var runAt = DateTimeOffset.UtcNow;

        var caller = new ThrottleAwareCaller(http);
        var calls = new List<HttpObservation>();

        var graph = await source.GetTokenAsync(ProbeAudience.Graph, cancellationToken);
        if (!graph.Succeeded || graph.AccessToken is null)
        {
            report.MarkIncomplete($"no Graph token: {graph.ErrorCode}");
            report.Add(Observation.NotRun("every file", $"no Graph token was issued: {graph.ErrorDetail}"));
            report.Finish();
            return report;
        }

        console.WriteLine("Resolving the site...");
        var site = await caller.GetAsync(SiteUrl(), graph.AccessToken, cancellationToken);
        calls.Add(site);

        var siteId = ReadString(site, "id");
        if (siteId is null)
        {
            report.MarkIncomplete("the site was never resolved");
            report.Add(Observation.NotRun("every file", $"the site was never resolved ({site.StatusText})"));
            report.Add(BuildCallTable(calls));
            report.Finish();
            return report;
        }

        var drive = await caller.GetAsync($"{GraphBase}/sites/{siteId}/drive", graph.AccessToken, cancellationToken);
        calls.Add(drive);
        var libraryPath = AclResponses.DriveServerRelativePath(drive);

        var sharePoint = await source.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken);

        console.WriteLine("Asking the list which columns a label could go in...");
        var (columns, columnsUnread) = await ColumnsAsync(
            caller, libraryPath, sharePoint.AccessToken, calls, cancellationToken);

        var subjects = new List<Subject>();
        foreach (var path in options.Files)
        {
            console.WriteLine($"Reading {path} three ways...");
            var subject = new Subject { Path = path };
            subjects.Add(subject);

            await ReadGraphAsync(caller, siteId, subject, graph.AccessToken, calls, cancellationToken);

            if (subject.ItemId is not null)
            {
                await ExtractAsync(caller, siteId, subject, graph.AccessToken, calls, cancellationToken);
            }

            if (subject.ItemId is not null)
            {
                await ReadFieldsAsync(caller, siteId, subject, columns, graph.AccessToken, calls, cancellationToken);
            }

            if (subject.ListItemId is not null && libraryPath is not null)
            {
                await ReadListAsync(
                    caller, libraryPath, subject, sharePoint.AccessToken, calls, cancellationToken);
            }
        }

        report.Subject["throttling"] = caller.Record.Summary;

        report.Add(BuildColumnTable(columns, columnsUnread, sharePoint));
        report.Add(BuildPromotionTable(subjects, columns));
        report.Add(BuildProvenanceTable(subjects, runAt));
        report.Add(BuildCallTable(calls));

        // Whole, outside the grid. Six fields are gathered out of this bag and the rest dropped,
        // which was enough while the question was whether a file carries a label. It is not enough
        // for a question about who applied one: a parser that keeps only what it was told to look
        // for cannot show a field nobody named.
        foreach (var subject in subjects.Where(s => s.RawMetaInfo is not null))
        {
            report.Quote($"MetaInfo for {subject.Path}", subject.RawMetaInfo!);
        }

        foreach (var subject in subjects)
        {
            report.Add(SubjectObservation(subject));
        }

        report.Add(FieldBagObservation(subjects));
        report.Add(DocumentIdObservation(columns, subjects));
        report.Add(VerdictObservation(subjects));
        report.Finish();
        return report;
    }

    private string SiteUrl()
    {
        var relative = options.SiteServerRelativePath;
        return string.IsNullOrEmpty(relative)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relative)}";
    }

    /// <summary>
    /// The list's own column definitions, filtered to the ones a label could land in. Asked for once
    /// per run: what exists is a fact about the library, not about any file in it.
    /// </summary>
    private async Task<(IReadOnlyList<Column> Columns, string? Unread)> ColumnsAsync(
        ThrottleAwareCaller caller,
        string? libraryPath,
        string? sharePointToken,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        if (libraryPath is null)
        {
            return ([], "the library path was never discovered, so its columns were never asked for");
        }

        if (sharePointToken is null)
        {
            return ([], "no SharePoint token, so the columns were never asked for");
        }

        var url = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')/fields" +
                  "?$select=InternalName,Title,TypeAsString,Hidden";

        var observation = await caller.GetAsync(url, sharePointToken, cancellationToken, SharePointAccept);
        calls.Add(observation);

        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return ([], $"the columns could not be read ({Describe(observation)})");
        }

        var columns = new List<Column>();
        foreach (var field in value.EnumerateArray())
        {
            var internalName = Text(field, "InternalName");
            if (internalName is null || !IsInteresting(internalName))
            {
                continue;
            }

            columns.Add(new Column(
                internalName,
                Text(field, "Title") ?? internalName,
                Text(field, "TypeAsString") ?? "(no type)",
                field.TryGetProperty("Hidden", out var hidden) && hidden.ValueKind == JsonValueKind.True));
        }

        return (columns, null);
    }

    private async Task ReadGraphAsync(
        ThrottleAwareCaller caller,
        string siteId,
        Subject subject,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{GraphBase}/sites/{siteId}/drive/root:{EscapePath(subject.Path)}?$select={ItemSelect}";
        var observation = await caller.GetAsync(url, token, cancellationToken);
        calls.Add(observation);

        var root = Root(observation);
        if (root is null)
        {
            subject.Unreadable = $"Graph did not return the item ({Describe(observation)})";
            return;
        }

        subject.ItemId = Text(root.Value, "id");
        subject.Size = root.Value.TryGetProperty("size", out var size) && size.ValueKind == JsonValueKind.Number
            ? size.GetInt64()
            : null;
        subject.Publication = root.Value.TryGetProperty("publication", out var publication)
            ? publication.GetRawText()
            : "(the key is not on this item)";
        subject.Created = Text(root.Value, "createdDateTime");
        subject.Modified = Text(root.Value, "lastModifiedDateTime");
        subject.GraphCreatedBy = Identity(root.Value, "createdBy");
        subject.LastModifiedBy = Identity(root.Value, "lastModifiedBy");

        if (root.Value.TryGetProperty("sharepointIds", out var ids) && ids.ValueKind == JsonValueKind.Object)
        {
            subject.ListItemId = Text(ids, "listItemId");
        }

        if (root.Value.TryGetProperty("sensitivityLabel", out var label) && label.ValueKind == JsonValueKind.Object)
        {
            subject.FacetPresent = true;
            subject.FacetLabelId = Text(label, "id");
            subject.FacetProtectionEnabled =
                label.TryGetProperty("protectionEnabled", out var flag) &&
                flag.ValueKind is JsonValueKind.True or JsonValueKind.False
                    ? flag.GetBoolean()
                    : null;
        }

        if (subject.ItemId is null)
        {
            subject.Unreadable = $"Graph answered without an id ({observation.StatusText})";
        }
    }

    private async Task ExtractAsync(
        ThrottleAwareCaller caller,
        string siteId,
        Subject subject,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{GraphBase}/sites/{siteId}/drive/items/{subject.ItemId}/extractSensitivityLabels";
        var observation = await caller.PostAsync(url, token, cancellationToken);
        calls.Add(observation);

        subject.ExtractStatus = observation.StatusText;

        if (observation.IsSuccess)
        {
            var root = Root(observation);
            subject.ExtractFoundLabels = root is not null &&
                                         root.Value.TryGetProperty("labels", out var labels) &&
                                         labels.ValueKind == JsonValueKind.Array &&
                                         labels.GetArrayLength() > 0;
            return;
        }

        var chain = ErrorCodeChain(observation);
        subject.ExtractCodes = chain.Count > 0 ? string.Join(" / ", chain) : null;
    }

    /// <summary>
    /// The list item's <c>MetaInfo</c>, which is the document's own property bag and arrives from
    /// nowhere else. Only that: run 76 measured the field expansion asked for here not taking effect -
    /// every hidden Lookup column came back absent and the people columns came back as lookup ids -
    /// so the columns are read from Graph instead, and this call is left doing the one job it does.
    /// </summary>
    private async Task ReadListAsync(
        ThrottleAwareCaller caller,
        string libraryPath,
        Subject subject,
        string? sharePointToken,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        if (sharePointToken is null)
        {
            subject.MetaInfoUnread = "no SharePoint token";
            return;
        }

        var url = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')" +
                  $"/items({subject.ListItemId})?$expand=FieldValuesAsText";

        var observation = await caller.GetAsync(url, sharePointToken, cancellationToken, SharePointAccept);
        calls.Add(observation);

        var root = Root(observation);
        if (root is null)
        {
            subject.MetaInfoUnread = Describe(observation);
            return;
        }

        // Run 77 removed the expansion above on the reasoning that it was not taking effect, and lost
        // MetaInfo entirely - it had been arriving through it all along. Both places are read now, and
        // which one answered is recorded, so the next person to think this call is redundant can see
        // that it is not.
        var expanded = root.Value.TryGetProperty("FieldValuesAsText", out var text) &&
                       text.ValueKind == JsonValueKind.Object
            ? text
            : default;

        var metaInfo = expanded.ValueKind == JsonValueKind.Object ? Text(expanded, "MetaInfo") : null;
        subject.MetaInfoFrom = metaInfo is null ? null : "FieldValuesAsText";

        if (metaInfo is null)
        {
            metaInfo = Text(root.Value, "MetaInfo");
            subject.MetaInfoFrom = metaInfo is null ? null : "the item itself";
        }

        if (metaInfo is null)
        {
            subject.MetaInfoUnread = expanded.ValueKind == JsonValueKind.Object
                ? "neither the item nor its expanded text values carried MetaInfo"
                : "the item came back with no MetaInfo and no FieldValuesAsText";
            return;
        }

        subject.MetaInfoRead = true;
        subject.RawMetaInfo = metaInfo;
        subject.InFile = SharePointMetaInfo.Labels(SharePointMetaInfo.Parse(metaInfo));
    }

    /// <summary>
    /// The list item's columns, through Graph.
    /// <para>
    /// This is the route that was known to work and was not being used. The label columns are hidden
    /// Lookups, which SharePoint REST leaves out of an item's default projection and refuses to
    /// <c>$select</c> by name (finding 14); Graph's <c>listItem</c> expansion returns them, empty
    /// value and all - which is the distinction this whole run is about.
    /// </para>
    /// </summary>
    private async Task ReadFieldsAsync(
        ThrottleAwareCaller caller,
        string siteId,
        Subject subject,
        IReadOnlyList<Column> columns,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{GraphBase}/sites/{siteId}/drive/items/{subject.ItemId}/listItem?$expand=fields";
        var observation = await caller.GetAsync(url, token, cancellationToken);
        calls.Add(observation);

        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("fields", out var fields) ||
            fields.ValueKind != JsonValueKind.Object)
        {
            subject.FieldsUnread = Describe(observation);
            return;
        }

        subject.FieldsRead = true;
        subject.FieldNames = fields.EnumerateObject().Select(p => p.Name).ToList();
        Harvest(fields, columns, subject);

        var wanted = columns.Select(c => c.InternalName).Concat(NamedColumns)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (wanted.All(subject.Columns.ContainsKey))
        {
            return;
        }

        // The default expansion left some of them out. Asking for them by name is a different
        // question from asking for everything, and SharePoint has already been measured answering
        // the two differently (finding 14: /fields lists a column that $select then calls
        // nonexistent). So it is asked, and what comes back is reported either way.
        var missing = string.Join(",", wanted.Where(w => !subject.Columns.ContainsKey(w)));
        var second = await caller.GetAsync(
            $"{GraphBase}/sites/{siteId}/drive/items/{subject.ItemId}/listItem" +
            $"?$expand=fields($select={Uri.EscapeDataString(missing)})",
            token,
            cancellationToken);
        calls.Add(second);

        var retryRoot = Root(second);
        if (retryRoot is null || !retryRoot.Value.TryGetProperty("fields", out var named) ||
            named.ValueKind != JsonValueKind.Object)
        {
            subject.NamedSelectRefused = Describe(second);
            return;
        }

        subject.NamedSelectAnswered = named.EnumerateObject().Select(p => p.Name).ToList();
        Harvest(named, columns, subject);
    }

    private static void Harvest(JsonElement fields, IReadOnlyList<Column> columns, Subject subject)
    {
        foreach (var name in columns.Select(c => c.InternalName).Concat(NamedColumns)
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!fields.TryGetProperty(name, out var value))
            {
                continue;
            }

            subject.Columns[name] = value.ValueKind switch
            {
                JsonValueKind.String => value.GetString() ?? string.Empty,
                JsonValueKind.Null => string.Empty,
                _ => value.GetRawText(),
            };
        }
    }

    /// <summary>
    /// The columns a label could land in, as the list defines them. Printed before anything about a
    /// file, because "the column is empty" and "there is no such column" are different findings and
    /// the earlier round of this investigation confused them.
    /// </summary>
    private static ProbeTable BuildColumnTable(
        IReadOnlyList<Column> columns, string? unread, Auth.TokenResult sharePoint)
    {
        if (unread is not null)
        {
            return new ProbeTable(
                "Columns a label could go in, as the list defines them",
                ["column", "title", "type", "hidden"],
                [[unread, "-", "-", sharePoint.Succeeded ? "-" : $"no SharePoint token: {sharePoint.ErrorCode}"]]);
        }

        return new ProbeTable(
            "Columns a label could go in, as the list defines them",
            ["column", "title", "type", "hidden"],
            columns.Count == 0
                ? [["(the list defines none)", "-", "-", "-"]]
                : columns.Select(c => (IReadOnlyList<string?>)new[]
                {
                    c.InternalName, c.Title, c.Type, c.Hidden ? "yes" : "no",
                }).ToList());
    }

    /// <summary>
    /// The table this subcommand exists for: what the file carries, next to what the list says about
    /// it, next to what Graph says about it. Three sources on one row, so a disagreement is visible
    /// rather than reconstructed.
    /// </summary>
    private static ProbeTable BuildPromotionTable(IReadOnlyList<Subject> subjects, IReadOnlyList<Column> columns) =>
        new("Each file, on all four faces. Values are quoted as they arrived",
            ["file", "sensitivityLabel", "extractSensitivityLabels", "MetaInfo", "the named columns", "same label?"],
            subjects.Select(s => (IReadOnlyList<string?>)new[]
            {
                s.Path,
                Facet(s),
                Extraction(s),
                Carried(s),
                Named(s, columns),
                s.Promoted,
            }).ToList());

    /// <summary>
    /// Face 1. A file this could not read says so; a facet that did not arrive says so; a facet that
    /// arrived saying false says false. No cell is ever blank, because a blank one would be read as a
    /// value the service returned.
    /// </summary>
    private static string Facet(Subject subject)
    {
        if (subject.Unreadable is not null)
        {
            return "not read";
        }

        if (!subject.FacetPresent)
        {
            return "no sensitivityLabel property arrived";
        }

        var flag = subject.FacetProtectionEnabled switch
        {
            true => "protectionEnabled: true",
            false => "protectionEnabled: false",
            null => "protectionEnabled: not a boolean",
        };

        return subject.FacetLabelId is { Length: > 0 } id ? $"{flag}, id {id}" : $"{flag}, no id";
    }

    /// <summary>Face 2, refusals carried down to the innermost code as asked.</summary>
    private static string Extraction(Subject subject)
    {
        if (subject.Unreadable is not null)
        {
            return "not asked";
        }

        if (subject.ExtractStatus is null)
        {
            return "not asked";
        }

        if (subject.ExtractCodes is not null)
        {
            return $"{subject.ExtractStatus} ({subject.ExtractCodes})";
        }

        return subject.ExtractFoundLabels switch
        {
            true => $"{subject.ExtractStatus}, labels returned",
            false => $"{subject.ExtractStatus}, labels empty",
            null => $"{subject.ExtractStatus}, body unreadable",
        };
    }

    /// <summary>Face 3: what the document itself carries, quoted from its property bag.</summary>
    private static string Carried(Subject subject)
    {
        if (subject.Unreadable is not null)
        {
            return "not read";
        }

        if (subject.MetaInfoRead is not true)
        {
            return $"MetaInfo did not arrive ({subject.MetaInfoUnread ?? "not asked"})";
        }

        var from = subject.MetaInfoFrom is null ? "" : $" [from {subject.MetaInfoFrom}]";
        return subject.InFile.Count == 0
            ? $"no MSIP_Label entries{from}"
            : $"{string.Join("; ", subject.InFile.Select(l => l.Describe))}{from}";
    }

    /// <summary>
    /// Face 4. Each of the three named columns gets its own verdict, and there are four of them: a
    /// value, an empty value, a column the response did not include, and a column the list does not
    /// define at all. Only the first two are about this file.
    /// </summary>
    private static string Named(Subject subject, IReadOnlyList<Column> columns)
    {
        if (subject.Unreadable is not null)
        {
            return "not read";
        }

        if (!subject.FieldsRead)
        {
            return $"the field bag never arrived ({subject.FieldsUnread ?? "not asked"})";
        }

        var parts = NamedColumns.Select(name =>
        {
            if (subject.Columns.TryGetValue(name, out var value))
            {
                return value.Length == 0 ? $"{name}: empty" : $"{name}={value}";
            }

            // The bag arrived and this key was not in it. Whether the list even declares the column
            // is the other half of that answer, and the two together say something the pair apart
            // does not: a declared column Graph omits is not the same as a column nobody defined.
            return columns.Any(c => c.InternalName.Equals(name, StringComparison.OrdinalIgnoreCase))
                ? $"{name}: declared by the list, absent from the field bag"
                : $"{name}: the list defines no such column, and it was absent";
        });

        return string.Join("; ", parts);
    }

    /// <summary>
    /// Which of the label columns hold anything. An empty string is reported as empty and a column
    /// that never arrived is reported as absent - the distinction the earlier attempt lost.
    /// </summary>
    private static string Filled(Subject subject, IReadOnlyList<Column> columns)
    {
        if (subject.Unreadable is not null)
        {
            return "-";
        }

        var labelColumns = columns
            .Where(c => !c.InternalName.StartsWith("_dlc", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (labelColumns.Count == 0)
        {
            return "(no label columns to fill)";
        }

        var filled = labelColumns
            .Where(c => subject.Columns.TryGetValue(c.InternalName, out var v) && !string.IsNullOrEmpty(v))
            .Select(c => $"{c.InternalName}={subject.Columns[c.InternalName]}")
            .ToList();

        if (filled.Count > 0)
        {
            return string.Join("; ", filled);
        }

        if (!subject.FieldsRead)
        {
            return $"the field bag never arrived ({subject.FieldsUnread ?? "not asked"})";
        }

        var absent = labelColumns.Count(c => !subject.Columns.ContainsKey(c.InternalName));
        return absent == labelColumns.Count
            ? $"all {absent} declared columns were absent from the field bag"
            : $"all empty ({labelColumns.Count - absent} arrived empty, {absent} were absent)";
    }

    /// <summary>
    /// Who made each file and when, from both APIs. Finding 12 measured Graph's <c>createdBy</c>
    /// naming the person who uploaded rather than the person who protected, so the two names are kept
    /// apart - leg 4 of this experiment turns on exactly that difference.
    /// </summary>
    private static ProbeTable BuildProvenanceTable(IReadOnlyList<Subject> subjects, DateTimeOffset runAt) =>
        new("Who made each file, how old it is now, and what identifiers it got",
            ["file", "since it changed", "uploaded by", "last written by", "modified", "Document ID",
             "bytes", "publication"],
            subjects.Select(s => (IReadOnlyList<string?>)new[]
            {
                s.Path,
                Age(s.Modified ?? s.Created, runAt),
                s.GraphCreatedBy ?? "not read",
                s.LastModifiedBy ?? "not read",
                s.Modified ?? "not read",
                s.Columns.TryGetValue("_dlc_DocId", out var docId)
                    ? docId.Length > 0 ? docId : "empty"
                    : "did not arrive",
                s.Size?.ToString() ?? "not read",

                // Whether the file is checked out is a condition an operator would otherwise assert
                // from memory across a run taken while it was on and one taken after it was lifted.
                // The service reports it, so the run records it rather than being told.
                s.Publication ?? "not read",
            }).ToList());

    /// <summary>
    /// How long ago the file last changed, measured against this run's own clock. Promotion is a
    /// background job, so the gap between a file being written and this being asked is the variable
    /// the second run exists to move - and a gap the report computes is one nobody has to remember.
    /// </summary>
    private static string Age(string? timestamp, DateTimeOffset runAt)
    {
        if (!DateTimeOffset.TryParse(timestamp, out var when))
        {
            return "not read";
        }

        var elapsed = runAt - when;
        if (elapsed < TimeSpan.Zero)
        {
            return "in the future (clock skew)";
        }

        return elapsed.TotalMinutes < 1
            ? $"{(int)elapsed.TotalSeconds}s"
            : elapsed.TotalHours < 1
                ? $"{(int)elapsed.TotalMinutes}m"
                : $"{(int)elapsed.TotalHours}h {(int)elapsed.Minutes}m";
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)new[]
            {
                c.Method, c.Url, c.StatusText, c.ElapsedMs.ToString(), ApiError.Code(c),
            }).ToList());

    private static Observation SubjectObservation(Subject subject)
    {
        if (subject.Unreadable is not null)
        {
            return Observation.NotRun(subject.Path, subject.Unreadable);
        }

        var observed = subject.Promoted switch
        {
            "yes" => $"the file carries {subject.CarriedLabelId ?? "a label"}, and " +
                     $"{subject.Match!.Value.Key} holds \"{subject.Match!.Value.Value}\"",
            "no" => $"the file carries {subject.CarriedLabelId ?? "a label"}; no column names it",
            "-" => "the file carries no label",
            _ when subject.MetaInfoRead is not true =>
                $"undecided - MetaInfo was never read ({subject.MetaInfoUnread ?? "not asked"})",
            _ => $"undecided - the columns were never read ({subject.FieldsUnread ?? "not asked"})",
        };

        return Observation.Measured(subject.Path, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["promoted"] = subject.Promoted,
                ["matchingColumn"] = subject.Match?.Key,
                ["matchingValue"] = subject.Match?.Value,
                ["columnsRead"] = subject.Columns.Count == 0
                    ? "(none)"
                    : string.Join("; ", subject.Columns.Select(c =>
                        $"{c.Key}={(c.Value.Length == 0 ? "(empty)" : c.Value)}")),
                ["labelInFile"] = subject.InFile.Count == 0
                    ? null
                    : string.Join("; ", subject.InFile.Select(l => l.Describe)),
                ["encryptsPerContentBits"] = subject.InFile.Count == 1
                    ? subject.InFile[0].Encrypts?.ToString()
                    : null,
                ["setDate"] = subject.InFile.Count == 1 ? subject.InFile[0].SetDate : null,
                ["method"] = subject.InFile.Count == 1 ? subject.InFile[0].Method : null,
                ["facetProtectionEnabled"] = subject.FacetPresent
                    ? subject.FacetProtectionEnabled?.ToString()
                    : "(no sensitivityLabel property)",
                ["extractStatus"] = subject.ExtractStatus,
                ["extractCodes"] = subject.ExtractCodes,
                ["graphCreatedBy"] = subject.GraphCreatedBy,
                ["lastModifiedBy"] = subject.LastModifiedBy,
                ["listItemId"] = subject.ListItemId,
                ["created"] = subject.Created,
                ["modified"] = subject.Modified,
            },
        };
    }

    /// <summary>
    /// Whether the Document ID service is on here, answered from the library rather than from a
    /// settings page. It is one of the documented reasons promotion does not run, and it is the only
    /// one of them this can see without changing anything.
    /// </summary>
    /// <summary>
    /// Every key Graph put in the field bag, listed rather than searched.
    /// <para>
    /// Three routes have now been asked for the label columns and none of them returned one, while a
    /// delegated PowerShell call during finding 14 read <c>_IpLabelId</c> as an empty string. That
    /// gap is either about the route or about the caller, and neither can be told apart by trying
    /// another name from memory. So the keys that did arrive are printed, once, and whatever is
    /// missing from that list is missing as a fact rather than as a guess.
    /// </para>
    /// </summary>
    private static Observation FieldBagObservation(IReadOnlyList<Subject> subjects)
    {
        var read = subjects.Where(s => s.FieldsRead).ToList();
        if (read.Count == 0)
        {
            return Observation.NotRun(
                "what the field bag actually contains",
                "no file's field bag came back, so there was nothing to enumerate");
        }

        var sample = read[0];
        var everywhere = read.Skip(1)
            .Aggregate(
                new HashSet<string>(sample.FieldNames, StringComparer.Ordinal),
                (set, s) => { set.IntersectWith(s.FieldNames); return set; });

        var labelish = everywhere.Where(IsInteresting).OrderBy(n => n, StringComparer.Ordinal).ToList();

        return Observation.Measured(
            "what the field bag actually contains",
            $"{everywhere.Count} keys arrive for every file; {labelish.Count} of them could hold a label" +
            (labelish.Count == 0 ? " - none" : $" - {string.Join(", ", labelish)}")) with
        {
            Details = new Dictionary<string, string?>
            {
                ["keysCommonToEveryFile"] = string.Join(", ", everywhere.OrderBy(n => n, StringComparer.Ordinal)),
                ["labelCapableKeys"] = labelish.Count == 0 ? "(none)" : string.Join(", ", labelish),
                ["answeredWhenAskedByName"] = read.Any(s => s.NamedSelectAnswered.Count > 0)
                    ? string.Join(", ", read.SelectMany(s => s.NamedSelectAnswered).Distinct(StringComparer.Ordinal))
                    : "(nothing extra)",
                ["refusedWhenAskedByName"] = read.Select(s => s.NamedSelectRefused).FirstOrDefault(r => r is not null),
                ["note"] = "the list declares the label columns as hidden Lookups; whether that, the " +
                           "route, or the app-only caller is what keeps them out of this bag has not " +
                           "been separated",
            },
        };
    }

    private static Observation DocumentIdObservation(
        IReadOnlyList<Column> columns, IReadOnlyList<Subject> subjects)
    {
        var defined = columns.Any(c => c.InternalName.Equals("_dlc_DocId", StringComparison.OrdinalIgnoreCase));
        var stamped = subjects.Count(s =>
            s.Columns.TryGetValue("_dlc_DocId", out var value) && value.Length > 0);

        var observed = !defined
            ? "the library defines no _dlc_DocId column - the Document ID service is not on for it"
            : $"the library defines _dlc_DocId; {stamped} of {subjects.Count} files carry a value";

        return Observation.Measured("is the Document ID service on", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["columnDefined"] = defined.ToString(),
                ["filesWithADocumentId"] = stamped.ToString(),
                ["note"] = "read from the library's own columns. A defined column with no value on a " +
                           "file means the service is on but has not stamped that file yet, which is " +
                           "a different state from the service being off",
            },
        };
    }

    /// <summary>
    /// The line the run exists to produce: does this happen to files made now, or only to the ones
    /// that were already there? Stated as a split of the files that had a label to promote, because
    /// any other summary would need the reader to know which path was which leg.
    /// </summary>
    private static Observation VerdictObservation(IReadOnlyList<Subject> subjects)
    {
        var withLabel = subjects.Where(s => s.Unreadable is null && s.InFile.Count > 0).ToList();
        var promoted = withLabel.Where(s => s.Promoted == "yes").Select(s => s.Path).ToList();
        var not = withLabel.Where(s => s.Promoted == "no").Select(s => s.Path).ToList();
        var undecided = withLabel.Where(s => s.Promoted == "?").Select(s => s.Path).ToList();

        if (withLabel.Count == 0)
        {
            return Observation.Measured(
                "does this happen to files made now",
                "no file in this run carried a label, so nothing was promotable - this run answers nothing");
        }

        if (undecided.Count == withLabel.Count)
        {
            return Observation.Measured(
                "does this happen to files made now",
                $"undecided for all {withLabel.Count} labelled files - their columns were never read, " +
                "so nothing here says whether promotion happened");
        }

        var observed = (not.Count == 0 ? $"every one of the {promoted.Count} decided files promoted"
                : promoted.Count == 0
                    ? $"none of the {not.Count} decided files promoted"
                    : $"{promoted.Count} promoted, {not.Count} did not") +
            (undecided.Count == 0 ? "" : $"; {undecided.Count} undecided (columns never read)");

        return Observation.Measured("does this happen to files made now", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["labelledFiles"] = withLabel.Count.ToString(),
                ["promoted"] = promoted.Count == 0 ? "(none)" : string.Join(", ", promoted),
                ["notPromoted"] = not.Count == 0 ? "(none)" : string.Join(", ", not),
                ["undecided"] = undecided.Count == 0 ? "(none)" : string.Join(", ", undecided),
                ["note"] = "every file here was read in one call sequence, so the difference between " +
                           "rows is how each file was made and not when it was measured",
            },
        };
    }

    private static string Describe(HttpObservation observation)
    {
        if (observation.IsSuccess)
        {
            return $"{observation.StatusText}, but the body could not be read";
        }

        var code = ApiError.Code(observation);
        return $"{observation.StatusText}: {(code.Length > 0 ? code : observation.RefusalDiagnostic ?? "no reason given")}";
    }

    private static IReadOnlyList<string> ErrorCodeChain(HttpObservation observation)
    {
        var codes = new List<string>();
        var root = Root(observation);

        if (root is null || !root.Value.TryGetProperty("error", out var current))
        {
            return codes;
        }

        while (true)
        {
            if (Text(current, "code") is { Length: > 0 } code)
            {
                codes.Add(code);
            }

            if (!current.TryGetProperty("innerError", out var inner) || inner.ValueKind != JsonValueKind.Object)
            {
                return codes;
            }

            current = inner;
        }
    }

    private static string? Identity(JsonElement element, string property) =>
        element.TryGetProperty(property, out var by) && by.ValueKind == JsonValueKind.Object &&
        by.TryGetProperty("user", out var user) && user.ValueKind == JsonValueKind.Object
            ? Text(user, "email") ?? Text(user, "userPrincipalName") ?? Text(user, "displayName")
            : null;

    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/').Select(Uri.EscapeDataString));

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
