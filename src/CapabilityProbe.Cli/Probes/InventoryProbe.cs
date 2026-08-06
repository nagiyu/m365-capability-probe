using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// One row per file: what it is called, and whether it is protected.
/// <para>
/// This is the one subcommand meant to be used rather than only read. The others exist to find out
/// what happens; this one exists to answer "what is in this library", and that difference shows up in
/// two places. It honours <c>Retry-After</c>, which nothing else here does. And it never prints a
/// value it did not establish - a file whose protection could not be determined says so, in its own
/// word, rather than defaulting to "not protected".
/// </para>
/// <para>
/// That last rule is not fastidiousness. Finding 14 measured Graph returning
/// <c>protectionEnabled: false</c> for three files this tool had already decrypted, with exactly the
/// same value it returns for a file carrying no label at all. A column that copied that through would
/// list encrypted documents as unprotected, and would look completely healthy doing it.
/// </para>
/// <para>
/// So protection is asked twice. The cheap question rides along with the listing and costs nothing.
/// Only the files it could not answer for are asked the expensive one, whose <em>refusal</em> is the
/// informative outcome: a service that cannot decrypt a file is telling you the file is encrypted.
/// </para>
/// </summary>
public sealed class InventoryProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    /// <summary>SharePoint answers with a verbose envelope unless asked otherwise.</summary>
    private const string SharePointAccept = "application/json;odata=nometadata";

    /// <summary>
    /// What section B asks the list for. Deliberately short.
    /// <para>
    /// Today's measuring found SharePoint's <c>$select</c> refusing named columns that
    /// <c>/fields</c> plainly lists - a Lookup and a Computed one both came back as "does not exist" -
    /// so anything selected here is a column that was watched arriving. The expansions carry no nested
    /// <c>$select</c> for the same reason: expanding whole objects costs bytes and asks nothing of the
    /// service's projection rules.
    /// </para>
    /// </summary>
    private const string SharingQuery =
        "$select=Id,FileLeafRef,FileRef,HasUniqueRoleAssignments" +
        "&$expand=RoleAssignments/Member,RoleAssignments/RoleDefinitionBindings";

    /// <summary>
    /// What the listing is asked for. <c>sensitivityLabel</c> is not in Graph's documented property
    /// table for driveItem, in v1.0 or beta - it is asked for anyway because it answers the question
    /// and it was measured to arrive. Its absence would be a finding, not a crash, so nothing here
    /// depends on it being there.
    /// </summary>
    private const string ListingSelect = "id,name,size,folder,file,webUrl,createdBy,sensitivityLabel";

    /// <summary>How a file's protection was established, in the order the tool tries to establish it.</summary>
    private enum Basis
    {
        /// <summary>Nothing was asked yet.</summary>
        None,

        /// <summary>The listing carried a label with protection turned on. Free.</summary>
        Listing,

        /// <summary>Extraction succeeded and reported no labels at all.</summary>
        ExtractedNoLabels,

        /// <summary>Extraction succeeded and reported labels. Says labelled, not encrypted.</summary>
        ExtractedLabels,

        /// <summary>Extraction was refused because the file could not be decrypted. That is the answer.</summary>
        Undecryptable,

        /// <summary>Extraction was refused for some other reason, or never answered.</summary>
        Unresolved,

        /// <summary>Not a file. Folders carry no label and are not asked.</summary>
        NotAFile,
    }

    private sealed record Item
    {
        public required string Id { get; init; }
        public required string Name { get; init; }
        public bool IsFolder { get; init; }
        public long? Size { get; init; }
        public string? CreatedBy { get; init; }

        /// <summary>The listing's own answer, kept exactly as it arrived including a bare false.</summary>
        public bool? ListingSaysProtected { get; init; }

        public string? LabelId { get; init; }
        public string? LabelName { get; init; }

        /// <summary>True when the listing carried no <c>sensitivityLabel</c> object at all.</summary>
        public bool ListingCarriedNoLabelFacet { get; init; }

        public Basis Basis { get; set; } = Basis.None;

        /// <summary>The reason code a refused extraction named, when it named one.</summary>
        public string? RefusalCode { get; set; }

        /// <summary>What the extraction call answered, for the record.</summary>
        public string? ExtractStatus { get; set; }

        /// <summary>
        /// yes / no / unknown. Never a bare boolean: the whole point of finding 14 is that a false
        /// here is indistinguishable from an answer nobody established.
        /// </summary>
        public string Protected => Basis switch
        {
            Basis.Listing => "yes",
            Basis.Undecryptable => "yes",
            Basis.ExtractedNoLabels => "no",
            Basis.ExtractedLabels => "unknown",
            Basis.NotAFile => "-",
            _ => "unknown",
        };

        public string HowWeKnow => Basis switch
        {
            Basis.Listing => "the listing said so",
            Basis.Undecryptable => $"could not be decrypted ({RefusalCode})",
            Basis.ExtractedNoLabels => "extraction found no labels",
            Basis.ExtractedLabels => "labelled, but nothing said whether the label encrypts",
            Basis.NotAFile => "a folder",
            Basis.Unresolved => RefusalCode is null
                ? $"nothing established it ({ExtractStatus ?? "not asked"})"
                : $"refused, and not in a way this recognises ({RefusalCode})",
            _ => "nothing established it",
        };
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("inventory");
        var app = options.InventoryApp;

        report.Subject["tenant"] = options.TenantId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["speaking as"] = app.Label;

        // Certificate first, and not as a preference. The routes this subcommand will grow into need
        // SharePoint REST, which refuses a client secret outright - so a run that quietly used the
        // secret would work today and fail later for a reason that looks nothing like this choice.
        var source = AppOnlyTokenSource.WithCertificate(options, app);
        if (source.IsUnavailable)
        {
            console.WriteLine($"No certificate for {app.Label}: {source.Identity}. Falling back to the secret.");
            source = AppOnlyTokenSource.WithSecret(options, app);
        }

        report.Subject["proof of identity"] = source.Identity;

        var caller = new ThrottleAwareCaller(http);
        var calls = new List<HttpObservation>();

        var token = await source.GetTokenAsync(ProbeAudience.Graph, cancellationToken);
        if (!token.Succeeded || token.AccessToken is null)
        {
            report.MarkIncomplete($"no Graph token: {token.ErrorCode}");
            report.Add(Observation.NotRun(
                "the listing",
                token.Requested
                    ? $"no Graph token was issued: {token.ErrorCode} - {token.ErrorDetail}"
                    : $"no token was ever requested: {token.ErrorDetail}"));
            report.Finish();
            return report;
        }

        console.WriteLine($"Resolving the site as {app.Label}...");
        var siteId = await ResolveSiteAsync(caller, token.AccessToken, calls, cancellationToken);
        if (siteId is null)
        {
            report.MarkIncomplete("the site was never resolved");
            report.Add(Observation.NotRun("the listing", "the site was never resolved, so nothing was listed"));
            report.Add(BuildCallTable(calls));
            report.Finish();
            return report;
        }

        console.WriteLine("Listing the library's root...");
        var (items, ending) = await ListAsync(caller, siteId, token.AccessToken, calls, cancellationToken);

        console.WriteLine($"Asking about protection for {items.Count(NeedsExtraction)} of {items.Count} items...");
        foreach (var item in items.Where(NeedsExtraction))
        {
            await ExtractAsync(caller, siteId, item, token.AccessToken, calls, cancellationToken);
        }

        report.Subject["listing ended"] = ending;

        // Asked for once and carried through both sections. Section C needs the same token to read a
        // SharePoint group's members, and a second acquisition would make a run where the two halves
        // disagreed impossible to tell apart from a run where the token changed underneath them.
        var sharePoint = await source.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken);

        console.WriteLine("Asking the list who each item is shared with...");
        var sharing = await ShareAsync(caller, sharePoint, siteId, token.AccessToken, calls, cancellationToken);

        report.Subject["sharing ended"] = sharing.Ending;

        console.WriteLine($"Turning {sharing.Grants.Count} grants into people...");
        var reach = await new InventoryReach(caller, options.SiteUrl, options.PagesToFollow, calls)
            .ResolveAsync(sharing.Grants, token.AccessToken, sharePoint.AccessToken, cancellationToken);

        report.Subject["throttling"] = caller.Record.Summary;

        report.Add(BuildFileTable(items));
        report.Add(BuildSharingTable(sharing));
        report.Add(BuildReachTable(reach));
        report.Add(BuildGapTable(reach));
        report.Add(BuildCallTable(calls));

        foreach (var item in items)
        {
            report.Add(FileObservation(item));
        }

        report.Add(SharingObservation(sharing));
        report.Add(ReachObservation(reach, sharing));
        report.Add(CoverageObservation(items, sharing, reach, caller.Record, ending));
        report.Finish();
        return report;
    }

    /// <summary>
    /// Which items still owe an answer. A folder never does. A file whose listing already said it is
    /// protected does not either - the expensive call could only agree. Everything else does,
    /// <em>including</em> a file the listing called unprotected, because finding 14 measured that
    /// exact answer being wrong.
    /// </summary>
    private static bool NeedsExtraction(Item item) =>
        !item.IsFolder && item.Basis != Basis.Listing;

    private async Task<string?> ResolveSiteAsync(
        ThrottleAwareCaller caller, string token, List<HttpObservation> calls, CancellationToken cancellationToken)
    {
        var relativePath = options.SiteServerRelativePath;
        var url = string.IsNullOrEmpty(relativePath)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relativePath)}";

        var site = await caller.GetAsync(url, token, cancellationToken);
        calls.Add(site);
        return ReadString(site, "id");
    }

    /// <summary>
    /// The root's children, following continuation links to the end. The page size is whatever the
    /// service chooses: asking for a specific one would measure our own number back.
    /// </summary>
    private async Task<(IReadOnlyList<Item> Items, string Ending)> ListAsync(
        ThrottleAwareCaller caller,
        string siteId,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var items = new List<Item>();
        string? next = $"{GraphBase}/sites/{siteId}/drive/root/children?$select={ListingSelect}";
        var pages = 0;

        while (next is not null)
        {
            var page = await caller.GetAsync(next, token, cancellationToken);
            calls.Add(page);
            pages++;

            var parsed = ReadPage(page);
            if (parsed is null)
            {
                return (items, pages == 1
                    ? $"the first page never came back ({page.StatusText})"
                    : $"page {pages} did not come back ({page.StatusText})");
            }

            items.AddRange(parsed.Value.Items);
            next = parsed.Value.NextLink;

            if (next is not null && pages >= options.PagesToFollow)
            {
                return (items, $"stopped at the {options.PagesToFollow}-page limit - more was waiting");
            }
        }

        return (items, pages == 1 ? "one page, no continuation offered" : $"{pages} pages, then the collection ended");
    }

    /// <summary>
    /// Asks the protection service to extract the file's labels. The interesting outcome is the
    /// refusal: a documented reason code saying the content could not be decrypted is a positive
    /// answer about encryption, where a success carrying no labels is a positive answer the other way.
    /// </summary>
    private async Task ExtractAsync(
        ThrottleAwareCaller caller,
        string siteId,
        Item item,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{GraphBase}/sites/{siteId}/drive/items/{item.Id}/extractSensitivityLabels";
        var observation = await caller.PostAsync(url, token, cancellationToken);
        calls.Add(observation);
        item.ExtractStatus = observation.StatusText;

        if (observation.IsSuccess)
        {
            item.Basis = HasLabels(observation) ? Basis.ExtractedLabels : Basis.ExtractedNoLabels;
            return;
        }

        // The codes are nested several deep and the useful one is not reliably at either end. A real
        // refusal here reads notSupported -> fileDecryptionNotSupported -> unsupportedUser: the
        // generic one outermost, the one naming decryption in the middle, and a detail innermost.
        // Taking the innermost was the first thing this did, and it classified every protected file as
        // unresolved. So the whole chain is kept, and matched against the documented set.
        var chain = ErrorCodeChain(observation);
        item.RefusalCode = chain.Count > 0 ? string.Join(" / ", chain) : null;
        item.Basis = chain.Any(c => UndecryptableCodes.Contains(c))
            ? Basis.Undecryptable
            : Basis.Unresolved;
    }

    /// <summary>
    /// What section B found, and how far it got. Kept as one value because the grants alone are
    /// meaningless without knowing whether the walk finished - a short list and a truncated list look
    /// identical once the reason is dropped.
    /// </summary>
    private sealed record Sharing(
        IReadOnlyList<InventorySharing.Grant> Grants,
        int Items,
        int Pages,
        string Ending,
        string? Refusal,
        string Walks);

    /// <summary>
    /// Who each item in the list is shared with, in one call per page rather than one per item.
    /// <para>
    /// This is the only bulk route that has ever worked here (finding 8), and it works through
    /// SharePoint REST, which refuses a client secret outright and wants full control (finding 5 and
    /// its follow-ups). All three of those conditions are recorded rather than assumed, because a
    /// refusal here is far more likely to be one of them than a fact about the library.
    /// </para>
    /// <para>
    /// It walks a different set from section A. Section A lists the root folder's children; this walks
    /// every item in the list, at any depth. Two different counts are not a disagreement, and the
    /// <c>walks</c> line says so on the report rather than leaving a reader to work it out - the same
    /// column finding 8 had to grow for the same reason.
    /// </para>
    /// </summary>
    private async Task<Sharing> ShareAsync(
        ThrottleAwareCaller caller,
        TokenResult sharePoint,
        string siteId,
        string graphToken,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        const string walks = "every item in the library list, at any depth";

        if (!sharePoint.Succeeded || sharePoint.AccessToken is null)
        {
            return new Sharing([], 0, 0, "no SharePoint token", 
                sharePoint.Requested
                    ? $"no SharePoint token was issued: {sharePoint.ErrorCode} - {sharePoint.ErrorDetail}"
                    : $"no SharePoint token was requested: {sharePoint.ErrorDetail}",
                walks);
        }

        // The library's server-relative path comes from Graph's answer for the same drive, so the two
        // APIs are pointed at the same library rather than at whatever each of them would have picked.
        var drive = await caller.GetAsync($"{GraphBase}/sites/{siteId}/drive", graphToken, cancellationToken);
        calls.Add(drive);

        var libraryPath = AclResponses.DriveServerRelativePath(drive);
        if (libraryPath is null)
        {
            return new Sharing([], 0, 0, "the library path was never discovered",
                $"the library path was never discovered ({drive.StatusText})", walks);
        }

        var grants = new List<InventorySharing.Grant>();
        var items = 0;
        var pages = 0;

        string? next = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')" +
                       $"/items?{SharingQuery}&$top={options.RequestedPageSize ?? 100}";

        while (next is not null)
        {
            var observation = await caller.GetAsync(next, sharePoint.AccessToken, cancellationToken, SharePointAccept);
            calls.Add(observation);
            pages++;

            var page = InventorySharing.ReadPage(observation);
            if (page is null)
            {
                // A body the probe cut short is a fact about the probe, and must never be reported as
                // a fact about the list. Expanding members and role names makes this response several
                // times larger than the one finding 8 measured, so it is the likelier failure here.
                var why = observation.BodyTruncated
                    ? $"the probe cut the body short before it could be read ({observation.StatusText})"
                    : Describe(observation);

                return new Sharing(grants, items, pages,
                    pages == 1 ? "the first page never came back" : $"page {pages} did not come back",
                    why, walks);
            }

            grants.AddRange(page.Grants);
            items += page.Items;
            next = page.NextLink;

            if (next is not null && pages >= options.PagesToFollow)
            {
                return new Sharing(grants, items, pages,
                    $"stopped at the {options.PagesToFollow}-page limit - more was waiting", null, walks);
            }
        }

        return new Sharing(grants, items, pages,
            pages == 1 ? "one page, no continuation offered" : $"{pages} pages, then the collection ended",
            null, walks);
    }

    /// <summary>
    /// Why a page produced nothing. A refusal and a success whose body could not be read are different
    /// things, and used to print the same way.
    /// </summary>
    private static string Describe(HttpObservation observation)
    {
        if (observation.IsSuccess)
        {
            return $"{observation.StatusText}, but the body held no collection this could read";
        }

        var code = ApiError.Code(observation);
        var message = code.Length > 0 ? code : observation.RefusalDiagnostic ?? "no reason given";
        return $"{observation.StatusText}: {message}";
    }

    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/').Select(Uri.EscapeDataString));

    private static (IReadOnlyList<Item> Items, string? NextLink)? ReadPage(HttpObservation observation)
    {
        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var items = new List<Item>();
        foreach (var entry in value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object ||
                !entry.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var isFolder = entry.TryGetProperty("folder", out _);
            var hasFacet = entry.TryGetProperty("sensitivityLabel", out var label) &&
                           label.ValueKind == JsonValueKind.Object;

            var item = new Item
            {
                Id = id.GetString()!,
                Name = Text(entry, "name") ?? id.GetString()!,
                IsFolder = isFolder,
                Size = entry.TryGetProperty("size", out var size) && size.ValueKind == JsonValueKind.Number
                    ? size.GetInt64()
                    : null,
                CreatedBy = CreatedBy(entry),
                ListingCarriedNoLabelFacet = !hasFacet,
                ListingSaysProtected = hasFacet && label.TryGetProperty("protectionEnabled", out var flag) &&
                                       flag.ValueKind is JsonValueKind.True or JsonValueKind.False
                    ? flag.GetBoolean()
                    : null,
                LabelId = hasFacet ? Text(label, "id") : null,
                LabelName = hasFacet ? Text(label, "displayName") : null,
            };

            item.Basis = item.IsFolder
                ? Basis.NotAFile
                : item.ListingSaysProtected == true ? Basis.Listing : Basis.None;

            items.Add(item);
        }

        var nextLink = root.Value.TryGetProperty("@odata.nextLink", out var link) &&
                       link.ValueKind == JsonValueKind.String &&
                       Uri.TryCreate(link.GetString(), UriKind.Absolute, out _)
            ? link.GetString()
            : null;

        return (items, nextLink);
    }

    private static bool HasLabels(HttpObservation observation)
    {
        var root = Root(observation);
        return root is not null &&
               root.Value.TryGetProperty("labels", out var labels) &&
               labels.ValueKind == JsonValueKind.Array &&
               labels.GetArrayLength() > 0;
    }

    /// <summary>
    /// The codes Microsoft documents for a refusal that means the file is encrypted in a way the
    /// service cannot open. Matched as an exact set rather than by looking for "decryption" in the
    /// text: a substring rule would quietly reclassify any future code that happens to contain the
    /// word, and this column decides whether a document is reported as protected.
    /// </summary>
    private static readonly HashSet<string> UndecryptableCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        "fileDecryptionNotSupported",
        "fileDoubleKeyEncrypted",
        "fileDecryptionDeferred",
    };

    /// <summary>
    /// Every code in the nested <c>innerError</c> chain, outermost first. All of them are kept because
    /// none of the positions is reliably the informative one, and because printing the chain is what
    /// lets a reader see a refusal this tool did not recognise for what it was.
    /// </summary>
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

    private static string? CreatedBy(JsonElement entry) =>
        entry.TryGetProperty("createdBy", out var by) && by.ValueKind == JsonValueKind.Object &&
        by.TryGetProperty("user", out var user) && user.ValueKind == JsonValueKind.Object
            ? Text(user, "email") ?? Text(user, "userPrincipalName") ?? Text(user, "displayName")
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
        if (!observation.IsSuccess && observation.StatusCode is null)
        {
            return null;
        }

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

    /// <summary>
    /// The table this subcommand exists to print. <c>the listing said</c> is kept beside the answer on
    /// purpose: where the two disagree, that disagreement is the most useful thing on the row.
    /// </summary>
    private static ProbeTable BuildFileTable(IReadOnlyList<Item> items) =>
        new("What is in this library, and whether it is protected",
            ["file", "protected", "how we know", "the listing said", "label", "bytes", "created by"],
            items.Select(i => (IReadOnlyList<string?>)new[]
            {
                i.Name,
                i.Protected,
                i.HowWeKnow,
                i.IsFolder
                    ? "-"
                    : i.ListingCarriedNoLabelFacet
                        ? "(no sensitivityLabel at all)"
                        : i.ListingSaysProtected switch
                        {
                            true => "protectionEnabled: true",
                            false => "protectionEnabled: false",
                            null => "(the property was not a boolean)",
                        },
                i.LabelName ?? i.LabelId ?? "-",
                i.Size?.ToString() ?? "-",
                i.CreatedBy ?? "-",
            }).ToList());

    /// <summary>
    /// One row per grant, not per item: an item shared four ways is four facts, and collapsing them
    /// into a count would lose exactly the part somebody reading an inventory came for.
    /// </summary>
    private static ProbeTable BuildSharingTable(Sharing sharing)
    {
        if (sharing.Grants.Count == 0)
        {
            return new ProbeTable(
                $"Who each item is shared with ({sharing.Walks})",
                ["item", "shared with", "what that principal is", "roles", "unique permissions"],
                [[sharing.Refusal ?? "nothing came back", "-", "-", "-", "-"]]);
        }

        return new ProbeTable(
            $"Who each item is shared with ({sharing.Walks})",
            ["item", "shared with", "what that principal is", "roles", "unique permissions"],
            sharing.Grants.Select(g => (IReadOnlyList<string?>)new[]
            {
                g.FileName ?? g.Path ?? g.ItemId,
                g.PrincipalTitle,
                g.Kind,
                g.Roles.Count == 0 ? "(no role named)" : string.Join(", ", g.Roles.Select(r => r.Describe)),
                g.HasUniqueRoleAssignments switch { true => "yes", false => "no (inherited)", null => "-" },
            }).ToList());
    }

    /// <summary>
    /// The table the whole subcommand was asked for: the people, per file. It is printed next to the
    /// gap table on purpose - this one alone would read as a complete answer, and it is only ever as
    /// complete as the one after it says.
    /// </summary>
    private static ProbeTable BuildReachTable(InventoryReach.Result reach) =>
        new("Who can actually open each file",
            ["file", "person", "through", "role"],
            reach.Rows.Count == 0
                ? [["(nothing resolved to a person)", "-", "-", "-"]]
                : reach.Rows.Select(r => (IReadOnlyList<string?>)new[] { r.Item, r.Person, r.Via, r.Roles }).ToList());

    /// <summary>
    /// Everything the table above does not account for. Two kinds live here and they are different
    /// findings: a grant that was deliberately not counted as reach - Limited Access, almost always -
    /// and a principal this could not turn into people at all. Both would otherwise be invisible, and
    /// the second one is the one that makes a reach report wrong rather than merely narrow.
    /// </summary>
    private static ProbeTable BuildGapTable(InventoryReach.Result reach) =>
        new("What is not in the table above, and why",
            ["file", "principal", "why"],
            reach.Gaps.Count == 0
                ? [["(nothing)", "-", "every grant on every item resolved to people"]]
                : reach.Gaps.Select(g => (IReadOnlyList<string?>)new[] { g.Item, g.Principal, g.Why }).ToList());

    private static ProbeTable BuildCallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)new[]
            {
                c.Method, c.Url, c.StatusText, c.ElapsedMs.ToString(), ApiError.Code(c),
            }).ToList());

    private static Observation FileObservation(Item item)
    {
        var subject = item.Name;

        if (item.IsFolder)
        {
            return Observation.Measured(subject, "a folder - carries no label and was not asked");
        }

        return Observation.Measured(subject, $"protected: {item.Protected} - {item.HowWeKnow}") with
        {
            Details = new Dictionary<string, string?>
            {
                ["protected"] = item.Protected,
                ["basis"] = item.Basis.ToString(),
                ["listingSaidProtected"] = item.ListingCarriedNoLabelFacet
                    ? "(no sensitivityLabel property)"
                    : item.ListingSaysProtected?.ToString(),
                ["labelId"] = item.LabelId,
                ["labelName"] = item.LabelName,
                ["extractStatus"] = item.ExtractStatus,
                ["refusalCode"] = item.RefusalCode,
                ["bytes"] = item.Size?.ToString(),
                ["createdBy"] = item.CreatedBy,
            },
        };
    }

    private static Observation SharingObservation(Sharing sharing)
    {
        if (sharing.Refusal is not null)
        {
            return Observation.Measured("who each item is shared with", $"nothing came back - {sharing.Refusal}") with
            {
                Details = new Dictionary<string, string?>
                {
                    ["walks"] = sharing.Walks,
                    ["refusal"] = sharing.Refusal,
                    ["ending"] = sharing.Ending,
                    ["note"] = "the bulk route needs a certificate and full control (findings 5 and 8); " +
                               "a refusal here is more likely to be one of those than a fact about the library",
                },
            };
        }

        var principals = sharing.Grants
            .Select(g => g.PrincipalTitle)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        return Observation.Measured(
            "who each item is shared with",
            $"{sharing.Items} items, {sharing.Grants.Count} grants naming {principals} distinct " +
            $"principals, in {sharing.Pages} pages - {sharing.Ending}") with
        {
            Details = new Dictionary<string, string?>
            {
                ["walks"] = sharing.Walks,
                ["items"] = sharing.Items.ToString(),
                ["grants"] = sharing.Grants.Count.ToString(),
                ["distinctPrincipals"] = principals.ToString(),
                ["pages"] = sharing.Pages.ToString(),
                ["ending"] = sharing.Ending,
                ["note"] = "this section walks the whole list; section A walks the root folder's " +
                           "children. Two different counts are a difference of range, not a disagreement",
            },
        };
    }

    private static Observation ReachObservation(InventoryReach.Result reach, Sharing sharing)
    {
        if (sharing.Refusal is not null)
        {
            return Observation.NotRun(
                "who can open each file",
                "the grants were never read, so there was nothing to turn into people");
        }

        var notCounted = reach.Gaps.Count(g => g.Why.StartsWith("not counted", StringComparison.Ordinal));

        return Observation.Measured(
            "who can open each file",
            $"{reach.DistinctPeople} distinct people across {reach.Rows.Count} file/person pairs; " +
            $"{reach.PrincipalsResolved} principals expanded, {reach.PrincipalsUnresolved} could not be; " +
            $"{notCounted} grants not counted as reach") with
        {
            Details = new Dictionary<string, string?>
            {
                ["people"] = reach.DistinctPeople.ToString(),
                ["pairs"] = reach.Rows.Count.ToString(),
                ["principalsResolved"] = reach.PrincipalsResolved.ToString(),
                ["principalsUnresolved"] = reach.PrincipalsUnresolved.ToString(),
                ["grantsNotCountedAsReach"] = notCounted.ToString(),
                ["note"] = "a grant carrying only Limited Access is not reach: SharePoint adds it to the " +
                           "parent list whenever somebody is given one item inside, so counting it would " +
                           "report that person on every item in the library",
            },
        };
    }

    /// <summary>
    /// The one line that says whether this report can be trusted as a whole. An inventory whose walk
    /// stopped early, or which left files unresolved, or which was throttled and gave up, is a partial
    /// answer - and a partial answer that does not announce itself is the failure this tool spends
    /// fourteen findings warning about.
    /// </summary>
    private static Observation CoverageObservation(
        IReadOnlyList<Item> items,
        Sharing sharing,
        InventoryReach.Result reach,
        ThrottleRecord throttling,
        string ending)
    {
        var files = items.Count(i => !i.IsFolder);
        var unknown = items.Count(i => !i.IsFolder && i.Protected == "unknown");

        var complete = unknown == 0 &&
                       throttling.GaveUp == 0 &&
                       sharing.Refusal is null &&
                       reach.PrincipalsUnresolved == 0 &&
                       ending.Contains("ended", StringComparison.Ordinal);

        var observed = complete
            ? $"{files} files, all resolved; sharing read; every principal expanded; " +
              $"the walk {ending}; {throttling.Summary}"
            : $"{files} files, {unknown} unresolved; " +
              (sharing.Refusal is null ? "sharing read" : "sharing NOT read") +
              $"; {reach.PrincipalsUnresolved} principals NOT expanded" +
              $"; the walk {ending}; {throttling.Summary}";

        return Observation.Measured("is this inventory complete", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["files"] = files.ToString(),
                ["unresolved"] = unknown.ToString(),
                ["listingEnded"] = ending,
                ["sharingEnded"] = sharing.Ending,
                ["sharingRefusal"] = sharing.Refusal,
                ["principalsUnresolved"] = reach.PrincipalsUnresolved.ToString(),
                ["peopleNamed"] = reach.DistinctPeople.ToString(),
                ["throttledCalls"] = throttling.Throttled.ToString(),
                ["gaveUp"] = throttling.GaveUp.ToString(),
                ["waitedMs"] = throttling.WaitedMs.ToString(),
                ["complete"] = complete.ToString(),
                ["note"] = complete
                    ? "every file got an answer, the sharing read, and nothing was left waiting"
                    : "this is a partial answer - the counts above say which part is missing",
            },
        };
    }
}
