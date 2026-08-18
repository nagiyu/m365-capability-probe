using System.Text;
using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Whether a hidden column answers the same way to an app as it does to a person.
/// <para>
/// Finding 24 measured <c>$select</c> refusing a column that exists, in wording indistinguishable
/// from the wording it uses for a name nobody ever defined. That was measured while speaking for a
/// signed-in person. Hidden is supposed to be a display flag rather than a permission - but app-only
/// callers are trimmed differently, and "supposed to be" is not a measurement.
/// </para>
/// <para>
/// So the same three routes are put to every identity in one run: the list's own field definitions,
/// the projection that refused before, and <c>RenderListDataAsStream</c>, which is said to hand back
/// what the projection will not. The interesting outcome is a column that answers one identity and
/// not the other; the run is built so that such a column cannot hide in a difference of route,
/// of list, or of when it was asked.
/// </para>
/// <para>
/// Values are never recorded. Whether a value arrived is the measurement; what the value said is
/// somebody's file name or somebody's name, and this tool has no business keeping it.
/// </para>
/// </summary>
public sealed class HiddenFieldsProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string SharePointAccept = "application/json;odata=nometadata";

    /// <summary>
    /// What counts as a sensitivity or protection column. The needles are a choice this tool makes,
    /// so they are printed in the report: a sweep is only as wide as its needles, and a reader who
    /// cannot see them cannot tell an absent column from an unasked one. The request said
    /// "IpLabel / Sensitivity / Rms などが入るもの" and left the count open, so nothing here caps it.
    /// </summary>
    private static readonly string[] Needles =
        ["IpLabel", "Sensitivity", "Rms", "MSIP", "Encrypt", "Protect", "Classif"];

    /// <summary>
    /// A name nobody defined, asked for beside the real ones.
    /// <para>
    /// Finding 24's trap is that <c>'X' は存在しません</c> is not a statement about existence: the
    /// invented name and the real one were refused in the same words. Without this control, a route
    /// that answers "no such column" cannot be read at all. It is asked on its own rather than mixed
    /// into the real request, because a single bad name can take a whole call down with it - and then
    /// the control would have destroyed the measurement it exists to qualify.
    /// </para>
    /// </summary>
    private const string InventedColumn = "_ProbeNoSuchColumnXyzzy";

    /// <summary>
    /// A bound on rows, high enough for a test library and reported whenever it bites. The question is
    /// which columns come back rather than how many files there are, but a silently truncated listing
    /// would make "no file carried a value" mean two different things.
    /// </summary>
    private const int RowLimit = 200;

    private sealed record Column(string InternalName, string Title, string Type, bool Hidden);

    /// <summary>One identity, and everything it managed to ask.</summary>
    private sealed class Leg
    {
        public required string Name { get; init; }
        public required string Identity { get; init; }
        public string? SharePointToken { get; init; }
        public string? GraphToken { get; init; }

        /// <summary>Why this leg asked nothing, or null. A leg with no token is not a leg that was refused.</summary>
        public string? Silent { get; set; }

        /// <summary>The columns this identity saw in the list's own field definitions.</summary>
        public HashSet<string> InFields { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Those columns as the list described them, kept so the union carries a definition.</summary>
        public Dictionary<string, Column> Columns { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string? FieldsStatus { get; set; }
        public string? SelectStatus { get; set; }
        public string? StreamStatus { get; set; }
        public string? InventedStatus { get; set; }
        public string? InventedDetail { get; set; }

        /// <summary>Columns whose key came back at all, from RenderListDataAsStream.</summary>
        public HashSet<string> KeyReturned { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Columns that carried a non-empty value on at least one row.</summary>
        public HashSet<string> ValueSeen { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Per named file, the columns that carried a value there.</summary>
        public Dictionary<string, HashSet<string>> PerFile { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public int RowsReturned { get; set; }
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("hidden");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["registrations"] =
            $"{options.ProbeApp.Label} and {options.InventoryApp.Label} - " +
            "the first because it is the only one device code is configured on, the second because " +
            "findings 24, 25 and 29 were measured with it";
        report.Subject["needles"] = string.Join(", ", Needles);
        report.Subject["invented name"] = InventedColumn;
        report.Subject["files named"] = options.Files.Count == 0
            ? "(none - every row is counted, none is named)"
            : string.Join(", ", options.Files);

        var calls = new List<HttpObservation>();
        var caller = new ThrottleAwareCaller(http);

        var legs = await IdentitiesAsync(report, cancellationToken);

        var (libraryPath, resolvedBy) = await LibraryAsync(caller, legs, calls, cancellationToken);
        report.Subject["library"] = libraryPath is null
            ? "(never resolved - see the identity table)"
            : $"{libraryPath} (resolved by {resolvedBy})";

        if (libraryPath is null)
        {
            report.MarkIncomplete(
                "the library was never resolved by any identity, so no route below was ever addressed");
            report.Add(IdentityTable(legs));
            report.Add(CallTable(calls));
            report.Finish();
            return report;
        }

        // The sweep is done by every identity, because "this column is not in the field definitions"
        // and "this column is defined but its data does not come back" are different answers - and
        // whether they differ by identity is part of what is being asked.
        foreach (var leg in legs)
        {
            await SweepAsync(caller, leg, libraryPath, calls, cancellationToken);
        }

        // The union, so that every identity is asked for the same columns. Asking each identity only
        // for what it could see would make the request differ with the answer, and a column missing
        // from one leg's request would then look like a column that leg was refused.
        var columns = UnionColumns(legs);
        report.Subject["columns swept"] = columns.Count == 0
            ? "0 - no identity saw a matching column"
            : $"{columns.Count}: {string.Join(", ", columns.Select(c => c.InternalName))}";

        if (columns.Count == 0)
        {
            report.MarkIncomplete(
                "no identity found a column matching the needles, so there was nothing to ask for");
        }

        var names = columns.Select(c => c.InternalName).ToList();

        foreach (var leg in legs)
        {
            if (leg.SharePointToken is null)
            {
                continue;
            }

            if (names.Count > 0)
            {
                leg.SelectStatus = await SelectAsync(caller, leg, libraryPath, names, calls, cancellationToken);
                await StreamAsync(caller, leg, libraryPath, names, calls, cancellationToken);
            }

            await InventedAsync(caller, leg, libraryPath, calls, cancellationToken);
        }

        report.Add(IdentityTable(legs));
        report.Add(RouteTable(legs));
        report.Add(ColumnTable(legs, columns));

        if (options.Files.Count > 0)
        {
            report.Add(FileTable(legs, names.Count));
        }

        report.Add(CallTable(calls));

        foreach (var observation in Observations(legs, columns))
        {
            report.Add(observation);
        }

        report.Subject["throttling"] = caller.Record.Summary;
        report.Finish();
        return report;
    }

    // ---- identities -------------------------------------------------------------------------

    /// <summary>
    /// The three ways this registration can speak, all established before anything is asked.
    /// <para>
    /// The secret leg is here even though finding 6 already measured it being refused at
    /// SharePoint's door: it is the control that says the route was reachable at all in this run. A
    /// wall of refusals with nothing beside it could mean anything.
    /// </para>
    /// </summary>
    private async Task<List<Leg>> IdentitiesAsync(ProbeReport report, CancellationToken cancellationToken)
    {
        var legs = new List<Leg>();

        // The probe's own registration first, because it is the only one that can ever fill the
        // delegated column - device code is configured on it and nowhere else. Every app-only row in
        // this run would otherwise be a registration that cannot be asked the second half of the
        // question, and the comparison would be between two apps rather than between two ways of
        // speaking.
        console.WriteLine("Establishing the probe registration (certificate)...");
        var certificate = AppOnlyTokenSource.WithCertificate(options);
        legs.Add(await AppLegAsync("app-only cert (probe)", certificate, cancellationToken));

        // And the registration findings 24, 25 and 29 were measured with. Without it, a refusal here
        // and a refusal there would be attributed to the route when they might belong to the app.
        var inventory = options.InventoryApp;
        console.WriteLine($"Establishing {inventory.Label} (certificate)...");
        var inventoryCertificate = AppOnlyTokenSource.WithCertificate(options, inventory);
        legs.Add(await AppLegAsync("app-only cert (inventory)", inventoryCertificate, cancellationToken));

        console.WriteLine("Establishing the probe registration (shared secret)...");
        var secret = AppOnlyTokenSource.WithSecret(options);
        legs.Add(await AppLegAsync("app-only secret (probe)", secret, cancellationToken));

        var delegated = new DelegatedTokenSource(options, console);
        console.WriteLine(delegated.Enabled
            ? "Establishing the delegated identity (device code)..."
            : $"Not establishing a delegated identity: Identities is '{ProbeOptions.AppOnlyIdentities}'.");

        var signIn = await delegated.SignInAsync(cancellationToken);
        report.Subject["signed in"] = delegated.SignedInSummary;

        if (delegated.IncompleteReason is { } incomplete)
        {
            report.MarkIncomplete(incomplete);
        }

        var sharePoint = signIn.Succeeded
            ? await delegated.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken)
            : signIn with { Audience = ProbeAudience.SharePoint };
        var graph = signIn.Succeeded
            ? await delegated.GetTokenAsync(ProbeAudience.Graph, cancellationToken)
            : signIn;

        legs.Add(new Leg
        {
            Name = "delegated",
            Identity = delegated.SignedInSummary,
            SharePointToken = sharePoint.AccessToken,
            GraphToken = graph.AccessToken,
            // Why the column is empty, in words that cannot be read as an answer about columns. A
            // delegated leg can come up empty for three unrelated reasons - it was switched off, the
            // sign-in was refused, or the app holds no delegated grant for SharePoint - and only the
            // last one is about this registration's reach. Finding 7 is the live one in this tenant:
            // device code is refused by security defaults, which is a fact about the tenant's sign-in
            // policy and says nothing whatever about hidden columns.
            Silent = sharePoint.AccessToken is null
                ? delegated.Enabled
                    ? $"no SharePoint token ({TokenReason(sharePoint)}); sign-in: {delegated.SignedInSummary}"
                    : $"not asked - {delegated.SignedInSummary}"
                : null,
        });

        return legs;
    }

    private static async Task<Leg> AppLegAsync(
        string name,
        AppOnlyTokenSource source,
        CancellationToken cancellationToken)
    {
        if (source.IsUnavailable)
        {
            return new Leg { Name = name, Identity = source.Identity, Silent = source.Identity };
        }

        var sharePoint = await source.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken);
        var graph = await source.GetTokenAsync(ProbeAudience.Graph, cancellationToken);

        return new Leg
        {
            Name = name,
            Identity = source.Identity,
            SharePointToken = sharePoint.AccessToken,
            GraphToken = graph.AccessToken,
            Silent = sharePoint.AccessToken is null
                ? $"no SharePoint token ({TokenReason(sharePoint)})"
                : null,
        };
    }

    private static string TokenReason(TokenResult token) =>
        token.Requested ? token.ErrorCode ?? "refused, no code" : "never requested";

    // ---- the library ------------------------------------------------------------------------

    /// <summary>
    /// Where the library lives, asked of each identity in turn until one answers.
    /// <para>
    /// Borrowed rather than required, because an identity that cannot resolve the site would
    /// otherwise take its own routes down with it - and then the very thing being measured, whether
    /// that identity is served the columns, would go unasked for a reason that has nothing to do with
    /// columns. Which identity supplied it is recorded: a borrowed address is not the borrower's
    /// measurement.
    /// </para>
    /// </summary>
    private async Task<(string? Path, string? By)> LibraryAsync(
        ThrottleAwareCaller caller,
        IReadOnlyList<Leg> legs,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var relative = options.SiteServerRelativePath;
        var siteUrl = string.IsNullOrEmpty(relative)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relative)}";

        foreach (var leg in legs)
        {
            if (leg.GraphToken is null)
            {
                continue;
            }

            var site = await caller.GetAsync(siteUrl, leg.GraphToken, cancellationToken);
            calls.Add(site);

            var siteId = Text(Root(site), "id");
            if (siteId is null)
            {
                continue;
            }

            var drive = await caller.GetAsync(
                $"{GraphBase}/sites/{siteId}/drive", leg.GraphToken, cancellationToken);
            calls.Add(drive);

            var path = AclResponses.DriveServerRelativePath(drive);
            if (path is not null)
            {
                return (path, leg.Name);
            }
        }

        return (null, null);
    }

    // ---- step 1: the list's own field definitions --------------------------------------------

    private async Task SweepAsync(
        ThrottleAwareCaller caller,
        Leg leg,
        string libraryPath,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        if (leg.SharePointToken is null)
        {
            leg.FieldsStatus = "not asked";
            return;
        }

        var url = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')/fields" +
                  "?$select=InternalName,Title,TypeAsString,Hidden";

        console.WriteLine($"/fields as {leg.Name}...");
        var observation = await caller.GetAsync(url, leg.SharePointToken, cancellationToken, SharePointAccept);
        calls.Add(observation);
        leg.FieldsStatus = observation.StatusText;

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

            leg.InFields.Add(internalName);
            leg.Columns[internalName] = new Column(
                internalName,
                title ?? internalName,
                Text(field, "TypeAsString") ?? "(no type)",
                field.TryGetProperty("Hidden", out var hidden) && hidden.ValueKind == JsonValueKind.True);
        }
    }

    private static bool Matches(string internalName, string? title) =>
        Needles.Any(needle =>
            internalName.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
            (title is not null && title.Contains(needle, StringComparison.OrdinalIgnoreCase)));

    private static List<Column> UnionColumns(IReadOnlyList<Leg> legs) =>
        legs.SelectMany(l => l.Columns.Values)
            .GroupBy(c => c.InternalName, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(c => c.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToList();

    // ---- step 2: the projection that refused before ------------------------------------------

    /// <summary>
    /// The route finding 24 measured, run again here so the contrast sits inside one run. Its refusal
    /// is the expected value rather than a problem: what this run adds is whether the refusal is the
    /// same for an app as for a person.
    /// </summary>
    private async Task<string> SelectAsync(
        ThrottleAwareCaller caller,
        Leg leg,
        string libraryPath,
        IReadOnlyList<string> names,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')/items" +
                  $"?$select=Id,FileLeafRef,{string.Join(",", names)}&$top={RowLimit}";

        console.WriteLine($"$select of the swept columns as {leg.Name}...");
        var observation = await caller.GetAsync(
            url, leg.SharePointToken!, cancellationToken, SharePointAccept);
        calls.Add(observation);

        return observation.StatusText;
    }

    // ---- step 3: RenderListDataAsStream ------------------------------------------------------

    private async Task StreamAsync(
        ThrottleAwareCaller caller,
        Leg leg,
        string libraryPath,
        IReadOnlyList<string> names,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')" +
                  "/RenderListDataAsStream";

        console.WriteLine($"RenderListDataAsStream of the swept columns as {leg.Name}...");
        var observation = await caller.PostAsync(
            url, leg.SharePointToken!, cancellationToken, Body(names.Prepend("FileLeafRef")));
        calls.Add(observation);
        leg.StreamStatus = observation.StatusText;

        var rows = Rows(observation);
        if (rows is null)
        {
            return;
        }

        leg.RowsReturned = rows.Count;

        foreach (var row in rows)
        {
            var leaf = Text(row, "FileLeafRef");

            foreach (var name in names)
            {
                if (!row.TryGetProperty(name, out var cell))
                {
                    continue;
                }

                leg.KeyReturned.Add(name);

                if (!HasValue(cell))
                {
                    continue;
                }

                leg.ValueSeen.Add(name);

                if (leaf is not null && Named(leaf) is { } named)
                {
                    if (!leg.PerFile.TryGetValue(named, out var set))
                    {
                        set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        leg.PerFile[named] = set;
                    }

                    set.Add(name);
                }
            }
        }
    }

    /// <summary>
    /// The invented name, asked on its own. Whatever comes back is the yardstick the real columns are
    /// read against: a route that refuses a name it never defined in the same breath it refuses one it
    /// did cannot be used to conclude anything about existence.
    /// </summary>
    private async Task InventedAsync(
        ThrottleAwareCaller caller,
        Leg leg,
        string libraryPath,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var url = $"{options.SiteUrl.TrimEnd('/')}/_api/web/GetList('{Uri.EscapeDataString(libraryPath)}')" +
                  "/RenderListDataAsStream";

        console.WriteLine($"RenderListDataAsStream of an invented name as {leg.Name}...");
        var observation = await caller.PostAsync(
            url, leg.SharePointToken!, cancellationToken, Body(["FileLeafRef", InventedColumn]));
        calls.Add(observation);

        leg.InventedStatus = observation.StatusText;

        var rows = Rows(observation);
        leg.InventedDetail = rows is null
            ? ApiError.Code(observation) ?? "no rows and no error code"
            : rows.Any(r => r.TryGetProperty(InventedColumn, out _))
                ? "the key came back for an undefined name"
                : $"{rows.Count} row(s), and the key is absent - silently dropped";
    }

    /// <summary>The request body, with the view built rather than pasted so the names are the only variable.</summary>
    private static string Body(IEnumerable<string> fieldNames)
    {
        var view = new StringBuilder("<View><ViewFields>");

        foreach (var name in fieldNames)
        {
            view.Append("<FieldRef Name='").Append(Attribute(name)).Append("' />");
        }

        view.Append("</ViewFields><RowLimit>").Append(RowLimit).Append("</RowLimit></View>");

        // RenderOptions 2 is ListData - the rows and nothing else. Anything wider would pull back the
        // schema and the context alongside them, which is not what is being asked and would put more
        // of somebody's tenant into a body this tool then has to hold.
        return JsonSerializer.Serialize(new
        {
            parameters = new
            {
                RenderOptions = 2,
                ViewXml = view.ToString(),
            },
        });
    }

    private static string Attribute(string value) =>
        value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("'", "&apos;");

    private static IReadOnlyList<JsonElement>? Rows(HttpObservation observation)
    {
        var root = Root(observation);

        return root is not null &&
               root.Value.TryGetProperty("Row", out var rows) &&
               rows.ValueKind == JsonValueKind.Array
            ? rows.EnumerateArray().Select(r => r.Clone()).ToList()
            : null;
    }

    /// <summary>
    /// Whether a cell carried anything. Never what it carried: the values here are file names, user
    /// names and label identifiers, and the question was only ever whether they arrived.
    /// </summary>
    private static bool HasValue(JsonElement cell) => cell.ValueKind switch
    {
        JsonValueKind.Null or JsonValueKind.Undefined => false,
        JsonValueKind.String => !string.IsNullOrEmpty(cell.GetString()),
        JsonValueKind.Array => cell.GetArrayLength() > 0,
        JsonValueKind.Object => cell.EnumerateObject().Any(),
        _ => true,
    };

    /// <summary>The configured path this leaf name belongs to, or null when the run did not name it.</summary>
    private string? Named(string leaf) =>
        options.Files.FirstOrDefault(f =>
            f.TrimEnd('/').EndsWith('/' + leaf, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(f.Trim('/'), leaf, StringComparison.OrdinalIgnoreCase));

    // ---- tables -----------------------------------------------------------------------------

    private static ProbeTable IdentityTable(IReadOnlyList<Leg> legs) =>
        new("Who spoke, and whether they got as far as the door",
            ["identity", "proof", "SharePoint token", "/fields"],
            legs.Select(l => (IReadOnlyList<string?>)
            [
                l.Name,
                l.Identity,
                l.SharePointToken is null ? l.Silent ?? "none" : "held",
                l.FieldsStatus ?? (l.Silent is null ? "not asked" : "not asked - " + l.Silent),
            ]).ToList());

    private static ProbeTable RouteTable(IReadOnlyList<Leg> legs) =>
        new("The three routes, put to every identity against the same list and the same columns",
            ["identity", "$select (finding 24's route)", "RenderListDataAsStream", "rows", "invented name"],
            legs.Select(l => (IReadOnlyList<string?>)
            [
                l.Name,
                l.SelectStatus ?? "not asked",
                l.StreamStatus ?? "not asked",
                l.StreamStatus is null ? "-" : l.RowsReturned.ToString(),
                l.InventedStatus is null ? "not asked" : $"{l.InventedStatus} - {l.InventedDetail}",
            ]).ToList());

    /// <summary>
    /// The answer, one row per column. Each identity gets two cells rather than one, because "the key
    /// came back" and "something was in it" are different facts and a single cell would have to pick
    /// one of them to report.
    /// </summary>
    private static ProbeTable ColumnTable(IReadOnlyList<Leg> legs, IReadOnlyList<Column> columns)
    {
        var speaking = legs.Where(l => l.SharePointToken is not null).ToList();

        var header = new List<string> { "internal name", "type", "hidden" };
        header.AddRange(speaking.Select(l => $"{l.Name}: fields / key / value"));

        var rows = columns.Select(column => (IReadOnlyList<string?>)
            new List<string?>
            {
                column.InternalName,
                column.Type,
                column.Hidden ? "yes" : "no",
            }.Concat(speaking.Select(leg => Cell(leg, column.InternalName))).ToList()).ToList();

        return new ProbeTable(
            "Each column, as every identity was answered. 'fields' is the list's own definition; " +
            "'key' is whether RenderListDataAsStream returned it; 'value' is whether anything was in it",
            header,
            rows);
    }

    private static string Cell(Leg leg, string name) =>
        $"{(leg.InFields.Contains(name) ? "yes" : "no")} / " +
        $"{(leg.KeyReturned.Contains(name) ? "yes" : "no")} / " +
        $"{(leg.ValueSeen.Contains(name) ? "yes" : "no")}";

    /// <summary>
    /// The named files, because a column that comes back empty on every file and a column that comes
    /// back empty on the unlabelled one are different answers. Files the run did not name are counted
    /// in the route table and named nowhere.
    /// </summary>
    private ProbeTable FileTable(IReadOnlyList<Leg> legs, int columnCount)
    {
        var speaking = legs.Where(l => l.SharePointToken is not null).ToList();

        var header = new List<string> { "file" };
        header.AddRange(speaking.Select(l => l.Name));

        var rows = options.Files.Select(file => (IReadOnlyList<string?>)
            new List<string?> { file }
                .Concat(speaking.Select(leg =>
                    leg.StreamStatus is null
                        ? "not asked"
                        : leg.PerFile.TryGetValue(file, out var set)
                            ? $"{set.Count} of {columnCount}: {Join(set)}"
                            : $"0 of {columnCount}"))
                .ToList()).ToList();

        return new ProbeTable(
            "Columns that carried a value, per file - which ones, never what was in them. A file the " +
            "listing never returned reads as 0 here, so the row count in the route table is what " +
            "separates 'empty' from 'absent'",
            header,
            rows);
    }

    private static ProbeTable CallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)
            [
                c.Method, c.Url, c.StatusText, c.ElapsedMs.ToString(), ApiError.Code(c),
            ]).ToList());

    // ---- observations -----------------------------------------------------------------------

    private static IEnumerable<Observation> Observations(IReadOnlyList<Leg> legs, IReadOnlyList<Column> columns)
    {
        var speaking = legs.Where(l => l.SharePointToken is not null).ToList();

        foreach (var leg in legs)
        {
            if (leg.SharePointToken is null)
            {
                yield return Observation.NotRun(leg.Name, leg.Silent ?? "no SharePoint token");
                continue;
            }

            // Counts first. Three runs put the deciding number past the column's clip before this one.
            yield return Observation.Measured(
                leg.Name,
                $"{leg.KeyReturned.Count} of {columns.Count} keys returned, " +
                $"{leg.ValueSeen.Count} carried a value, {leg.InFields.Count} were in /fields")
                with
            {
                Details = new Dictionary<string, string?>
                {
                    ["$select"] = leg.SelectStatus,
                    ["RenderListDataAsStream"] = leg.StreamStatus,
                    ["rows"] = leg.RowsReturned.ToString(),
                    ["invented name"] = $"{leg.InventedStatus} - {leg.InventedDetail}",
                    ["keys returned"] = Join(leg.KeyReturned),
                    ["carried a value"] = Join(leg.ValueSeen),
                    ["in /fields but no key"] = Join(leg.InFields.Except(leg.KeyReturned, StringComparer.OrdinalIgnoreCase)),
                },
            };
        }

        // Only the identities the route actually answered. An identity refused at the door returns no
        // columns for a reason that has nothing to do with columns, and counting it here would report
        // finding 6 - the secret being turned away by SharePoint - as though hidden columns were
        // identity-dependent. Run 129 did exactly that, and the headline read "8 of 8 columns differ
        // between identities" about a leg that never got inside.
        var answered = speaking.Where(l => l.StreamStatus is not null && l.StreamStatus.StartsWith("200")).ToList();
        var turnedAway = speaking.Except(answered).ToList();

        if (answered.Count < 2)
        {
            yield return Observation.NotRun(
                "whether the answer depends on who is asking",
                $"{answered.Count} of {speaking.Count} identities were answered by the route " +
                $"({Join(turnedAway.Select(l => $"{l.Name}: {l.StreamStatus ?? "not asked"}"))}), " +
                "so there was no pair to compare");
            yield break;
        }

        // The comparison the run exists for, stated as a difference rather than as two lists a reader
        // has to diff by eye.
        var everywhere = answered.Skip(1)
            .Aggregate(new HashSet<string>(answered[0].KeyReturned, StringComparer.OrdinalIgnoreCase),
                (acc, leg) => { acc.IntersectWith(leg.KeyReturned); return acc; });

        var anywhere = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var leg in answered)
        {
            anywhere.UnionWith(leg.KeyReturned);
        }

        var split = anywhere.Except(everywhere, StringComparer.OrdinalIgnoreCase).ToList();

        yield return Observation.Measured(
            "whether the answer depends on who is asking",
            $"{split.Count} of {anywhere.Count} returned columns differ between identities")
            with
        {
            Details = new Dictionary<string, string?>
            {
                ["identities compared"] = string.Join(", ", answered.Select(l => l.Name)),
                ["turned away at the door, not compared"] = turnedAway.Count == 0
                    ? "(none)"
                    : string.Join("; ", turnedAway.Select(l => $"{l.Name}: {l.StreamStatus ?? "not asked"}")),
                ["returned to every identity"] = Join(everywhere),
                ["returned to some but not all"] = Join(split),
                ["per identity"] = string.Join("; ",
                    answered.Select(l => $"{l.Name}={l.KeyReturned.Count}")),
                ["note"] = "one list, one set of column names, one run - so a difference here is the " +
                           "caller and not the route, the library or the moment",
            },
        };
    }

    private static string Join(IEnumerable<string> names)
    {
        var list = names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        return list.Count == 0 ? "(none)" : string.Join(", ", list);
    }

    // ---- json helpers -----------------------------------------------------------------------

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
