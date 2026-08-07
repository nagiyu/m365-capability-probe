using System.Text.Json;
using CapabilityProbe.Http;

namespace CapabilityProbe.Probes;

/// <summary>
/// Section C: turning grants into people.
/// <para>
/// Sections A and B answer questions a service will answer directly. This one does not exist as an
/// API call anywhere - "who can open this file" has to be assembled, and every step of the assembly
/// is a place to be confidently wrong. So the rule here is that a name only appears under a file when
/// something was read that put it there, and everything else appears in the second table with the
/// reason it could not be resolved. An empty gap table and a gap table nobody printed look nothing
/// alike, which is the whole point.
/// </para>
/// <para>
/// Three things this deliberately does not do. It does not treat a Limited Access grant as reach
/// (see <see cref="InventorySharing.Role"/>). It does not expand a claim that stands for a population
/// - "everyone except external users" has no membership to read, and printing a number there would be
/// an invention. And it does not walk group membership itself: Graph's <c>transitiveMembers</c> was
/// measured in finding 13 to terminate on a two-group cycle, deduplicate, and answer identically from
/// either end, so re-implementing that traversal here would only add a way to get it wrong.
/// </para>
/// </summary>
public sealed class InventoryReach(
    ThrottleAwareCaller caller,
    string siteUrl,
    int pageLimit,
    List<HttpObservation> calls)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string SharePointAccept = "application/json;odata=nometadata";

    /// <summary>
    /// One person, as far as anything could be read about them, and what stood between them and the
    /// grant.
    /// <para>
    /// <see cref="Through"/> is not decoration either. Run 73 printed a user as reachable "through
    /// probe 閲覧者" when the actual chain was probe 閲覧者 → probe-group → that user, and answering
    /// "why can this person open this file" meant going back to the call list and matching a group id
    /// against an Entra blade by hand. A path with its middle missing is not a shorter answer, it is a
    /// different one.
    /// </para>
    /// <para>
    /// It names what this walked. Graph's <c>transitiveMembers</c> flattens nesting below a directory
    /// group, so members that arrived through a group inside a group appear under the directory group
    /// this asked about, with nothing between - that is a limit of the route, not an assertion that
    /// there was nothing there.
    /// </para>
    /// </summary>
    public sealed record Person(string Display, string? Upn, IReadOnlyList<string> Through)
    {
        public Person(string display, string? upn) : this(display, upn, [])
        {
        }

        /// <summary>Identity, which the route must not be part of: one person reached two ways is one person.</summary>
        public string Key => Upn ?? Display;

        public Person Below(string container) => this with { Through = [container, .. Through] };
    }

    /// <summary>
    /// How a principal turned out, kept apart from how many people it produced.
    /// <para>
    /// Run 72 is why this exists. Two groups were read successfully and contained nobody, and because
    /// nothing had gone wrong the report counted them as expanded and said "0 principals NOT expanded"
    /// while quietly naming no one for a role that plainly grants access. Finding 6 is the same shape:
    /// a count of zero, about an object the reader cannot tell was even asked about.
    /// </para>
    /// </summary>
    private enum Outcome
    {
        /// <summary>Read, and it named people.</summary>
        People,

        /// <summary>Read, and it named nobody. A fact about the group, and it must be printed.</summary>
        Empty,

        /// <summary>Not read. Whatever it contains is missing from the report.</summary>
        Refused,

        /// <summary>There was never a membership to read - a claim standing for a population.</summary>
        NotApplicable,
    }

    /// <summary>What one principal turned out to contain, or why it did not.</summary>
    private sealed record Resolution(IReadOnlyList<Person> People, string? Gap, Outcome Outcome);

    /// <summary>
    /// One (file, person) pair, with every route that put them there.
    /// <para>
    /// <see cref="ItemKey"/> is the SharePoint list item id and <see cref="Item"/> is the path shown
    /// to a reader. They are separate because the walk now recurses: two folders may each hold a
    /// <c>test.docx</c>, and a row keyed on anything a person chose rather than on the id both APIs
    /// agree about would merge two files into one.
    /// </para>
    /// </summary>
    public sealed record Row(string ItemKey, string Item, string Person, string Via, string Roles);

    /// <summary>One thing this could not turn into people, and why. Never silently dropped.</summary>
    public sealed record Gap(string ItemKey, string Item, string Principal, string Why);

    public sealed record Result(
        IReadOnlyList<Row> Rows,
        IReadOnlyList<Gap> Gaps,
        int DistinctPeople,
        int PrincipalsResolved,
        int PrincipalsEmpty,
        int PrincipalsUnresolved,
        int PrincipalsNotApplicable);

    /// <summary>
    /// Resolved principals, so a group named on eight items costs one call. Keyed on the login name
    /// because that is what identifies a principal across items; the numeric Id is site-scoped and the
    /// title is not unique.
    /// </summary>
    private readonly Dictionary<string, Resolution> _cache = new(StringComparer.OrdinalIgnoreCase);

    public async Task<Result> ResolveAsync(
        IReadOnlyList<InventorySharing.Grant> grants,
        string graphToken,
        string? sharePointToken,
        CancellationToken cancellationToken)
    {
        // (item, person) -> the routes and roles that got them there. A person reachable two ways is
        // one row naming both, not two rows that read like two different people.
        var reached = new Dictionary<(string Key, string Person),
            (string Item, SortedSet<string> Via, SortedSet<string> Roles)>();
        var gaps = new List<Gap>();

        foreach (var grant in grants)
        {
            var item = grant.Path ?? grant.FileName ?? grant.ItemId;
            var reaching = grant.Roles.Where(r => r.Reaches).ToList();

            if (reaching.Count == 0)
            {
                gaps.Add(new Gap(grant.ItemId, item, grant.PrincipalTitle,
                    $"not counted as reach: {string.Join(", ", grant.Roles.Select(r => r.Describe))}"));
                continue;
            }

            var resolution = await ResolveOnceAsync(grant, graphToken, sharePointToken, cancellationToken);

            if (resolution.Gap is not null)
            {
                gaps.Add(new Gap(grant.ItemId, item, grant.PrincipalTitle, resolution.Gap));
            }

            var roles = string.Join(", ", reaching.Select(r => r.Describe));
            foreach (var person in resolution.People)
            {
                var key = (grant.ItemId, person.Key);
                if (!reached.TryGetValue(key, out var entry))
                {
                    entry = (item,
                             new SortedSet<string>(StringComparer.OrdinalIgnoreCase),
                             new SortedSet<string>(StringComparer.OrdinalIgnoreCase));
                    reached[key] = entry;
                }

                entry.Via.Add(string.Join(" -> ", new[] { grant.PrincipalTitle }.Concat(person.Through)));
                entry.Roles.Add(roles);
            }
        }

        var rows = reached
            .OrderBy(e => e.Value.Item, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Key.Person, StringComparer.OrdinalIgnoreCase)
            .Select(e => new Row(
                e.Key.Key,
                e.Value.Item,
                e.Key.Person,
                string.Join(" + ", e.Value.Via),
                string.Join(" / ", e.Value.Roles)))
            .ToList();

        return new Result(
            rows,
            gaps,
            rows.Select(r => r.Person).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            _cache.Values.Count(r => r.Outcome == Outcome.People),
            _cache.Values.Count(r => r.Outcome == Outcome.Empty),
            _cache.Values.Count(r => r.Outcome == Outcome.Refused),
            _cache.Values.Count(r => r.Outcome == Outcome.NotApplicable));
    }

    private async Task<Resolution> ResolveOnceAsync(
        InventorySharing.Grant grant,
        string graphToken,
        string? sharePointToken,
        CancellationToken cancellationToken)
    {
        var key = grant.LoginName ?? $"#{grant.PrincipalId?.ToString() ?? grant.PrincipalTitle}";
        if (_cache.TryGetValue(key, out var cached))
        {
            return cached;
        }

        var resolution = await ResolveUncachedAsync(grant, graphToken, sharePointToken, cancellationToken);
        _cache[key] = resolution;
        return resolution;
    }

    private async Task<Resolution> ResolveUncachedAsync(
        InventorySharing.Grant grant,
        string graphToken,
        string? sharePointToken,
        CancellationToken cancellationToken)
    {
        var login = grant.LoginName ?? string.Empty;

        // Claims first, and before anything looks at the principal type: SharePoint types these as
        // ordinary groups, and a caller that trusted the type would go looking for a membership that
        // does not exist. There is no wrong answer to find here - the right answer is that the
        // question does not apply.
        if (login.Contains("spo-grid-all-users", StringComparison.OrdinalIgnoreCase))
        {
            return new Resolution([],
                "every internal user in the tenant - a claim with no membership to enumerate",
                Outcome.NotApplicable);
        }

        if (login.StartsWith("c:0(.s|true", StringComparison.OrdinalIgnoreCase))
        {
            return new Resolution([],
                "everyone, including anonymous - a claim with no membership to enumerate",
                Outcome.NotApplicable);
        }

        return grant.PrincipalType switch
        {
            1 => new Resolution([new Person(grant.PrincipalTitle, UpnFrom(login))], null, Outcome.People),
            8 => await SharePointGroupAsync(grant, graphToken, sharePointToken, cancellationToken),
            2 or 4 => await DirectoryGroupAsync(grant, graphToken, cancellationToken),
            _ => new Resolution([],
                $"principal type {grant.PrincipalType?.ToString() ?? "(absent)"} - nothing here knows how to expand it",
                Outcome.Refused),
        };
    }

    /// <summary>
    /// A SharePoint group's members, from the site itself. Its members can be directory groups in
    /// turn, so each one is put back through the resolver rather than listed as if it were a person.
    /// </summary>
    private async Task<Resolution> SharePointGroupAsync(
        InventorySharing.Grant grant,
        string graphToken,
        string? sharePointToken,
        CancellationToken cancellationToken)
    {
        if (sharePointToken is null)
        {
            return new Resolution([], "no SharePoint token, so its members were never asked for", Outcome.Refused);
        }

        if (grant.PrincipalId is null)
        {
            return new Resolution([],
                "the group arrived with no Id, so there was nothing to ask about", Outcome.Refused);
        }

        var url = $"{siteUrl.TrimEnd('/')}/_api/web/sitegroups({grant.PrincipalId})/users";
        var observation = await caller.GetAsync(url, sharePointToken, cancellationToken, SharePointAccept);
        calls.Add(observation);

        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return new Resolution([], $"its members could not be read ({Describe(observation)})", Outcome.Refused);
        }

        var people = new List<Person>();
        var nested = new List<string>();

        foreach (var entry in value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var title = Text(entry, "Title") ?? "(no title)";
            var login = Text(entry, "LoginName") ?? string.Empty;
            var type = entry.TryGetProperty("PrincipalType", out var pt) && pt.ValueKind == JsonValueKind.Number
                ? pt.GetInt32()
                : (int?)null;

            if (type == 1)
            {
                people.Add(new Person(title, Text(entry, "Email") ?? UpnFrom(login)));
                continue;
            }

            var inner = await ResolveUncachedAsync(
                grant with { PrincipalId = null, PrincipalTitle = title, LoginName = login, PrincipalType = type },
                graphToken,
                sharePointToken: null, // a SharePoint group cannot contain another SharePoint group
                cancellationToken);

            people.AddRange(inner.People.Select(p => p.Below(title)));
            if (inner.Gap is not null)
            {
                nested.Add($"{title}: {inner.Gap}");
            }
        }

        if (people.Count > 0)
        {
            return new Resolution(people, nested.Count == 0 ? null : string.Join("; ", nested), Outcome.People);
        }

        // Read, and nobody in it. Run 72 printed this as success and named no one, which is the exact
        // failure finding 6 recorded: a zero that reads like an answer. It is a fact about the group
        // and it gets a row.
        var empty = nested.Count > 0
            ? $"the group was read; nothing in it resolved to a person ({string.Join("; ", nested)})"
            : "the group was read and has no members";

        return new Resolution([], $"{empty}{LinkCaveat(grant.PrincipalTitle)}", Outcome.Empty);
    }

    /// <summary>
    /// What an empty sharing-link group does and does not mean.
    /// <para>
    /// An empty group here is not "nobody can open this" - a link aimed at an audience rather than at
    /// named people has nobody to list. But which audience is not this function's to say. The earlier
    /// version read it out of the group's name, which is undocumented, and stated it as fact; the
    /// audience now comes from Graph and lives in its own table, so this points there rather than
    /// answering. Naming the link is what makes the two tables joinable by eye.
    /// </para>
    /// </summary>
    private static string LinkCaveat(string title) =>
        title.StartsWith("SharingLinks.", StringComparison.OrdinalIgnoreCase)
            ? " - this backs a sharing link, and an empty membership does not mean nobody can open " +
              "the file. What the link reaches is in the links table, which Graph answered; this " +
              "group's membership does not describe it"
            : string.Empty;

    /// <summary>
    /// A directory group's members, through Graph's <c>transitiveMembers</c> cast to users. The cast
    /// is what keeps nested groups from being printed as if they were people; the transitivity is what
    /// makes their members appear anyway. Finding 13 measured both, including on a cycle.
    /// </summary>
    private async Task<Resolution> DirectoryGroupAsync(
        InventorySharing.Grant grant, string graphToken, CancellationToken cancellationToken)
    {
        var objectId = ObjectIdFrom(grant.LoginName);
        if (objectId is null)
        {
            return new Resolution([],
                $"no directory object id could be read out of its login name ({grant.LoginName ?? "absent"})",
                Outcome.Refused);
        }

        var people = new List<Person>();
        string? next = $"{GraphBase}/groups/{objectId}/transitiveMembers/microsoft.graph.user" +
                       "?$select=id,displayName,userPrincipalName&$top=999";
        var pages = 0;

        while (next is not null)
        {
            var observation = await caller.GetAsync(next, graphToken, cancellationToken);
            calls.Add(observation);
            pages++;

            var root = Root(observation);
            if (root is null || !root.Value.TryGetProperty("value", out var value) ||
                value.ValueKind != JsonValueKind.Array)
            {
                return new Resolution(
                    people, $"its members could not be read ({Describe(observation)})", Outcome.Refused);
            }

            foreach (var entry in value.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object)
                {
                    people.Add(new Person(
                        Text(entry, "displayName") ?? Text(entry, "userPrincipalName") ?? "(unnamed)",
                        Text(entry, "userPrincipalName")));
                }
            }

            next = root.Value.TryGetProperty("@odata.nextLink", out var link) &&
                   link.ValueKind == JsonValueKind.String &&
                   Uri.TryCreate(link.GetString(), UriKind.Absolute, out _)
                ? link.GetString()
                : null;

            if (next is not null && pages >= pageLimit)
            {
                return new Resolution(people,
                    $"stopped at the {pageLimit}-page limit with more members waiting - this list is short, not complete",
                    Outcome.Refused);
            }
        }

        return people.Count > 0
            ? new Resolution(people, null, Outcome.People)
            : new Resolution([], "the directory group was read and has no members", Outcome.Empty);
    }

    /// <summary>
    /// The directory object id inside a SharePoint claim login name. Claims look like
    /// <c>c:0t.c|tenant|&lt;guid&gt;</c> or <c>c:0o.c|federateddirectoryclaimprovider|&lt;guid&gt;</c>,
    /// the latter sometimes with an <c>_o</c> suffix marking the owners of the group rather than its
    /// members. Anything that is not a GUID once the suffix is off returns null and becomes a gap.
    /// </summary>
    private static string? ObjectIdFrom(string? loginName)
    {
        if (string.IsNullOrWhiteSpace(loginName))
        {
            return null;
        }

        var last = loginName[(loginName.LastIndexOf('|') + 1)..].Trim();
        if (last.EndsWith("_o", StringComparison.OrdinalIgnoreCase))
        {
            last = last[..^2];
        }

        return Guid.TryParse(last, out var id) ? id.ToString() : null;
    }

    /// <summary>The address inside a member claim: <c>i:0#.f|membership|someone@example.com</c>.</summary>
    private static string? UpnFrom(string? loginName)
    {
        if (string.IsNullOrWhiteSpace(loginName))
        {
            return null;
        }

        var last = loginName[(loginName.LastIndexOf('|') + 1)..].Trim();
        return last.Contains('@') ? last : null;
    }

    private static string Describe(HttpObservation observation)
    {
        if (observation.IsSuccess)
        {
            return $"{observation.StatusText}, but the body held no collection this could read";
        }

        var code = ApiError.Code(observation);
        return $"{observation.StatusText}: {(code.Length > 0 ? code : observation.RefusalDiagnostic ?? "no reason given")}";
    }

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static JsonElement? Root(HttpObservation observation)
    {
        if (!observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
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
