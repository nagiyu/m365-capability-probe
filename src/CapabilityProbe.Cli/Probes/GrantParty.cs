using System.Text.Json;

namespace CapabilityProbe.Probes;

/// <summary>
/// One grant on one item, reduced to something two different APIs can be compared on.
/// <para>
/// Graph's <c>driveItem/permissions</c> and SharePoint's <c>RoleAssignments</c> describe the same
/// library and name its principals differently. Finding 16 measured that directly - a link whose
/// backing group is called <c>...Flexible...</c> is <c>users</c> in Graph - so any comparison built
/// on names would report a difference that is only a difference of vocabulary.
/// </para>
/// <para>
/// So each side produces a set of candidate keys rather than one, and two parties are the same party
/// when their sets intersect. Which key matched is carried into the report: a join is a claim, and a
/// claim whose basis is not printed cannot be checked.
/// </para>
/// </summary>
public sealed record GrantParty
{
    /// <summary>What kind of thing holds the grant, in this side's own terms.</summary>
    public required string Kind { get; init; }

    /// <summary>How the side named it. Display only - never joined on.</summary>
    public required string Name { get; init; }

    /// <summary>The grant itself: roles, or a link's scope and type.</summary>
    public required string Detail { get; init; }

    /// <summary>
    /// Every handle this side offered for the same principal, best first. Empty means the side named
    /// something this tool cannot key on, which is reported as an unjoinable row rather than dropped.
    /// </summary>
    public required IReadOnlyList<string> Keys { get; init; }

    /// <summary>Where the keys came from, for the report.</summary>
    public required string KeyBasis { get; init; }

    /// <summary>
    /// Whether this grant lets its holder read the document, or only appear beside it. Null where the
    /// side does not say - Graph has no equivalent of Limited Access, so its parties leave this unset
    /// rather than claim an answer.
    /// <para>
    /// Finding 15 is the reason this is a field and not a reading of <see cref="Detail"/>: 制限付き
    /// アクセス is a row SharePoint really does hold and Graph really does not return, so the
    /// subtraction is right to print it - and a reader who stops at the count concludes Graph is
    /// hiding a person. The count and the capability have to arrive together.
    /// </para>
    /// </summary>
    public bool? ConveysAccess { get; init; }

    public bool CanJoin => Keys.Count > 0;

    public string KeyList => Keys.Count == 0 ? "(none)" : string.Join(", ", Keys);

    /// <summary>The first key the other side also has, or null when the two do not meet.</summary>
    public string? MatchIn(IEnumerable<GrantParty> others)
    {
        var theirs = others.SelectMany(o => o.Keys).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return Keys.FirstOrDefault(theirs.Contains);
    }

    /// <summary>
    /// The party on the other side this one meets, rather than only the key they meet on.
    /// <para>
    /// Run 106 printed four rows as "only SharePoint" without saying what the grant was, and the
    /// obvious reading - Graph is hiding a person - is one this repository has been wrong about
    /// before. Whether that row is a real grant or a Limited Access artefact (finding 15) is decided
    /// by its roles, so the roles have to travel into the comparison.
    /// </para>
    /// </summary>
    public GrantParty? PartyIn(IEnumerable<GrantParty> others) =>
        others.FirstOrDefault(o => o.Keys.Any(k => Keys.Contains(k, StringComparer.OrdinalIgnoreCase)));

    /// <summary>
    /// What Graph returned for one item, one party per permission entry.
    /// <para>
    /// A sharing link is emitted as its own party and deliberately carries no key. The two APIs do
    /// name links, but not with the same identifier, and a join invented here would be the fifth time
    /// in this repository that a plausible guess produced a confident wrong answer. The link rows are
    /// therefore reported side by side and counted, and the report says the identities were not
    /// joined.
    /// </para>
    /// </summary>
    public static IReadOnlyList<GrantParty> FromGraph(JsonElement permissions)
    {
        var parties = new List<GrantParty>();

        foreach (var entry in permissions.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var roles = Roles(entry);

            if (entry.TryGetProperty("link", out var link) && link.ValueKind == JsonValueKind.Object)
            {
                var scope = Text(link, "scope") ?? "(no scope)";
                var type = Text(link, "type") ?? "(no type)";
                var named = NamedOnLink(entry);

                parties.Add(new GrantParty
                {
                    Kind = "sharing link",
                    Name = $"{type} link, scope {scope}",
                    Detail = named.Count == 0
                        ? $"roles {roles}; names nobody"
                        : $"roles {roles}; names {string.Join(", ", named)}",
                    Keys = [],
                    KeyBasis = "not joined - the two APIs identify links differently (finding 16)",
                });

                continue;
            }

            if (!entry.TryGetProperty("grantedToV2", out var granted) || granted.ValueKind != JsonValueKind.Object)
            {
                parties.Add(new GrantParty
                {
                    Kind = "(no grantedToV2 and no link)",
                    Name = Text(entry, "id") ?? "(no id)",
                    Detail = $"roles {roles}",
                    Keys = [],
                    KeyBasis = "the entry named no principal this tool could read",
                });

                continue;
            }

            var (kind, name, keys, basis) = ReadIdentitySet(granted);

            parties.Add(new GrantParty
            {
                Kind = kind,
                Name = name,
                Detail = $"roles {roles}",
                Keys = keys,
                KeyBasis = basis,
            });
        }

        return parties;
    }

    /// <summary>
    /// The same for one item's SharePoint role assignments, reusing the reading
    /// <see cref="InventorySharing"/> already does so the two subcommands cannot drift apart.
    /// </summary>
    public static IReadOnlyList<GrantParty> FromSharePoint(IEnumerable<InventorySharing.Grant> grants) =>
        grants.Select(g =>
        {
            var keys = new List<string>();
            var basis = new List<string>();

            // Some rows here are not grants to anybody. Run 99 counted seven of them as "in SharePoint
            // and not in Graph", which read as Graph hiding seven things - and every one was either a
            // sharing link's backing group, which Graph does return as a 'link' entry, or one of
            // SharePoint's own Limited Access bookkeeping groups, which Graph does not model at all.
            //
            // Neither is a missing grant. Keying them would put them in the subtraction and produce
            // exactly the confident wrong number this repository keeps recording, so they are keyed
            // as unjoinable and land in the table that says why.
            var modelledHere = ModelledOnlyBySharePoint(g.Kind);
            if (modelledHere is not null)
            {
                return new GrantParty
                {
                    Kind = g.Kind,
                    Name = g.PrincipalTitle,
                    Detail = g.Roles.Count == 0
                        ? "(no role definitions arrived)"
                        : string.Join(", ", g.Roles.Select(r => r.Describe)),
                    Keys = [],
                    KeyBasis = modelledHere,
                };
            }

            if (!string.IsNullOrWhiteSpace(g.LoginName))
            {
                keys.Add($"login:{g.LoginName.ToLowerInvariant()}");
                basis.Add("Member.LoginName");

                // Both directory claim forms carry an object id, which is what Graph puts in
                // user.id and group.id. Taken only when it parses as a GUID: a claim whose tail is
                // something else would otherwise become a key that silently matches nothing.
                var directoryId = DirectoryId(g.LoginName);
                if (directoryId is not null)
                {
                    keys.Add($"aad:{directoryId}");
                    basis.Add("the object id inside the claim");
                }

                var upn = Upn(g.LoginName);
                if (upn is not null)
                {
                    keys.Add($"upn:{upn}");
                    basis.Add("the address inside the membership claim");
                }
            }

            if (g.PrincipalId is { } id)
            {
                keys.Add($"spid:{id}");
                basis.Add("Member.Id");
            }

            return new GrantParty
            {
                Kind = g.Kind,
                Name = g.PrincipalTitle,
                Detail = g.Roles.Count == 0
                    ? "(no role definitions arrived)"
                    : string.Join(", ", g.Roles.Select(r => r.Describe)),
                Keys = keys,
                KeyBasis = basis.Count == 0 ? "the assignment named nothing this tool could key on" : string.Join(" + ", basis),

                // InventorySharing.Role.Reaches, not a second opinion about the same masks - findings
                // 15 and 71 were measured with it, and a row this tool classified differently would be
                // two implementations disagreeing rather than anything about the tenant.
                ConveysAccess = g.Roles.Count == 0 ? null : g.Roles.Any(r => r.Reaches),
            };
        }).ToList();

    /// <summary>
    /// Whether a SharePoint role assignment names something Graph's permission collection does not
    /// model as a principal, and why. Null when it names an ordinary user or team, which is what the
    /// subtraction is about.
    /// <para>
    /// The classification is <see cref="InventorySharing"/>'s, not a second copy of the same idea -
    /// findings 15 and 16 were measured with it, and a row this tool categorised differently from
    /// the inventory would be a disagreement between two implementations rather than about the data.
    /// </para>
    /// </summary>
    private static string? ModelledOnlyBySharePoint(string kind) => kind switch
    {
        "a sharing link's backing group" =>
            "not a missing grant - Graph returns this link as a 'link' entry instead, and the two " +
            "identifiers cannot be joined (finding 16). Both sides' link rows are in this table",

        "a system group SharePoint generated" =>
            "not a missing grant - SharePoint's own Limited Access bookkeeping, which Graph's " +
            "permission collection does not model at all",

        _ when kind.Contains("a claim, not a membership", StringComparison.Ordinal) =>
            "not a missing grant - a claim standing for a population, with no principal to key on",

        _ => null,
    };

    /// <summary>
    /// Graph's identity set, read for every shape it has been seen in. <c>siteUser</c> and
    /// <c>siteGroup</c> come first because they carry SharePoint's own login name and principal id -
    /// the strongest join available, since it is the very string the other side is keyed on.
    /// </summary>
    private static (string Kind, string Name, IReadOnlyList<string> Keys, string Basis) ReadIdentitySet(JsonElement set)
    {
        var keys = new List<string>();
        var basis = new List<string>();
        var kinds = new List<string>();
        var names = new List<string>();

        foreach (var property in set.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            kinds.Add(property.Name);

            var display = Text(property.Value, "displayName");
            if (display is not null)
            {
                names.Add(display);
            }

            var login = Text(property.Value, "loginName");
            if (login is not null)
            {
                keys.Add($"login:{login.ToLowerInvariant()}");
                basis.Add($"{property.Name}.loginName");
            }

            var id = Text(property.Value, "id");
            if (id is not null)
            {
                // A site principal id is a small integer and an AAD object id is a GUID. They live in
                // different key spaces, and putting both under one prefix would let a SharePoint id
                // of 12 match a directory object that happens to be called 12 somewhere else.
                if (property.Name is "siteUser" or "siteGroup")
                {
                    keys.Add($"spid:{id}");
                    basis.Add($"{property.Name}.id");
                }
                else if (Guid.TryParse(id, out var objectId))
                {
                    keys.Add($"aad:{objectId:D}");
                    basis.Add($"{property.Name}.id");
                }
            }

            var email = Text(property.Value, "email") ?? Text(property.Value, "userPrincipalName");
            if (email is not null)
            {
                keys.Add($"upn:{email.ToLowerInvariant()}");
                basis.Add($"{property.Name}.email");
            }
        }

        return (
            kinds.Count == 0 ? "(an empty identity set)" : string.Join(" + ", kinds),
            names.Count == 0 ? "(no displayName)" : string.Join(" / ", names.Distinct()),
            keys,
            basis.Count == 0 ? "the identity set carried nothing this tool could key on" : string.Join(" + ", basis));
    }

    /// <summary>
    /// Who a link names, when it names anybody. A link with <c>scope: users</c> carries the people it
    /// was made for; one with a wider scope carries nobody, and that difference is the whole of
    /// finding 16.
    /// </summary>
    private static IReadOnlyList<string> NamedOnLink(JsonElement entry)
    {
        var names = new List<string>();

        if (!entry.TryGetProperty("grantedToIdentitiesV2", out var list) || list.ValueKind != JsonValueKind.Array)
        {
            return names;
        }

        foreach (var set in list.EnumerateArray())
        {
            if (set.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var property in set.EnumerateObject())
            {
                var display = property.Value.ValueKind == JsonValueKind.Object
                    ? Text(property.Value, "displayName")
                    : null;

                if (display is not null)
                {
                    names.Add(display);
                }
            }
        }

        return names.Distinct().ToList();
    }

    /// <summary>
    /// The directory object id inside a SharePoint claim. Two providers write one:
    /// <c>c:0t.c|tenant|&lt;guid&gt;</c> for a security group and
    /// <c>c:0o.c|federateddirectoryclaimprovider|&lt;guid&gt;</c> for a Microsoft 365 group, whose
    /// value may carry a <c>_o</c> suffix meaning the group's owners rather than its members.
    /// </summary>
    private static string? DirectoryId(string loginName)
    {
        var last = loginName.LastIndexOf('|');
        if (last < 0 || last == loginName.Length - 1)
        {
            return null;
        }

        var tail = loginName[(last + 1)..];

        // The owners claim points at the same directory object as the members claim, so the suffix is
        // dropped for keying. Which of the two it was stays visible in the login name itself, which
        // the report prints beside the key.
        if (tail.EndsWith("_o", StringComparison.OrdinalIgnoreCase))
        {
            tail = tail[..^2];
        }

        return Guid.TryParse(tail, out var id) ? id.ToString("D") : null;
    }

    /// <summary>The address inside <c>i:0#.f|membership|someone@example.com</c>.</summary>
    private static string? Upn(string loginName)
    {
        var last = loginName.LastIndexOf('|');
        if (last < 0)
        {
            return null;
        }

        var tail = loginName[(last + 1)..];
        return tail.Contains('@') ? tail.ToLowerInvariant() : null;
    }

    private static string Roles(JsonElement entry) =>
        entry.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array
            ? string.Join("+", roles.EnumerateArray()
                .Where(r => r.ValueKind == JsonValueKind.String)
                .Select(r => r.GetString()))
            : "(none listed)";

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
