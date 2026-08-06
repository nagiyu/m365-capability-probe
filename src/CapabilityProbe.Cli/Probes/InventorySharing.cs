using System.Text.Json;
using CapabilityProbe.Http;

namespace CapabilityProbe.Probes;

/// <summary>
/// Reading the sharing half of an inventory: who a SharePoint list item is shared with, and under
/// which role. Kept apart from the probe that issues the calls, for the same reason
/// <see cref="AclResponses"/> is - so a body can be handed to it and checked without a tenant.
/// </summary>
public static class InventorySharing
{
    /// <summary>
    /// One grant on one item: a principal, and the roles it was given.
    /// <para>
    /// <see cref="Kind"/> is not decoration. Finding 6 measured this tool reporting "0 members" about
    /// a group nobody had chosen - it had taken the first in the collection, and the first happened to
    /// be a SharePoint-generated one. A row that names only a count is a number about an object the
    /// reader cannot identify, and the identification has to travel with it.
    /// </para>
    /// </summary>
    public sealed record Grant(
        string ItemId,
        string? FileName,
        string? Path,
        bool? HasUniqueRoleAssignments,
        int? PrincipalId,
        string PrincipalTitle,
        string? LoginName,
        int? PrincipalType,
        string Kind,
        IReadOnlyList<Role> Roles);

    /// <summary>
    /// A role definition as it arrived, plus the one thing about it that matters to a reach report:
    /// whether it lets its holder see the item at all.
    /// <para>
    /// The name cannot answer that. Run 71 came back in Japanese - 閲覧, 編集, 制限付きアクセス - because
    /// the site is Japanese, so any rule written against English role names would have silently found
    /// nothing to exclude and reported the widest possible reach. <see cref="GrantsView"/> reads the
    /// permission mask instead, which is the same number in every locale.
    /// </para>
    /// </summary>
    public sealed record Role(string Name, int? TypeKind, bool? GrantsView)
    {
        /// <summary>
        /// Limited Access is the trap this exists for. SharePoint adds it to a parent list whenever
        /// somebody is given access to one item inside, so a person granted one file appears on every
        /// item in the library. Run 71 measured exactly that: one user held 閲覧 on a single document
        /// and 制限付きアクセス on four others, and counting the latter as reach would have overstated
        /// that person's access fivefold.
        /// </summary>
        /// <summary>
        /// The permission mask decides. <c>RoleTypeKind</c> 1 - Guest, which is what Limited Access is
        /// defined as - is a fallback for when the mask does not arrive, and a role with neither is
        /// counted as reach rather than excluded: overstating what could not be established would hide
        /// a grant, and a reach report that hides grants is worse than one that includes a doubtful
        /// row and says so.
        /// </summary>
        public bool Reaches => GrantsView ?? TypeKind is not 1;

        public string Describe => (GrantsView, TypeKind) switch
        {
            (true, _) => Name,
            (false, _) => $"{Name} (no view)",
            (null, 1) => $"{Name} (no view, by role type - no permission mask arrived)",
            (null, _) => $"{Name} (capability unknown - no permission mask arrived)",
        };
    }

    public sealed record Page(IReadOnlyList<Grant> Grants, int Items, string? NextLink);

    /// <summary>
    /// <c>ViewListItems</c>, the low bit of SharePoint's base permission mask. Limited Access carries
    /// Open and ViewFormPages but not this one, which is what makes it distinguishable from a role that
    /// genuinely lets somebody read the document.
    /// </summary>
    private const ulong ViewListItems = 0x1;

    /// <summary>
    /// What SharePoint's numeric principal type means, per the CSOM enumeration. Anything outside it
    /// is reported as the raw number rather than guessed at.
    /// </summary>
    private static string TypeName(int? principalType) => principalType switch
    {
        1 => "user",
        2 => "distribution list",
        4 => "security group",
        8 => "SharePoint group",
        null => "(no type)",
        _ => $"(type {principalType})",
    };

    /// <summary>
    /// The kind of thing a grant names, which is not the same question as its type.
    /// <para>
    /// SharePoint puts objects in this collection that are not people or teams: groups it generated to
    /// hold a sharing link, groups it generated to give somebody reach into one item, and claims that
    /// stand for a whole population and have no membership to read at all. All of them are typed as
    /// ordinary groups. A report that expanded them like ordinary groups would produce confident,
    /// wrong numbers, so they are named here instead.
    /// </para>
    /// </summary>
    private static string Classify(string title, string? loginName, int? principalType)
    {
        var login = loginName ?? string.Empty;

        if (login.Contains("spo-grid-all-users", StringComparison.OrdinalIgnoreCase))
        {
            return "everyone except external users (a claim, not a membership)";
        }

        if (login.StartsWith("c:0(.s|true", StringComparison.OrdinalIgnoreCase))
        {
            return "everyone (a claim, not a membership)";
        }

        if (title.StartsWith("SharingLinks.", StringComparison.OrdinalIgnoreCase))
        {
            return "a sharing link's backing group";
        }

        if (title.StartsWith("Limited Access System Group", StringComparison.OrdinalIgnoreCase))
        {
            return "a system group SharePoint generated";
        }

        return TypeName(principalType);
    }

    /// <summary>
    /// Reads one page of list items with their role assignments expanded. Returns null when the body
    /// held no collection this could read - which the caller must report as an unread page rather than
    /// as an item with no grants.
    /// </summary>
    public static Page? ReadPage(HttpObservation? observation)
    {
        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var grants = new List<Grant>();
        var items = 0;

        foreach (var entry in value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            items++;

            var itemId = entry.TryGetProperty("Id", out var id) && id.ValueKind == JsonValueKind.Number
                ? id.GetRawText()
                : "(no Id)";
            var fileName = Text(entry, "FileLeafRef");
            var path = Text(entry, "FileRef");
            var unique = entry.TryGetProperty("HasUniqueRoleAssignments", out var uniq) &&
                         uniq.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? uniq.GetBoolean()
                : (bool?)null;

            foreach (var assignment in Assignments(entry))
            {
                var member = assignment.TryGetProperty("Member", out var m) && m.ValueKind == JsonValueKind.Object
                    ? m
                    : default;

                var title = member.ValueKind == JsonValueKind.Object
                    ? Text(member, "Title") ?? "(no title)"
                    : "(no member)";
                var login = member.ValueKind == JsonValueKind.Object ? Text(member, "LoginName") : null;
                var type = member.ValueKind == JsonValueKind.Object &&
                           member.TryGetProperty("PrincipalType", out var pt) &&
                           pt.ValueKind == JsonValueKind.Number
                    ? pt.GetInt32()
                    : (int?)null;
                var principalId = member.ValueKind == JsonValueKind.Object &&
                                  member.TryGetProperty("Id", out var mid) &&
                                  mid.ValueKind == JsonValueKind.Number
                    ? mid.GetInt32()
                    : (int?)null;

                grants.Add(new Grant(
                    itemId,
                    fileName,
                    path,
                    unique,
                    principalId,
                    title,
                    login,
                    type,
                    Classify(title, login, type),
                    Roles(assignment)));
            }
        }

        return new Page(grants, items, Link(root.Value, "odata.nextLink") ?? Link(root.Value, "@odata.nextLink"));
    }

    /// <summary>
    /// SharePoint writes an expanded collection as a bare array under <c>nometadata</c> and as an
    /// object with a <c>results</c> array under the verbose formats. The probe asks for the first and
    /// does not get to decide what arrives, so both are read.
    /// </summary>
    private static IEnumerable<JsonElement> Assignments(JsonElement entry) =>
        Collection(entry, "RoleAssignments");

    private static IReadOnlyList<Role> Roles(JsonElement assignment) =>
        Collection(assignment, "RoleDefinitionBindings")
            .Select(b => new Role(
                Text(b, "Name") ?? "(unnamed role)",
                b.TryGetProperty("RoleTypeKind", out var kind) && kind.ValueKind == JsonValueKind.Number
                    ? kind.GetInt32()
                    : null,
                GrantsView(b)))
            .ToList();

    /// <summary>
    /// Whether a role definition carries <c>ViewListItems</c>. Null when the mask did not arrive - the
    /// probe does not ask for these fields by name (finding: SharePoint's <c>$select</c> refused named
    /// columns that <c>/fields</c> lists), so it takes what the expansion happens to include, and an
    /// absent mask must read as "not established" rather than as "no".
    /// </summary>
    private static bool? GrantsView(JsonElement binding)
    {
        if (!binding.TryGetProperty("BasePermissions", out var permissions) ||
            permissions.ValueKind != JsonValueKind.Object ||
            !permissions.TryGetProperty("Low", out var low))
        {
            return null;
        }

        // SharePoint sends the two halves of a 64-bit mask as strings under nometadata, because
        // JavaScript cannot hold them as numbers. Both forms are read rather than assumed.
        var raw = low.ValueKind switch
        {
            JsonValueKind.String => low.GetString(),
            JsonValueKind.Number => low.GetRawText(),
            _ => null,
        };

        return ulong.TryParse(raw, out var mask) ? (mask & ViewListItems) != 0 : null;
    }

    private static IEnumerable<JsonElement> Collection(JsonElement parent, string property)
    {
        if (!parent.TryGetProperty(property, out var collection))
        {
            yield break;
        }

        var array = collection.ValueKind switch
        {
            JsonValueKind.Array => collection,
            JsonValueKind.Object when collection.TryGetProperty("results", out var results) &&
                                      results.ValueKind == JsonValueKind.Array => results,
            _ => default,
        };

        if (array.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var element in array.EnumerateArray())
        {
            yield return element;
        }
    }

    private static string? Link(JsonElement root, string property) =>
        root.TryGetProperty(property, out var link) &&
        link.ValueKind == JsonValueKind.String &&
        Uri.TryCreate(link.GetString(), UriKind.Absolute, out _)
            ? link.GetString()
            : null;

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
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
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
