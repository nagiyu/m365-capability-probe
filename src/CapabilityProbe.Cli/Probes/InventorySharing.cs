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
        string PrincipalTitle,
        string? LoginName,
        int? PrincipalType,
        string Kind,
        IReadOnlyList<string> Roles);

    public sealed record Page(IReadOnlyList<Grant> Grants, int Items, string? NextLink);

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

                grants.Add(new Grant(
                    itemId,
                    fileName,
                    path,
                    unique,
                    title,
                    login,
                    type,
                    Classify(title, login, type),
                    RoleNames(assignment)));
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

    private static IReadOnlyList<string> RoleNames(JsonElement assignment) =>
        Collection(assignment, "RoleDefinitionBindings")
            .Select(b => Text(b, "Name") ?? "(unnamed role)")
            .ToList();

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
