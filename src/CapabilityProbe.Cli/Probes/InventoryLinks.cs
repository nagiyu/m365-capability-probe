using System.Text.Json;
using CapabilityProbe.Http;

namespace CapabilityProbe.Probes;

/// <summary>
/// What a sharing link actually grants, from the service rather than from its name.
/// <para>
/// Section B finds groups called <c>SharingLinks.&lt;item&gt;.OrganizationEdit.&lt;link&gt;</c> and
/// they are tempting: the audience appears to be right there in the string. Run 73 leaned on that and
/// printed a caveat asserting an audience nobody had asked the service about. The naming is
/// undocumented, and a reach report that guesses at who a link reaches has stopped being a
/// measurement.
/// </para>
/// <para>
/// So the audience is read from <c>driveItem/permissions</c>, where it is a documented field, and the
/// group name is printed beside it. Where the two agree, a future version can stop making this call;
/// where they disagree, the name was never usable. Either outcome is worth one call per file.
/// </para>
/// </summary>
public static class InventoryLinks
{
    /// <summary>
    /// One sharing link on one file. <see cref="Scope"/> and <see cref="Type"/> are quoted from Graph
    /// verbatim rather than translated into words of this tool's choosing, so that a value this
    /// version has never seen still arrives intact.
    /// </summary>
    public sealed record Link(
        string FileName,
        string PermissionId,
        string? Scope,
        string? Type,
        bool? PreventsDownload,
        IReadOnlyList<string> GrantedTo,
        IReadOnlyList<string> Roles,
        bool HasPassword,
        string? Expires);

    /// <summary>
    /// Whether a link's scope hands reach to anybody who did not already have it.
    /// <para>
    /// <c>existingAccess</c> is the one that does not: Microsoft documents it as re-sharing with
    /// people who can already open the item. A backing group exists for it all the same, so a report
    /// that counted sharing-link groups as reach would credit this link with an audience it never
    /// granted. Null for a scope this version has not been taught, which prints as unknown rather
    /// than as either answer.
    /// </para>
    /// </summary>
    public static bool? AddsReach(string? scope) => scope?.ToLowerInvariant() switch
    {
        "existingaccess" => false,
        "anonymous" or "organization" or "users" => true,
        _ => null,
    };

    /// <summary>Who a link reaches, in the terms the scope allows. Never a count for a population.</summary>
    public static string Audience(Link link) => link.Scope?.ToLowerInvariant() switch
    {
        "existingaccess" => "nobody new - only people who could already open it",
        "anonymous" => "anyone with the link, including outside the tenant - not enumerable",
        "organization" => "anyone inside the tenant who has the link - not enumerable",
        "users" => link.GrantedTo.Count > 0
            ? string.Join(", ", link.GrantedTo)
            : "named people, but the identities did not arrive",
        null => "(the link carried no scope)",
        _ => $"(scope '{link.Scope}' - this version does not know what it reaches)",
    };

    /// <summary>
    /// Reads the link permissions off one item's permission collection. Permissions that are not
    /// links - a person granted the item directly - are left out: section B reads those from the list,
    /// and reporting the same grant twice from two routes would double it.
    /// </summary>
    public static IReadOnlyList<Link>? Read(HttpObservation observation, string fileName)
    {
        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var links = new List<Link>();

        foreach (var entry in value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object ||
                !entry.TryGetProperty("link", out var link) ||
                link.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            links.Add(new Link(
                fileName,
                Text(entry, "id") ?? "(no id)",
                Text(link, "scope"),
                Text(link, "type"),
                link.TryGetProperty("preventsDownload", out var block) &&
                block.ValueKind is JsonValueKind.True or JsonValueKind.False
                    ? block.GetBoolean()
                    : null,
                Identities(entry),
                Strings(entry, "roles"),
                entry.TryGetProperty("hasPassword", out var password) && password.ValueKind == JsonValueKind.True,
                Text(entry, "expirationDateTime")));
        }

        return links;
    }

    /// <summary>
    /// The people a "specific people" link names. Both the current and the superseded property are
    /// read: which one arrives is Graph's choice, not the caller's, and an empty list here would be
    /// reported as a link that reaches nobody.
    /// </summary>
    private static IReadOnlyList<string> Identities(JsonElement permission)
    {
        var names = new List<string>();

        foreach (var property in new[] { "grantedToIdentitiesV2", "grantedToIdentities" })
        {
            if (!permission.TryGetProperty(property, out var identities) ||
                identities.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var identity in identities.EnumerateArray())
            {
                if (identity.ValueKind != JsonValueKind.Object ||
                    !identity.TryGetProperty("user", out var user) ||
                    user.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var name = Text(user, "email") ?? Text(user, "userPrincipalName") ?? Text(user, "displayName");
                if (name is not null && !names.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    names.Add(name);
                }
            }
        }

        return names;
    }

    private static IReadOnlyList<string> Strings(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return array.EnumerateArray()
            .Where(v => v.ValueKind == JsonValueKind.String)
            .Select(v => v.GetString()!)
            .ToList();
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
