using System.Text.Json;
using CapabilityProbe.Http;

namespace CapabilityProbe.Probes;

/// <summary>
/// Reading the bodies the bulk routes return, kept apart from the probe that issues the calls - the
/// same reason <see cref="SharePointResponses"/> is separate. None of this runs until someone points
/// the tool at a real tenant, so it is put where it can be handed a body and checked.
/// </summary>
public static class AclResponses
{
    /// <summary>One item as a bulk answer described it: its identity, and the ACL that came with it.</summary>
    public sealed record Item(string Id, string? Name, PermissionSummary.Entries? Permissions);

    /// <summary>
    /// A page of items. <see cref="NextLink"/> is the honest half of a page-at-a-time measurement:
    /// one call answering quickly means nothing if it answered for a fraction of the drive.
    /// <para>
    /// The link is kept rather than reduced to a flag. "More were waiting" says a route was measured
    /// against part of a library; following it says how much of the library there was. Which of those
    /// two a run does is a decision, and a decision needs the link in hand to be made at all.
    /// </para>
    /// </summary>
    public sealed record Page(IReadOnlyList<Item> Items, string? NextLink)
    {
        /// <summary>Whether the service said there was more after this page.</summary>
        public bool MorePages => NextLink is not null;
    }

    /// <summary>
    /// How many ACL entries a set of items carried in total, or null when not one of them carried an
    /// ACL - a route whose expansion was ignored throughout has no total, and reporting zero would
    /// say the items are shared with nobody.
    /// <para>
    /// Taken over a whole walk rather than over one page, so that a route which pages is counted the
    /// same way as one that does not.
    /// </para>
    /// </summary>
    public static int? TotalEntries(IReadOnlyList<Item> items) =>
        items.All(i => i.Permissions is null) && items.Count > 0
            ? null
            : items.Sum(i => i.Permissions?.Count ?? 0);

    /// <summary>How many of the items actually carried an expanded permission collection.</summary>
    public static int Expanded(IReadOnlyList<Item> items) => items.Count(i => i.Permissions is not null);

    /// <summary>
    /// A Graph collection - <c>children</c> or <c>delta</c> - with <c>permissions</c> expanded onto
    /// each entry, if the service honoured the expansion.
    /// <para>
    /// An item with no <c>permissions</c> property is recorded with a null ACL rather than a zero,
    /// because "the expansion was ignored" and "this item is shared with nobody" are the two answers
    /// this call exists to tell apart.
    /// </para>
    /// <para>
    /// <c>delta</c> reports deletions as entries carrying a <c>deleted</c> facet and no content.
    /// They are skipped: a tombstone is not an item whose ACL could have been read.
    /// </para>
    /// </summary>
    public static Page? GraphPage(HttpObservation? observation)
    {
        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var items = new List<Item>();
        foreach (var entry in value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object ||
                entry.TryGetProperty("deleted", out _) ||
                !entry.TryGetProperty("id", out var id) ||
                id.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var permissions = entry.TryGetProperty("permissions", out var expanded) &&
                              expanded.ValueKind == JsonValueKind.Array
                ? PermissionSummary.ReadArray(expanded)
                : null;

            items.Add(new Item(
                id.GetString()!,
                entry.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String
                    ? name.GetString()
                    : null,
                permissions));
        }

        return new Page(items, Link(root.Value, "@odata.nextLink"));
    }

    /// <summary>The permission collection from a single-item <c>/permissions</c> call.</summary>
    public static PermissionSummary.Entries? Permissions(HttpObservation? observation)
    {
        var root = Root(observation);
        return root is null ? null : PermissionSummary.Read(root.Value);
    }

    /// <summary>
    /// A SharePoint list-items answer with <c>RoleAssignments</c> expanded.
    /// <para>
    /// The role assignments are counted, not translated. A SharePoint role assignment and a Graph
    /// permission entry are different objects describing overlapping facts, so the counts are recorded
    /// side by side and never compared for equality - that comparison would be this tool asserting the
    /// two models line up, which it has not measured.
    /// </para>
    /// </summary>
    public static Page? SharePointPage(HttpObservation? observation)
    {
        var root = Root(observation);
        if (root is null || !root.Value.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var items = new List<Item>();
        foreach (var entry in value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var assignments = RoleAssignments(entry);

            items.Add(new Item(
                entry.TryGetProperty("Id", out var id) && id.ValueKind == JsonValueKind.Number
                    ? id.GetRawText()
                    : "(no Id)",
                entry.TryGetProperty("FileLeafRef", out var leaf) && leaf.ValueKind == JsonValueKind.String
                    ? leaf.GetString()
                    : null,
                assignments is null ? null : new PermissionSummary.Entries(assignments.Value, [])));
        }

        // SharePoint writes the link without the '@' under nometadata and with it under the verbose
        // formats. The probe asks for the first but does not get to decide what arrives.
        return new Page(items, Link(root.Value, "odata.nextLink") ?? Link(root.Value, "@odata.nextLink"));
    }

    /// <summary>
    /// A continuation link, or null when the property is absent or is not a usable absolute URL.
    /// A link that cannot be followed is reported as no link rather than as a walk that failed - the
    /// service saying "there is more" and the probe being able to go and get it are separate facts.
    /// </summary>
    private static string? Link(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var link) &&
        link.ValueKind == JsonValueKind.String &&
        Uri.TryCreate(link.GetString(), UriKind.Absolute, out _)
            ? link.GetString()
            : null;

    /// <summary>
    /// How many role assignments an item carried, or null when the expansion produced nothing to count.
    /// SharePoint writes an expanded collection as a bare array under <c>nometadata</c> and as an
    /// object with a <c>results</c> array under the verbose formats, and the probe asks for the first
    /// but does not get to decide what arrives.
    /// </summary>
    private static int? RoleAssignments(JsonElement entry)
    {
        if (!entry.TryGetProperty("RoleAssignments", out var assignments))
        {
            return null;
        }

        return assignments.ValueKind switch
        {
            JsonValueKind.Array => assignments.GetArrayLength(),
            JsonValueKind.Object when assignments.TryGetProperty("results", out var results) &&
                                      results.ValueKind == JsonValueKind.Array => results.GetArrayLength(),
            _ => null,
        };
    }

    /// <summary>The server-relative path of a drive, taken from the <c>webUrl</c> Graph reports for it.</summary>
    public static string? DriveServerRelativePath(HttpObservation? observation)
    {
        var root = Root(observation);
        if (root is null ||
            !root.Value.TryGetProperty("webUrl", out var webUrl) ||
            webUrl.ValueKind != JsonValueKind.String ||
            !Uri.TryCreate(webUrl.GetString(), UriKind.Absolute, out var uri))
        {
            return null;
        }

        // Graph percent-encodes the path; SharePoint's GetList takes the decoded form as a string
        // literal, and the caller encodes it again for transport.
        return Uri.UnescapeDataString(uri.AbsolutePath).TrimEnd('/');
    }

    private static JsonElement? Root(HttpObservation? observation)
    {
        if (observation is null || !observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            // JsonDocument owns the buffer, so the element is cloned before the document is disposed.
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
