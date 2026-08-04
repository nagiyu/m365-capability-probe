using System.Text.Json;

namespace CapabilityProbe.Probes;

/// <summary>
/// What a Graph permission collection contains, counted and characterised but never named.
/// <para>
/// This lives on its own because two subcommands read the same collection and their answers have to
/// be comparable. <c>access</c> reads it one item at a time; <c>acl</c> asks whether a whole page of
/// items can be read in one call and then checks the two against each other. If each of them counted
/// entries its own way, a disagreement between them would say nothing about the APIs - it would be a
/// difference between two copies of the same idea.
/// </para>
/// <para>
/// Entries are counted and the kinds of principal are named; the principals themselves are not. Who
/// has access to a file is somebody's directory, and these reports are read where that directory is
/// not.
/// </para>
/// </summary>
public static class PermissionSummary
{
    /// <summary>An item's permission collection: how many entries, and what kinds appear in them.</summary>
    public sealed record Entries(int Count, IReadOnlyList<string> PrincipalKinds)
    {
        /// <summary>
        /// The whole summary as one comparable string. Two of these being equal is the strongest thing
        /// this tool can say about two answers matching without recording who is in them.
        /// </summary>
        public string Fingerprint =>
            PrincipalKinds.Count == 0 ? $"{Count}/-" : $"{Count}/{string.Join('+', PrincipalKinds)}";
    }

    /// <summary>
    /// Reads a <c>value</c> array of permission entries. Null when there is no such array to read -
    /// a refusal and an empty collection are different observations and must not collapse into one.
    /// </summary>
    public static Entries? Read(JsonElement parent, string propertyName = "value")
    {
        if (!parent.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        return ReadArray(value);
    }

    /// <summary>The same, given the array itself.</summary>
    public static Entries ReadArray(JsonElement entries)
    {
        var kinds = new SortedSet<string>(StringComparer.Ordinal);
        var count = 0;

        foreach (var entry in entries.EnumerateArray())
        {
            count++;

            CollectSet(entry, "grantedToV2", kinds);
            CollectSet(entry, "grantedTo", kinds);
            CollectList(entry, "grantedToIdentitiesV2", kinds);
            CollectList(entry, "grantedToIdentities", kinds);

            if (entry.TryGetProperty("link", out var link) && link.ValueKind == JsonValueKind.Object)
            {
                var scope = link.TryGetProperty("scope", out var s) ? s.GetString() : null;
                kinds.Add(scope is null ? "link" : $"link:{scope}");
            }

            if (entry.TryGetProperty("invitation", out var invitation) && invitation.ValueKind == JsonValueKind.Object)
            {
                kinds.Add("invitation");
            }
        }

        return new Entries(count, kinds.ToList());
    }

    private static void CollectSet(JsonElement entry, string propertyName, SortedSet<string> kinds)
    {
        if (entry.TryGetProperty(propertyName, out var identitySet) && identitySet.ValueKind == JsonValueKind.Object)
        {
            foreach (var kind in identitySet.EnumerateObject())
            {
                if (kind.Value.ValueKind == JsonValueKind.Object)
                {
                    kinds.Add(kind.Name);
                }
            }
        }
    }

    private static void CollectList(JsonElement entry, string propertyName, SortedSet<string> kinds)
    {
        if (entry.TryGetProperty(propertyName, out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var identitySet in list.EnumerateArray())
            {
                foreach (var kind in identitySet.EnumerateObject())
                {
                    if (kind.Value.ValueKind == JsonValueKind.Object)
                    {
                        kinds.Add(kind.Name);
                    }
                }
            }
        }
    }
}
