using System.Text.Json;
using CapabilityProbe.Http;

namespace CapabilityProbe.Probes;

/// <summary>
/// Reading SharePoint REST responses, kept apart from the probe that issues the calls.
/// <para>
/// Separate because this is the part that cannot be exercised without a tenant. The orchestration
/// around it runs on every build; these functions only ever see a real body when someone points the
/// tool at a real site. Getting one of them wrong produces a report that is confidently incorrect,
/// which is the worst outcome available to a tool like this, so they are pulled out where they can be
/// handed a body and checked.
/// </para>
/// </summary>
public static class SharePointResponses
{
    /// <summary>
    /// The first of the named fields that is present, as a short proof that something real came back.
    /// Several names because Graph and SharePoint spell the same idea differently.
    /// </summary>
    public static string Field(HttpObservation observation, params string[] names)
    {
        if (!observation.IsSuccess)
        {
            return Refusal(observation);
        }

        if (string.IsNullOrWhiteSpace(observation.Body))
        {
            return "(empty body)";
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            foreach (var name in names)
            {
                if (document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
                {
                    return $"{name}: {value.GetString()}";
                }
            }

            return $"(no {string.Join(" or ", names)} in the response)";
        }
        catch (JsonException)
        {
            return "(response was not JSON)";
        }
    }

    /// <summary>Group names, which name the site rather than any person, so they are safe to print.</summary>
    public static string Groups(HttpObservation observation)
    {
        if (!observation.IsSuccess)
        {
            return Refusal(observation);
        }

        var titles = Collection(observation, e =>
            e.TryGetProperty("Title", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null);

        return titles is null
            ? "(no collection in the response)"
            : titles.Count == 0
                ? "0 groups"
                : $"{titles.Count} groups: {string.Join(", ", titles)}";
    }

    /// <summary>
    /// Membership is counted, not named. Whether the members can be enumerated is the measurement;
    /// who they are is somebody's directory, and this report gets read in places the directory is not.
    /// The principal types are kept as the raw numbers SharePoint sent, because a label invented here
    /// would be this tool's guess presented as the service's answer.
    /// </summary>
    public static string Users(HttpObservation observation)
    {
        if (!observation.IsSuccess)
        {
            return Refusal(observation);
        }

        var members = Collection(observation, e =>
            e.TryGetProperty("PrincipalType", out var p) && p.ValueKind == JsonValueKind.Number
                ? p.GetRawText()
                : "?");

        if (members is null)
        {
            return "(no collection in the response)";
        }

        var kinds = members.Distinct().Order(StringComparer.Ordinal).ToList();
        return members.Count == 0
            ? "0 members"
            : $"{members.Count} members (PrincipalType {string.Join(", ", kinds)})";
    }

    /// <summary>One site group, as much of it as is needed to ask about its membership and say whose.</summary>
    public sealed record SiteGroup(string Id, string? Title)
    {
        public string Display => $"{Id} \"{Title ?? "(untitled)"}\"";
    }

    /// <summary>
    /// Every site group in a listing - each one's ID for building a membership call, and its title.
    /// <para>
    /// All of them rather than one, because choosing one is a prediction about where the answer lives,
    /// and this probe does not make those. It made this one once by accident: it took whichever group
    /// the site happened to list first, that turned out to be bookkeeping SharePoint had generated for
    /// itself, and its emptiness was very nearly read as a fact about the site's groups in general.
    /// Asking about all of them turns "which group" from a choice into a constant.
    /// </para>
    /// <para>
    /// The title travels with the ID because a membership count is meaningless without knowing whose
    /// membership it is. A site's groups are not interchangeable: some an administrator created and
    /// filled, some the service made for its own purposes. "0 members" is unremarkable for the second
    /// kind and surprising for the first.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Null and empty mean different things here, as they do everywhere else in this tool: null is
    /// "there was no listing to read", empty is "the listing was read and the site has no groups".
    /// Collapsing them would let a refusal be reported as a site with nothing in it.
    /// </remarks>
    public static IReadOnlyList<SiteGroup>? AllGroups(HttpObservation? observation)
    {
        if (observation is null || !observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            if (!document.RootElement.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var groups = new List<SiteGroup>();
            foreach (var entry in value.EnumerateArray())
            {
                if (entry.TryGetProperty("Id", out var id) && id.ValueKind == JsonValueKind.Number)
                {
                    groups.Add(new SiteGroup(
                        id.GetRawText(),
                        entry.TryGetProperty("Title", out var title) && title.ValueKind == JsonValueKind.String
                            ? title.GetString()
                            : null));
                }
            }

            return groups;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>How many groups a readable listing held, or null when there was no listing to count.</summary>
    public static int? GroupCount(HttpObservation? observation) => AllGroups(observation)?.Count;

    /// <summary>What the service said about a refusal: its own code, or failing that the headers.</summary>
    public static string Refusal(HttpObservation observation)
    {
        var code = ApiError.Code(observation);
        return code.Length > 0 ? code : observation.RefusalDiagnostic ?? "(no reason given)";
    }

    private static List<string>? Collection(HttpObservation observation, Func<JsonElement, string?> select)
    {
        if (string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            if (!document.RootElement.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            return value.EnumerateArray().Select(select).Where(s => s is not null).Select(s => s!).ToList();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
