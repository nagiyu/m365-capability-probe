using System.Text.Json;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// The label definitions themselves, read beside the files that carry them.
/// <para>
/// A listing hands back a label's display name and nothing else. Sorting those names into "this one
/// protects" and "this one only classifies" means asking the label definition, and whether that can
/// be asked at all - by this identity, through any route - had never been measured here.
/// </para>
/// <para>
/// Which route serves it is not something to settle by picking one and reporting what it said. Four
/// are tried, and every reply is quoted whole: the request asks for the bag rather than for a lookup,
/// because a key nobody knows the name of cannot be searched for. A route that refuses is quoted too
/// - the refusal names what is missing, which is the next step rather than a dead end.
/// </para>
/// </summary>
public static class LabelDefinitions
{
    private const string V1 = "https://graph.microsoft.com/v1.0";
    private const string Beta = "https://graph.microsoft.com/beta";

    /// <summary>
    /// The routes that might carry a label definition. Both surfaces, both versions - the pair is the
    /// point: a route missing on one version and present on the other says something a single call
    /// cannot, and so does the same route refusing on both.
    /// </summary>
    private static readonly (string Name, string Url)[] Routes =
    [
        ("security/informationProtection (v1.0)", $"{V1}/security/informationProtection/sensitivityLabels"),
        ("security/informationProtection (beta)", $"{Beta}/security/informationProtection/sensitivityLabels"),
        ("informationProtection/policy (v1.0)", $"{V1}/informationProtection/policy/labels"),
        ("informationProtection/policy (beta)", $"{Beta}/informationProtection/policy/labels"),
    ];

    /// <summary>
    /// A <c>User-Agent</c>, sent on every route.
    /// <para>
    /// The tool had never sent one, and no endpoint measured before this one had ever asked for it.
    /// Both beta routes refused the first run with <c>400 invalidRequest</c> and, in the inner error,
    /// <c>Value cannot be null. (Parameter 'User-Agent')</c>. That is a fact about the request this
    /// probe built, not about what the identity may read - and reporting it in the same column as a
    /// refusal would have made the tool's own omission look like the tenant's answer.
    /// </para>
    /// <para>
    /// It goes on all four routes rather than only the two that asked, so the version and the surface
    /// stay the only things that differ between rows. It is recorded in the request headers, so a
    /// reader can see it was sent and re-issue the call by hand.
    /// </para>
    /// </summary>
    private static readonly (string Name, string Value)[] Headers =
    [
        ("User-Agent", "m365-capability-probe"),
    ];

    /// <summary>
    /// Walks every route once, quoting what each returned. Returns the table; the quotes go straight
    /// onto the report, because a label definition is exactly the kind of value a cell would clip.
    /// </summary>
    public static async Task<ProbeTable> ReadAsync(
        ThrottleAwareCaller caller,
        string token,
        List<HttpObservation> calls,
        ProbeReport report,
        CancellationToken cancellationToken)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var (name, url) in Routes)
        {
            var observation = await caller.GetAsync(url, token, cancellationToken, extraHeaders: Headers);
            calls.Add(observation);

            if (!observation.IsSuccess)
            {
                // The refusal is the useful part when a route is refused: it names the grant that is
                // missing, and that is what the next run needs. A cell would clip it, so it is quoted.
                rows.Add([name, observation.StatusText, ApiError.Code(observation), "-", "-"]);

                report.Quote($"label definitions - {name}",
                    string.IsNullOrWhiteSpace(observation.Body)
                        ? $"{observation.StatusText}, and the body was empty"
                        : $"{observation.StatusText}\n{observation.Body}");

                continue;
            }

            var labels = Labels(observation);
            if (labels is null)
            {
                rows.Add([name, observation.StatusText, null, "-", "the reply carried no 'value' array"]);
                report.Quote($"label definitions - {name}", observation.Body);
                continue;
            }

            var withActions = 0;
            var emptyActions = 0;
            var noActionsKey = 0;

            foreach (var label in labels)
            {
                // Three outcomes, kept apart. "The key is absent" and "the key is there and empty" are
                // different facts about a label that does not protect, and reading the first as the
                // second is the shape finding 24 recorded: a name's absence is not a statement.
                if (!label.TryGetProperty("labelActions", out var actions))
                {
                    noActionsKey++;
                }
                else if (actions.ValueKind == JsonValueKind.Array && actions.GetArrayLength() == 0)
                {
                    emptyActions++;
                }
                else
                {
                    withActions++;
                }

                report.Quote(
                    $"label definition - {Text(label, "displayName") ?? Text(label, "name") ?? "(no name)"} " +
                    $"({name}), whole",
                    JsonSerializer.Serialize(label, new JsonSerializerOptions { WriteIndented = true }));
            }

            rows.Add([
                name,
                observation.StatusText,
                null,
                labels.Count.ToString(),
                $"{withActions} with labelActions, {emptyActions} with it empty, {noActionsKey} without the key",
            ]);
        }

        return new ProbeTable(
            "Where a label definition can be read from, and what each route said",
            ["route", "status", "error code", "labels", "labelActions across them"],
            rows);
    }

    private static IReadOnlyList<JsonElement>? Labels(HttpObservation observation)
    {
        try
        {
            var root = JsonDocument.Parse(observation.Body).RootElement;
            return root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array
                ? value.EnumerateArray().Select(e => e.Clone()).ToList()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
