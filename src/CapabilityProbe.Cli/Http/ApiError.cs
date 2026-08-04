using System.Text.Json;

namespace CapabilityProbe.Http;

/// <summary>
/// Pulls the service's own error code and message out of a failed response.
/// <para>
/// Graph and SharePoint REST disagree about the shape. Graph writes
/// <c>{"error":{"code":"itemNotFound","message":"..."}}</c>; SharePoint writes
/// <c>{"error":{"code":"-2147024891, System.UnauthorizedAccessException","message":{"value":"..."}}}</c>.
/// Both are handled here rather than in each probe, because the code is the part of a refusal worth
/// reading and it should not depend on which service happened to answer.
/// </para>
/// </summary>
public static class ApiError
{
    public static string Code(HttpObservation observation) => Read(observation, "code");

    public static string Message(HttpObservation observation) => Read(observation, "message");

    private static string Read(HttpObservation observation, string property)
    {
        if (observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return "";
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            if (!document.RootElement.TryGetProperty("error", out var error))
            {
                // Some refusals from the identity layer answer with a flat object instead.
                return document.RootElement.TryGetProperty($"error_{property}", out var flat) &&
                       flat.ValueKind == JsonValueKind.String
                    ? flat.GetString() ?? ""
                    : "";
            }

            if (error.ValueKind == JsonValueKind.String)
            {
                return property == "code" ? error.GetString() ?? "" : "";
            }

            if (!error.TryGetProperty(property, out var value))
            {
                return "";
            }

            return value.ValueKind switch
            {
                JsonValueKind.String => value.GetString() ?? "",

                // SharePoint nests the human-readable half one level deeper.
                JsonValueKind.Object when value.TryGetProperty("value", out var inner) &&
                                          inner.ValueKind == JsonValueKind.String => inner.GetString() ?? "",

                _ => "",
            };
        }
        catch (JsonException)
        {
            return "";
        }
    }
}
