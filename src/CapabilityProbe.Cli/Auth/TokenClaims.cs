using System.Text;
using System.Text.Json;

namespace CapabilityProbe.Auth;

/// <summary>
/// The parts of an issued token that say what it can actually do.
/// <para>
/// A token being issued is not the same as the app being able to do anything. Client credentials with
/// a <c>.default</c> scope succeed against a resource the app was granted nothing for, as long as that
/// resource exists in the tenant - the token simply comes back with no <c>roles</c> in it, and every
/// call made with it is refused. Reporting only "token issued" would hide exactly that.
/// </para>
/// </summary>
public sealed record TokenClaims(
    string? Audience,
    string? AppId,
    string? SignedInAs,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Scopes,
    string? CredentialClass)
{
    /// <summary>
    /// The claim name this token used to say how the app authenticated, or null when it said nothing.
    /// Kept alongside the value because the two spellings belong to different token versions, and a
    /// report that flattened them would lose which kind of token it was reading.
    /// </summary>
    public string? CredentialClassClaim { get; init; }

    /// <summary>
    /// How the app proved itself, as the issuer recorded it - <c>appidacr</c> in a v1 token,
    /// <c>azpacr</c> in a v2 one.
    /// <para>
    /// The raw value, not a translation of it. Entra publishes what the numbers mean, but this probe
    /// did not measure that mapping, and a report that printed "certificate" where the token said
    /// <c>2</c> would be passing off a lookup as an observation. The same rule the group membership
    /// summaries follow for <c>PrincipalType</c>.
    /// </para>
    /// <para>
    /// It is read at all because it is the one claim that differs between two tokens for the same app,
    /// the same tenant and the same roles, requested seconds apart. Without it, two identical-looking
    /// grants getting different answers from a resource has nothing in the report to hang on.
    /// </para>
    /// </summary>
    public string? CredentialClassText =>
        CredentialClass is null ? null : $"{CredentialClassClaim}: {CredentialClass}";

    /// <summary>True when the token carries at least one application role or delegated scope.</summary>
    public bool CarriesPermission => Roles.Count > 0 || Scopes.Count > 0;

    public string GrantSummary()
    {
        var parts = new List<string>();
        if (Roles.Count > 0)
        {
            parts.Add($"roles: {string.Join(' ', Roles)}");
        }

        if (Scopes.Count > 0)
        {
            parts.Add($"scp: {string.Join(' ', Scopes)}");
        }

        return parts.Count == 0 ? "no roles, no scp" : string.Join("; ", parts);
    }
}

/// <summary>
/// Reads the payload of a JWT access token.
/// <para>
/// The signature is deliberately not verified, and no library is pulled in to do so. This tool is not
/// the audience of any of these tokens and makes no trust decision based on them: it reports what the
/// issuer put inside a token it just received over TLS from that issuer. Verification would answer a
/// question nobody here is asking.
/// </para>
/// <para>
/// Not every access token is a readable JWT, so this returns null rather than guessing when it cannot
/// read one, and the report says so instead of implying an empty grant.
/// </para>
/// </summary>
public static class TokenClaimsReader
{
    public static TokenClaims? Read(string? accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return null;
        }

        var segments = accessToken.Split('.');
        if (segments.Length < 2)
        {
            return null;
        }

        var payload = DecodeSegment(segments[1]);
        if (payload is null)
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;

            // v1 tokens spell it 'appidacr', v2 tokens 'azpacr'. Which one is present is itself worth
            // keeping: it says which token version the resource is being handed.
            var credentialClaim = ReadScalar(root, "appidacr") is not null ? "appidacr" : "azpacr";

            return new TokenClaims(
                Audience: ReadString(root, "aud"),
                AppId: ReadString(root, "appid") ?? ReadString(root, "azp"),
                SignedInAs: ReadString(root, "upn") ?? ReadString(root, "preferred_username"),
                Roles: ReadStringList(root, "roles"),
                Scopes: ReadStringList(root, "scp"),
                CredentialClass: ReadScalar(root, credentialClaim))
            {
                CredentialClassClaim = credentialClaim,
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static byte[]? DecodeSegment(string segment)
    {
        var normalised = segment.Replace('-', '+').Replace('_', '/');
        normalised = normalised.PadRight(normalised.Length + ((4 - (normalised.Length % 4)) % 4), '=');

        try
        {
            return Convert.FromBase64String(normalised);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>
    /// A claim whose value is written as text, taken as text whichever way it was written. Entra sends
    /// the authentication-class claims as strings, but they read as numbers, and a report that dropped
    /// one because a token spelled it <c>2</c> instead of <c>"2"</c> would be reporting an absence
    /// that is not there.
    /// </summary>
    private static string? ReadScalar(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value)
            ? value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number => value.GetRawText(),
                _ => null,
            }
            : null;

    /// <summary>Entra writes 'roles' as an array and 'scp' as a space separated string. Accept either.</summary>
    private static IReadOnlyList<string> ReadStringList(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            return [];
        }

        return value.ValueKind switch
        {
            JsonValueKind.Array => value.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString()!)
                .ToList(),

            JsonValueKind.String => value.GetString()!
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),

            _ => [],
        };
    }
}
