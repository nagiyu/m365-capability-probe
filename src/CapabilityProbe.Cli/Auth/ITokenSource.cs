namespace CapabilityProbe.Auth;

/// <summary>
/// What a token request produced. A failure is a value here, not an exception:
/// "this app cannot get a token for that resource" is a result the report wants to print.
/// </summary>
public sealed record TokenResult(
    ProbeMode Mode,
    ProbeAudience Audience,
    string Scope,
    bool Succeeded,
    string? ErrorCode,
    string? ErrorDetail,
    DateTimeOffset? ExpiresOn,
    long ElapsedMs)
{
    public string? AccessToken { get; init; }

    /// <summary>What the issued token carries. Null when there is no token, or none that could be read.</summary>
    public TokenClaims? Claims { get; init; }

    /// <summary>
    /// True when the credential answered from its in-memory cache instead of asking the issuer.
    /// Without this a cached hit reads as a network request that took no time at all.
    /// </summary>
    public bool ServedFromCache { get; init; }

    /// <summary>
    /// True when the app can actually use this token. A token with neither roles nor scopes is issued,
    /// valid, and refused by every call made with it. An unreadable token falls back to its issuance,
    /// and the report says the claims could not be read rather than implying an empty grant.
    /// </summary>
    public bool CarriesPermission => Succeeded && (Claims is null || Claims.CarriesPermission);

    public static TokenResult Success(
        ProbeMode mode,
        ProbeAudience audience,
        string scope,
        string token,
        DateTimeOffset expiresOn,
        long elapsedMs,
        bool servedFromCache = false) =>
        new(mode, audience, scope, true, null, null, expiresOn, elapsedMs)
        {
            AccessToken = token,
            Claims = TokenClaimsReader.Read(token),
            ServedFromCache = servedFromCache,
        };

    public static TokenResult Failure(
        ProbeMode mode, ProbeAudience audience, string scope, string errorCode, string errorDetail, long elapsedMs) =>
        new(mode, audience, scope, false, errorCode, errorDetail, null, elapsedMs);
}

/// <summary>
/// One acquisition entry point that takes the audience as an argument, so a single credential set
/// serves all three resources and the report can attribute every token to a (mode, audience) pair.
/// </summary>
public interface ITokenSource
{
    ProbeMode Mode { get; }

    Task<TokenResult> GetTokenAsync(ProbeAudience audience, CancellationToken cancellationToken);
}
