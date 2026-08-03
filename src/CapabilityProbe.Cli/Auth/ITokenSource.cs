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

    public static TokenResult Success(
        ProbeMode mode, ProbeAudience audience, string scope, string token, DateTimeOffset expiresOn, long elapsedMs) =>
        new(mode, audience, scope, true, null, null, expiresOn, elapsedMs) { AccessToken = token };

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
