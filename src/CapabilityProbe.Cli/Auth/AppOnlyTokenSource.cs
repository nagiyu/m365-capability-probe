using System.Diagnostics;
using Azure.Core;
using Azure.Identity;
using CapabilityProbe.Configuration;

namespace CapabilityProbe.Auth;

/// <summary>
/// The app registration speaking as itself: client credentials, no user, no consent prompt.
/// What it can reach is exactly what an administrator granted as application permissions.
/// </summary>
public sealed class AppOnlyTokenSource : ITokenSource
{
    private readonly ProbeOptions _options;
    private readonly ClientSecretCredential _credential;

    public AppOnlyTokenSource(ProbeOptions options)
    {
        _options = options;
        _credential = new ClientSecretCredential(options.TenantId, options.ClientId, options.ClientSecret);
    }

    public ProbeMode Mode => ProbeMode.AppOnly;

    public async Task<TokenResult> GetTokenAsync(ProbeAudience audience, CancellationToken cancellationToken)
    {
        var scope = ScopeResolver.Resolve(audience, _options);
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var token = await _credential.GetTokenAsync(new TokenRequestContext([scope]), cancellationToken);
            stopwatch.Stop();
            return TokenResult.Success(Mode, audience, scope, token.Token, token.ExpiresOn, stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stopwatch.Stop();
            var (code, detail) = AuthErrorCode.Describe(ex);
            return TokenResult.Failure(Mode, audience, scope, code, detail, stopwatch.ElapsedMilliseconds);
        }
    }
}
