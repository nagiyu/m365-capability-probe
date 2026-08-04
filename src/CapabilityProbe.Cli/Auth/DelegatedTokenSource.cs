using System.Diagnostics;
using Azure.Core;
using Azure.Identity;
using CapabilityProbe.Configuration;

namespace CapabilityProbe.Auth;

/// <summary>
/// The app speaking on behalf of a signed-in person, via device code. Reach is the intersection of
/// what the app was granted and what that person can already see, which is why the sign-in account matters.
/// <para>
/// Sign-in happens once, against Graph, and every later audience is requested silently
/// (<see cref="DeviceCodeCredentialOptions.DisableAutomaticAuthentication"/>). An audience the app has no
/// delegated grant for then comes back as a refused token request instead of parking the run on a second
/// device code prompt that nobody is waiting to complete.
/// </para>
/// </summary>
public sealed class DelegatedTokenSource : ITokenSource
{
    private readonly ProbeOptions _options;
    private readonly DeviceCodeCredential _credential;
    private readonly TextWriter _console;
    private readonly HashSet<string> _alreadyAcquired = new(StringComparer.OrdinalIgnoreCase);

    public DelegatedTokenSource(ProbeOptions options, TextWriter console)
    {
        _options = options;
        _console = console;

        _credential = new DeviceCodeCredential(new DeviceCodeCredentialOptions
        {
            TenantId = options.TenantId,
            ClientId = options.ClientId,
            DisableAutomaticAuthentication = true,
            DeviceCodeCallback = (info, _) =>
            {
                WriteDeviceCodePrompt(info);
                return Task.CompletedTask;
            },
        });
    }

    public ProbeMode Mode => ProbeMode.Delegated;

    /// <summary>True once a person has completed the device code flow in this run.</summary>
    public bool IsSignedIn { get; private set; }

    /// <summary>
    /// The account that actually completed the sign-in, which is not necessarily
    /// <see cref="ProbeOptions.DelegatedUserHint"/>. The hint is a setting; this is what happened.
    /// A report that records the hint is asserting something it did not measure.
    /// </summary>
    public string? SignedInAs { get; private set; }

    /// <summary>
    /// Runs the device code flow once, using Graph as the baseline resource.
    /// Returns the same shaped result as any other token request so a refused sign-in is reportable.
    /// </summary>
    public async Task<TokenResult> SignInAsync(CancellationToken cancellationToken)
    {
        var scope = ScopeResolver.Resolve(ProbeAudience.Graph, _options);
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var context = new TokenRequestContext([scope]);
            var record = await _credential.AuthenticateAsync(context, cancellationToken);
            var token = await _credential.GetTokenAsync(context, cancellationToken);
            stopwatch.Stop();

            IsSignedIn = true;
            SignedInAs = record.Username;
            _alreadyAcquired.Add(scope);
            _console.WriteLine($"Signed in as: {record.Username}");
            if (!string.Equals(record.Username, _options.DelegatedUserHint, StringComparison.OrdinalIgnoreCase))
            {
                _console.WriteLine(
                    $"NOTE: this differs from DelegatedUserHint ({_options.DelegatedUserHint}). " +
                    "The delegated column reflects whoever actually signed in.");
            }

            _console.WriteLine();
            return TokenResult.Success(Mode, ProbeAudience.Graph, scope, token.Token, token.ExpiresOn, stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stopwatch.Stop();
            var (code, detail) = AuthErrorCode.Describe(ex);
            return TokenResult.Failure(Mode, ProbeAudience.Graph, scope, code, detail, stopwatch.ElapsedMilliseconds);
        }
    }

    public async Task<TokenResult> GetTokenAsync(ProbeAudience audience, CancellationToken cancellationToken)
    {
        var scope = ScopeResolver.Resolve(audience, _options);

        if (!IsSignedIn)
        {
            var signIn = await SignInAsync(cancellationToken);
            if (!signIn.Succeeded)
            {
                return signIn with { Audience = audience, Scope = scope };
            }
        }

        var servedFromCache = _alreadyAcquired.Contains(scope);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            var token = await _credential.GetTokenAsync(new TokenRequestContext([scope]), cancellationToken);
            stopwatch.Stop();
            _alreadyAcquired.Add(scope);
            return TokenResult.Success(
                Mode, audience, scope, token.Token, token.ExpiresOn, stopwatch.ElapsedMilliseconds, servedFromCache);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stopwatch.Stop();
            var (code, detail) = AuthErrorCode.Describe(ex);
            return TokenResult.Failure(Mode, audience, scope, code, detail, stopwatch.ElapsedMilliseconds);
        }
    }

    private void WriteDeviceCodePrompt(DeviceCodeInfo info)
    {
        _console.WriteLine();
        _console.WriteLine("--- device code sign-in ---------------------------------------");
        _console.WriteLine($"  Sign in as     : {_options.DelegatedUserHint}");
        _console.WriteLine("                   Signing in with an administrator account instead");
        _console.WriteLine("                   invalidates the comparison this tool is making.");
        _console.WriteLine($"  Open           : {info.VerificationUri}");
        _console.WriteLine($"  Enter the code : {info.UserCode}");
        _console.WriteLine($"  Expires        : {info.ExpiresOn:u}");
        _console.WriteLine("---------------------------------------------------------------");
        _console.WriteLine();
        _console.Flush();
    }
}
