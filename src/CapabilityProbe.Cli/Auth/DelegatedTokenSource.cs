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

    /// <summary>
    /// False when the run was narrowed to the application's own identities. Nothing is requested and
    /// no code is printed; the rows still appear, saying that is what was asked for.
    /// </summary>
    public bool Enabled => _options.RunDelegated;

    /// <summary>True once a person has completed the device code flow in this run.</summary>
    public bool IsSignedIn { get; private set; }

    /// <summary>
    /// Why this run could not measure what it set out to, or null.
    /// <para>
    /// A sign-in that was never attempted is not a shortfall - it is the run doing what it was told,
    /// and it must not colour the exit code. Only a code that was printed and left uncompleted does.
    /// </para>
    /// </summary>
    public string? IncompleteReason =>
        Enabled && !IsSignedIn
            ? "the device code was printed but the sign-in was never completed, so the delegated rows " +
              "are empty for want of an identity rather than for want of an answer"
            : null;

    /// <summary>What the report should say about who signed in, including when nobody was asked to.</summary>
    public string SignedInSummary => (Enabled, SignedInAs) switch
    {
        (false, _) => $"(nobody - this run was configured for {ProbeOptions.AppOnlyIdentities} identities)",
        (true, null) => "(nobody - sign-in did not complete)",
        (true, var account) => account,
    };

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

        if (!Enabled)
        {
            return TokenResult.NotRequested(
                Mode,
                ProbeAudience.Graph,
                scope,
                "NotAttempted",
                $"Identities is set to '{ProbeOptions.AppOnlyIdentities}', so no device code was printed " +
                "and nothing was asked of the identity provider on a person's behalf");
        }

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
