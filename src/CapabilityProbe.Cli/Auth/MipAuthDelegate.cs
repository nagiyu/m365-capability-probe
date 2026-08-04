using Azure.Core;
using Microsoft.InformationProtection;

namespace CapabilityProbe.Auth;

/// <summary>
/// Hands the Information Protection SDK a token when it asks for one.
/// <para>
/// The SDK does not take a credential; it takes this callback and calls it with the authority and
/// resource it decided on. That is the first place the tool loses sight of its own request - it never
/// chooses the URL - and it is recorded here for the report rather than left implicit, because every
/// other subcommand can show which endpoint it called and this one cannot.
/// </para>
/// <para>
/// The callback is synchronous, so the asynchronous credential is blocked on. Nothing else is running
/// on this thread: the SDK calls out from its own, and the probe is doing one thing at a time.
/// </para>
/// </summary>
public sealed class MipAuthDelegate(TokenCredential credential, TextWriter console) : IAuthDelegate
{
    private readonly List<string> _requests = [];

    /// <summary>
    /// What the SDK asked for, in the order it asked. The tool did not choose any of these, which is
    /// exactly why they are worth writing down.
    /// </summary>
    public IReadOnlyList<string> Requests => _requests;

    public string AcquireToken(Identity identity, string authority, string resource, string claims)
    {
        // MIP passes a resource URI; Entra wants a scope. The .default suffix asks for whatever the
        // app was granted for that resource - the same shape every other subcommand here uses.
        var scope = resource.TrimEnd('/') + "/.default";
        var record = $"authority={authority} resource={resource} identity={identity?.Email ?? "(none)"}";

        _requests.Add(record);
        console.WriteLine($"  SDK asked for a token: {record}");

        try
        {
            var token = credential.GetToken(new TokenRequestContext([scope]), CancellationToken.None);
            return token.Token;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Returning empty rather than throwing: the SDK turns a missing token into its own error,
            // and that error is the thing being measured. An exception thrown from inside a native
            // callback is a worse way to find out.
            var (code, detail) = AuthErrorCode.Describe(ex);
            _requests.Add($"  -> refused: {code} {detail}");
            console.WriteLine($"  the token was refused: {code}");
            return string.Empty;
        }
    }
}

/// <summary>
/// Answers the SDK's consent prompt without a person present.
/// <para>
/// The prompt exists for interactive applications being sent to an endpoint they have not used before.
/// This probe has no one to ask, and refusing would end every run before it measured anything, so it
/// accepts - and the report says that it did, because "the tool agreed to something on your behalf" is
/// not a detail to leave out of a measurement.
/// </para>
/// </summary>
public sealed class MipConsentDelegate(TextWriter console) : IConsentDelegate
{
    private readonly List<string> _consented = [];

    public IReadOnlyList<string> Consented => _consented;

    public Consent GetUserConsent(string url)
    {
        _consented.Add(url);
        console.WriteLine($"  the SDK asked for consent to contact {url} - accepted without asking anyone");
        return Consent.Accept;
    }
}
