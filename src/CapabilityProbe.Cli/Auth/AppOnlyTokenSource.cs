using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using CapabilityProbe.Configuration;

namespace CapabilityProbe.Auth;

/// <summary>
/// The app registration speaking as itself: client credentials, no user, no consent prompt.
/// What it can reach is exactly what an administrator granted as application permissions.
/// <para>
/// There are two ways for the app to prove it is itself - a shared secret, or possession of a private
/// key whose certificate the tenant holds. Both are built here because the question is whether anything
/// downstream treats them differently, and the only way to answer that is to hold both at once against
/// the same tenant, the same app registration and the same grants.
/// </para>
/// <para>
/// A certificate that cannot be loaded is not an exception. It is the same kind of fact as a refused
/// token: something about this setup meant no token could be asked for, and the report says which.
/// </para>
/// </summary>
public sealed class AppOnlyTokenSource : ITokenSource
{
    private readonly ProbeOptions _options;
    private readonly TokenCredential? _credential;
    private readonly string _unavailableCode;
    private readonly string _unavailableDetail;
    private readonly HashSet<string> _alreadyAcquired = new(StringComparer.OrdinalIgnoreCase);

    private AppOnlyTokenSource(
        ProbeOptions options,
        ProbeMode mode,
        TokenCredential? credential,
        string identity,
        string unavailableCode = "",
        string unavailableDetail = "")
    {
        _options = options;
        _credential = credential;
        _unavailableCode = unavailableCode;
        _unavailableDetail = unavailableDetail;
        Mode = mode;
        Identity = identity;
    }

    public ProbeMode Mode { get; }

    /// <summary>
    /// How this source proves the app's identity, in words a reader can check against the tenant.
    /// For the certificate leg that is the thumbprint, because the thumbprint is what the app
    /// registration lists - it is the one value that says whether the key in hand is the key Entra
    /// was told about.
    /// </summary>
    public string Identity { get; }

    /// <summary>True when no token can be requested at all, and <see cref="Identity"/> says why.</summary>
    public bool IsUnavailable => _credential is null;

    public static AppOnlyTokenSource WithSecret(ProbeOptions options) =>
        new(options,
            ProbeMode.AppOnly,
            new ClientSecretCredential(options.TenantId, options.ClientId, options.ClientSecret),
            $"client secret, {options.ClientSecret.Length} characters");

    /// <summary>
    /// The same app registration, authenticating with a private key instead. Every reason this cannot
    /// be done comes back as a source that reports itself unavailable, so the leg appears in the report
    /// with a reason rather than disappearing from it.
    /// </summary>
    public static AppOnlyTokenSource WithCertificate(ProbeOptions options)
    {
        if (!options.HasCertificate)
        {
            return Unavailable(
                options,
                "NoCertificateConfigured",
                "ClientCertificatePath is empty, so no certificate leg was attempted",
                "(no certificate configured)");
        }

        var path = options.ClientCertificatePath;
        if (!File.Exists(path))
        {
            return Unavailable(
                options,
                "CertificateFileNotFound",
                $"no file at '{path}'",
                $"(no file at {path})");
        }

        X509Certificate2 certificate;
        try
        {
            certificate = Load(path, options.ClientCertificatePassword);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unavailable(
                options,
                "CertificateNotLoadable",
                $"{ex.GetType().Name}: {ex.Message}",
                "(certificate could not be loaded)");
        }

        // Entra is sent a signature, not the certificate, so a file carrying only the public half
        // authenticates nothing. Caught here it names the problem; left alone it surfaces at token
        // time as a failure that reads like a rejected app.
        if (!certificate.HasPrivateKey)
        {
            var thumbprint = certificate.Thumbprint;
            certificate.Dispose();
            return Unavailable(
                options,
                "CertificateHasNoPrivateKey",
                $"the file at '{path}' holds a certificate ({thumbprint}) but not its private key",
                "(certificate without its private key)");
        }

        return new AppOnlyTokenSource(
            options,
            ProbeMode.AppOnlyCertificate,
            new ClientCertificateCredential(options.TenantId, options.ClientId, certificate),
            $"certificate {certificate.Thumbprint}, subject {certificate.Subject}, " +
            $"not after {certificate.NotAfter:yyyy-MM-dd}");
    }

    /// <summary>
    /// Reads the PKCS#12 file, preferring a key that never touches the key store. The default on
    /// Windows persists the private key into the user's profile, which outlives the run; a probe
    /// should not leave key material behind on a machine it was pointed at. Not every platform can
    /// do it, and where it cannot the ordinary path is taken rather than the run refused.
    /// </summary>
    private static X509Certificate2 Load(string path, string password)
    {
        // Null and empty are different passwords to PKCS#12, and a file protected by neither is
        // usually the null one.
        var secret = string.IsNullOrEmpty(password) ? null : password;

        try
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, secret, X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (PlatformNotSupportedException)
        {
            return X509CertificateLoader.LoadPkcs12FromFile(path, secret);
        }
    }

    private static AppOnlyTokenSource Unavailable(
        ProbeOptions options, string code, string detail, string identity) =>
        new(options, ProbeMode.AppOnlyCertificate, null, identity, code, detail);

    public async Task<TokenResult> GetTokenAsync(ProbeAudience audience, CancellationToken cancellationToken)
    {
        var scope = ScopeResolver.Resolve(audience, _options);

        if (_credential is null)
        {
            return TokenResult.NotRequested(Mode, audience, scope, _unavailableCode, _unavailableDetail);
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
}
