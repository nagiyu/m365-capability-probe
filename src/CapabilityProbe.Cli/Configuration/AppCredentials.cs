namespace CapabilityProbe.Configuration;

/// <summary>
/// One app registration's identity: which app, and the two ways it can prove it is that app.
/// <para>
/// This exists because the tool now points at two of them. The probe's own registration is a
/// measurement subject - thirteen findings are pinned to its exact set of grants, and several of them
/// were only separable because a permission was added, measured and taken away again. A tool that has
/// to work needs permissions that stay, and adding those to the subject would make the findings
/// unreproducible. So <c>inventory</c> gets its own registration and the probe's is left frozen.
/// </para>
/// <para>
/// The tenant is not part of this. Both registrations live in the same directory - a second tenant
/// would make it a multi-tenant app, which is a different thing and would change the premise of
/// finding 1 rather than reuse it.
/// </para>
/// </summary>
public sealed record AppCredentials(
    string TenantId,
    string ClientId,
    string ClientSecret,
    string CertificatePath,
    string CertificatePassword,
    string Label)
{
    /// <summary>True when a certificate was configured, whether or not it turns out to be loadable.</summary>
    public bool HasCertificate => !string.IsNullOrWhiteSpace(CertificatePath);

    /// <summary>True when this registration has no client ID and so cannot ask for anything.</summary>
    public bool IsEmpty => string.IsNullOrWhiteSpace(ClientId);
}
