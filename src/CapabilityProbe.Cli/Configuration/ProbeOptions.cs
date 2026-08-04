namespace CapabilityProbe.Configuration;

/// <summary>
/// The settings the probe needs. The six required ones are not optional-by-convenience: each is
/// either supplied by the operator or the run is refused up front. The certificate is the exception -
/// it adds an identity when present, and its absence is reported rather than assumed.
/// </summary>
public sealed class ProbeOptions
{
    /// <summary>Directory (tenant) ID of the Entra tenant the app registration lives in.</summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>Application (client) ID of the app registration under test.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Client secret of the app registration. Keep this in user-secrets.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Path to a PKCS#12 (<c>.pfx</c>) file holding a certificate and its private key, for the
    /// app-only leg that authenticates with a certificate instead of the secret.
    /// <para>
    /// Optional. Left empty, that leg is reported as not run rather than quietly skipped - an absent
    /// measurement and a measurement of nothing are different things.
    /// </para>
    /// <para>
    /// A file path rather than an inline blob because the same value has to work from a developer's
    /// machine and from CI, and a path works in both: CI writes its secret to a temporary file first.
    /// One input, one code path.
    /// </para>
    /// </summary>
    public string ClientCertificatePath { get; set; } = string.Empty;

    /// <summary>Password protecting the <c>.pfx</c>, if it has one. Keep it in user-secrets.</summary>
    public string ClientCertificatePassword { get; set; } = string.Empty;

    /// <summary>True when a certificate was configured, whether or not it turns out to be loadable.</summary>
    public bool HasCertificate => !string.IsNullOrWhiteSpace(ClientCertificatePath);

    /// <summary>Site collection URL in the form <c>https://&lt;host&gt;/sites/&lt;name&gt;</c>.</summary>
    public string SiteUrl { get; set; } = string.Empty;

    /// <summary>
    /// One or more paths to read, separated by <c>|</c>.
    /// <para>
    /// Each path is relative to the root of the site's default document library and does not include
    /// the library's own name - a file sitting directly in that library is just <c>/test.docx</c>.
    /// This is what the probe appends to <c>/drive/root:</c>, and prefixing it with the library name
    /// looks for a folder of that name inside the library instead.
    /// </para>
    /// <para>
    /// A delimited string rather than an array because this value has to survive five configuration
    /// layers and a workflow dispatch input, and an array is awkward in four of the six.
    /// <c>|</c> is one of the characters SharePoint refuses in a file or folder name, so it can never
    /// occur inside a path and never needs escaping.
    /// </para>
    /// </summary>
    public string FilePaths { get; set; } = string.Empty;

    /// <summary>The paths, split and trimmed. Empty when none are configured.</summary>
    public IReadOnlyList<string> Files =>
        FilePaths.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Sign-in name the operator should use for the delegated (device code) leg.</summary>
    public string DelegatedUserHint { get; set; } = string.Empty;

    /// <summary>
    /// Which identities a run should establish: <c>all</c>, or <c>app-only</c> to leave the delegated
    /// leg alone.
    /// <para>
    /// The delegated leg needs a person at a browser, and there are places a run happens where there
    /// is no person - and times when the sign-in is refused for reasons that have nothing to do with
    /// what the app can reach. Narrowing the run is better than a report full of rows that failed for
    /// a reason the report is not about.
    /// </para>
    /// <para>
    /// It narrows the run; it does not hide it. The delegated rows still appear, as not run, saying
    /// that this is what the run was asked for. A leg that vanishes from a report reads as a leg that
    /// was never worth measuring.
    /// </para>
    /// </summary>
    public string Identities { get; set; } = string.Empty;

    /// <summary>The two values <see cref="Identities"/> accepts, for validation and for messages.</summary>
    public const string AllIdentities = "all";
    public const string AppOnlyIdentities = "app-only";

    /// <summary>True unless the run was explicitly narrowed to the application's own identities.</summary>
    public bool RunDelegated =>
        !string.Equals(Identities.Trim(), AppOnlyIdentities, StringComparison.OrdinalIgnoreCase);

    /// <summary>Host name taken from <see cref="SiteUrl"/>. Used to build the SharePoint scope.</summary>
    public string SiteHost =>
        Uri.TryCreate(SiteUrl, UriKind.Absolute, out var uri) ? uri.Host : string.Empty;

    /// <summary>Server-relative path taken from <see cref="SiteUrl"/>, e.g. <c>/sites/name</c>.</summary>
    public string SiteServerRelativePath =>
        Uri.TryCreate(SiteUrl, UriKind.Absolute, out var uri)
            ? uri.AbsolutePath.TrimEnd('/')
            : string.Empty;
}
