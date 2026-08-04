namespace CapabilityProbe.Configuration;

/// <summary>
/// The six settings the probe needs. Nothing here is optional-by-convenience:
/// every value is either supplied by the operator or the run is refused up front.
/// </summary>
public sealed class ProbeOptions
{
    /// <summary>Directory (tenant) ID of the Entra tenant the app registration lives in.</summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>Application (client) ID of the app registration under test.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Client secret of the app registration. Keep this in user-secrets.</summary>
    public string ClientSecret { get; set; } = string.Empty;

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

    /// <summary>Host name taken from <see cref="SiteUrl"/>. Used to build the SharePoint scope.</summary>
    public string SiteHost =>
        Uri.TryCreate(SiteUrl, UriKind.Absolute, out var uri) ? uri.Host : string.Empty;

    /// <summary>Server-relative path taken from <see cref="SiteUrl"/>, e.g. <c>/sites/name</c>.</summary>
    public string SiteServerRelativePath =>
        Uri.TryCreate(SiteUrl, UriKind.Absolute, out var uri)
            ? uri.AbsolutePath.TrimEnd('/')
            : string.Empty;
}
