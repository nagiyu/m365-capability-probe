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

    /// <summary>Library-relative path of the file to read, e.g. <c>/Shared Documents/test.docx</c>.</summary>
    public string FilePath { get; set; } = string.Empty;

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
