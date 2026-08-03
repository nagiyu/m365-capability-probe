using CapabilityProbe.Configuration;

namespace CapabilityProbe.Auth;

/// <summary>
/// Turns an audience into the scope string that is actually sent to the token endpoint.
/// The SharePoint scope is derived from the configured site's host name rather than hard-coded,
/// so the tool carries no built-in list of tenants.
/// </summary>
public static class ScopeResolver
{
    public const string GraphScope = "https://graph.microsoft.com/.default";
    public const string AzureRmsScope = "https://aadrm.com/.default";

    public static string Resolve(ProbeAudience audience, ProbeOptions options) => audience switch
    {
        ProbeAudience.Graph => GraphScope,
        ProbeAudience.SharePoint => $"https://{options.SiteHost}/.default",
        ProbeAudience.AzureRms => AzureRmsScope,
        _ => throw new ArgumentOutOfRangeException(nameof(audience), audience, "unknown audience"),
    };
}
