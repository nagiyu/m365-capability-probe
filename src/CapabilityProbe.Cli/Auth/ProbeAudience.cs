namespace CapabilityProbe.Auth;

/// <summary>The resource a token is requested for. One token request per audience; no token is reused across them.</summary>
public enum ProbeAudience
{
    /// <summary>Microsoft Graph.</summary>
    Graph,

    /// <summary>The SharePoint tenant itself, addressed by the host name of the configured site.</summary>
    SharePoint,

    /// <summary>Azure Rights Management. Deliberately unconsented here; its failure code is the observation.</summary>
    AzureRms,
}

public static class ProbeAudienceNames
{
    public static string Display(this ProbeAudience audience) => audience switch
    {
        ProbeAudience.Graph => "Graph",
        ProbeAudience.SharePoint => "SharePoint",
        ProbeAudience.AzureRms => "Azure RMS",
        _ => audience.ToString(),
    };
}
