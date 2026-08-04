namespace CapabilityProbe.Auth;

/// <summary>Which identity the call is made as. The whole point of the tool is the contrast between them.</summary>
public enum ProbeMode
{
    /// <summary>The app itself, via client credentials and a shared secret. No user in the picture.</summary>
    AppOnly,

    /// <summary>
    /// The app itself again, but proving who it is with a certificate instead of a secret.
    /// <para>
    /// A separate identity here rather than a configuration detail of the one above, because the whole
    /// question is whether a resource treats the two differently. The app registration, the tenant and
    /// the granted roles are identical; only how the app authenticates to Entra changes. If a resource
    /// answers these two differently, that difference is the finding, and it is only visible if both
    /// appear in the same report.
    /// </para>
    /// </summary>
    AppOnlyCertificate,

    /// <summary>A signed-in person, via device code. The app acts on their behalf and inherits their reach.</summary>
    Delegated,
}

public static class ProbeModeNames
{
    public static string Display(this ProbeMode mode) => mode switch
    {
        ProbeMode.AppOnly => "app-only (secret)",
        ProbeMode.AppOnlyCertificate => "app-only (cert)",
        ProbeMode.Delegated => "delegated",
        _ => mode.ToString(),
    };

    /// <summary>
    /// The same three, named in as few characters as still tells them apart. Used where several modes
    /// share one line: a contrast that says the same thing in half the width survives a terminal that
    /// would otherwise clip away the end of it, which is usually where the finding is.
    /// </summary>
    public static string ShortName(this ProbeMode mode) => mode switch
    {
        ProbeMode.AppOnly => "secret",
        ProbeMode.AppOnlyCertificate => "cert",
        ProbeMode.Delegated => "delegated",
        _ => mode.ToString(),
    };
}
