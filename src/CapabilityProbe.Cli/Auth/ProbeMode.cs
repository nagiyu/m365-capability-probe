namespace CapabilityProbe.Auth;

/// <summary>Which identity the call is made as. The whole point of the tool is the contrast between them.</summary>
public enum ProbeMode
{
    /// <summary>The app itself, via client credentials. No user in the picture.</summary>
    AppOnly,

    /// <summary>A signed-in person, via device code. The app acts on their behalf and inherits their reach.</summary>
    Delegated,
}

public static class ProbeModeNames
{
    public static string Display(this ProbeMode mode) => mode switch
    {
        ProbeMode.AppOnly => "app-only",
        ProbeMode.Delegated => "delegated",
        _ => mode.ToString(),
    };
}
