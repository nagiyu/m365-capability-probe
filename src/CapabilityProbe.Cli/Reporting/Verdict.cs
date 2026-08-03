namespace CapabilityProbe.Reporting;

/// <summary>
/// Whether the observation supports the claim it was made against.
/// <para>
/// <see cref="NotRun"/> exists so that "we never got far enough to look" has a value of its own.
/// A blank cell reads as a pass; a cell that says NotRun cannot.
/// </para>
/// <para>
/// Note that <see cref="Ok"/> does not mean "the call succeeded". Several claims here are claims of
/// refusal - the app is expected to be turned away - and for those, a 403 is what Ok looks like.
/// </para>
/// </summary>
public enum Verdict
{
    /// <summary>The observation matches the claim.</summary>
    Ok,

    /// <summary>The observation contradicts the claim. This is a finding, not necessarily a defect.</summary>
    Failed,

    /// <summary>The step never executed, so nothing is known either way.</summary>
    NotRun,
}
