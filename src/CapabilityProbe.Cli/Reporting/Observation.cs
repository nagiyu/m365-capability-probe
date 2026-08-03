namespace CapabilityProbe.Reporting;

/// <summary>
/// One line of the report: what was claimed, what was seen, and whether the two agree.
/// The claim is written before the run; the observation is whatever came back, including refusals.
/// </summary>
public sealed record Observation(
    string Claim,
    string Observed,
    Verdict Verdict)
{
    /// <summary>Free-form supporting values (URL called, error code, elapsed ms, ...).</summary>
    public IReadOnlyDictionary<string, string?> Details { get; init; } =
        new Dictionary<string, string?>();

    public static Observation NotRun(string claim, string reason) =>
        new(claim, $"not run - {reason}", Verdict.NotRun);
}
