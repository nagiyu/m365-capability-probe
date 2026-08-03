namespace CapabilityProbe.Reporting;

/// <summary>
/// One line of the report: what was measured, and what came back.
/// <para>
/// There is no verdict here. A refusal is a value like any other, and whether a given value is good
/// news, bad news or the whole point depends on what the reader came to find out.
/// </para>
/// </summary>
public sealed record Observation(
    string Subject,
    string Observed,
    MeasurementStatus Status)
{
    /// <summary>Supporting values (URL called, headers sent, error code, elapsed ms, ...).</summary>
    public IReadOnlyDictionary<string, string?> Details { get; init; } =
        new Dictionary<string, string?>();

    public static Observation Measured(string subject, string observed) =>
        new(subject, observed, MeasurementStatus.Measured);

    public static Observation NotRun(string subject, string reason) =>
        new(subject, $"not run - {reason}", MeasurementStatus.NotRun);
}
