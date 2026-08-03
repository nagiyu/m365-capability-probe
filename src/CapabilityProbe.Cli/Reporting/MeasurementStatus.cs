namespace CapabilityProbe.Reporting;

/// <summary>
/// Whether a measurement happened. Deliberately not whether its result was good.
/// <para>
/// This report used to carry a verdict - each row asserted what the tenant ought to produce and then
/// graded the tenant against it. Every one of those assertions turned out to be the author's
/// prediction rather than a fact, and each was wrong at least once. A tool that grades a tenant
/// against a guess reports on the guess. So the expectations are gone: what the numbers mean belongs
/// to whoever is reading them, argued in prose that can carry a date and a reason, not frozen into a
/// switch expression that quietly becomes a lie.
/// </para>
/// <para>
/// What survives is this, because it is a fact about the run rather than a judgement about the
/// tenant: either a step executed and produced a value, or it never executed and nothing is known.
/// That distinction has to be typed. A blank cell reads as a measurement of zero; <see cref="NotRun"/>
/// cannot be read that way.
/// </para>
/// </summary>
public enum MeasurementStatus
{
    /// <summary>The step ran and the value next to it is what came back.</summary>
    Measured,

    /// <summary>The step never ran, so there is no value - not a zero, not an empty, nothing.</summary>
    NotRun,
}
