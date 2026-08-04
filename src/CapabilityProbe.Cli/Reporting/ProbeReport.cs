namespace CapabilityProbe.Reporting;

/// <summary>A grid of raw measurements. Writers render it without knowing what the columns mean.</summary>
public sealed record ProbeTable(string Title, IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<string?>> Rows);

/// <summary>
/// Everything one subcommand run produced. The console writer and the JSON writer consume this
/// same object, so the file on disk and the text on screen cannot drift apart.
/// </summary>
public sealed class ProbeReport
{
    public ProbeReport(string command)
    {
        Command = command;
        StartedAtUtc = DateTimeOffset.UtcNow;
    }

    public string Command { get; }

    public DateTimeOffset StartedAtUtc { get; }

    public DateTimeOffset? FinishedAtUtc { get; private set; }

    /// <summary>Context worth carrying into the JSON: site host, client ID, sign-in hint, ...</summary>
    public Dictionary<string, string?> Subject { get; } = [];

    public List<ProbeTable> Tables { get; } = [];

    public List<Observation> Observations { get; } = [];

    public void Add(Observation observation) => Observations.Add(observation);

    public void Add(ProbeTable table) => Tables.Add(table);

    public void Finish() => FinishedAtUtc = DateTimeOffset.UtcNow;

    public int Count(MeasurementStatus status) => Observations.Count(o => o.Status == status);

    /// <summary>
    /// Why this run could not measure what it set out to, if it could not. In practice there is one
    /// such case: the device code was printed and nobody completed the sign-in, so the delegated half
    /// of the report is empty for want of an identity rather than for want of an answer.
    /// </summary>
    public string? IncompleteReason { get; private set; }

    public void MarkIncomplete(string reason) => IncompleteReason ??= reason;

    /// <summary>
    /// Exit code for the process. It answers "could the probe do its job", not "did the tenant behave"
    /// and not "did every step run".
    /// <para>
    /// <see cref="MeasurementStatus.NotRun"/> rows deliberately do not affect it. A step that was never
    /// reached was made unreachable by the measurement above it - a file that answers 404 has no item
    /// ID to ask permissions for, and that 404 is the finding, not a shortfall. Colouring such a run
    /// red trains a reader to ignore red.
    /// </para>
    /// </summary>
    public int ExitCode => IncompleteReason is null ? 0 : 2;
}
