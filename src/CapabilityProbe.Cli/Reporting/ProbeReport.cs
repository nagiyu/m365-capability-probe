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
    /// Exit code for the process. It answers "did the probe finish measuring", not "did the tenant
    /// behave". A refusal, an empty list and a token carrying nothing are all successful measurements
    /// and all exit zero; only a step that never ran leaves the run incomplete.
    /// </summary>
    public int ExitCode => Count(MeasurementStatus.NotRun) > 0 ? 2 : 0;
}
