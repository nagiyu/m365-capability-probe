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

    public int Count(Verdict verdict) => Observations.Count(o => o.Verdict == verdict);

    /// <summary>
    /// Exit code for the process. Non-zero only when an observation contradicted its claim or a step
    /// never ran - never merely because a call was refused, since refusals are the expected result here.
    /// </summary>
    public int ExitCode => Count(Verdict.Failed) > 0 ? 1 : Count(Verdict.NotRun) > 0 ? 2 : 0;
}
