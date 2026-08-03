using System.Text;

namespace CapabilityProbe.Reporting;

/// <summary>Renders a <see cref="ProbeReport"/> as plain-text tables. Same content as the JSON file.</summary>
public sealed class ConsoleReportWriter(TextWriter writer)
{
    private const int MaxCellWidth = 78;

    public void Write(ProbeReport report)
    {
        writer.WriteLine();
        writer.WriteLine($"=== {report.Command} =========================================================");
        writer.WriteLine($"started  {report.StartedAtUtc:u}");
        foreach (var (key, value) in report.Subject)
        {
            writer.WriteLine($"{key,-9}{value}");
        }

        foreach (var table in report.Tables)
        {
            writer.WriteLine();
            writer.WriteLine(table.Title);
            WriteGrid(table.Columns, table.Rows);
        }

        writer.WriteLine();
        writer.WriteLine("Claims");
        WriteGrid(
            ["claim", "observed", "verdict"],
            report.Observations.Select(o => (IReadOnlyList<string?>)new[] { o.Claim, o.Observed, o.Verdict.ToString() }).ToList());

        writer.WriteLine();
        writer.WriteLine(
            $"{report.Count(Verdict.Ok)} Ok / {report.Count(Verdict.Failed)} Failed / {report.Count(Verdict.NotRun)} NotRun");

        if (report.Count(Verdict.Failed) > 0)
        {
            writer.WriteLine("Failed means the observation contradicted the claim - read the row, then decide");
            writer.WriteLine("whether the claim or the tenant is what needs revisiting.");
        }

        writer.WriteLine();
    }

    private void WriteGrid(IReadOnlyList<string> columns, IReadOnlyList<IReadOnlyList<string?>> rows)
    {
        var widths = columns
            .Select((c, i) => Math.Min(
                MaxCellWidth,
                Math.Max(c.Length, rows.Count == 0 ? 0 : rows.Max(r => Cell(r, i).Length))))
            .ToArray();

        writer.WriteLine(Separator(widths));
        writer.WriteLine(Row(columns.Select((c, i) => Clip(c, widths[i])).ToArray(), widths));
        writer.WriteLine(Separator(widths));

        foreach (var row in rows)
        {
            writer.WriteLine(Row(widths.Select((w, i) => Clip(Cell(row, i), w)).ToArray(), widths));
        }

        writer.WriteLine(Separator(widths));
    }

    private static string Cell(IReadOnlyList<string?> row, int index) =>
        index < row.Count ? row[index]?.Replace('\n', ' ').Replace('\r', ' ') ?? string.Empty : string.Empty;

    private static string Clip(string value, int width) =>
        value.Length <= width ? value : value[..Math.Max(0, width - 3)] + "...";

    private static string Row(IReadOnlyList<string> cells, IReadOnlyList<int> widths)
    {
        var builder = new StringBuilder("|");
        for (var i = 0; i < widths.Count; i++)
        {
            builder.Append(' ').Append(cells[i].PadRight(widths[i])).Append(" |");
        }

        return builder.ToString();
    }

    private static string Separator(IReadOnlyList<int> widths) =>
        "+" + string.Join("+", widths.Select(w => new string('-', w + 2))) + "+";
}
