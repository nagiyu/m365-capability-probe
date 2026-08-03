using System.Text.Json;
using System.Text.Json.Serialization;

namespace CapabilityProbe.Reporting;

/// <summary>
/// Writes the same report to <c>reports/</c> as JSON. The status is serialised by name, so
/// <c>NotRun</c> stays legible in the file and cannot be mistaken for a measurement of zero.
/// </summary>
public sealed class JsonReportWriter(string outputDirectory)
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public string Write(ProbeReport report)
    {
        Directory.CreateDirectory(outputDirectory);

        var fileName = $"{report.Command}-{report.StartedAtUtc:yyyyMMdd'T'HHmmss'Z'}.json";
        var path = Path.Combine(outputDirectory, fileName);

        var payload = new
        {
            command = report.Command,
            startedAtUtc = report.StartedAtUtc,
            finishedAtUtc = report.FinishedAtUtc,
            subject = report.Subject,
            tables = report.Tables.Select(t => new
            {
                title = t.Title,
                columns = t.Columns,
                rows = t.Rows,
            }),
            observations = report.Observations.Select(o => new
            {
                subject = o.Subject,
                observed = o.Observed,
                status = o.Status,
                details = o.Details,
            }),
            summary = new
            {
                measured = report.Count(MeasurementStatus.Measured),
                notRun = report.Count(MeasurementStatus.NotRun),
            },
        };

        File.WriteAllText(path, JsonSerializer.Serialize(payload, SerializerOptions));
        return path;
    }
}
