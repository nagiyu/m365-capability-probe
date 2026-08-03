using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Probes;
using CapabilityProbe.Reporting;

namespace CapabilityProbe;

/// <summary>Subcommand dispatch. Everything with an opinion in it lives under the folders below.</summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var command = args.Length > 0 && !args[0].StartsWith('-') ? args[0].ToLowerInvariant() : null;
        var configArgs = args.Length > 0 ? args[1..] : [];

        if (command is null or "help" || command is not (ProbeOptionsLoader.AuthCommand or ProbeOptionsLoader.AccessCommand))
        {
            WriteUsage(Console.Out);
            return command is null or "help" ? 0 : 64;
        }

        var configuration = ProbeOptionsLoader.Load(configArgs);
        if (configuration.Problems.Count > 0)
        {
            ProbeOptionsLoader.WriteProblems(Console.Out, configuration.Problems);
            if (!configuration.IsUsable(command))
            {
                return 78;
            }

            Console.Out.WriteLine($"None of the above blocks '{command}'. Continuing.");
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancellation.Cancel();
        };

        try
        {
            var report = command switch
            {
                ProbeOptionsLoader.AuthCommand =>
                    await new AuthProbe(configuration.Options, Console.Out).RunAsync(cancellation.Token),

                ProbeOptionsLoader.AccessCommand =>
                    await RunAccessAsync(configuration.Options, cancellation.Token),

                _ => throw new InvalidOperationException($"unreachable subcommand '{command}'"),
            };

            new ConsoleReportWriter(Console.Out).Write(report);

            var reportPath = new JsonReportWriter(Path.Combine(Directory.GetCurrentDirectory(), "reports")).Write(report);
            Console.Out.WriteLine($"JSON report: {reportPath}");

            return report.ExitCode;
        }
        catch (OperationCanceledException)
        {
            Console.Out.WriteLine("Cancelled. No report was written; the run is incomplete rather than negative.");
            return 130;
        }
    }

    private static async Task<ProbeReport> RunAccessAsync(ProbeOptions options, CancellationToken cancellationToken)
    {
        using var http = new ProbeHttpClient();
        return await new AccessProbe(options, http, Console.Out).RunAsync(cancellationToken);
    }

    private static void WriteUsage(TextWriter writer)
    {
        writer.WriteLine("capability-probe - observe what one Entra app registration can reach in Microsoft 365.");
        writer.WriteLine();
        writer.WriteLine("Usage:");
        writer.WriteLine("  auth     request a token for Graph, SharePoint and Azure RMS, as the app and as a person");
        writer.WriteLine("  access   read one file's permission list twice in a row, as the app and as a person");
        writer.WriteLine();
        writer.WriteLine("Settings (later layers win): appsettings.json, appsettings.local.json, user-secrets,");
        writer.WriteLine("PROBE_* environment variables, --Key=Value arguments.");
        writer.WriteLine();
        writer.WriteLine("  TenantId ClientId ClientSecret SiteUrl FilePath DelegatedUserHint");
        writer.WriteLine();
        writer.WriteLine("Example:");
        writer.WriteLine("  dotnet run --project src/CapabilityProbe.Cli -- auth");
        writer.WriteLine("  dotnet run --project src/CapabilityProbe.Cli -- access --FilePath=\"/Shared Documents/test.docx\"");
        writer.WriteLine();
        writer.WriteLine("Exit codes: 0 every claim held, 1 a claim was contradicted, 2 something never ran,");
        writer.WriteLine("            64 bad usage, 78 incomplete configuration, 130 cancelled.");
    }
}
