using System.Text;
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
        UseUtf8Console();

        var command = args.Length > 0 && !args[0].StartsWith('-') ? args[0].ToLowerInvariant() : null;
        var configArgs = args.Length > 0 ? args[1..] : [];

        if (command is null or "help" || !ProbeOptionsLoader.AllCommands.Contains(command))
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
                Console.Out.WriteLine($"'{command}' cannot run without the above. Nothing was probed.");
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

                ProbeOptionsLoader.SharePointCommand =>
                    await RunSharePointAsync(configuration.Options, cancellation.Token),

                ProbeOptionsLoader.AclCommand =>
                    await RunAclAsync(configuration.Options, cancellation.Token),

                ProbeOptionsLoader.MipCommand =>
                    await new MipProbe(Console.Out).RunAsync(cancellation.Token),

                ProbeOptionsLoader.ConsumeCommand =>
                    await RunConsumeAsync(configuration.Options, cancellation.Token),

                ProbeOptionsLoader.InventoryCommand =>
                    await RunInventoryAsync(configuration.Options, cancellation.Token),

                ProbeOptionsLoader.PromotionCommand =>
                    await RunPromotionAsync(configuration.Options, cancellation.Token),

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

    private static async Task<ProbeReport> RunSharePointAsync(ProbeOptions options, CancellationToken cancellationToken)
    {
        using var http = new ProbeHttpClient();
        return await new SharePointProbe(options, http, Console.Out).RunAsync(cancellationToken);
    }

    private static async Task<ProbeReport> RunAclAsync(ProbeOptions options, CancellationToken cancellationToken)
    {
        using var http = new ProbeHttpClient();
        return await new AclProbe(options, http, Console.Out).RunAsync(cancellationToken);
    }

    private static async Task<ProbeReport> RunConsumeAsync(ProbeOptions options, CancellationToken cancellationToken)
    {
        using var http = new ProbeHttpClient();
        return await new ConsumeProbe(options, http, Console.Out).RunAsync(cancellationToken);
    }

    private static async Task<ProbeReport> RunInventoryAsync(ProbeOptions options, CancellationToken cancellationToken)
    {
        using var http = new ProbeHttpClient();
        return await new InventoryProbe(options, http, Console.Out).RunAsync(cancellationToken);
    }

    private static async Task<ProbeReport> RunPromotionAsync(ProbeOptions options, CancellationToken cancellationToken)
    {
        using var http = new ProbeHttpClient();
        return await new PromotionProbe(options, http, Console.Out).RunAsync(cancellationToken);
    }

    /// <summary>
    /// Graph and Entra return display names and messages in whatever language the tenant uses, and the
    /// Windows console otherwise falls back to a code page that turns anything outside it into '?'.
    /// Written without a byte order mark so redirected output stays a clean stream.
    /// </summary>
    private static void UseUtf8Console()
    {
        try
        {
            Console.OutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        }
        catch (IOException)
        {
            // No console attached. Nothing to configure, and nothing worth failing a run over.
        }
    }

    private static void WriteUsage(TextWriter writer)
    {
        writer.WriteLine("capability-probe - observe what one Entra app registration can reach in Microsoft 365.");
        writer.WriteLine();
        writer.WriteLine("Usage:");
        writer.WriteLine("  auth        request a token for Graph, SharePoint and Azure RMS, as the app and as a person");
        writer.WriteLine("  access      read every file's permission list as the app and as a person, in one run");
        writer.WriteLine("  sharepoint  spend the SharePoint token against SharePoint REST, every way: what Entra");
        writer.WriteLine("              issued, next to what the resource does about it");
        writer.WriteLine("  acl         can a page of items' permissions be fetched in one call instead of one");
        writer.WriteLine("              call per item? three candidate routes against the one-at-a-time baseline");
        writer.WriteLine("  mip         can this build reach the Information Protection SDK at all? needs no");
        writer.WriteLine("              configuration and no tenant - it asks about this machine, not about M365");
        writer.WriteLine("  consume     open each protected file once per DelegatedUserEmail, plus once with the");
        writer.WriteLine("              value unset, and report what licence the protection service issued");
        writer.WriteLine("  inventory   every file in a site: what it is called, whether it is protected, who it");
        writer.WriteLine("              is shared with, and who can actually open it. the one subcommand meant to");
        writer.WriteLine("              be used rather than only read - it honours Retry-After, it never prints a");
        writer.WriteLine("              protection value it did not establish, and whatever it could not resolve");
        writer.WriteLine("              gets a row of its own saying why");
        writer.WriteLine("  promotion   why a label inside a document does not reach the list's columns. takes");
        writer.WriteLine("              several files in FilePaths and reads all of them in one call sequence,");
        writer.WriteLine("              so the difference between rows is how each file was made, not when");
        writer.WriteLine("              it was measured"); 
        writer.WriteLine();
        writer.WriteLine("Settings (later layers win): appsettings.json, appsettings.local.json, user-secrets,");
        writer.WriteLine("PROBE_* environment variables, --Key=Value arguments.");
        writer.WriteLine();
        writer.WriteLine("  TenantId ClientId ClientSecret SiteUrl FilePaths DelegatedUserHint");
        writer.WriteLine("  ClientCertificatePath ClientCertificatePassword   (optional)");
        writer.WriteLine("  Identities                                       (optional: all | app-only)");
        writer.WriteLine();
        writer.WriteLine("Identities=app-only leaves the delegated leg alone: no device code is printed and");
        writer.WriteLine("nothing is asked of the identity provider on a person's behalf. Its rows still appear,");
        writer.WriteLine("as not run, saying that is what the run was asked for - and the run still exits 0,");
        writer.WriteLine("because a sign-in nobody attempted is not a sign-in that failed. Use it where there is");
        writer.WriteLine("no person at a browser, or where the sign-in is being refused for reasons this tool is");
        writer.WriteLine("not measuring.");
        writer.WriteLine();
        writer.WriteLine("Point ClientCertificatePath at a .pfx holding a certificate and its private key, and");
        writer.WriteLine("'auth' and 'sharepoint' add a third identity: the same app registration, with the same");
        writer.WriteLine("grants, proving itself with a key instead of the secret. Both are asked in one run, so");
        writer.WriteLine("nothing but the proof of identity differs between them. Left empty, that leg is reported");
        writer.WriteLine("as not run, with the reason, rather than left out.");
        writer.WriteLine();
        writer.WriteLine("'consume' takes its files from one of two places, never both: ProtectedFilePaths, paths on");
        writer.WriteLine("this machine, or ProtectedSiteFiles, paths inside the site's document library which the");
        writer.WriteLine("app fetches with its own token and deletes when the run ends. The second needs SiteUrl,");
        writer.WriteLine("and exists so a run with nobody at the keyboard still has a file to open - and so that");
        writer.WriteLine("which file is being opened stays a run's input rather than something stored beside a");
        writer.WriteLine("credential. Each fetch is measured like any other call.");
        writer.WriteLine();
        writer.WriteLine("Both take several paths separated by '|', and every file is opened by every leg in the");
        writer.WriteLine("same run. Two files measured in separate runs can only be compared by assuming nothing");
        writer.WriteLine("moved in between; held together, a difference between them is a fact about the files.");
        writer.WriteLine();
        writer.WriteLine("FilePaths takes one or more paths separated by '|'. Each is relative to the root of the");
        writer.WriteLine("site's default document library and does not include the library's own name: a file");
        writer.WriteLine("sitting directly in it is just /test.docx. All of them are read in a single run, so the");
        writer.WriteLine("device code sign-in happens once no matter how many files are listed.");
        writer.WriteLine();
        writer.WriteLine("Example:");
        writer.WriteLine("  dotnet run --project src/CapabilityProbe.Cli -- auth");
        writer.WriteLine("  dotnet run --project src/CapabilityProbe.Cli -- access --FilePaths=\"/a.docx|/drafts/b.docx\"");
        writer.WriteLine("  dotnet run --project src/CapabilityProbe.Cli -- sharepoint");
        writer.WriteLine();
        writer.WriteLine("Exit codes say whether the probe could do its job, not whether the tenant behaved.");
        writer.WriteLine("A refusal, an empty list, a 404 and a token carrying nothing are all measurements,");
        writer.WriteLine("and so is a step left unreachable by one of them. All of those exit 0.");
        writer.WriteLine("  0 the probe ran, 2 the delegated sign-in was never completed,");
        writer.WriteLine("  64 bad usage, 78 incomplete configuration, 130 cancelled.");
    }
}
