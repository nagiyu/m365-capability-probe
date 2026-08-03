using Microsoft.Extensions.Configuration;

namespace CapabilityProbe.Configuration;

/// <summary>Outcome of loading configuration. Never an exception: a bad setup is a reportable state.</summary>
public sealed record ProbeOptionsResult(ProbeOptions Options, IReadOnlyList<ConfigurationProblem> Problems)
{
    public bool IsUsable(string command) =>
        !Problems.Any(p => p.BlockedCommands.Contains(command, StringComparer.OrdinalIgnoreCase));
}

/// <summary>A single missing or malformed setting, plus the subcommands it stops from running.</summary>
public sealed record ConfigurationProblem(string Key, string Detail, IReadOnlyList<string> BlockedCommands);

public static class ProbeOptionsLoader
{
    public const string AuthCommand = "auth";
    public const string AccessCommand = "access";

    private static readonly string[] BothCommands = [AuthCommand, AccessCommand];
    private static readonly string[] AccessOnly = [AccessCommand];

    /// <summary>
    /// Layers, lowest priority first. The last one that supplies a key wins:
    /// appsettings.json -> appsettings.local.json -> user-secrets -> PROBE_* env vars -> command line.
    /// </summary>
    public static ProbeOptionsResult Load(string[] configArgs)
    {
        var options = new ProbeOptions();
        var problems = new List<ConfigurationProblem>();

        try
        {
            new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
                .AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: false)
                .AddUserSecrets(typeof(ProbeOptionsLoader).Assembly, optional: true)
                .AddEnvironmentVariables("PROBE_")
                .AddCommandLine(configArgs)
                .Build()
                .Bind(options);
        }
        catch (Exception ex) when (ex is FormatException or InvalidDataException)
        {
            // A malformed layer is a setup problem to report, not a stack trace to print.
            problems.Add(new ConfigurationProblem(
                "(configuration)",
                $"could not be read: {ex.Message}",
                BothCommands));
        }

        Require(problems, "TenantId", options.TenantId, BothCommands,
            "directory (tenant) ID of the app registration");
        Require(problems, "ClientId", options.ClientId, BothCommands,
            "application (client) ID of the app registration");
        Require(problems, "ClientSecret", options.ClientSecret, BothCommands,
            "client secret; keep it in user-secrets, not in a committed file");
        Require(problems, "SiteUrl", options.SiteUrl, BothCommands,
            "https://<host>/sites/<name>; the SharePoint scope is built from its host name");
        Require(problems, "DelegatedUserHint", options.DelegatedUserHint, BothCommands,
            "sign-in name to use for the device code leg, shown on screen before sign-in");
        Require(problems, "FilePath", options.FilePath, AccessOnly,
            "library-relative path, e.g. /Shared Documents/test.docx");

        if (!string.IsNullOrWhiteSpace(options.SiteUrl))
        {
            if (!Uri.TryCreate(options.SiteUrl, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps ||
                string.IsNullOrEmpty(uri.Host))
            {
                problems.Add(new ConfigurationProblem(
                    "SiteUrl",
                    $"not an absolute https URL: '{options.SiteUrl}' (expected https://<host>/sites/<name>)",
                    BothCommands));
            }
        }

        if (!string.IsNullOrWhiteSpace(options.FilePath) && !options.FilePath.StartsWith('/'))
        {
            problems.Add(new ConfigurationProblem(
                "FilePath",
                $"must start with '/': '{options.FilePath}' (expected e.g. /Shared Documents/test.docx)",
                AccessOnly));
        }

        return new ProbeOptionsResult(options, problems);
    }

    private static void Require(
        List<ConfigurationProblem> problems,
        string key,
        string value,
        IReadOnlyList<string> blockedCommands,
        string detail)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            problems.Add(new ConfigurationProblem(key, $"missing - {detail}", blockedCommands));
        }
    }

    /// <summary>
    /// Prints what is missing, by name, and which subcommand each gap blocks.
    /// Reads as "fill these in and this subcommand starts working".
    /// </summary>
    public static void WriteProblems(TextWriter writer, IReadOnlyList<ConfigurationProblem> problems)
    {
        writer.WriteLine("Configuration is incomplete. Nothing was probed.");
        writer.WriteLine();
        writer.WriteLine("Missing or invalid keys:");
        foreach (var problem in problems)
        {
            writer.WriteLine($"  {problem.Key,-18} {problem.Detail}");
            writer.WriteLine($"  {"",-18} blocks: {string.Join(", ", problem.BlockedCommands)}");
        }

        writer.WriteLine();
        writer.WriteLine("Subcommand readiness:");
        foreach (var command in BothCommands)
        {
            var blockers = problems
                .Where(p => p.BlockedCommands.Contains(command, StringComparer.OrdinalIgnoreCase))
                .Select(p => p.Key)
                .Distinct()
                .ToList();

            writer.WriteLine(blockers.Count == 0
                ? $"  {command,-8} ready"
                : $"  {command,-8} needs {string.Join(", ", blockers)}");
        }

        writer.WriteLine();
        writer.WriteLine("Supply values in any of these layers (later layers win):");
        writer.WriteLine("  1. appsettings.json          (committed, keys only, values empty)");
        writer.WriteLine("  2. appsettings.local.json    (git-ignored)");
        writer.WriteLine("  3. user-secrets              dotnet user-secrets set \"ClientSecret\" \"...\"");
        writer.WriteLine("  4. environment variables     PROBE_ClientSecret=...");
        writer.WriteLine("  5. command line              --ClientSecret=...");
    }
}
