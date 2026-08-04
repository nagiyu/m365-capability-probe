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
    public const string SharePointCommand = "sharepoint";
    public const string AclCommand = "acl";
    public const string MipCommand = "mip";
    public const string ConsumeCommand = "consume";

    public static readonly string[] AllCommands =
        [AuthCommand, AccessCommand, SharePointCommand, AclCommand, MipCommand, ConsumeCommand];

    /// <summary>Everything that authenticates as the app registration, whatever it then talks to.</summary>
    private static readonly string[] NeedsApp =
        [AuthCommand, AccessCommand, SharePointCommand, AclCommand, ConsumeCommand];

    private static readonly string[] ConsumeOnly = [ConsumeCommand];

    /// <summary>
    /// The subcommands that talk to the tenant. They cannot run without an identity and a site.
    /// <para>
    /// <c>mip</c> is deliberately absent: it asks whether this build can reach the SDK at all, which is
    /// a question about the machine and not about any tenant. Requiring a tenant ID to answer it would
    /// mean the one subcommand that works before anything is configured refuses to run.
    /// </para>
    /// </summary>
    private static readonly string[] NeedsTenant =
        [AuthCommand, AccessCommand, SharePointCommand, AclCommand];

    private static readonly string[] AccessOnly = [AccessCommand];

    /// <summary>
    /// Layers, lowest priority first. The last one that supplies a key wins:
    /// appsettings.json -> appsettings.local.json -> user-secrets -> PROBE_* env vars -> command line.
    /// </summary>
    public static ProbeOptionsResult Load(string[] configArgs)
    {
        var options = new ProbeOptions();
        var problems = new List<ConfigurationProblem>();
        IConfigurationRoot? configuration = null;

        try
        {
            configuration = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
                .AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: false)
                .AddUserSecrets(typeof(ProbeOptionsLoader).Assembly, optional: true)
                .AddEnvironmentVariables("PROBE_")
                .AddCommandLine(configArgs)
                .Build();

            configuration.Bind(options);
        }
        catch (Exception ex) when (ex is FormatException or InvalidDataException)
        {
            // A malformed layer is a setup problem to report, not a stack trace to print.
            problems.Add(new ConfigurationProblem(
                "(configuration)",
                $"could not be read: {ex.Message}",
                NeedsTenant));
        }

        Require(problems, "TenantId", options.TenantId, NeedsApp,
            "directory (tenant) ID of the app registration");
        Require(problems, "ClientId", options.ClientId, NeedsApp,
            "application (client) ID of the app registration");
        Require(problems, "ClientSecret", options.ClientSecret, NeedsTenant,
            "client secret; keep it in user-secrets, not in a committed file");
        Require(problems, "ProtectedFilePath", options.ProtectedFilePath, ConsumeOnly,
            "path to a protected file to open; inside the container this is under /work/samples");
        Require(problems, "DelegatedUserEmails", options.DelegatedUserEmails, ConsumeOnly,
            "one or more addresses to put in DelegatedUserEmail, separated by '|'; a leg with the value unset is always added");

        // consume can prove itself either way, so neither credential is required on its own - but
        // one of them has to be there, and saying which is missing beats a failure at token time.
        if (string.IsNullOrWhiteSpace(options.ClientSecret) && !options.HasCertificate)
        {
            problems.Add(new ConfigurationProblem(
                "ClientSecret / ClientCertificatePath",
                "neither is set, and 'consume' needs one of them to authenticate as the app",
                ConsumeOnly));
        }
        Require(problems, "SiteUrl", options.SiteUrl, NeedsTenant,
            "https://<host>/sites/<name>; the SharePoint scope is built from its host name");
        // Only when there is a delegated leg to name an account for. A run narrowed to the app's own
        // identities has no use for it, and a setting that blocks a run it takes no part in is noise.
        if (options.RunDelegated)
        {
            Require(problems, "DelegatedUserHint", options.DelegatedUserHint, NeedsTenant,
                "sign-in name to use for the device code leg, shown on screen before sign-in");
        }
        Require(problems, "FilePaths", options.FilePaths, AccessOnly,
            "one or more paths inside the site's default document library, separated by '|', e.g. /test.docx|/drafts/q3.docx");

        // This key used to be singular. Saying so beats leaving a stale value silently ignored while
        // the run reports that nothing is configured.
        if (!string.IsNullOrWhiteSpace(configuration?["FilePath"]))
        {
            problems.Add(new ConfigurationProblem(
                "FilePath",
                "renamed to FilePaths, which takes several paths separated by '|'. The old value is being ignored",
                AccessOnly));
        }

        if (!string.IsNullOrWhiteSpace(options.SiteUrl))
        {
            if (!Uri.TryCreate(options.SiteUrl, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps ||
                string.IsNullOrEmpty(uri.Host))
            {
                problems.Add(new ConfigurationProblem(
                    "SiteUrl",
                    $"not an absolute https URL: '{options.SiteUrl}' (expected https://<host>/sites/<name>)",
                    NeedsTenant));
            }
        }

        // A typo here is not a small thing: it decides which identities the run establishes, so an
        // unrecognised value silently falling back to "all" would produce a report about something
        // other than what was asked for. Better to stop and say the word was not understood.
        var identities = options.Identities.Trim();
        if (identities.Length > 0 &&
            !identities.Equals(ProbeOptions.AllIdentities, StringComparison.OrdinalIgnoreCase) &&
            !identities.Equals(ProbeOptions.AppOnlyIdentities, StringComparison.OrdinalIgnoreCase))
        {
            problems.Add(new ConfigurationProblem(
                "Identities",
                $"'{options.Identities}' is not a value this understands - use " +
                $"'{ProbeOptions.AllIdentities}' or '{ProbeOptions.AppOnlyIdentities}' (empty means all)",
                NeedsTenant));
        }

        // A password with nothing to unlock is the shape a half-finished setup takes: the certificate
        // path was removed, or never set, and the run silently loses a leg it was meant to have. It
        // stops nothing, so it does not block a subcommand - but going unsaid, it reads as a tool that
        // ignored what it was given.
        if (!string.IsNullOrWhiteSpace(options.ClientCertificatePassword) && !options.HasCertificate)
        {
            problems.Add(new ConfigurationProblem(
                "ClientCertificatePassword",
                "set, but ClientCertificatePath is empty, so there is no certificate for it to open",
                []));
        }

        foreach (var file in options.Files.Where(f => !f.StartsWith('/')))
        {
            problems.Add(new ConfigurationProblem(
                "FilePaths",
                $"every path must start with '/': '{file}' (expected e.g. /test.docx)",
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
        // Whether this stops the run is decided by the caller, so this says what is wrong and not
        // what became of the run. Not every gap blocks something.
        writer.WriteLine("Configuration has gaps.");
        writer.WriteLine();
        writer.WriteLine("Missing or invalid keys:");
        foreach (var problem in problems)
        {
            writer.WriteLine($"  {problem.Key,-26} {problem.Detail}");
            writer.WriteLine($"  {"",-26} blocks: " + (problem.BlockedCommands.Count == 0
                ? "nothing - worth saying, not worth stopping for"
                : string.Join(", ", problem.BlockedCommands)));
        }

        writer.WriteLine();
        writer.WriteLine("Subcommand readiness:");
        foreach (var command in AllCommands)
        {
            var blockers = problems
                .Where(p => p.BlockedCommands.Contains(command, StringComparer.OrdinalIgnoreCase))
                .Select(p => p.Key)
                .Distinct()
                .ToList();

            writer.WriteLine(blockers.Count == 0
                ? $"  {command,-11} ready"
                : $"  {command,-11} needs {string.Join(", ", blockers)}");
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
