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
    public const string InventoryCommand = "inventory";

    /// <summary>
    /// Why a label inside a document does not reach the list's columns (finding 14's open question).
    /// Kept apart from <c>inventory</c> because it asks about named files rather than a library, and
    /// because its answer is a comparison between them rather than a picture of what is there.
    /// </summary>
    public const string PromotionCommand = "promotion";

    /// <summary>
    /// What <c>Prefer: hierarchicalsharing</c> does to a drive's delta, and what it costs. The header
    /// is documented as existing without its required permission being written down anywhere, which
    /// makes it a thing to measure.
    /// </summary>
    public const string DeltaCommand = "delta";

    public static readonly string[] AllCommands =
    [
        AuthCommand, AccessCommand, SharePointCommand, AclCommand, MipCommand, ConsumeCommand,
        InventoryCommand, PromotionCommand, DeltaCommand,
    ];

    /// <summary>Everything that authenticates as the app registration, whatever it then talks to.</summary>
    private static readonly string[] NeedsApp =
    [
        AuthCommand, AccessCommand, SharePointCommand, AclCommand, ConsumeCommand, InventoryCommand,
        PromotionCommand, DeltaCommand,
    ];

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

    /// <summary>
    /// <c>inventory</c> needs a site and an identity, but not the probe's own secret: it prefers a
    /// certificate, and may be pointed at a second app registration entirely. Its requirements are
    /// listed separately so a run that has everything <c>inventory</c> wants is not blocked by a gap
    /// that only matters to the subcommands measuring the probe's own registration.
    /// </summary>
    private static readonly string[] InventoryOnly = [InventoryCommand];

    /// <summary>Everything that speaks as the inventory registration and needs a site to point at.</summary>
    private static readonly string[] SiteReaders = [InventoryCommand, PromotionCommand, DeltaCommand];

    /// <summary>
    /// <c>promotion</c> takes the same key for the same reason: it is asked about named files, and a
    /// run with none configured has nothing to compare.
    /// </summary>
    private static readonly string[] NeedsFilePaths = [AccessCommand, PromotionCommand];

    private static readonly string[] AclOnly = [AclCommand];

    /// <summary>
    /// Keys that took one value and now take several. A stale singular value binds to nothing and
    /// would otherwise leave a run reporting that no file was configured while one plainly was.
    /// </summary>
    private static readonly (string Old, string New)[] RenamedConsumeKeys =
    [
        ("ProtectedFilePath", "ProtectedFilePaths"),
        ("ProtectedSiteFile", "ProtectedSiteFiles"),
    ];

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
        // consume takes its file from one of two places and never both: a path on this machine, or a
        // path inside the site's document library. The second exists because a run can happen where
        // there is nobody to hand a file over - and because which file is being opened is what a run
        // is about, which makes it an input rather than something stored alongside the credentials.
        var hasLocalFile = !string.IsNullOrWhiteSpace(options.ProtectedFilePaths);
        var hasSiteFile = !string.IsNullOrWhiteSpace(options.ProtectedSiteFiles);

        if (!hasLocalFile && !hasSiteFile)
        {
            // FilePaths is the key every other subcommand takes its paths from, and a run of 'consume'
            // that has one set and the other empty is almost certainly a value put in the wrong box
            // rather than a run nobody configured. Saying so costs a sentence and saves a round trip.
            var misplaced = string.IsNullOrWhiteSpace(options.FilePaths)
                ? string.Empty
                : $". FilePaths is set ({options.Files.Count} path(s)) - 'consume' does not read it; " +
                  "the same values probably belong in ProtectedSiteFiles";

            problems.Add(new ConfigurationProblem(
                "ProtectedFilePaths / ProtectedSiteFiles",
                "neither is set - 'consume' needs at least one protected file, either paths on this machine " +
                "(inside the container, under /work/samples) or paths inside the site's document library" +
                misplaced,
                ConsumeOnly));
        }
        else if (hasLocalFile && hasSiteFile)
        {
            problems.Add(new ConfigurationProblem(
                "ProtectedFilePaths / ProtectedSiteFiles",
                "both are set, and there is no reading of that which does not quietly ignore one of them",
                ConsumeOnly));
        }

        foreach (var file in options.ProtectedSiteFileList.Where(f => !f.StartsWith('/')))
        {
            problems.Add(new ConfigurationProblem(
                "ProtectedSiteFiles",
                $"every path must start with '/': '{file}' (expected e.g. /probe.docx). Each is " +
                "relative to the root of the site's default document library and does not include the library's name",
                ConsumeOnly));
        }

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
        // inventory can speak as either registration, so what it needs is "one of them can prove
        // itself" rather than any particular key. Naming both is what makes the message actionable.
        var inventoryApp = options.InventoryApp;
        if (inventoryApp.IsEmpty ||
            (!inventoryApp.HasCertificate && string.IsNullOrWhiteSpace(inventoryApp.ClientSecret)))
        {
            problems.Add(new ConfigurationProblem(
                "InventoryClientId / ClientId",
                "'inventory' found no app registration it can prove: set InventoryClientId with " +
                "InventoryCertificatePath, or leave them empty to fall back to the probe's own registration",
                InventoryOnly));
        }

        // consume normally needs no site at all. It does once its file is named as living in one, and
        // then a missing SiteUrl stops it just as surely as it stops the others.
        string[] siteUrlBlocks = hasSiteFile
            ? [.. NeedsTenant, ConsumeCommand, .. SiteReaders]
            : [.. NeedsTenant, .. SiteReaders];

        Require(problems, "SiteUrl", options.SiteUrl, siteUrlBlocks,
            "https://<host>/sites/<name>; the SharePoint scope is built from its host name");
        // Only when there is a delegated leg to name an account for. A run narrowed to the app's own
        // identities has no use for it, and a setting that blocks a run it takes no part in is noise.
        if (options.RunDelegated)
        {
            Require(problems, "DelegatedUserHint", options.DelegatedUserHint, NeedsTenant,
                "sign-in name to use for the device code leg, shown on screen before sign-in");
        }
        Require(problems, "FilePaths", options.FilePaths, NeedsFilePaths,
            "one or more paths inside the site's default document library, separated by '|', e.g. /test.docx|/drafts/q3.docx");

        // These keys used to be singular. Saying so beats leaving a stale value silently ignored while
        // the run reports that nothing is configured.
        if (!string.IsNullOrWhiteSpace(configuration?["FilePath"]))
        {
            problems.Add(new ConfigurationProblem(
                "FilePath",
                "renamed to FilePaths, which takes several paths separated by '|'. The old value is being ignored",
                NeedsFilePaths));
        }

        foreach (var (oldKey, newKey) in RenamedConsumeKeys)
        {
            if (!string.IsNullOrWhiteSpace(configuration?[oldKey]))
            {
                problems.Add(new ConfigurationProblem(
                    oldKey,
                    $"renamed to {newKey}, which takes several paths separated by '|'. The old value is being ignored",
                    ConsumeOnly));
            }
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
                    siteUrlBlocks));
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
                NeedsFilePaths));
        }

        // Both of these decide how much of a library a run looked at. A value that failed to parse
        // would fall back to a default and produce a report about a different question than the one
        // asked, so a typo stops the run rather than quietly changing what it measured.
        foreach (var (key, value) in new[] { ("PageSize", options.PageSize), ("PageLimit", options.PageLimit) })
        {
            if (!string.IsNullOrWhiteSpace(value) && !(int.TryParse(value.Trim(), out var n) && n > 0))
            {
                problems.Add(new ConfigurationProblem(
                    key,
                    $"'{value}' is not a positive whole number (empty leaves it at the default)",
                    AclOnly));
            }
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
