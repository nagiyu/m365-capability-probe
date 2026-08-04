using Azure.Core;
using Azure.Identity;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Reporting;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.File;

namespace CapabilityProbe.Probes;

/// <summary>
/// Opens one protected file several times over, changing only the address the app claims to be acting
/// for, and reports what the protection service issued each time.
/// <para>
/// The question is whether <c>FileEngineSettings.DelegatedUserEmail</c> takes part in the authorisation
/// decision or is merely carried along. An app with an application-level grant on the protection
/// service is not obviously constrained by a value it chooses for itself, and nothing in the SDK's
/// surface says which it is.
/// </para>
/// <para>
/// One leg per configured address, plus one with the value left unset. The tool is not told which
/// address is supposed to have rights: it runs each and reports what came back, and which of them was
/// the control belongs in prose where it can carry a date and a reason. Without the unset leg, "the
/// value is honoured" and "the value is required but unread" look the same.
/// </para>
/// <para>
/// It never writes the file's contents anywhere. What is measured is whether the content could be
/// opened and what licence came back with it - the plaintext is not the answer to anything here, and
/// producing it would make this a different tool.
/// </para>
/// </summary>
public sealed class ConsumeProbe(ProbeOptions options, TextWriter console)
{
    /// <summary>Identifies this tool to the protection service. It appears in that service's logs.</summary>
    private const string ApplicationName = "m365-capability-probe";

    private const string UnsetLeg = "(DelegatedUserEmail unset)";

    /// <summary>The SDK needs a concrete one; nothing here varies from its defaults.</summary>
    private sealed class ProbeFileExecutionState : FileExecutionState;

    private sealed record LegResult
    {
        public required string DelegatedUserEmail { get; init; }
        public required string IdentityEmail { get; init; }
        public string? Failure { get; init; }
        public string? FailureType { get; init; }
        public bool Opened { get; init; }
        public bool? IsProtected { get; init; }
        public string? Owner { get; init; }
        public string? IssuedTo { get; init; }
        public bool? IssuedToOwner { get; init; }
        public IReadOnlyList<string> Rights { get; init; } = [];
        public string? LabelId { get; init; }
        public long ElapsedMs { get; init; }
        public long? DecryptedBytes { get; init; }
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("consume");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["client"] = options.ClientId;
        report.Subject["file"] = options.ProtectedFilePath;

        var credential = BuildCredential(out var credentialDescription);
        report.Subject["credential"] = credentialDescription;

        // Whether Identity moves with the leg or stays put is the difference between measuring the
        // pair and measuring one of them, so the report says which was done before any row is read.
        report.Subject["identity"] = string.IsNullOrWhiteSpace(options.MipIdentityEmail)
            ? "mirrors DelegatedUserEmail on every leg - the two move together"
            : $"pinned to {options.MipIdentityEmail} on every leg - only DelegatedUserEmail varies";

        var legs = options.DelegatedUsers.Append(UnsetLeg).ToList();
        report.Subject["legs"] = string.Join(", ", legs);

        if (!File.Exists(options.ProtectedFilePath))
        {
            report.Add(Observation.NotRun(
                "the protected file",
                $"no file at '{options.ProtectedFilePath}', so nothing could be opened as anyone"));
            report.Finish();
            return report;
        }

        var consent = new MipConsentDelegate(console);
        var results = new List<LegResult>();

        foreach (var leg in legs)
        {
            console.WriteLine($"Opening the file as {leg}...");
            results.Add(await OpenAsync(leg, credential, consent, cancellationToken));
        }

        report.Add(BuildTable(results));
        report.Add(BuildRightsTable(results));

        foreach (var result in results)
        {
            report.Add(LegObservation(result));
        }

        report.Add(ContrastObservation(results));
        report.Finish();
        return report;
    }

    private async Task<LegResult> OpenAsync(
        string leg,
        TokenCredential credential,
        MipConsentDelegate consent,
        CancellationToken cancellationToken)
    {
        var unset = leg == UnsetLeg;
        var delegatedUserEmail = unset ? string.Empty : leg;

        // With no pin, Identity follows the leg; with one, it is held still so the only thing moving
        // between legs is DelegatedUserEmail.
        var identityEmail = string.IsNullOrWhiteSpace(options.MipIdentityEmail)
            ? delegatedUserEmail
            : options.MipIdentityEmail;

        var started = System.Diagnostics.Stopwatch.StartNew();
        var authDelegate = new MipAuthDelegate(credential, console);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var directory = AppContext.BaseDirectory;
            MIP.Initialize(MipComponent.File, directory);

            var appInfo = new ApplicationInfo
            {
                ApplicationId = options.ClientId,
                ApplicationName = ApplicationName,
                ApplicationVersion = "1.0.0",
            };

            // In memory rather than on disk: a cached licence would let a later leg answer from an
            // earlier leg's decision, and the whole subcommand is a comparison between legs.
            using var mipContext = MIP.CreateMipContext(
                new MipConfiguration(
                    appInfo,
                    Path.Combine(Path.GetTempPath(), "mip_data"),
                    LogLevel.Error,
                    isOfflineOnly: false,
                    cacheStorageType: CacheStorageType.InMemory));

            var profile = await MIP.LoadFileProfileAsync(
                new FileProfileSettings(mipContext, CacheStorageType.InMemory, consent));

            var engineSettings = new FileEngineSettings(
                engineId: string.Empty,
                authDelegate: authDelegate,
                clientData: string.Empty,
                locale: "en-US")
            {
                Identity = new Identity(identityEmail),
                // The subject of the whole subcommand. Left empty on the last leg on purpose.
                DelegatedUserEmail = delegatedUserEmail,
                ProtectionOnlyEngine = true,
            };

            var engine = await profile.AddEngineAsync(engineSettings);

            var handler = await engine.CreateFileHandlerAsync(
                options.ProtectedFilePath,
                options.ProtectedFilePath,
                isAuditDiscoveryEnabled: false,
                fileExecutionState: new ProbeFileExecutionState(),
                isGetSensitivityLabelAuditDiscoveryEnabled: false);

            var protection = handler.Protection;
            long? decryptedBytes = null;

            if (protection is not null)
            {
                // Reading the decrypted stream is the difference between holding a licence and using
                // it. Only its length is kept: the contents are what this tool has no business with,
                // and the stream is dropped as soon as it has been counted.
                await using var decrypted = await handler.GetDecryptedTemporaryStreamAsync();
                decryptedBytes = decrypted.Length;
            }

            started.Stop();

            return new LegResult
            {
                DelegatedUserEmail = leg,
                IdentityEmail = identityEmail.Length == 0 ? "(empty)" : identityEmail,
                Opened = true,
                IsProtected = protection is not null,
                Owner = protection?.Owner,
                IssuedTo = protection?.IssuedTo,
                IssuedToOwner = protection?.IsIssuedToOwner,
                Rights = protection?.Rights?.ToList() ?? [],
                LabelId = protection?.ProtectionDescriptor?.LabelId,
                DecryptedBytes = decryptedBytes,
                ElapsedMs = started.ElapsedMilliseconds,
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            started.Stop();

            // A refusal is the answer half the time here, so it is caught and recorded like any other
            // result. The SDK's own exception type is the closest thing to an error code it offers.
            return new LegResult
            {
                DelegatedUserEmail = leg,
                IdentityEmail = identityEmail.Length == 0 ? "(empty)" : identityEmail,
                Opened = false,
                FailureType = ex.GetType().Name,
                Failure = FirstLine(ex.Message),
                ElapsedMs = started.ElapsedMilliseconds,
            };
        }
    }

    /// <summary>
    /// The app's own credential. A certificate is preferred when one is configured, because the
    /// protection service has already been measured treating the two differently elsewhere in this
    /// tool - and the report names which was used rather than leaving it to be guessed.
    /// </summary>
    private TokenCredential BuildCredential(out string description)
    {
        if (options.HasCertificate && File.Exists(options.ClientCertificatePath))
        {
            var source = AppOnlyTokenSource.WithCertificate(options);
            if (!source.IsUnavailable)
            {
                description = $"app-only, {source.Identity}";
                return new ClientCertificateCredential(
                    options.TenantId,
                    options.ClientId,
                    options.ClientCertificatePath,
                    new ClientCertificateCredentialOptions());
            }

            description = $"app-only, secret ({source.Identity} - falling back)";
            return new ClientSecretCredential(options.TenantId, options.ClientId, options.ClientSecret);
        }

        description = $"app-only, client secret, {options.ClientSecret.Length} characters";
        return new ClientSecretCredential(options.TenantId, options.ClientId, options.ClientSecret);
    }

    private static ProbeTable BuildTable(IReadOnlyList<LegResult> results) =>
        new("What the protection service issued for each DelegatedUserEmail",
            ["DelegatedUserEmail", "Identity", "opened", "protected", "issued to", "owner", "to owner", "ms"],
            results
                .Select(r => (IReadOnlyList<string?>)new[]
                {
                    r.DelegatedUserEmail,
                    r.IdentityEmail,
                    r.Opened ? "yes" : $"no: {r.FailureType}",
                    r.IsProtected switch { true => "yes", false => "no", null => "-" },
                    r.IssuedTo ?? "-",
                    r.Owner ?? "-",
                    r.IssuedToOwner switch { true => "yes", false => "no", null => "-" },
                    r.ElapsedMs.ToString(),
                })
                .ToList());

    private static ProbeTable BuildRightsTable(IReadOnlyList<LegResult> results) =>
        new("What each leg was allowed to do with the content (rights as the service named them)",
            ["DelegatedUserEmail", "rights", "decrypted bytes", "why not"],
            results
                .Select(r => (IReadOnlyList<string?>)new[]
                {
                    r.DelegatedUserEmail,
                    r.Rights.Count == 0 ? "-" : string.Join(", ", r.Rights),
                    r.DecryptedBytes?.ToString() ?? "-",
                    r.Failure ?? "",
                })
                .ToList());

    private static Observation LegObservation(LegResult result)
    {
        var subject = $"DelegatedUserEmail = {result.DelegatedUserEmail}";

        var observed = result switch
        {
            { Opened: false } => $"refused: {result.FailureType} - {result.Failure}",
            { IsProtected: false } => "opened, but the file carries no protection",
            _ => $"opened; licence issued to {result.IssuedTo ?? "(not stated)"}, " +
                 $"rights {(result.Rights.Count == 0 ? "(none)" : string.Join("/", result.Rights))}, " +
                 $"{result.DecryptedBytes?.ToString() ?? "no"} bytes decrypted",
        };

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["delegatedUserEmail"] = result.DelegatedUserEmail,
                ["identity"] = result.IdentityEmail,
                ["opened"] = result.Opened ? "true" : "false",
                ["isProtected"] = result.IsProtected?.ToString(),
                ["owner"] = result.Owner,
                ["issuedTo"] = result.IssuedTo,
                ["isIssuedToOwner"] = result.IssuedToOwner?.ToString(),
                ["rights"] = result.Rights.Count == 0 ? null : string.Join(" ", result.Rights),
                ["labelId"] = result.LabelId,
                ["decryptedBytes"] = result.DecryptedBytes?.ToString(),
                ["failureType"] = result.FailureType,
                ["failure"] = result.Failure,
                ["elapsedMs"] = result.ElapsedMs.ToString(),
            },
        };
    }

    /// <summary>
    /// The legs on one line. It states no expectation about which of them should have worked - what
    /// the addresses were supposed to mean is an argument about a particular tenant, and it belongs
    /// somewhere it can be dated.
    /// </summary>
    private static Observation ContrastObservation(IReadOnlyList<LegResult> results)
    {
        var observed = string.Join("; ", results.Select(r =>
            $"{Short(r.DelegatedUserEmail)} {(r.Opened ? r.IssuedTo is null ? "opened" : $"issued to {Short(r.IssuedTo)}" : "refused")}"));

        return Observation.Measured("DelegatedUserEmail: does the value change the answer", observed) with
        {
            Details = results.ToDictionary(
                r => r.DelegatedUserEmail,
                r => (string?)(r.Opened ? $"issuedTo={r.IssuedTo}; rights={string.Join(" ", r.Rights)}" : $"refused: {r.FailureType}")),
        };
    }

    private static string Short(string email)
    {
        var at = email.IndexOf('@');
        return at <= 0 ? email : email[..at];
    }

    private static string FirstLine(string message)
    {
        var line = message.Split('\n', '\r').FirstOrDefault(l => !string.IsNullOrWhiteSpace(l))?.Trim() ?? message;
        return line.Length <= 300 ? line : line[..300] + "...";
    }
}
