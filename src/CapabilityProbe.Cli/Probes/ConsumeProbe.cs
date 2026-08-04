using System.Text.Json;
using Azure.Core;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
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
/// <para>
/// The file itself comes from one of two places: a path on this machine, or a path inside the site's
/// document library, fetched with the app's own token before any leg runs and deleted afterwards.
/// The second is there so that a run happening where nobody can hand a file over still has one, and
/// so that the file being opened stays a run's input rather than something stored beside a credential.
/// </para>
/// </summary>
public sealed class ConsumeProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    /// <summary>Identifies this tool to the protection service. It appears in that service's logs.</summary>
    private const string ApplicationName = "m365-capability-probe";

    private const string UnsetLeg = "(DelegatedUserEmail unset)";

    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    /// <summary>The SDK needs a concrete one; nothing here varies from its defaults.</summary>
    private sealed class ProbeFileExecutionState : FileExecutionState;

    /// <summary>
    /// Where the file came from, and what happened on the way. A source that could not be got hold of
    /// is a state to report, not an exception: it says which step refused, and the legs below then say
    /// they were never run rather than saying nothing.
    /// </summary>
    private sealed record FileSource
    {
        public required string Description { get; init; }

        /// <summary>The file on disk, or null when there is nothing to open.</summary>
        public string? Path { get; init; }

        public string? Problem { get; init; }

        /// <summary>True when this probe wrote the file and has to clean it up.</summary>
        public bool IsTemporary { get; init; }

        public long? Bytes { get; init; }

        public IReadOnlyList<(string Step, HttpObservation Observation)> Calls { get; init; } = [];
    }

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

        var credential = BuildCredential(out var credentialDescription);
        report.Subject["credential"] = credentialDescription;

        // Whether Identity moves with the leg or stays put is the difference between measuring the
        // pair and measuring one of them, so the report says which was done before any row is read.
        report.Subject["identity"] = string.IsNullOrWhiteSpace(options.MipIdentityEmail)
            ? "mirrors DelegatedUserEmail on every leg - the two move together"
            : $"pinned to {options.MipIdentityEmail} on every leg - only DelegatedUserEmail varies";

        var legs = options.DelegatedUsers.Append(UnsetLeg).ToList();
        report.Subject["legs"] = string.Join(", ", legs);

        if (credential is null)
        {
            report.Add(Observation.NotRun(
                "the application's own identity",
                "there is nothing for the app to prove itself with, so no leg was attempted"));
            report.Finish();
            return report;
        }

        var source = await GetFileAsync(credential, cancellationToken);
        report.Subject["file"] = source.Description;

        try
        {
            foreach (var (step, observation) in source.Calls)
            {
                report.Add(FetchObservation(step, observation));
            }

            if (source.Path is null)
            {
                // The console grid clips a long cell, and this row's entire value is the reason.
                // Written out here in full so the log carries it even where the table cannot.
                console.WriteLine($"The file was not fetched: {source.Problem}");
                report.Add(Observation.NotRun("the protected file", source.Problem!));
                report.Finish();
                return report;
            }

            report.Add(Observation.Measured(
                "the protected file",
                $"{source.Bytes?.ToString() ?? "?"} bytes at hand, from {source.Description}"));

            var consent = new MipConsentDelegate(console);
            var results = new List<LegResult>();

            foreach (var leg in legs)
            {
                console.WriteLine($"Opening the file as {leg}...");
                results.Add(await OpenAsync(source.Path, leg, credential, consent, cancellationToken));
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
        finally
        {
            // What was fetched is somebody's file. It exists for the length of a run and no longer,
            // and a run that ends badly is exactly when that matters most.
            if (source is { IsTemporary: true, Path: not null })
            {
                Delete(source.Path);
            }
        }
    }

    /// <summary>
    /// Puts the protected file on disk, from wherever it was said to be. Every HTTP call it makes is
    /// returned alongside the result, because a file that never arrived is a measurement about this
    /// app's reach - the same measurement <c>access</c> makes, taken here for a different reason.
    /// </summary>
    private async Task<FileSource> GetFileAsync(TokenCredential credential, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(options.ProtectedSiteFile))
        {
            var path = options.ProtectedFilePath;
            var exists = File.Exists(path);

            return new FileSource
            {
                Description = $"{path} (this machine)",
                Path = exists ? path : null,
                Bytes = exists ? new FileInfo(path).Length : null,
                Problem = exists ? null : $"no file at '{path}', so nothing could be opened as anyone",
            };
        }

        var description = $"{options.ProtectedSiteFile} in {options.SiteUrl}";
        console.WriteLine($"Fetching {options.ProtectedSiteFile} from the site as the application...");

        var calls = new List<(string Step, HttpObservation Observation)>();

        string accessToken;
        try
        {
            var token = await credential.GetTokenAsync(
                new TokenRequestContext(["https://graph.microsoft.com/.default"]),
                cancellationToken);
            accessToken = token.Token;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Code first, prose after: this whole row is the reason, and a console cell is narrow
            // enough that whatever leads is the only part a reader is guaranteed to see.
            var (code, detail) = AuthErrorCode.Describe(ex);
            return new FileSource
            {
                Description = description,
                Problem = $"{code}: {detail} - no Graph token, so the file was never fetched",
            };
        }

        // Same two hops as 'access': the site URL becomes an ID, then the path becomes an item ID
        // under it. Graph's path addressing takes one colon segment, so the two cannot be chained.
        var relativePath = options.SiteServerRelativePath;
        var siteUrl = string.IsNullOrEmpty(relativePath)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relativePath)}";

        var site = await http.GetAsync(siteUrl, accessToken, cancellationToken);
        calls.Add(("resolve site", site));

        if (ReadStringProperty(site, "id") is not { } siteId)
        {
            return new FileSource
            {
                Description = description,
                Calls = calls,
                Problem = $"the site did not resolve ({site.StatusText} {ApiError.Code(site)}".TrimEnd() +
                          "), so the file was never looked for",
            };
        }

        var itemUrl = $"{GraphBase}/sites/{siteId}/drive/root:{EscapePath(options.ProtectedSiteFile)}";
        var item = await http.GetAsync(itemUrl, accessToken, cancellationToken);
        calls.Add(("resolve item", item));

        if (ReadStringProperty(item, "id") is not { } itemId)
        {
            return new FileSource
            {
                Description = description,
                Calls = calls,
                Problem = $"the file did not resolve ({item.StatusText} {ApiError.Code(item)}".TrimEnd() +
                          $"). A caller who may not see a file is told it does not exist, so this is also what a mistyped path looks like",
            };
        }

        // The name matters: the SDK decides how to read a file from its extension, so a downloaded
        // copy called anything else would be a different measurement.
        var name = ReadStringProperty(item, "name") ?? options.ProtectedSiteFile.Split('/').Last();
        var directory = Path.Combine(Path.GetTempPath(), $"capability-probe-{Guid.NewGuid():n}");
        Directory.CreateDirectory(directory);
        var destination = Path.Combine(directory, name);

        var content = await http.DownloadAsync(
            $"{GraphBase}/sites/{siteId}/drive/items/{itemId}/content",
            accessToken,
            destination,
            cancellationToken);
        calls.Add(("download content", content));

        if (content.DownloadedBytes is not { } bytes)
        {
            Delete(destination);
            return new FileSource
            {
                Description = description,
                Calls = calls,
                IsTemporary = true,
                Problem = $"the content was not returned ({content.StatusText} {ApiError.Code(content)}".TrimEnd() +
                          "), so there was nothing to open",
            };
        }

        return new FileSource
        {
            Description = description,
            Path = destination,
            IsTemporary = true,
            Bytes = bytes,
            Calls = calls,
        };
    }

    /// <summary>Escapes each segment but keeps the separators, so '/my drafts/q3.docx' stays a path.</summary>
    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/').Select(Uri.EscapeDataString));

    private static string? ReadStringProperty(HttpObservation observation, string propertyName)
    {
        if (!observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Deletes the copy this probe made, and the directory it was alone in. A failure to clean up is
    /// not something to end a run over, but it is not nothing either, so it is said out loud.
    /// </summary>
    private void Delete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            var directory = Path.GetDirectoryName(path);
            if (directory is not null && Directory.Exists(directory) && Directory.GetFileSystemEntries(directory).Length == 0)
            {
                Directory.Delete(directory);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            console.WriteLine($"Could not remove the downloaded copy at {path}: {ex.Message}");
        }
    }

    private static Observation FetchObservation(string step, HttpObservation observation) =>
        Observation.Measured(
            $"fetching the file: {step}",
            observation.DownloadedBytes is { } bytes
                ? $"{observation.StatusText}, {bytes} bytes"
                : $"{observation.StatusText} {ApiError.Code(observation)}".TrimEnd()) with
        {
            Details = new Dictionary<string, string?>
            {
                ["url"] = observation.Url,
                ["status"] = observation.StatusText,
                ["graphErrorCode"] = ApiError.Code(observation),
                ["downloadedBytes"] = observation.DownloadedBytes?.ToString(),
                ["elapsedMs"] = observation.ElapsedMs.ToString(),
            },
        };

    private async Task<LegResult> OpenAsync(
        string filePath,
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
                filePath,
                filePath,
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
    /// <para>
    /// It is taken from <see cref="AppOnlyTokenSource"/> rather than built here. This method used to
    /// build its own from the certificate's <em>path</em>, which meant a second, passwordless attempt
    /// at a file the source had already opened with its password: the report printed the thumbprint
    /// off the loaded certificate and then said the credential was unavailable. One place loads the
    /// file, and everything else asks that place for what it made.
    /// </para>
    /// </summary>
    private TokenCredential? BuildCredential(out string description)
    {
        var certificate = AppOnlyTokenSource.WithCertificate(options);
        if (certificate.Credential is { } certificateCredential)
        {
            description = $"app-only, {certificate.Identity}";
            return certificateCredential;
        }

        if (!string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            var secret = AppOnlyTokenSource.WithSecret(options);
            description = options.HasCertificate
                ? $"app-only, {secret.Identity} - the certificate leg was not usable: {certificate.Identity}"
                : $"app-only, {secret.Identity}";
            return secret.Credential;
        }

        description = $"none - {certificate.Identity}, and no client secret is set";
        return null;
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
