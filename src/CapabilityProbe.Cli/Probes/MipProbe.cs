using System.Reflection;
using System.Runtime.InteropServices;
using CapabilityProbe.Reporting;
using Microsoft.InformationProtection;

namespace CapabilityProbe.Probes;

/// <summary>
/// Whether this build, on this machine, can talk to the Microsoft Information Protection SDK at all.
/// <para>
/// It asks nothing of any tenant and needs no configuration. That is the point: before measuring what
/// an app can decrypt, there is a prior question - can the measurement be taken here - and answering it
/// separately keeps the two apart. An experiment that fails because a shared library was missing looks
/// exactly like an experiment that fails because the tenant refused, and only one of those is a finding.
/// </para>
/// <para>
/// This is also where the tool's one dependency on an SDK is visible. Everywhere else the probe builds
/// its own requests so a reader can see the URL and the headers; the MIP SDK hides all of that behind
/// native code. It is here because the question it answers - whether a value passed to the SDK gates
/// authorisation - cannot be asked without it. Every other subcommand is still plain HTTP.
/// </para>
/// <para>
/// The SDK ships one package per platform and only the platform packages carry native binaries. This
/// build references the Ubuntu one, so on Windows the managed types still load and the native call
/// still fails - which this subcommand reports rather than crashes on.
/// </para>
/// </summary>
public sealed class MipProbe(TextWriter console)
{
    /// <summary>The native libraries the managed wrapper needs beside it, in load order.</summary>
    private static readonly string[] ExpectedNativeLibraries =
    [
        "libmip_dotnet.so",
        "libmip_core.so",
        "libmip_file_sdk.so",
        "libmip_protection_sdk.so",
        "libmip_upe_sdk.so",
    ];

    /// <summary>
    /// The system libraries those five link against, and the Debian/Ubuntu package that supplies each.
    /// <para>
    /// Taken from <c>objdump -p</c> on the shipped binaries rather than from a documentation page, so
    /// the list is what the files actually ask for. It is checked because the loader's own message when
    /// one is missing is <c>LoadLibrary failed with error code 0</c> - which names the library that
    /// failed to load but not the one it could not find, and reads like the SDK being broken.
    /// </para>
    /// </summary>
    private static readonly (string Library, string Package)[] SystemDependencies =
    [
        ("libssl.so.3", "libssl3t64"),
        ("libcrypto.so.3", "libssl3t64"),
        ("libsecret-1.so.0", "libsecret-1-0"),
        ("libglib-2.0.so.0", "libglib2.0-0t64"),
        ("libgobject-2.0.so.0", "libglib2.0-0t64"),
        ("libcurl.so.4", "libcurl4t64"),
        ("libxml2.so.2", "libxml2"),
        ("libuuid.so.1", "libuuid1"),
        ("libgsf-1.so.114", "libgsf-1-114"),
        ("libgmime-3.0.so.0", "libgmime-3.0-0"),
    ];

    public Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var report = new ProbeReport("mip");

        var assembly = typeof(MIP).Assembly;
        var directory = Path.GetDirectoryName(assembly.Location) ?? AppContext.BaseDirectory;

        report.Subject["runtime"] = RuntimeInformation.FrameworkDescription;
        report.Subject["os"] = RuntimeInformation.OSDescription.Split('\n')[0];
        report.Subject["arch"] = RuntimeInformation.ProcessArchitecture.ToString();
        report.Subject["sdk"] = $"{assembly.GetName().Name} {assembly.GetName().Version}";

        console.WriteLine("Looking for the SDK's native libraries...");
        var present = ExpectedNativeLibraries
            .Select(name => (Name: name, Path: Path.Combine(directory, name)))
            .Select(x => (x.Name, Exists: File.Exists(x.Path), Size: FileSize(x.Path)))
            .ToList();

        report.Add(new ProbeTable(
            "Native libraries beside the managed assembly",
            ["library", "present", "bytes"],
            present
                .Select(x => (IReadOnlyList<string?>)new[] { x.Name, x.Exists ? "yes" : "no", x.Size })
                .ToList()));

        foreach (var (name, exists, size) in present)
        {
            report.Add(Observation.Measured(
                $"native library {name}",
                exists ? $"present, {size} bytes" : "missing from the output directory"));
        }

        console.WriteLine("Checking the system libraries those link against...");
        var missing = new List<string>();
        var dependencyRows = new List<IReadOnlyList<string?>>();

        foreach (var (library, package) in SystemDependencies)
        {
            var loadable = NativeLibrary.TryLoad(library, out var handle);
            if (loadable)
            {
                NativeLibrary.Free(handle);
            }
            else
            {
                missing.Add($"{library} ({package})");
            }

            dependencyRows.Add(new[] { library, loadable ? "yes" : "no", package });
        }

        report.Add(new ProbeTable(
            "System libraries the SDK links against (names read from the binaries, not from a document)",
            ["library", "loadable", "supplied by (Ubuntu 24.04)"],
            dependencyRows));

        report.Add(missing.Count == 0
            ? Observation.Measured(
                "system libraries the SDK needs",
                $"all {SystemDependencies.Length} could be loaded")
            : Observation.Measured(
                "system libraries the SDK needs",
                $"{missing.Count} of {SystemDependencies.Length} could not be loaded: {string.Join(", ", missing)}") with
            {
                Details = new Dictionary<string, string?>
                {
                    ["missing"] = string.Join(" ", missing),
                    ["note"] = "the SDK's own failure message names the library that failed to load, " +
                               "not the one it could not find - this row is that one",
                },
            });

        console.WriteLine("Initialising the SDK (this is the first call into native code)...");
        report.Add(InitialiseObservation(directory));

        report.Finish();
        return Task.FromResult(report);
    }

    /// <summary>
    /// The measurement this subcommand exists for. Everything above it is managed-only and would pass
    /// on a machine where the SDK cannot run at all; this is the first line that actually crosses into
    /// the native libraries.
    /// <para>
    /// A failure here is recorded, not thrown. The reason matters and differs: a missing file, a
    /// missing system library, a version of glibc too old. Each of those is something a reader can act
    /// on, and none of them is a fact about a tenant.
    /// </para>
    /// </summary>
    private Observation InitialiseObservation(string directory)
    {
        const string subject = "MIP.Initialize(File): can this build reach the SDK";

        try
        {
            MIP.Initialize(MipComponent.File, directory);
            return Observation.Measured(subject, "initialised - the native libraries loaded and ran") with
            {
                Details = new Dictionary<string, string?>
                {
                    ["path"] = directory,
                    ["outcome"] = "initialised",
                },
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // DllNotFoundException names the library it could not open; the loader's own message
            // underneath usually names the system library that was missing, which is the part a
            // Dockerfile has to answer for.
            var detail = ex.Message.Split('\n').FirstOrDefault(l => !string.IsNullOrWhiteSpace(l))?.Trim()
                         ?? ex.Message;

            return Observation.Measured(subject, $"{ex.GetType().Name}: {Clip(detail)}") with
            {
                Details = new Dictionary<string, string?>
                {
                    ["path"] = directory,
                    ["outcome"] = "failed",
                    ["exception"] = ex.GetType().FullName,
                    ["message"] = Clip(ex.Message),
                    ["inner"] = ex.InnerException is null
                        ? null
                        : $"{ex.InnerException.GetType().Name}: {Clip(ex.InnerException.Message)}",
                },
            };
        }
    }

    /// <summary>True when the SDK reached its native code, for a caller that wants a yes or no.</summary>
    public static bool Initialised(ProbeReport report) =>
        report.Observations.Any(o =>
            o.Subject.StartsWith("MIP.Initialize", StringComparison.Ordinal) &&
            o.Details.TryGetValue("outcome", out var outcome) &&
            outcome == "initialised");

    private static string FileSize(string path)
    {
        try
        {
            return File.Exists(path) ? new FileInfo(path).Length.ToString() : "-";
        }
        catch (IOException)
        {
            return "-";
        }
    }

    private static string Clip(string value) =>
        value.Length <= 400 ? value : value[..400] + "...";
}
