using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Asks for a token in all three audiences, twice over - once as the app, once as a person -
/// and reports the six answers. Nothing is called with the tokens; this subcommand only measures
/// which doors the app registration is allowed to knock on.
/// </summary>
public sealed class AuthProbe(ProbeOptions options, TextWriter console)
{
    private static readonly ProbeAudience[] Audiences =
        [ProbeAudience.Graph, ProbeAudience.SharePoint, ProbeAudience.AzureRms];

    private static readonly ProbeMode[] Modes =
        [ProbeMode.AppOnly, ProbeMode.Delegated];

    /// <summary>
    /// Whether the app is expected to hold a usable permission for this pair, given the grants the
    /// README asks for. A cell that lands somewhere else is the finding - either the grants are not
    /// what they were believed to be, or the tenant is not.
    /// <para>
    /// This is deliberately not "is a token issued". Entra hands out tokens for resources an app was
    /// granted nothing for, and those tokens carry no roles and no scopes. Judging by issuance alone
    /// would report such an app as reaching a resource it cannot touch.
    /// </para>
    /// </summary>
    private static bool ExpectsPermission(ProbeAudience audience, ProbeMode mode) => (audience, mode) switch
    {
        (ProbeAudience.Graph, _) => true,

        // Sites.Read.All is granted to the application, not to the delegated flow.
        (ProbeAudience.SharePoint, ProbeMode.AppOnly) => true,
        (ProbeAudience.SharePoint, ProbeMode.Delegated) => false,

        // No Azure RMS permission was granted at all, in either direction.
        (ProbeAudience.AzureRms, _) => false,

        _ => false,
    };

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("auth");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["client"] = options.ClientId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["sign-in"] = options.DelegatedUserHint;

        var results = new Dictionary<(ProbeAudience, ProbeMode), TokenResult?>();

        var appOnly = new AppOnlyTokenSource(options);
        console.WriteLine("Requesting app-only tokens (client credentials, no user)...");
        foreach (var audience in Audiences)
        {
            results[(audience, ProbeMode.AppOnly)] = await appOnly.GetTokenAsync(audience, cancellationToken);
        }

        var delegated = new DelegatedTokenSource(options, console);
        console.WriteLine("Requesting delegated tokens (device code, on behalf of a person)...");
        var signIn = await delegated.SignInAsync(cancellationToken);

        if (signIn.Succeeded)
        {
            foreach (var audience in Audiences)
            {
                results[(audience, ProbeMode.Delegated)] = await delegated.GetTokenAsync(audience, cancellationToken);
            }
        }
        else
        {
            // Sign-in is itself the delegated Graph token request, so that cell is measured.
            // The other two audiences were never reached and must not read as anything else.
            results[(ProbeAudience.Graph, ProbeMode.Delegated)] = signIn;
            results[(ProbeAudience.SharePoint, ProbeMode.Delegated)] = null;
            results[(ProbeAudience.AzureRms, ProbeMode.Delegated)] = null;
        }

        report.Add(BuildMatrix(results));
        report.Add(BuildDetail(results));

        foreach (var audience in Audiences)
        {
            foreach (var mode in Modes)
            {
                report.Add(BuildObservation(audience, mode, results[(audience, mode)]));
            }
        }

        report.Finish();
        return report;
    }

    private ProbeTable BuildMatrix(IReadOnlyDictionary<(ProbeAudience, ProbeMode), TokenResult?> results)
    {
        var rows = Audiences
            .Select(audience => (IReadOnlyList<string?>)new[]
            {
                audience.Display(),
                ScopeResolver.Resolve(audience, options),
                MatrixCell(audience, ProbeMode.AppOnly, results[(audience, ProbeMode.AppOnly)]),
                MatrixCell(audience, ProbeMode.Delegated, results[(audience, ProbeMode.Delegated)]),
            })
            .ToList();

        return new ProbeTable(
            "What the app holds ([!] marks a cell that missed its expectation)",
            ["audience", "scope", "app-only", "delegated"],
            rows);
    }

    private static string MatrixCell(ProbeAudience audience, ProbeMode mode, TokenResult? result)
    {
        if (result is null)
        {
            return "NotRun";
        }

        var text = result switch
        {
            { Succeeded: false } => $"refused: {result.ErrorCode}",
            { Claims: null } => "token, claims unreadable",
            { Claims.CarriesPermission: false } => "token, but nothing granted",
            _ => $"token, {result.Claims.GrantSummary()}",
        };

        if (result.ServedFromCache)
        {
            text += " (cached)";
        }

        return result.CarriesPermission == ExpectsPermission(audience, mode) ? text : $"[!] {text}";
    }

    private static ProbeTable BuildDetail(IReadOnlyDictionary<(ProbeAudience, ProbeMode), TokenResult?> results)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var audience in Audiences)
        {
            foreach (var mode in Modes)
            {
                var result = results[(audience, mode)];
                rows.Add(new[]
                {
                    audience.Display(),
                    mode.Display(),
                    ExpectsPermission(audience, mode) ? "permission" : "none",
                    result is null ? "NotRun" : result.Succeeded ? "issued" : "refused",
                    result?.Claims?.GrantSummary() ?? (result?.Succeeded == true ? "(claims unreadable)" : ""),
                    result?.Claims?.Audience ?? "",
                    result?.ErrorCode ?? "",
                    result is null ? "" : result.ServedFromCache ? "cached" : result.ElapsedMs.ToString(),
                    result?.ErrorDetail ?? "",
                });
            }
        }

        return new ProbeTable(
            "Token requests in detail (token claims are read, not verified - this tool is not their audience)",
            ["audience", "mode", "expected", "token", "granted", "aud claim", "error code", "ms", "error detail"],
            rows);
    }

    private static Observation BuildObservation(ProbeAudience audience, ProbeMode mode, TokenResult? result)
    {
        var expectsPermission = ExpectsPermission(audience, mode);
        var claim = expectsPermission
            ? $"{audience.Display()} / {mode.Display()}: the app holds a usable permission"
            : $"{audience.Display()} / {mode.Display()}: the app holds no usable permission";

        if (result is null)
        {
            return Observation.NotRun(claim, "the delegated sign-in did not complete, so this audience was never requested");
        }

        var timing = result.ServedFromCache ? "from the credential's cache" : $"{result.ElapsedMs} ms";

        var observed = result switch
        {
            { Succeeded: false } => $"token refused with {result.ErrorCode} ({timing})",
            { Claims: null } => $"token issued, but its claims could not be read ({timing})",
            { Claims.CarriesPermission: false } =>
                $"token issued carrying no roles and no scopes - nothing can be called with it ({timing})",
            _ => $"token issued carrying {result.Claims.GrantSummary()} ({timing})",
        };

        return new Observation(claim, observed, result.CarriesPermission == expectsPermission ? Verdict.Ok : Verdict.Failed)
        {
            Details = new Dictionary<string, string?>
            {
                ["audience"] = audience.Display(),
                ["mode"] = mode.Display(),
                ["scope"] = result.Scope,
                ["expectedPermission"] = expectsPermission ? "true" : "false",
                ["tokenIssued"] = result.Succeeded ? "true" : "false",
                ["carriesPermission"] = result.CarriesPermission ? "true" : "false",
                ["audClaim"] = result.Claims?.Audience,
                ["roles"] = result.Claims is null ? null : string.Join(' ', result.Claims.Roles),
                ["scp"] = result.Claims is null ? null : string.Join(' ', result.Claims.Scopes),
                ["signedInAs"] = result.Claims?.SignedInAs,
                ["errorCode"] = result.ErrorCode,
                ["errorDetail"] = result.ErrorDetail,
                ["servedFromCache"] = result.ServedFromCache ? "true" : "false",
                ["elapsedMs"] = result.ElapsedMs.ToString(),
            },
        };
    }
}
