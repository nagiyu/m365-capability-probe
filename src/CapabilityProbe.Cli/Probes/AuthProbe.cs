using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Asks for a token in all three audiences, twice over - once as the app, once as a person - and
/// reports the six answers. Nothing is called with the tokens; this subcommand only records which
/// doors the app registration is allowed to knock on, and what it is holding when it gets in.
/// <para>
/// It states no expectation about any of that. What the grants ought to produce is an argument about
/// a particular tenant, and it belongs in prose where it can carry a date and a reason.
/// </para>
/// </summary>
public sealed class AuthProbe(ProbeOptions options, TextWriter console)
{
    private static readonly ProbeAudience[] Audiences =
        [ProbeAudience.Graph, ProbeAudience.SharePoint, ProbeAudience.AzureRms];

    private static readonly ProbeMode[] Modes =
        [ProbeMode.AppOnly, ProbeMode.Delegated];

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("auth");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["client"] = options.ClientId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["hint"] = options.DelegatedUserHint;

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

        // Who actually signed in, not who was configured to. A run completed by the wrong account
        // measures that account's reach, and the report has to say so on its own months from now.
        report.Subject["signed in"] = delegated.SignedInAs ?? "(nobody - sign-in did not complete)";

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
                MatrixCell(results[(audience, ProbeMode.AppOnly)]),
                MatrixCell(results[(audience, ProbeMode.Delegated)]),
            })
            .ToList();

        return new ProbeTable(
            "What the app holds",
            ["audience", "scope", "app-only", "delegated"],
            rows);
    }

    private static string MatrixCell(TokenResult? result)
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

        return result.ServedFromCache ? $"{text} (cached)" : text;
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
                    result is null ? "NotRun" : result.Succeeded ? "issued" : "refused",
                    result?.Claims?.GrantSummary() ?? (result?.Succeeded == true ? "(claims unreadable)" : ""),
                    result?.Claims?.Audience ?? "",
                    result?.Claims?.SignedInAs ?? "",
                    result?.ErrorCode ?? "",
                    result is null ? "" : result.ServedFromCache ? "cached" : result.ElapsedMs.ToString(),
                    result?.ErrorDetail ?? "",
                });
            }
        }

        return new ProbeTable(
            "Token requests in detail (token claims are read, not verified - this tool is not their audience)",
            ["audience", "mode", "token", "granted", "aud claim", "upn claim", "error code", "ms", "error detail"],
            rows);
    }

    private static Observation BuildObservation(ProbeAudience audience, ProbeMode mode, TokenResult? result)
    {
        var subject = $"{audience.Display()} / {mode.Display()}: what the app holds";

        if (result is null)
        {
            return Observation.NotRun(subject, "the delegated sign-in did not complete, so this audience was never requested");
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

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["audience"] = audience.Display(),
                ["mode"] = mode.Display(),
                ["scope"] = result.Scope,
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
