using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// Takes the SharePoint-audience token and actually spends it, as the app and as a person.
/// <para>
/// This exists because <c>auth</c> deliberately stops one step short. It can say a token came back
/// carrying <c>Sites.Read.All</c>, and that is a fact about what Entra issued - not about what
/// SharePoint accepts. The two are different questions and the second one had gone unmeasured: an app
/// can hold a claim the resource declines to honour, and nothing in the token would say so.
/// </para>
/// <para>
/// It matters most for the delegated leg. This app registration has no SharePoint delegated permission
/// at all, yet the delegated token comes back with the SharePoint audience and an <c>scp</c> mirroring
/// the app's Microsoft Graph grants. Whether SharePoint honours a claim that arrived that way is
/// exactly the sort of thing that cannot be reasoned out from the permissions screen.
/// </para>
/// <para>
/// Two calls, because "did the token work" and "as whom" are separate answers.
/// <c>/_api/web</c> is the plainest thing a reader of a site can ask for. <c>/_api/web/currentuser</c>
/// says who SharePoint thinks is calling, which is how the two legs are shown to be genuinely
/// different identities at the resource and not just at the token endpoint.
/// </para>
/// </summary>
public sealed class SharePointProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    /// <summary>SharePoint answers with a verbose OData envelope unless asked for something plainer.</summary>
    private const string Accept = "application/json;odata=nometadata";

    private sealed record Call(string Name, string Url, Func<HttpObservation, string> Summarise);

    private sealed record Leg
    {
        public required ProbeMode Mode { get; init; }
        public required TokenResult Token { get; init; }
        public IReadOnlyList<(Call Call, HttpObservation? Observation)> Results { get; init; } = [];
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("sharepoint");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["client"] = options.ClientId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["scope"] = ScopeResolver.Resolve(ProbeAudience.SharePoint, options);
        report.Subject["hint"] = options.DelegatedUserHint;

        var siteUrl = options.SiteUrl.TrimEnd('/');
        var calls = new[]
        {
            new Call("GET /_api/web", $"{siteUrl}/_api/web", o => Describe(o, "Title")),
            new Call("GET /_api/web/currentuser", $"{siteUrl}/_api/web/currentuser", o => Describe(o, "LoginName")),
        };

        console.WriteLine("Requesting a SharePoint token as the application (client credentials)...");
        var appOnlyToken = await new AppOnlyTokenSource(options)
            .GetTokenAsync(ProbeAudience.SharePoint, cancellationToken);

        console.WriteLine("Requesting a SharePoint token on behalf of a person (device code)...");
        var delegatedSource = new DelegatedTokenSource(options, console);
        var signIn = await delegatedSource.SignInAsync(cancellationToken);

        report.Subject["signed in"] = delegatedSource.SignedInAs ?? "(nobody - sign-in did not complete)";

        if (!delegatedSource.IsSignedIn)
        {
            report.MarkIncomplete(
                "the device code was printed but the sign-in was never completed, so the delegated half " +
                "is empty for want of an identity rather than for want of an answer");
        }

        var delegatedToken = signIn.Succeeded
            ? await delegatedSource.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken)
            : signIn with { Audience = ProbeAudience.SharePoint };

        var appOnly = await SpendAsync(ProbeMode.AppOnly, appOnlyToken, calls, cancellationToken);
        var delegated = await SpendAsync(ProbeMode.Delegated, delegatedToken, calls, cancellationToken);

        report.Add(BuildHoldsTable(appOnly, delegated));
        report.Add(BuildHonoursTable(appOnly, delegated, calls));
        report.Add(BuildCallTable(appOnly, delegated));

        foreach (var leg in new[] { appOnly, delegated })
        {
            report.Add(TokenObservation(leg));
            foreach (var (call, observation) in leg.Results)
            {
                report.Add(CallObservation(leg, call, observation));
            }
        }

        foreach (var call in calls)
        {
            report.Add(ContrastObservation(call, appOnly, delegated));
        }

        report.Finish();
        return report;
    }

    private async Task<Leg> SpendAsync(
        ProbeMode mode,
        TokenResult token,
        IReadOnlyList<Call> calls,
        CancellationToken cancellationToken)
    {
        var leg = new Leg { Mode = mode, Token = token };

        if (!token.Succeeded || token.AccessToken is null)
        {
            return leg with { Results = calls.Select(c => (c, (HttpObservation?)null)).ToList() };
        }

        console.WriteLine($"Spending the {mode.Display()} SharePoint token...");

        var results = new List<(Call, HttpObservation?)>();
        foreach (var call in calls)
        {
            results.Add((call, await http.GetAsync(call.Url, token.AccessToken, cancellationToken, Accept)));
        }

        return leg with { Results = results };
    }

    /// <summary>
    /// A short readable proof that something actually came back, rather than just a 200.
    /// A status alone would not distinguish a real answer from an empty one.
    /// </summary>
    private static string Describe(HttpObservation observation, string property)
    {
        if (!observation.IsSuccess)
        {
            var code = ApiError.Code(observation);
            return code.Length == 0 ? "" : code;
        }

        if (string.IsNullOrWhiteSpace(observation.Body))
        {
            return "(empty body)";
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
                ? $"{property}: {value.GetString()}"
                : $"(no {property} in the response)";
        }
        catch (JsonException)
        {
            return "(response was not JSON)";
        }
    }

    private static ProbeTable BuildHoldsTable(Leg appOnly, Leg delegatedLeg)
    {
        var rows = new[] { appOnly, delegatedLeg }
            .Select(l => (IReadOnlyList<string?>)new[]
            {
                l.Mode.Display(),
                l.Token.Succeeded ? "issued" : $"refused: {l.Token.ErrorCode}",
                l.Token.Claims?.GrantSummary() ?? (l.Token.Succeeded ? "(claims unreadable)" : ""),
                l.Token.Claims?.Audience ?? "",
                l.Token.Claims?.SignedInAs ?? "",
            })
            .ToList();

        return new ProbeTable(
            "What Entra issued (claims are read, not verified - this tool is not their audience)",
            ["mode", "token", "granted", "aud claim", "upn claim"],
            rows);
    }

    private static ProbeTable BuildHonoursTable(Leg appOnly, Leg delegatedLeg, IReadOnlyList<Call> calls)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var call in calls)
        {
            foreach (var leg in new[] { appOnly, delegatedLeg })
            {
                var observation = leg.Results.FirstOrDefault(r => r.Call.Name == call.Name).Observation;
                rows.Add(new[]
                {
                    call.Name,
                    leg.Mode.Display(),
                    observation is null ? "NotRun" : observation.StatusText,
                    observation is null ? "" : call.Summarise(observation),
                    observation is null ? "" : observation.ElapsedMs.ToString(),
                });
            }
        }

        return new ProbeTable(
            "What SharePoint honoured",
            ["call", "mode", "status", "what came back", "ms"],
            rows);
    }

    private static ProbeTable BuildCallTable(Leg appOnly, Leg delegatedLeg)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var leg in new[] { appOnly, delegatedLeg })
        {
            foreach (var (call, observation) in leg.Results.Where(r => r.Observation is not null))
            {
                rows.Add(new[]
                {
                    leg.Mode.Display(),
                    observation!.Method,
                    observation.Url,
                    observation.StatusText,
                    observation.ElapsedMs.ToString(),
                    ApiError.Code(observation),
                    ApiError.Message(observation),
                });
            }
        }

        return new ProbeTable(
            $"Calls issued (every one carried 'Authorization: Bearer <token>' and 'Accept: {Accept}')",
            ["mode", "method", "url", "status", "ms", "error code", "error message"],
            rows);
    }

    private static Observation TokenObservation(Leg leg)
    {
        var subject = $"{leg.Mode.Display()}: what Entra issued for the SharePoint audience";

        if (!leg.Token.Succeeded)
        {
            return Observation.Measured(subject, $"refused with {leg.Token.ErrorCode}") with
            {
                Details = new Dictionary<string, string?>
                {
                    ["mode"] = leg.Mode.Display(),
                    ["scope"] = leg.Token.Scope,
                    ["errorCode"] = leg.Token.ErrorCode,
                    ["errorDetail"] = leg.Token.ErrorDetail,
                },
            };
        }

        var observed = leg.Token.Claims is null
            ? "token issued, but its claims could not be read"
            : leg.Token.Claims.CarriesPermission
                ? $"token issued carrying {leg.Token.Claims.GrantSummary()}"
                : "token issued carrying no roles and no scopes";

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["mode"] = leg.Mode.Display(),
                ["scope"] = leg.Token.Scope,
                ["audClaim"] = leg.Token.Claims?.Audience,
                ["roles"] = leg.Token.Claims is null ? null : string.Join(' ', leg.Token.Claims.Roles),
                ["scp"] = leg.Token.Claims is null ? null : string.Join(' ', leg.Token.Claims.Scopes),
                ["signedInAs"] = leg.Token.Claims?.SignedInAs,
            },
        };
    }

    private static Observation CallObservation(Leg leg, Call call, HttpObservation? observation)
    {
        var subject = $"{call.Name} / {leg.Mode.Display()}";

        if (observation is null)
        {
            return Observation.NotRun(subject, "no SharePoint token was issued for this mode");
        }

        var summary = call.Summarise(observation);
        var observed = observation.IsSuccess
            ? $"{observation.StatusText}, {summary}"
            : $"{observation.StatusText} {summary}".Trim();

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["mode"] = leg.Mode.Display(),
                ["url"] = observation.Url,
                ["requestHeaders"] = string.Join(" | ", observation.RequestHeaders),
                ["status"] = observation.StatusText,
                ["errorCode"] = ApiError.Code(observation),
                ["errorMessage"] = ApiError.Message(observation),
                ["elapsedMs"] = observation.ElapsedMs.ToString(),
            },
        };
    }

    /// <summary>
    /// The pairing that gives this subcommand its point: what the token said, next to what the resource
    /// did about it. A claim honoured and a claim declined look identical until the call is made.
    /// </summary>
    private static Observation ContrastObservation(Call call, Leg appOnly, Leg delegatedLeg)
    {
        var subject = $"{call.Name}: does SharePoint honour what the token carries";

        var appResult = appOnly.Results.FirstOrDefault(r => r.Call.Name == call.Name).Observation;
        var delegatedResult = delegatedLeg.Results.FirstOrDefault(r => r.Call.Name == call.Name).Observation;

        if (appResult is null && delegatedResult is null)
        {
            return Observation.NotRun(subject, "neither mode was issued a SharePoint token");
        }

        var observed =
            $"app-only {Side(appOnly, appResult)}; delegated {Side(delegatedLeg, delegatedResult)}";

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["call"] = call.Name,
                ["appOnlyGranted"] = appOnly.Token.Claims?.GrantSummary(),
                ["appOnlyStatus"] = appResult is null ? "NotRun" : appResult.StatusText,
                ["delegatedGranted"] = delegatedLeg.Token.Claims?.GrantSummary(),
                ["delegatedStatus"] = delegatedResult is null ? "NotRun" : delegatedResult.StatusText,
            },
        };
    }

    /// <summary>One identity's half: what it was granted, and what happened when it spent it.</summary>
    private static string Side(Leg leg, HttpObservation? observation)
    {
        var granted = leg.Token.Claims switch
        {
            null when !leg.Token.Succeeded => "no token",
            null => "unreadable claims",
            { CarriesPermission: false } => "nothing granted",
            var claims => claims.GrantSummary(),
        };

        return $"{granted} -> {(observation is null ? "NotRun" : observation.StatusText)}";
    }
}
