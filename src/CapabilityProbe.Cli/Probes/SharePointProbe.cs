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
/// The calls are not all the same kind of question. <c>/_api/web</c> asks whether the token opens the
/// door at all. <c>/_api/web/currentuser</c> asks who SharePoint thinks is knocking. The two
/// <c>sitegroups</c> calls ask whether the site's groups and their membership can be enumerated, which
/// is a separate capability worth measuring on its own - reading a site and reading who has access to
/// it are not the same permission, and an app can have one without the other.
/// </para>
/// <para>
/// One call goes to Graph instead, against the same site. It is the control: if the SharePoint calls
/// fail and Graph succeeds in the same run with the same credential, the app is not broken and the
/// tenant is not unreachable - the route is what differs. Without it, a wall of refusals could mean
/// anything.
/// </para>
/// <para>
/// Every report carries the token's <c>roles</c>, which is the record of what was granted at the
/// moment of measurement. Running this again after changing the app's permissions produces a report
/// that says, on its own, which grant it was measuring - so a stack of them can be compared without
/// anyone having to remember the order.
/// </para>
/// </summary>
public sealed class SharePointProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    /// <summary>SharePoint answers with a verbose OData envelope unless asked for something plainer.</summary>
    private const string SharePointAccept = "application/json;odata=nometadata";

    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    private sealed record Step(string Name, ProbeAudience Audience, string Url, Func<HttpObservation, string> Summarise)
    {
        public string Accept => Audience == ProbeAudience.SharePoint ? SharePointAccept : "application/json";
    }

    private sealed class Leg
    {
        public required ProbeMode Mode { get; init; }
        public required IReadOnlyDictionary<ProbeAudience, TokenResult> Tokens { get; init; }
        public List<(Step Step, HttpObservation? Observation)> Results { get; } = [];

        public HttpObservation? Find(string stepName) =>
            Results.FirstOrDefault(r => r.Step.Name == stepName).Observation;
    }

    private static readonly ProbeAudience[] Audiences = [ProbeAudience.SharePoint, ProbeAudience.Graph];

    private const string WebStep = "SP GET /_api/web";
    private const string CurrentUserStep = "SP GET /_api/web/currentuser";
    private const string SiteGroupsStep = "SP GET /_api/web/sitegroups";
    private const string GroupUsersStep = "SP GET /_api/web/sitegroups({id})/users";
    private const string GraphStep = "Graph GET /sites/{host}:{path}";

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("sharepoint");
        report.Subject["tenant"] = options.TenantId;
        report.Subject["client"] = options.ClientId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["scope"] = ScopeResolver.Resolve(ProbeAudience.SharePoint, options);
        report.Subject["hint"] = options.DelegatedUserHint;

        var siteUrl = options.SiteUrl.TrimEnd('/');
        var relativePath = options.SiteServerRelativePath;
        var graphSiteUrl = string.IsNullOrEmpty(relativePath)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:{EscapePath(relativePath)}";

        Step[] fixedSteps =
        [
            new(GraphStep, ProbeAudience.Graph, graphSiteUrl, o => SharePointResponses.Field(o, "displayName", "id")),
            new(WebStep, ProbeAudience.SharePoint, $"{siteUrl}/_api/web", o => SharePointResponses.Field(o, "Title")),
            new(CurrentUserStep, ProbeAudience.SharePoint, $"{siteUrl}/_api/web/currentuser", o => SharePointResponses.Field(o, "LoginName")),
            new(SiteGroupsStep, ProbeAudience.SharePoint, $"{siteUrl}/_api/web/sitegroups", SharePointResponses.Groups),
        ];

        console.WriteLine("Establishing the application identity (client credentials, shared secret)...");
        var secretSource = AppOnlyTokenSource.WithSecret(options);
        var secretTokens = await TokensFor(secretSource, cancellationToken);

        // The same app registration proving itself with a key instead. Built whether or not a
        // certificate is configured: an absent one is reported as the reason the leg holds nothing,
        // which is a different statement from the leg not being in the report at all.
        var certificateSource = AppOnlyTokenSource.WithCertificate(options);
        console.WriteLine(certificateSource.IsUnavailable
            ? $"Skipping the certificate identity: {certificateSource.Identity}"
            : "Establishing the application identity (client credentials, certificate)...");
        var certificateTokens = await TokensFor(certificateSource, cancellationToken);

        report.Subject["secret"] = secretSource.Identity;
        report.Subject["cert"] = certificateSource.Identity;

        console.WriteLine("Establishing the delegated identity (device code)...");
        var delegatedSource = new DelegatedTokenSource(options, console);
        var signIn = await delegatedSource.SignInAsync(cancellationToken);

        report.Subject["signed in"] = delegatedSource.SignedInAs ?? "(nobody - sign-in did not complete)";

        if (!delegatedSource.IsSignedIn)
        {
            report.MarkIncomplete(
                "the device code was printed but the sign-in was never completed, so the delegated half " +
                "is empty for want of an identity rather than for want of an answer");
        }

        var delegatedTokens = new Dictionary<ProbeAudience, TokenResult>
        {
            [ProbeAudience.SharePoint] = signIn.Succeeded
                ? await delegatedSource.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken)
                : signIn with { Audience = ProbeAudience.SharePoint },
            [ProbeAudience.Graph] = signIn.Succeeded
                ? await delegatedSource.GetTokenAsync(ProbeAudience.Graph, cancellationToken)
                : signIn,
        };

        // The grant being measured, in the report's own header. A stack of these compares without
        // anyone remembering which run had which permissions. Both app legs are read: they are the
        // same registration and ought to carry the same roles, and if they ever do not, the header is
        // where that has to show rather than the reader assuming one stands for both.
        report.Subject["app roles"] = RolesHeader(secretTokens, certificateTokens);

        var legs = new[]
        {
            new Leg { Mode = ProbeMode.AppOnly, Tokens = secretTokens },
            new Leg { Mode = ProbeMode.AppOnlyCertificate, Tokens = certificateTokens },
            new Leg { Mode = ProbeMode.Delegated, Tokens = delegatedTokens },
        };

        foreach (var step in fixedSteps)
        {
            console.WriteLine($"{step.Name} as every identity...");
            foreach (var leg in legs)
            {
                await RunStepAsync(leg, step, cancellationToken);
            }
        }

        // The chained call. Whichever identity managed to list the groups supplies the ID, and the
        // report says which one did - because an identity that was refused the listing cannot produce
        // an ID of its own, and leaving its membership call unmeasured would drop the very question
        // this run is asking. Borrowing the ID lets all of them be asked the same thing.
        var (groupId, groupSource) = PickGroupId(legs);
        report.Subject["group id"] = groupId is null
            ? "(no group id - no identity could list the site groups)"
            : $"{groupId} (discovered by {groupSource})";

        if (groupId is not null)
        {
            var step = new Step(
                GroupUsersStep,
                ProbeAudience.SharePoint,
                $"{siteUrl}/_api/web/sitegroups({groupId})/users",
                SharePointResponses.Users);

            console.WriteLine($"{step.Name} as every identity...");
            foreach (var leg in legs)
            {
                await RunStepAsync(leg, step, cancellationToken);
            }
        }
        else
        {
            var step = new Step(GroupUsersStep, ProbeAudience.SharePoint, "(not built)", _ => "");
            foreach (var leg in legs)
            {
                leg.Results.Add((step, null));
            }
        }

        report.Add(BuildHoldsTable(legs));
        report.Add(BuildHonoursTable(legs));
        report.Add(BuildCallTable(legs));

        foreach (var leg in legs)
        {
            foreach (var audience in Audiences)
            {
                report.Add(TokenObservation(leg, audience));
            }

            foreach (var (step, observation) in leg.Results)
            {
                report.Add(StepObservation(leg, step, observation));
            }
        }

        foreach (var (step, _) in legs[0].Results)
        {
            report.Add(ContrastObservation(step, legs));
        }

        report.Finish();
        return report;
    }

    private static async Task<IReadOnlyDictionary<ProbeAudience, TokenResult>> TokensFor(
        AppOnlyTokenSource source,
        CancellationToken cancellationToken)
    {
        var tokens = new Dictionary<ProbeAudience, TokenResult>();
        foreach (var audience in Audiences)
        {
            tokens[audience] = await source.GetTokenAsync(audience, cancellationToken);
        }

        return tokens;
    }

    /// <summary>
    /// What the app registration was granted, as both app legs saw it. One line when they agree,
    /// because they normally do and a header that repeats itself is noise; both spelled out when they
    /// do not, because then the disagreement is the more interesting fact in the run.
    /// </summary>
    private static string RolesHeader(
        IReadOnlyDictionary<ProbeAudience, TokenResult> secret,
        IReadOnlyDictionary<ProbeAudience, TokenResult> certificate)
    {
        var fromSecret = Roles(secret);
        var fromCertificate = Roles(certificate);

        return fromSecret == fromCertificate
            ? fromSecret
            : $"secret: {fromSecret} / cert: {fromCertificate}";

        static string Roles(IReadOnlyDictionary<ProbeAudience, TokenResult> tokens) =>
            tokens[ProbeAudience.SharePoint].Claims switch
            {
                null => "(no readable SharePoint token)",
                { Roles.Count: 0 } => "(none)",
                var claims => string.Join(' ', claims.Roles),
            };
    }

    private async Task RunStepAsync(Leg leg, Step step, CancellationToken cancellationToken)
    {
        var token = leg.Tokens[step.Audience];
        if (!token.Succeeded || token.AccessToken is null)
        {
            leg.Results.Add((step, null));
            return;
        }

        leg.Results.Add((step, await http.GetAsync(step.Url, token.AccessToken, cancellationToken, step.Accept)));
    }

    /// <summary>
    /// A site group ID for the membership call, and which identity's answer it came from. The legs are
    /// tried in order, so an identity that listed the groups itself supplies its own ID; the borrow is
    /// the fallback for the ones that were refused the listing.
    /// </summary>
    private static (string? Id, string Source) PickGroupId(IReadOnlyList<Leg> legs)
    {
        foreach (var leg in legs)
        {
            var id = SharePointResponses.FirstGroupId(leg.Find(SiteGroupsStep));
            if (id is not null)
            {
                return (id, leg.Mode.Display());
            }
        }

        return (null, "nobody");
    }

    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/').Select(Uri.EscapeDataString));

    private static ProbeTable BuildHoldsTable(IReadOnlyList<Leg> legs)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var audience in Audiences)
        {
            foreach (var leg in legs)
            {
                var token = leg.Tokens[audience];
                rows.Add(new[]
                {
                    audience.Display(),
                    leg.Mode.Display(),
                    token.StateText,
                    token.Claims?.GrantSummary() ?? (token.Succeeded ? "(claims unreadable)" : ""),
                    token.Claims?.Audience ?? "",
                });
            }
        }

        return new ProbeTable(
            "What Entra issued (claims are read, not verified - this tool is not their audience)",
            ["audience", "mode", "token", "granted", "aud claim"],
            rows);
    }

    private static ProbeTable BuildHonoursTable(IReadOnlyList<Leg> legs)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var (step, _) in legs[0].Results)
        {
            foreach (var leg in legs)
            {
                var observation = leg.Find(step.Name);
                rows.Add(new[]
                {
                    step.Name,
                    leg.Mode.Display(),
                    observation is null ? "NotRun" : observation.StatusText,
                    observation is null ? "" : step.Summarise(observation),
                    observation is null ? "" : observation.ElapsedMs.ToString(),
                });
            }
        }

        return new ProbeTable(
            "What each API honoured",
            ["call", "mode", "status", "what came back", "ms"],
            rows);
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<Leg> legs)
    {
        var rows = new List<IReadOnlyList<string?>>();

        foreach (var leg in legs)
        {
            foreach (var (step, observation) in leg.Results.Where(r => r.Observation is not null))
            {
                rows.Add(new[]
                {
                    leg.Mode.Display(),
                    observation!.Method,
                    observation.Url,
                    observation.StatusText,
                    observation.ElapsedMs.ToString(),
                    ApiError.Code(observation),
                    observation.IsSuccess ? "" : SharePointResponses.Refusal(observation),
                });
            }
        }

        return new ProbeTable(
            "Calls issued (each carried 'Authorization: Bearer <token>'; Accept differs per API, see details)",
            ["mode", "method", "url", "status", "ms", "error code", "why it was refused"],
            rows);
    }

    private static Observation TokenObservation(Leg leg, ProbeAudience audience)
    {
        var token = leg.Tokens[audience];
        var subject = $"{audience.Display()} / {leg.Mode.Display()}: what Entra issued";

        if (!token.Succeeded)
        {
            // A request that was never issued is not a measurement of Entra, so it is not recorded as
            // one. The reason still travels with it, in the row that says nothing was measured.
            var details = new Dictionary<string, string?>
            {
                ["audience"] = audience.Display(),
                ["mode"] = leg.Mode.Display(),
                ["scope"] = token.Scope,
                ["errorCode"] = token.ErrorCode,
                ["errorDetail"] = token.ErrorDetail,
            };

            return (token.Requested
                ? Observation.Measured(subject, $"refused with {token.ErrorCode}")
                : Observation.NotRun(subject, $"no request was issued: {token.ErrorDetail}")) with
            {
                Details = details,
            };
        }

        var observed = token.Claims is null
            ? "token issued, but its claims could not be read"
            : token.Claims.CarriesPermission
                ? $"token issued carrying {token.Claims.GrantSummary()}"
                : "token issued carrying no roles and no scopes";

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["audience"] = audience.Display(),
                ["mode"] = leg.Mode.Display(),
                ["scope"] = token.Scope,
                ["audClaim"] = token.Claims?.Audience,
                ["roles"] = token.Claims is null ? null : string.Join(' ', token.Claims.Roles),
                ["scp"] = token.Claims is null ? null : string.Join(' ', token.Claims.Scopes),
                ["signedInAs"] = token.Claims?.SignedInAs,
            },
        };
    }

    private static Observation StepObservation(Leg leg, Step step, HttpObservation? observation)
    {
        var subject = $"{step.Name} / {leg.Mode.Display()}";

        if (observation is null)
        {
            var token = leg.Tokens[step.Audience];
            return Observation.NotRun(
                subject,
                step.Url == "(not built)"
                    ? "no site group ID was available, so the membership URL was never built"
                    : token.Requested
                        ? $"no {step.Audience.Display()} token was issued for this mode: {token.ErrorCode}"
                        : $"this identity never asked for a token: {token.ErrorDetail}");
        }

        var summary = step.Summarise(observation);
        var observed = observation.IsSuccess
            ? $"{observation.StatusText}, {summary}"
            : $"{observation.StatusText} {summary}".Trim();

        return Observation.Measured(subject, observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["mode"] = leg.Mode.Display(),
                ["audience"] = step.Audience.Display(),
                ["url"] = observation.Url,
                ["requestHeaders"] = string.Join(" | ", observation.RequestHeaders),
                ["responseHeaders"] = string.Join(" | ", observation.ResponseHeaders.Select(h => $"{h.Key}: {h.Value}")),
                ["status"] = observation.StatusText,
                ["errorCode"] = ApiError.Code(observation),
                ["errorMessage"] = ApiError.Message(observation),
                ["unreadBodyShape"] = ShapeOfUnreadBody(observation, summary),
                ["elapsedMs"] = observation.ElapsedMs.ToString(),
            },
        };
    }

    /// <summary>
    /// The opening of a body the summariser could not make sense of, and nothing otherwise.
    /// <para>
    /// A successful call whose body did not parse leaves the same gap as a refusal with no reason: the
    /// report says it could not read the answer without showing what it failed to read. A prefix is
    /// enough to see the shape - whether SharePoint ignored the plain-JSON request and sent its verbose
    /// envelope, say. It is deliberately not the whole body, because the bodies this probe reads
    /// include a group's membership and this report is read in places that directory is not.
    /// </para>
    /// </summary>
    private static string? ShapeOfUnreadBody(HttpObservation observation, string summary)
    {
        // The summarisers wrap every "I could not read this" outcome in parentheses.
        if (!observation.IsSuccess || !summary.StartsWith('(') || string.IsNullOrEmpty(observation.Body))
        {
            return null;
        }

        const int prefix = 200;
        return observation.Body.Length <= prefix
            ? observation.Body
            : observation.Body[..prefix] + "...";
    }

    /// <summary>
    /// What the resource did about the same call for every identity, on one line.
    /// <para>
    /// Three legs no longer fit next to what each one was granted, so this row carries the statuses
    /// alone and the grants move into the details. The statuses are the part that has to survive a
    /// terminal: two identities holding the same claim and getting different answers is the finding,
    /// and it is unreadable if the end of the line is clipped away.
    /// </para>
    /// </summary>
    private static Observation ContrastObservation(Step step, IReadOnlyList<Leg> legs)
    {
        var subject = $"{step.Name}: granted vs honoured";

        if (legs.All(leg => leg.Find(step.Name) is null))
        {
            return Observation.NotRun(subject, "no identity reached this call");
        }

        var details = new Dictionary<string, string?>
        {
            ["call"] = step.Name,
            ["audience"] = step.Audience.Display(),
        };

        foreach (var leg in legs)
        {
            var key = leg.Mode.ShortName();
            details[$"{key}Granted"] = Granted(leg, step);
            details[$"{key}Status"] = Status(leg.Find(step.Name));
        }

        var observed = string.Join(
            "; ",
            legs.Select(leg => $"{leg.Mode.ShortName()} {Status(leg.Find(step.Name))}"));

        return Observation.Measured(subject, observed) with { Details = details };
    }

    private static string Status(HttpObservation? observation) =>
        observation is null ? "NotRun" : observation.StatusText;

    private static string Granted(Leg leg, Step step)
    {
        var token = leg.Tokens[step.Audience];
        return token.Claims switch
        {
            null when !token.Requested => "no request was issued",
            null when !token.Succeeded => "no token",
            null => "unreadable claims",
            { CarriesPermission: false } => "nothing granted",
            var claims => claims.GrantSummary(),
        };
    }
}
