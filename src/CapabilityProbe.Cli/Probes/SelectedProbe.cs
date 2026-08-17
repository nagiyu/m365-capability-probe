using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// What a site the app was never granted answers, under site-by-site permission.
/// <para>
/// With <c>Sites.Selected</c> the consent grants nothing on its own: each site has to be granted
/// separately, one <c>POST /sites/{id}/permissions</c> at a time. What an ungranted site says when
/// asked anyway is not written down - and the three answers it could give are not equally safe.
/// A <c>403</c> or a <c>404</c> is a refusal a caller can see. <b>A <c>200</c> with an empty
/// collection is not</b>: a site somebody forgot to grant then reads as a site with nothing in it,
/// and nothing in the reply says otherwise.
/// </para>
/// <para>
/// So the same ladder of calls is put to every site in one run - a granted one, a granted-with-more
/// one, and an ungranted one - and the replies are set side by side. One site alone cannot answer
/// this: an empty library and an empty answer look the same until a site known to have files answers
/// the same call.
/// </para>
/// <para>
/// The app must hold <c>Sites.Selected</c> and nothing wider. A tenant-wide read alongside it would
/// make every site answer, and the run would measure that instead - which is the one outcome that
/// looks like success while establishing nothing.
/// </para>
/// </summary>
public sealed class SelectedProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    private const string SharePointAccept = "application/json;odata=nometadata";

    /// <summary>One site, and what every rung of the ladder said about it.</summary>
    private sealed record Site(string Url)
    {
        public string? Id { get; set; }
        public string? DriveId { get; set; }
        public string? ItemId { get; set; }

        public List<Rung> Rungs { get; } = [];
    }

    /// <summary>
    /// One call against one site. <see cref="Count"/> is the point of the whole run: a status alone
    /// cannot tell a refusal from a silence, and <c>200</c> with zero rows is the answer this exists
    /// to catch.
    /// </summary>
    private sealed record Rung(string Name, string Method, string Url)
    {
        public int? Status { get; set; }
        public string StatusText { get; set; } = "(never issued)";
        public string? ErrorCode { get; set; }
        public int? Count { get; set; }
        public string? Note { get; set; }

        public bool Issued => Status is not null || Note is null;

        /// <summary>
        /// True where the service answered success and handed back nothing. Kept apart from a refusal
        /// and from "not asked", because those are three different things and only one of them is
        /// invisible to a caller who is only checking for errors.
        /// </summary>
        public bool SilentlyEmpty => Status is >= 200 and < 300 && Count == 0;

        public string Answer => Status is null
            ? Note ?? "(not issued)"
            : SilentlyEmpty
                ? $"{StatusText}, and the collection was EMPTY"
                : Count is { } count
                    ? $"{StatusText}, {count} row(s)"
                    : StatusText;
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("selected");
        var app = options.InventoryApp;

        report.Subject["tenant"] = options.TenantId;
        report.Subject["speaking as"] = app.Label;
        report.Subject["sites asked"] = string.Join(", ", options.Sites);
        report.Subject["asking"] = "what a site this app was never granted answers, beside sites it was";
        report.Subject["the answer that matters"] = "200 with an empty collection - a refusal is visible, " +
                                                    "a silence is not, and a site nobody granted then " +
                                                    "reads as a site with nothing in it";

        var source = AppOnlyTokenSource.WithCertificate(options, app);
        if (source.IsUnavailable)
        {
            console.WriteLine($"No certificate for {app.Label}: {source.Identity}. Falling back to the secret.");
            source = AppOnlyTokenSource.WithSecret(options, app);
        }

        report.Subject["proof of identity"] = source.Identity;

        var caller = new ThrottleAwareCaller(http);
        var calls = new List<HttpObservation>();

        var graph = await source.GetTokenAsync(ProbeAudience.Graph, cancellationToken);
        var sharePoint = await source.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken);

        report.Subject["Graph token"] = Describe(graph);
        report.Subject["SharePoint token"] = Describe(sharePoint);

        if (!graph.Succeeded || graph.AccessToken is null)
        {
            report.MarkIncomplete($"no Graph token: {graph.ErrorCode}");
            report.Add(Observation.NotRun("every site", $"no Graph token was issued: {graph.ErrorDetail}"));
            report.Finish();
            return report;
        }

        if (options.Sites.Count < 2)
        {
            report.Add(Observation.NotRun("the comparison",
                $"{options.Sites.Count} site(s) were named. This shape needs at least two - what an " +
                "ungranted site answers means nothing without a granted one answering the same call " +
                "in the same run. The rungs below still ran, and are reported as measurements"));
        }

        var sites = options.Sites.Select(u => new Site(u)).ToList();

        foreach (var site in sites)
        {
            console.WriteLine($"Walking {site.Url}...");
            await WalkAsync(caller, site, graph.AccessToken, sharePoint.AccessToken, calls, cancellationToken);
        }

        report.Subject["throttling"] = caller.Record.Summary;

        report.Add(BuildLadderTable(sites));
        report.Add(BuildShapeTable(sites));
        report.Add(BuildCallTable(calls));

        report.Add(SilenceObservation(sites));

        foreach (var site in sites)
        {
            report.Add(SiteObservation(site));
        }

        report.Add(GrantObservation());
        report.Finish();
        return report;
    }

    /// <summary>
    /// The same ladder for every site, in the same order, in one run. Identical by construction rather
    /// than by care: the rungs are built from the site's own ids as they are discovered, and a rung
    /// that could not be addressed says so instead of being skipped quietly.
    /// </summary>
    private async Task WalkAsync(
        ThrottleAwareCaller caller,
        Site site,
        string graphToken,
        string? sharePointToken,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(site.Url, UriKind.Absolute, out var uri))
        {
            site.Rungs.Add(new Rung("resolve the site", "GET", site.Url)
            {
                Note = "this is not an absolute URL, so nothing could be addressed",
            });
            return;
        }

        var address = $"{GraphBase}/sites/{uri.Host}:" +
                      string.Join('/', uri.AbsolutePath.TrimEnd('/').Split('/').Select(Uri.EscapeDataString));

        var resolved = await Ask(caller, site, "resolve the site", "GET", address, graphToken, calls,
            cancellationToken);

        site.Id = resolved is null ? null : Text(resolved.Value, "id");

        if (site.Id is null)
        {
            foreach (var name in new[] { "list the site's files", "read a file's label", "read a file's sharing", "read the site's own grants" })
            {
                site.Rungs.Add(new Rung(name, "GET", "(no site id)")
                {
                    Note = "the site was never resolved, so this rung had nothing to address",
                });
            }
        }
        else
        {
            var drive = await Ask(caller, site, "resolve the library", "GET",
                $"{GraphBase}/sites/{site.Id}/drive?$select=id,webUrl", graphToken, calls, cancellationToken);
            site.DriveId = drive is null ? null : Text(drive.Value, "id");

            var children = site.DriveId is null
                ? null
                : await Ask(caller, site, "list the site's files", "GET",
                    $"{GraphBase}/drives/{site.DriveId}/root/children?$select=id,name,file",
                    graphToken, calls, cancellationToken);

            site.ItemId = FirstId(children);

            if (site.DriveId is null)
            {
                site.Rungs.Add(new Rung("list the site's files", "GET", "(no drive id)")
                {
                    Note = "the library was never resolved, so this rung had nothing to address",
                });
            }

            if (site.ItemId is null)
            {
                foreach (var name in new[] { "read a file's label", "read a file's sharing" })
                {
                    site.Rungs.Add(new Rung(name, "GET", "(no item id)")
                    {
                        Note = "no file came back from the listing, so there was nothing to ask about. " +
                               "Whether that is an empty library or an empty answer is the row above",
                    });
                }
            }
            else
            {
                await Ask(caller, site, "read a file's label", "GET",
                    $"{GraphBase}/drives/{site.DriveId}/items/{site.ItemId}?$select=id,name,sensitivityLabel",
                    graphToken, calls, cancellationToken);

                await Ask(caller, site, "read a file's sharing", "GET",
                    $"{GraphBase}/drives/{site.DriveId}/items/{site.ItemId}/permissions",
                    graphToken, calls, cancellationToken);
            }

            await Ask(caller, site, "read the site's own grants", "GET",
                $"{GraphBase}/sites/{site.Id}/permissions", graphToken, calls, cancellationToken);
        }

        // The other surface. Sites.Selected is a Graph-side idea and SharePoint REST is a different
        // door onto the same site, so a run that only asks Graph would answer half the question.
        if (sharePointToken is null)
        {
            site.Rungs.Add(new Rung("list the site's groups", "GET", $"{site.Url}/_api/web/sitegroups")
            {
                Note = "no SharePoint token was issued, so this surface was never asked",
            });
            return;
        }

        await Ask(caller, site, "list the site's groups", "GET",
            $"{site.Url.TrimEnd('/')}/_api/web/sitegroups", sharePointToken, calls, cancellationToken,
            SharePointAccept);
    }

    /// <summary>One rung: issued, recorded, and reduced to a status plus a row count.</summary>
    private static async Task<JsonElement?> Ask(
        ThrottleAwareCaller caller,
        Site site,
        string name,
        string method,
        string url,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken,
        string? accept = null)
    {
        var observation = accept is null
            ? await caller.GetAsync(url, token, cancellationToken)
            : await caller.GetAsync(url, token, cancellationToken, accept);

        calls.Add(observation);

        var rung = new Rung(name, method, url)
        {
            Status = observation.StatusCode,
            StatusText = observation.StatusText,
            ErrorCode = ApiError.Code(observation),
        };

        var root = Root(observation);
        if (root is not null)
        {
            rung.Count = root.Value.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array
                ? value.GetArrayLength()
                : null;
        }

        site.Rungs.Add(rung);
        return root;
    }

    private static ProbeTable BuildLadderTable(IReadOnlyList<Site> sites)
    {
        var rows = sites
            .SelectMany(s => s.Rungs.Select(r => (IReadOnlyList<string?>)
            [
                s.Url,
                r.Name,
                r.SilentlyEmpty ? "EMPTY" : r.Status?.ToString() ?? "-",
                r.Answer,
                r.ErrorCode,
            ]))
            .ToList();

        return new ProbeTable(
            "The same ladder, put to every site",
            ["site", "rung", "status", "what came back", "error code"],
            rows.Count == 0 ? [["(no site was named)", "-", "-", "-", "-"]] : rows);
    }

    /// <summary>
    /// The rungs across sites, one row per rung, so a reader compares the thing that differs rather
    /// than scrolling between blocks. A difference between two sites on one rung is the measurement;
    /// a difference between two rungs on one site is not.
    /// </summary>
    private static ProbeTable BuildShapeTable(IReadOnlyList<Site> sites)
    {
        var names = sites.SelectMany(s => s.Rungs.Select(r => r.Name)).Distinct().ToList();

        var rows = names
            .Select(name => (IReadOnlyList<string?>)(new[] { name }
                .Concat(sites.Select(s => s.Rungs.FirstOrDefault(r => r.Name == name)?.Answer ?? "(no such rung)"))
                .ToArray()))
            .ToList();

        return new ProbeTable(
            "The same rung, across the sites",
            new[] { "rung" }.Concat(sites.Select(s => Short(s.Url))).ToArray(),
            rows.Count == 0 ? [["(no rung ran)"]] : rows);
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)new[]
            {
                c.Method, c.Url, c.StatusText, c.ElapsedMs.ToString(), ApiError.Code(c),
            }).ToList());

    /// <summary>
    /// The headline, and the count that decides it first. A silent empty is the outcome the request
    /// asked to have made loud, so it is counted before anything else in the sentence and named in
    /// capitals in the table - a reader skimming for red will otherwise skim past exactly this.
    /// </summary>
    private static Observation SilenceObservation(IReadOnlyList<Site> sites)
    {
        var silent = sites
            .SelectMany(s => s.Rungs.Where(r => r.SilentlyEmpty).Select(r => $"{Short(s.Url)}: {r.Name}"))
            .ToList();

        var refused = sites
            .SelectMany(s => s.Rungs.Where(r => r.Status is >= 400))
            .ToList();

        var observed =
            $"{silent.Count} rung(s) answered success with an empty collection, {refused.Count} refused" +
            (silent.Count == 0
                ? string.Empty
                : $". Silent: {string.Join("; ", silent)}");

        return Observation.Measured("did any site answer with a silence rather than a refusal", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["whyThisIsTheHeadline"] = "a refusal is visible to a caller and a silence is not. A site " +
                                           "nobody remembered to grant, answering 200 with nothing in it, " +
                                           "is indistinguishable from a site with nothing in it",
                ["refusalCodes"] = refused.Count == 0
                    ? "(none)"
                    : string.Join("; ", refused.Select(r => $"{r.Name}: {r.StatusText} {r.ErrorCode}").Distinct()),
            },
        };
    }

    private static Observation SiteObservation(Site site)
    {
        var issued = site.Rungs.Count(r => r.Status is not null);
        var ok = site.Rungs.Count(r => r.Status is >= 200 and < 300);
        var empty = site.Rungs.Count(r => r.SilentlyEmpty);
        var refused = site.Rungs.Count(r => r.Status is >= 400);
        var skipped = site.Rungs.Count(r => r.Status is null);

        return Observation.Measured(Short(site.Url),
            $"{empty} empty, {refused} refused, {ok - empty} answered with rows; " +
            $"{issued} rung(s) issued, {skipped} not issued") with
        {
            Details = new Dictionary<string, string?>
            {
                ["siteId"] = site.Id ?? "(never resolved)",
                ["driveId"] = site.DriveId ?? "(never resolved)",
                ["firstItemId"] = site.ItemId ?? "(no file came back)",
            },
        };
    }

    /// <summary>
    /// What this run does not establish about the grants themselves. The probe reads; it does not
    /// grant, and it cannot see the grant it was given - so "site 3 is ungranted" is the operator's
    /// statement, not a measurement, and the report says which is which.
    /// </summary>
    private static Observation GrantObservation() =>
        Observation.Measured("what this shape can and cannot claim",
            "it can say what each site answered to the same calls, in one run, as one identity. It " +
            "cannot say which sites were granted: that was done outside this tool, and the run has no " +
            "way to check it beyond the 'read the site's own grants' rung - which is itself one of the " +
            "calls under test, and answers nothing on a site that refuses everything");

    private static string Short(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.AbsolutePath.TrimEnd('/') : url;

    private static string? FirstId(JsonElement? body)
    {
        if (body is null || !body.Value.TryGetProperty("value", out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var entry in value.EnumerateArray())
        {
            if (entry.TryGetProperty("file", out _) && Text(entry, "id") is { } id)
            {
                return id;
            }
        }

        return null;
    }

    private static JsonElement? Root(HttpObservation? observation)
    {
        if (observation is null || !observation.IsSuccess || string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(observation.Body).RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string Describe(TokenResult token) =>
        !token.Succeeded
            ? $"none - {token.ErrorCode}: {token.ErrorDetail}"
            : token.Claims?.GrantSummary() ?? "issued, but its claims could not be read";
}
