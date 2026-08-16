using System.Text.Json;
using CapabilityProbe.Auth;
using CapabilityProbe.Configuration;
using CapabilityProbe.Http;
using CapabilityProbe.Reporting;

namespace CapabilityProbe.Probes;

/// <summary>
/// What <c>Prefer: hierarchicalsharing</c> does to a drive's delta, and what it costs in permission.
/// <para>
/// Microsoft documents the header's existence without saying what a caller must hold to use it. That
/// makes it a thing to measure rather than to look up, which is what this subcommand is for.
/// </para>
/// <para>
/// It is deliberately not the route finding 8 measured. That one was
/// <c>delta?$expand=permissions</c>, which answered <c>501 notSupported</c> under both grant states -
/// a closed door, and a different door. Nothing here asks for an expansion, so a refusal seen here is
/// about this header and not about that one.
/// </para>
/// <para>
/// Several legs in one run: the same call, once with nothing, once with the header under test, and
/// once with each of a set of controls. Everything else - the token, the drive, the minute - is held
/// still, so a difference between the legs is the header. Swapping the app's SharePoint grant between
/// runs is what splits the permission question, and the roles each token actually carries are printed
/// so the two runs label themselves rather than relying on anyone's memory of which one was which.
/// </para>
/// <para>
/// The controls are there because of what finding 19 could not settle. Three runs returned
/// <c>200 OK</c> with no <c>Preference-Applied</c>, which is what a preference being ignored looks
/// like - and also what a route that never echoes anything looks like. One leg cannot tell those
/// apart. Sending preferences whose fate is knowable alongside it can: a preference that visibly
/// changes the response proves the route acts on some of them, and a preference invented here proves
/// the echo means something when it does arrive.
/// </para>
/// </summary>
public sealed class DeltaProbe(ProbeOptions options, ProbeHttpClient http, TextWriter console)
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";

    /// <summary>
    /// The header under test. Sent exactly as written - a preference the service does not recognise
    /// is supposed to be ignored rather than refused, so the spelling is part of the measurement.
    /// </summary>
    private const string PreferenceName = "Prefer";

    private const string PreferenceValue = "hierarchicalsharing";

    /// <summary>
    /// A bound on how many pages one leg will follow. Delta enumerates a whole drive, and a run that
    /// walked forever would report nothing at all; reaching this is reported as reaching it.
    /// </summary>
    private const int DefaultPages = 20;

    /// <summary>
    /// The page size the OData control asks for. Small enough that a library of any size splits, so
    /// "it was applied" is visible as a page count rather than only as an echoed header.
    /// </summary>
    private const int ControlPageSize = 5;

    /// <summary>
    /// A preference made up for this run. Nothing can recognise it, so an echo of it would mean the
    /// echo is not evidence of anything - which is worth knowing before reading the other rows.
    /// </summary>
    private const string InventedPreference = "no-such-preference-e3f1";

    /// <summary>
    /// The preferences sent beside the one under test, and why each is here. None of them is expected
    /// to do anything in particular - they are here so that the answer for
    /// <c>hierarchicalsharing</c> has something to be read against.
    /// </summary>
    private static readonly (string Value, string Why)[] Controls =
    [
        // The one control whose fate can be read without trusting the echo at all: if the service
        // applies it, the walk takes more pages, and a page count is not something a header can hide.
        ($"odata.maxpagesize={ControlPageSize}",
            "standard OData - if applied, the page count moves, echo or no echo"),

        // Documented on this exact route, so if the route echoes anything it should echo these.
        ("deltashowremovedasdeleted", "documented for this route"),
        ("deltashowsharingchanges", "documented for this route - the nearest neighbour to the one under test"),
        ("deltatraversepermissiongaps", "documented for this route"),

        // Graph-wide rather than route-specific: a different way for an echo to be reachable.
        ("include-unknown-enum-members", "documented across Graph rather than for this route"),

        // Invented here. If this comes back echoed, an echo says nothing about whether a preference
        // was understood, and every other row in the table loses its meaning.
        (InventedPreference, "invented for this run - nothing should recognise it"),
    ];

    private sealed record Item(string Id, string Name, string Path, IReadOnlyList<string> Keys, JsonElement Raw);

    private sealed record Leg
    {
        public required string Name { get; init; }
        public required bool SendsHeader { get; init; }

        /// <summary>What this leg is in the run for, printed beside it so no row needs explaining.</summary>
        public required string Purpose { get; init; }

        /// <summary>The preference value sent, or null for the baseline.</summary>
        public string? Preference { get; init; }

        public List<Item> Items { get; } = [];

        public int Pages { get; set; }

        /// <summary>The status of the first call, which is where a refusal of the header would land.</summary>
        public string? FirstStatus { get; set; }

        /// <summary>What the service said it did with the preference, if it said anything.</summary>
        public string? PreferenceApplied { get; set; }

        /// <summary>The refusal body, kept whole. A header question is answered by what it said.</summary>
        public string? RefusalBody { get; set; }

        public string? Stopped { get; set; }

        public bool SawDeltaLink { get; set; }

        /// <summary>Every property name any item in this leg carried.</summary>
        public HashSet<string> Keys { get; } = new(StringComparer.Ordinal);
    }

    public async Task<ProbeReport> RunAsync(CancellationToken cancellationToken)
    {
        var report = new ProbeReport("delta");
        var app = options.InventoryApp;

        report.Subject["tenant"] = options.TenantId;
        report.Subject["site"] = options.SiteUrl;
        report.Subject["speaking as"] = app.Label;
        report.Subject["header under test"] = $"{PreferenceName}: {PreferenceValue}";
        report.Subject["sent beside it"] = $"{Controls.Length} controls - {string.Join(", ", Controls.Select(c => c.Value))}";

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

        // Both are printed even though only one is spent here. The grant being swapped between runs is
        // the SharePoint one, and delta is a Graph call - so which of the two moved, and whether the
        // other stayed put, is exactly what a reader comparing two runs needs and should not have to
        // take on trust.
        var sharePoint = await source.GetTokenAsync(ProbeAudience.SharePoint, cancellationToken);

        report.Subject["Graph token"] = Describe(graph);
        report.Subject["SharePoint token"] = Describe(sharePoint);

        if (!graph.Succeeded || graph.AccessToken is null)
        {
            report.MarkIncomplete($"no Graph token: {graph.ErrorCode}");
            report.Add(Observation.NotRun("the delta walk", $"no Graph token was issued: {graph.ErrorDetail}"));
            report.Finish();
            return report;
        }

        console.WriteLine("Resolving the site...");
        var site = await caller.GetAsync(SiteUrl(), graph.AccessToken, cancellationToken);
        calls.Add(site);

        var siteId = ReadString(site, "id");
        if (siteId is null)
        {
            report.MarkIncomplete("the site was never resolved");
            report.Add(Observation.NotRun("the delta walk", $"the site was never resolved ({site.StatusText})"));
            report.Add(BuildCallTable(calls));
            report.Finish();
            return report;
        }

        // Order matters only in that the baseline is first and the header under test second: the two
        // comparisons finding 19 was built on stay where they were, and the controls are added after.
        var legs = new List<Leg>
        {
            new() { Name = "no header", SendsHeader = false, Purpose = "the baseline" },
            new()
            {
                Name = $"{PreferenceName}: {PreferenceValue}",
                SendsHeader = true,
                Preference = PreferenceValue,
                Purpose = "the one under test",
            },
        };

        legs.AddRange(Controls.Select(c => new Leg
        {
            Name = $"{PreferenceName}: {c.Value}",
            SendsHeader = true,
            Preference = c.Value,
            Purpose = c.Why,
        }));

        foreach (var leg in legs)
        {
            console.WriteLine($"Walking delta - {leg.Name}...");
            await WalkAsync(caller, siteId, leg, graph.AccessToken, calls, cancellationToken);
        }

        report.Subject["throttling"] = caller.Record.Summary;

        report.Add(BuildAcceptanceTable(legs));
        report.Add(BuildEffectTable(legs));
        report.Add(BuildShapeTable(legs));
        report.Add(BuildCarrierTable(legs));
        report.Add(BuildCallTable(calls));

        foreach (var leg in legs)
        {
            report.Add(LegObservation(leg));
        }

        report.Add(AcceptanceObservation(legs));
        report.Add(EchoObservation(legs));
        report.Add(DifferenceObservation(legs));
        report.Finish();
        return report;
    }

    /// <summary>
    /// One leg's whole walk: the tokenless delta, followed to the end. Tokenless because a delta with
    /// a token answers "what changed since", and the question here is what a full enumeration carries.
    /// </summary>
    private async Task WalkAsync(
        ThrottleAwareCaller caller,
        string siteId,
        Leg leg,
        string token,
        List<HttpObservation> calls,
        CancellationToken cancellationToken)
    {
        var headers = leg.SendsHeader && leg.Preference is not null
            ? new[] { (PreferenceName, leg.Preference) }
            : null;

        string? next = $"{GraphBase}/sites/{siteId}/drive/root/delta";
        var limit = options.PagesToFollow > 0 ? options.PagesToFollow : DefaultPages;

        while (next is not null)
        {
            var observation = await caller.GetAsync(
                next, token, cancellationToken, "application/json", headers);
            calls.Add(observation);
            leg.Pages++;

            if (leg.Pages == 1)
            {
                leg.FirstStatus = observation.StatusText;
                leg.PreferenceApplied =
                    observation.ResponseHeaders.TryGetValue("Preference-Applied", out var applied)
                        ? applied
                        : null;
            }

            var root = Root(observation);
            if (root is null || !root.Value.TryGetProperty("value", out var value) ||
                value.ValueKind != JsonValueKind.Array)
            {
                // The body is kept whole rather than summarised. A question about a header is settled
                // by what the service said about it, and a paraphrase is not that.
                leg.RefusalBody = string.IsNullOrWhiteSpace(observation.Body)
                    ? "(no body)"
                    : observation.Body;
                leg.Stopped = leg.Pages == 1
                    ? $"the first page never came back ({observation.StatusText})"
                    : $"page {leg.Pages} did not come back ({observation.StatusText})";
                return;
            }

            foreach (var entry in value.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var keys = entry.EnumerateObject().Select(p => p.Name).ToList();
                foreach (var key in keys)
                {
                    leg.Keys.Add(key);
                }

                leg.Items.Add(new Item(
                    Text(entry, "id") ?? "(no id)",
                    Text(entry, "name") ?? "(no name)",
                    ParentPath(entry),
                    keys,
                    entry.Clone()));
            }

            leg.SawDeltaLink |= root.Value.TryGetProperty("@odata.deltaLink", out _);
            next = Link(root.Value, "@odata.nextLink");

            if (next is not null && leg.Pages >= limit)
            {
                leg.Stopped = $"stopped at the {limit}-page limit - more was waiting";
                return;
            }
        }

        leg.Stopped = leg.SawDeltaLink
            ? $"{leg.Pages} pages, then a deltaLink"
            : $"{leg.Pages} pages, and no deltaLink was offered";
    }

    /// <summary>
    /// Whether the header was taken. Three things settle it and all three are printed: the status, the
    /// <c>Preference-Applied</c> the service is supposed to echo, and - when it refused - the body it
    /// refused with, whole.
    /// </summary>
    private static ProbeTable BuildAcceptanceTable(IReadOnlyList<Leg> legs) =>
        new("Was the header taken",
            ["leg", "what it is for", "first status", "Preference-Applied", "refusal body"],
            legs.Select(l => (IReadOnlyList<string?>)new[]
            {
                l.Name,
                l.Purpose,
                l.FirstStatus ?? "never asked",
                l.PreferenceApplied ?? (l.SendsHeader ? "the service said nothing" : "-"),
                l.RefusalBody ?? "-",
            }).ToList());

    /// <summary>
    /// What each leg actually came back with, measured against the baseline. This is the half of the
    /// answer that does not depend on the service echoing anything: a preference that was acted on has
    /// to show up as a different page count, a different number of items, or a different set of keys.
    /// </summary>
    private static ProbeTable BuildEffectTable(IReadOnlyList<Leg> legs)
    {
        var baseline = legs[0];

        var rows = legs.Select(l =>
        {
            var extra = l.Keys.Except(baseline.Keys).OrderBy(k => k, StringComparer.Ordinal).ToList();
            var missing = baseline.Keys.Except(l.Keys).OrderBy(k => k, StringComparer.Ordinal).ToList();

            var moved = ReferenceEquals(l, baseline)
                ? "-"
                : l.Pages != baseline.Pages || l.Items.Count != baseline.Items.Count ||
                  extra.Count > 0 || missing.Count > 0
                    ? "yes"
                    : "no";

            return (IReadOnlyList<string?>)new[]
            {
                l.Name,
                l.Pages.ToString(),
                l.Items.Count.ToString(),
                l.Keys.Count.ToString(),
                extra.Count == 0 ? "-" : string.Join(", ", extra),
                missing.Count == 0 ? "-" : string.Join(", ", missing),
                moved,
                l.Stopped ?? "-",
            };
        }).ToList();

        return new ProbeTable(
            "What each leg came back with, against the baseline",
            ["leg", "pages", "items", "keys", "keys the baseline lacked", "keys it lost", "moved", "how it ended"],
            rows);
    }

    /// <summary>
    /// What the two legs' items are made of, as a set difference rather than a search.
    /// <para>
    /// Nothing here looks for a property called "sharing". Guessing a name from memory is how the
    /// earlier half of this investigation went wrong five times running; the two legs are asked the
    /// same question and their shapes are subtracted, so whatever the header adds shows up because it
    /// is there and not because it was expected.
    /// </para>
    /// </summary>
    private static ProbeTable BuildShapeTable(IReadOnlyList<Leg> legs)
    {
        // The baseline against the one under test. The controls have their own table; putting eight
        // legs into this one would make the column that matters the narrowest one on the page.
        var without = legs[0].Keys;
        var with = legs[1].Keys;

        var onlyWith = with.Except(without).OrderBy(k => k, StringComparer.Ordinal).ToList();
        var onlyWithout = without.Except(with).OrderBy(k => k, StringComparer.Ordinal).ToList();
        var both = with.Intersect(without).OrderBy(k => k, StringComparer.Ordinal).ToList();

        // One row per key rather than three rows of joined lists. The joined form truncated at the
        // console's cell width, which put the very list this comparison is made of behind an ellipsis -
        // a reader could not check whether a name was among the common keys, which is half the answer.
        var rows = without.Union(with)
            .OrderBy(k => k, StringComparer.Ordinal)
            .Select(k => (IReadOnlyList<string?>)new[]
            {
                k,
                without.Contains(k) ? "yes" : "-",
                with.Contains(k) ? "yes" : "-",
                onlyWith.Contains(k) ? "only with the header"
                    : onlyWithout.Contains(k) ? "only without it"
                    : "both",
            })
            .ToList();

        return new ProbeTable(
            $"Every key either leg returned ({onlyWith.Count} only with the header, " +
            $"{onlyWithout.Count} only without, {both.Count} in both)",
            ["key", "without header", "with header", "side"],
            rows.Count == 0 ? [["(neither leg returned an item)", "-", "-", "-"]] : rows);
    }

    /// <summary>
    /// Which items carry whatever the header added. This is the "root of the hierarchy, plus the ones
    /// that actually changed" question, and it is answered by listing the items rather than by
    /// counting them - a count cannot be checked against the library.
    /// </summary>
    private static ProbeTable BuildCarrierTable(IReadOnlyList<Leg> legs)
    {
        var added = legs[1].Keys.Except(legs[0].Keys).ToHashSet(StringComparer.Ordinal);
        if (added.Count == 0)
        {
            return new ProbeTable(
                "Which items carry what the header added",
                ["item", "path", "carries"],
                [["(the header added no key to any item)", "-", "-"]]);
        }

        var rows = legs[1].Items
            .Select(i => (Item: i, Carried: i.Keys.Where(added.Contains).ToList()))
            .Select(x => (IReadOnlyList<string?>)new[]
            {
                x.Item.Name,
                x.Item.Path,
                x.Carried.Count == 0 ? "(none of them)" : string.Join(", ", x.Carried),
            })
            .ToList();

        return new ProbeTable("Which items carry what the header added", ["item", "path", "carries"], rows);
    }

    private static ProbeTable BuildCallTable(IReadOnlyList<HttpObservation> calls) =>
        new("Calls issued (each carried 'Authorization: Bearer <token>')",
            ["method", "url", "sent", "status", "ms", "error code"],
            calls.Select(c => (IReadOnlyList<string?>)new[]
            {
                c.Method,
                c.Url,
                string.Join("; ", c.RequestHeaders.Where(h => h.StartsWith(PreferenceName, StringComparison.Ordinal))),
                c.StatusText,
                c.ElapsedMs.ToString(),
                ApiError.Code(c),
            }).ToList());

    private static Observation LegObservation(Leg leg) =>
        Observation.Measured(
            leg.Name,
            $"{leg.FirstStatus ?? "never asked"}; {leg.Items.Count} items over {leg.Pages} pages; " +
            $"{leg.Keys.Count} distinct keys; {leg.Stopped ?? "still going"}") with
        {
            Details = new Dictionary<string, string?>
            {
                ["preference"] = leg.Preference ?? "(none)",
                ["purpose"] = leg.Purpose,
                ["sentHeader"] = leg.SendsHeader.ToString(),
                ["firstStatus"] = leg.FirstStatus,
                ["preferenceApplied"] = leg.PreferenceApplied,
                ["items"] = leg.Items.Count.ToString(),
                ["pages"] = leg.Pages.ToString(),
                ["sawDeltaLink"] = leg.SawDeltaLink.ToString(),
                ["keys"] = string.Join(", ", leg.Keys.OrderBy(k => k, StringComparer.Ordinal)),
                ["stopped"] = leg.Stopped,
                ["refusalBody"] = leg.RefusalBody,
            },
        };

    private static Observation AcceptanceObservation(IReadOnlyList<Leg> legs)
    {
        var withHeader = legs.FirstOrDefault(l => l.Preference == PreferenceValue);
        if (withHeader is null)
        {
            return Observation.NotRun("was the header taken", "no leg sent it");
        }

        // Three outcomes, and the middle one is the one worth naming. A preference that is ignored
        // comes back as an ordinary success with nothing said about it, which reads exactly like one
        // that was honoured unless the echo is checked.
        var observed = withHeader.RefusalBody is not null
            ? $"refused - {withHeader.FirstStatus}. The body is in the table above, whole"
            : withHeader.PreferenceApplied is not null
                ? $"{withHeader.FirstStatus}, and the service echoed Preference-Applied: {withHeader.PreferenceApplied}"
                : $"{withHeader.FirstStatus}, and the service said nothing about the preference - " +
                  "accepted-and-ignored and accepted-and-applied look the same from here";

        return Observation.Measured("was the header taken", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["status"] = withHeader.FirstStatus,
                ["preferenceApplied"] = withHeader.PreferenceApplied,
                ["refused"] = (withHeader.RefusalBody is not null).ToString(),
                ["note"] = "a Prefer header the service does not recognise is specified to be ignored, " +
                           "not refused - so silence here is not the same as acceptance",
            },
        };
    }

    /// <summary>
    /// The question finding 19 left open: silence about a preference and a route that never speaks
    /// about preferences look identical from one leg. Several legs can separate them - but only in one
    /// direction each, so all three outcomes are named rather than folded into a verdict.
    /// </summary>
    private static Observation EchoObservation(IReadOnlyList<Leg> legs)
    {
        var sent = legs.Where(l => l.Preference is not null).ToList();
        if (sent.Count == 0)
        {
            return Observation.NotRun("does this route echo Preference-Applied at all", "no leg sent a preference");
        }

        var echoed = sent.Where(l => l.PreferenceApplied is not null).ToList();
        var baseline = legs[0];
        var acted = sent
            .Where(l => l.Pages != baseline.Pages || l.Items.Count != baseline.Items.Count ||
                        !l.Keys.SetEquals(baseline.Keys))
            .ToList();

        var invented = sent.FirstOrDefault(l => l.Preference == InventedPreference);
        var inventedEchoed = invented?.PreferenceApplied is not null;

        var observed = echoed.Count == 0
            ? $"no - none of the {sent.Count} preferences sent came back echoed, so this route's silence " +
              $"about {PreferenceValue} does not distinguish 'ignored' from 'never echoes anything'" +
              (acted.Count == 0
                  ? ". And none of them changed the response either, so nothing here shows the route " +
                    "acting on a preference at all"
                  : $". But {acted.Count} of them did change the response ({string.Join(", ", acted.Select(l => l.Preference))}), " +
                    "so the route acts on preferences without saying so - which makes the echo useless as evidence here")
            : inventedEchoed
                ? $"yes, but it echoed the invented one too - an echo says nothing about whether a " +
                  $"preference was understood. {echoed.Count} of {sent.Count} came back echoed"
                : $"yes - {echoed.Count} of {sent.Count} came back echoed " +
                  $"({string.Join(", ", echoed.Select(l => l.Preference))}), and the invented one did not. " +
                  $"So this route does echo, and it said nothing about {PreferenceValue}";

        return Observation.Measured("does this route echo Preference-Applied at all", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["preferencesSent"] = string.Join(", ", sent.Select(l => l.Preference)),
                ["echoed"] = echoed.Count == 0 ? "(none)" : string.Join(", ", echoed.Select(l => $"{l.Preference} -> {l.PreferenceApplied}")),
                ["changedTheResponse"] = acted.Count == 0 ? "(none)" : string.Join(", ", acted.Select(l => l.Preference)),
                ["inventedPreferenceEchoed"] = invented is null ? "(not sent)" : inventedEchoed.ToString(),
                ["note"] = "the echo and the effect are separate evidence. a preference can be applied " +
                           "without being echoed, and this run measures both rather than choosing one",
            },
        };
    }

    private static Observation DifferenceObservation(IReadOnlyList<Leg> legs)
    {
        if (legs[0].RefusalBody is not null || legs[1].RefusalBody is not null)
        {
            return Observation.NotRun(
                "what the header changed",
                "one of the two compared legs did not come back, so there was nothing to compare");
        }

        var added = legs[1].Keys.Except(legs[0].Keys).OrderBy(k => k, StringComparer.Ordinal).ToList();
        var removed = legs[0].Keys.Except(legs[1].Keys).OrderBy(k => k, StringComparer.Ordinal).ToList();
        var carriers = added.Count == 0
            ? 0
            : legs[1].Items.Count(i => i.Keys.Any(added.Contains));

        var observed = added.Count == 0 && removed.Count == 0 && legs[0].Items.Count == legs[1].Items.Count
            ? $"nothing changed - both legs returned {legs[0].Items.Count} items with the same {legs[0].Keys.Count} keys"
            : $"{legs[0].Items.Count} items without the header, {legs[1].Items.Count} with it; " +
              $"{added.Count} keys appeared, {removed.Count} disappeared" +
              (added.Count == 0 ? "" : $"; {carriers} of {legs[1].Items.Count} items carry the new ones");

        return Observation.Measured("what the header changed", observed) with
        {
            Details = new Dictionary<string, string?>
            {
                ["itemsWithoutHeader"] = legs[0].Items.Count.ToString(),
                ["itemsWithHeader"] = legs[1].Items.Count.ToString(),
                ["keysOnlyWithHeader"] = added.Count == 0 ? "(none)" : string.Join(", ", added),
                ["keysOnlyWithoutHeader"] = removed.Count == 0 ? "(none)" : string.Join(", ", removed),
                ["itemsCarryingTheNewKeys"] = carriers.ToString(),
                ["note"] = "the two key sets are subtracted rather than searched - whatever the header " +
                           "adds appears here because it arrived, not because it was looked for",
            },
        };
    }

    private static string Describe(TokenResult token) =>
        !token.Succeeded
            ? $"none - {token.ErrorCode}: {token.ErrorDetail}"
            : token.Claims?.GrantSummary() ?? "issued, but its claims could not be read";

    private string SiteUrl()
    {
        var relative = options.SiteServerRelativePath;
        return string.IsNullOrEmpty(relative)
            ? $"{GraphBase}/sites/{options.SiteHost}"
            : $"{GraphBase}/sites/{options.SiteHost}:" +
              string.Join('/', relative.Split('/').Select(Uri.EscapeDataString));
    }

    private static string ParentPath(JsonElement entry) =>
        entry.TryGetProperty("parentReference", out var parent) && parent.ValueKind == JsonValueKind.Object
            ? Text(parent, "path") ?? "(no path)"
            : "(no parentReference)";

    private static string? Link(JsonElement root, string property) =>
        root.TryGetProperty(property, out var link) &&
        link.ValueKind == JsonValueKind.String &&
        Uri.TryCreate(link.GetString(), UriKind.Absolute, out _)
            ? link.GetString()
            : null;

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? ReadString(HttpObservation observation, string property)
    {
        var root = Root(observation);
        return root is null ? null : Text(root.Value, property);
    }

    private static JsonElement? Root(HttpObservation observation)
    {
        if (string.IsNullOrWhiteSpace(observation.Body))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(observation.Body);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
