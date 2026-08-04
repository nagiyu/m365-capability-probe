using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace CapabilityProbe.Http;

/// <summary>
/// One request and what came back. A 403 is data here, exactly like a 200 is.
/// The request line and headers are kept because the point of the tool is that a reader can see
/// which URL was called with which headers, and re-issue it by hand.
/// </summary>
public sealed record HttpObservation(
    string Method,
    string Url,
    IReadOnlyList<string> RequestHeaders,
    int? StatusCode,
    string? ReasonPhrase,
    string Body,
    long ElapsedMs,
    string? TransportError)
{
    /// <summary>
    /// The few response headers that carry a reason rather than plumbing. Some refusals put their
    /// entire explanation here and leave the body empty - a 401 from SharePoint says why in
    /// <c>WWW-Authenticate</c> and <c>x-ms-diagnostics</c> and nowhere else. Dropping them would mean
    /// recording "refused, no idea why" about a service that did in fact say why.
    /// </summary>
    public IReadOnlyDictionary<string, string> ResponseHeaders { get; init; } =
        new Dictionary<string, string>();

    public bool IsSuccess => StatusCode is >= 200 and < 300;

    /// <summary>
    /// Whatever the service said about why it refused, taken from the headers rather than the body.
    /// <para>
    /// These headers are mostly boilerplate with one useful sentence buried in them - a
    /// <c>WWW-Authenticate</c> challenge spends its first hundred characters naming the realm, the
    /// resource and its trusted issuers before it gets to <c>error=</c>. Printing it whole means the
    /// reason is the part that gets truncated away, so the named parameters that carry meaning are
    /// pulled out and the rest is dropped.
    /// </para>
    /// </summary>
    public string? RefusalDiagnostic
    {
        get
        {
            foreach (var (header, wanted) in RefusalHeaders)
            {
                if (!ResponseHeaders.TryGetValue(header, out var raw) || string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }

                var parameters = HeaderParameters(raw).ToList();

                var interesting = parameters
                    .Where(p => wanted.Contains(p.Key, StringComparer.OrdinalIgnoreCase))
                    .Select(p => $"{p.Key}={p.Value}")
                    .ToList();

                if (interesting.Count > 0)
                {
                    return string.Join("; ", interesting);
                }

                // The header is there and says nothing about why. That is a different finding from
                // "no header at all", and a different one again from "unreadable", so it gets its own
                // wording. Parameter names rather than values, because a bare challenge names the
                // tenant in its realm - which a CI log will mask, taking the shape of the answer with
                // it. Names survive that; they are not anybody's secret.
                // Short enough that the parameter list - the evidence for "no reason" - survives the
                // column width. The header's name and full value are in the JSON either way.
                return parameters.Count > 0
                    ? $"no reason given ({string.Join(", ", parameters.Select(p => p.Key))})"
                    : $"{header}: {raw}";
            }

            return null;
        }
    }

    private static readonly (string Header, string[] Wanted)[] RefusalHeaders =
    [
        ("x-ms-diagnostics", ["reason", "error_category", "error", "error_description"]),
        ("WWW-Authenticate", ["error", "error_description"]),
        ("x-ms-ags-diagnostic", ["reason", "error", "error_description"]),
    ];

    /// <summary>Pulls <c>name="value"</c> pairs out of a header, which is how both shapes carry theirs.</summary>
    private static IEnumerable<KeyValuePair<string, string>> HeaderParameters(string header)
    {
        foreach (Match match in HeaderParameterPattern.Matches(header))
        {
            yield return new KeyValuePair<string, string>(match.Groups[1].Value, match.Groups[2].Value);
        }
    }

    private static readonly Regex HeaderParameterPattern =
        new(@"([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*""([^""]*)""", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public string StatusText => StatusCode is null
        ? $"(no response: {TransportError})"
        : $"{StatusCode} {ReasonPhrase}".TrimEnd();
}

/// <summary>
/// The only HTTP surface in the tool. It never throws on an HTTP status and never throws on a
/// transport failure: both are recorded and returned so the report can print them as measurements.
/// </summary>
public sealed class ProbeHttpClient : IDisposable
{
    private const int MaxRecordedBodyLength = 4000;

    /// <summary>
    /// Response headers worth keeping. An allow list rather than everything, because most of what a
    /// service returns is transport bookkeeping and the point of the record is to stay readable.
    /// The first two explain refusals; the rest are what a support request would ask for.
    /// </summary>
    private static readonly string[] InterestingResponseHeaders =
    [
        "WWW-Authenticate",
        "x-ms-diagnostics",
        "x-ms-ags-diagnostic",
        "request-id",
        "client-request-id",
        "SPRequestGuid",
        "Retry-After",
    ];

    private readonly HttpClient _http;

    public ProbeHttpClient(TimeSpan? timeout = null)
    {
        _http = new HttpClient
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(60),
        };
    }

    /// <param name="accept">
    /// SharePoint REST and Graph want different things here - Graph is happy with plain JSON, while
    /// SharePoint answers with a verbose envelope unless asked otherwise. It is a parameter rather
    /// than a constant so the recorded headers stay a record of what was actually sent.
    /// </param>
    public async Task<HttpObservation> GetAsync(
        string url,
        string accessToken,
        CancellationToken cancellationToken,
        string accept = "application/json")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(accept));

        // The bearer value is deliberately not recorded; its presence and shape are what matter.
        var recordedHeaders = new[]
        {
            $"Authorization: Bearer <{accessToken.Length} chars, redacted>",
            $"Accept: {accept}",
        };

        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            stopwatch.Stop();

            return new HttpObservation(
                Method: "GET",
                Url: url,
                RequestHeaders: recordedHeaders,
                StatusCode: (int)response.StatusCode,
                ReasonPhrase: response.ReasonPhrase ?? ((HttpStatusCode)response.StatusCode).ToString(),
                Body: Truncate(body),
                ElapsedMs: stopwatch.ElapsedMilliseconds,
                TransportError: null)
            {
                ResponseHeaders = CollectHeaders(response),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            return new HttpObservation(
                Method: "GET",
                Url: url,
                RequestHeaders: recordedHeaders,
                StatusCode: null,
                ReasonPhrase: null,
                Body: string.Empty,
                ElapsedMs: stopwatch.ElapsedMilliseconds,
                TransportError: $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static IReadOnlyDictionary<string, string> CollectHeaders(HttpResponseMessage response)
    {
        var collected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in InterestingResponseHeaders)
        {
            if (response.Headers.TryGetValues(name, out var values) ||
                response.Content.Headers.TryGetValues(name, out values))
            {
                collected[name] = Truncate(string.Join(", ", values));
            }
        }

        return collected;
    }

    private static string Truncate(string body) =>
        body.Length <= MaxRecordedBodyLength ? body : body[..MaxRecordedBodyLength] + "...[truncated]";

    public void Dispose() => _http.Dispose();
}
