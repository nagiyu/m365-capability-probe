using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;

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
    public bool IsSuccess => StatusCode is >= 200 and < 300;

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

    private readonly HttpClient _http;

    public ProbeHttpClient(TimeSpan? timeout = null)
    {
        _http = new HttpClient
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(60),
        };
    }

    public async Task<HttpObservation> GetAsync(string url, string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // The bearer value is deliberately not recorded; its presence and shape are what matter.
        var recordedHeaders = new[]
        {
            $"Authorization: Bearer <{accessToken.Length} chars, redacted>",
            "Accept: application/json",
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
                TransportError: null);
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

    private static string Truncate(string body) =>
        body.Length <= MaxRecordedBodyLength ? body : body[..MaxRecordedBodyLength] + "...[truncated]";

    public void Dispose() => _http.Dispose();
}
