using System.Globalization;

namespace CapabilityProbe.Http;

/// <summary>What waiting and retrying cost, and what it failed to buy.</summary>
public sealed record ThrottleRecord
{
    /// <summary>Calls this caller was asked to make, counting each one once however many attempts it took.</summary>
    public int Calls { get; private set; }

    /// <summary>Requests actually put on the wire, including every retry.</summary>
    public int Attempts { get; private set; }

    /// <summary>How many calls hit a throttle at least once.</summary>
    public int Throttled { get; private set; }

    /// <summary>Total time spent waiting because a service asked for it.</summary>
    public long WaitedMs { get; private set; }

    /// <summary>Calls that were still throttled when the attempt budget ran out.</summary>
    public int GaveUp { get; private set; }

    /// <summary>
    /// The longest single wait a service asked for. A run that waited five minutes across two hundred
    /// calls and a run that waited five minutes on one call are different situations, and the total
    /// alone does not tell them apart.
    /// </summary>
    public long LongestWaitMs { get; private set; }

    internal void Started() => Calls++;

    internal void Attempted() => Attempts++;

    internal void WasThrottled() => Throttled++;

    internal void Waited(long ms)
    {
        WaitedMs += ms;
        LongestWaitMs = Math.Max(LongestWaitMs, ms);
    }

    internal void RanOut() => GaveUp++;

    /// <summary>True when nothing was ever throttled, so the numbers below need no explaining.</summary>
    public bool Clean => Throttled == 0;

    public string Summary => Clean
        ? $"{Calls} calls, {Attempts} attempts, nothing throttled"
        : $"{Calls} calls, {Attempts} attempts, {Throttled} throttled, " +
          $"{WaitedMs} ms waited (longest {LongestWaitMs} ms), {GaveUp} gave up";
}

/// <summary>
/// A caller that honours <c>Retry-After</c>. This is a deliberate exception to a rule the rest of the
/// tool keeps, and it is confined to this class so the exception stays visible.
/// <para>
/// Everywhere else, a refused call is recorded as refused and the run moves on: making a failing call
/// succeed would mean the tool was reporting what it could arrange rather than what it found. A 429 is
/// a different kind of answer. It is not "you may not"; it is "not now" - the same request a minute
/// later is expected to succeed, and the service says how long to wait. Treating it like a 403 does not
/// preserve the measurement, it corrupts it: finding 8's second follow-up measured a run where a
/// throttled sweep quietly returned thirty-four fewer ACLs than the same sweep an hour later, and the
/// row count was identical both times.
/// </para>
/// <para>
/// What is not negotiable is saying so. Every wait is counted, and a call that was still throttled when
/// the budget ran out is counted separately - because "we retried and got everything" and "we retried
/// and still lost some" must never print the same way.
/// </para>
/// </summary>
public sealed class ThrottleAwareCaller(
    ProbeHttpClient http,
    int maxAttempts = 4,
    TimeSpan? longestWait = null)
{
    /// <summary>
    /// A ceiling on any single wait. Services normally ask for seconds; a request to wait ten minutes
    /// is a different situation from ordinary throttling, and sitting there would turn a probe into a
    /// hang. Past it the call is given up and counted as given up.
    /// </summary>
    private readonly TimeSpan _longestWait = longestWait ?? TimeSpan.FromSeconds(120);

    public ThrottleRecord Record { get; } = new();

    public Task<HttpObservation> GetAsync(
        string url,
        string accessToken,
        CancellationToken cancellationToken,
        string accept = "application/json",
        IReadOnlyList<(string Name, string Value)>? extraHeaders = null) =>
        SendAsync(() => http.GetAsync(url, accessToken, cancellationToken, accept, extraHeaders), cancellationToken);

    public Task<HttpObservation> PostAsync(
        string url, string accessToken, CancellationToken cancellationToken, string? body = null) =>
        SendAsync(() => http.PostAsync(url, accessToken, cancellationToken, body), cancellationToken);

    private async Task<HttpObservation> SendAsync(
        Func<Task<HttpObservation>> send, CancellationToken cancellationToken)
    {
        Record.Started();
        var countedThisCall = false;

        for (var attempt = 1; ; attempt++)
        {
            Record.Attempted();
            var observation = await send();

            if (!IsThrottled(observation))
            {
                return observation;
            }

            if (!countedThisCall)
            {
                Record.WasThrottled();
                countedThisCall = true;
            }

            if (attempt >= maxAttempts)
            {
                Record.RanOut();
                return observation;
            }

            var wait = WaitFor(observation, attempt);
            if (wait > _longestWait)
            {
                Record.RanOut();
                return observation;
            }

            Record.Waited((long)wait.TotalMilliseconds);
            await Task.Delay(wait, cancellationToken);
        }
    }

    /// <summary>
    /// 429 is the documented one. 503 is included because SharePoint uses it for the same thing and
    /// sends the same header with it; a 503 carrying no <c>Retry-After</c> is left alone, since that
    /// one is an outage rather than a queue.
    /// </summary>
    private static bool IsThrottled(HttpObservation observation) =>
        observation.StatusCode == 429 ||
        (observation.StatusCode == 503 && observation.ResponseHeaders.ContainsKey("Retry-After"));

    /// <summary>
    /// What the service asked for, or a backoff of our own when it did not say. The header may be a
    /// number of seconds or an HTTP date; both are accepted, and anything unparseable falls through to
    /// the backoff rather than being treated as zero.
    /// </summary>
    private static TimeSpan WaitFor(HttpObservation observation, int attempt)
    {
        if (observation.ResponseHeaders.TryGetValue("Retry-After", out var raw) &&
            !string.IsNullOrWhiteSpace(raw))
        {
            if (int.TryParse(raw.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) &&
                seconds >= 0)
            {
                return TimeSpan.FromSeconds(seconds);
            }

            if (DateTimeOffset.TryParse(
                    raw.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var when))
            {
                var until = when - DateTimeOffset.UtcNow;
                return until > TimeSpan.Zero ? until : TimeSpan.Zero;
            }
        }

        return TimeSpan.FromSeconds(Math.Pow(2, attempt));
    }
}
