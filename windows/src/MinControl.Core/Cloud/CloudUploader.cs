using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.Cloud;

/// <summary>Short-lived upload token issued over the authenticated WebSocket (API.md §2/§3).</summary>
public sealed class UploadTokenHolder
{
    private (string Token, DateTimeOffset ExpiresAt)? _current;
    private readonly object _gate = new();

    public void Set(string token, DateTimeOffset expiresAt) { lock (_gate) _current = (token, expiresAt); }
    public void Clear() { lock (_gate) _current = null; }

    public string? Valid(DateTimeOffset now)
    {
        lock (_gate) return _current is { } c && c.ExpiresAt > now.AddSeconds(10) ? c.Token : null;
    }

    public DateTimeOffset? ExpiresAt { get { lock (_gate) return _current?.ExpiresAt; } }
}

public enum UploadResult { Done, NothingToDo, NoToken, Unauthorized, Retry }

/// <summary>HTTPS uploads: event batches (≤ 500 per POST) from the outbox, plus on-demand blob relay.</summary>
public sealed class CloudUploader
{
    public const int MaxBatch = 500;

    private readonly HttpClient _http;
    private readonly StateStore _store;
    private readonly UploadTokenHolder _token;
    private readonly IClock _clock;
    private readonly Func<string?> _serverUrl;
    private readonly ILogger _log;

    /// <summary>Rows currently sent over the WebSocket and awaiting an ack are skipped by the batch path.</summary>
    public InFlightEvents? InFlight { get; set; }

    public CloudUploader(HttpClient http, StateStore store, UploadTokenHolder token, IClock clock, Func<string?> serverUrl, ILogger<CloudUploader>? log = null)
    {
        _http = http; _store = store; _token = token; _clock = clock; _serverUrl = serverUrl;
        _log = log ?? (ILogger)NullLogger.Instance;
    }

    /// <summary>web.* events are flushed this long after the first one is queued instead of waiting for the
    /// 60 s batch window (history polls every 10 s; this coalesces one poll's events into one POST).</summary>
    public static readonly TimeSpan WebFlushDelay = TimeSpan.FromSeconds(5);

    internal TimeSpan NudgeDelay { get; set; } = WebFlushDelay;
    private int _nudgePending;

    /// <summary>Raised when queued events should be flushed now (CloudLink signals its upload loop).</summary>
    public event Action? FlushDue;

    /// <summary>Called for every queued event: a web.* event schedules one <see cref="FlushDue"/> after
    /// <see cref="NudgeDelay"/> (further events inside that window join the same flush). Batches stay ≤ 500.</summary>
    public void Nudge(string eventType)
    {
        if (!eventType.StartsWith("web.", StringComparison.Ordinal)) return;
        if (Interlocked.Exchange(ref _nudgePending, 1) == 1) return;
        _ = Task.Delay(NudgeDelay).ContinueWith(_ =>
        {
            Volatile.Write(ref _nudgePending, 0);
            FlushDue?.Invoke();
        }, TaskScheduler.Default);
    }

    /// <summary>Uploads the whole outbox in batches. Stops at the first non-success.</summary>
    public async Task<UploadResult> FlushEventsAsync(CancellationToken ct)
    {
        var result = UploadResult.NothingToDo;
        while (true)
        {
            var items = _store.PeekOutbox(MaxBatch + (InFlight?.Count ?? 0));
            if (InFlight is { } inflight) items = items.Where(x => !inflight.IsInFlight(x.Id)).Take(MaxBatch).ToList();
            if (items.Count == 0) return result;
            var token = _token.Valid(_clock.UtcNow);
            var baseUrl = _serverUrl();
            var deviceId = _store.GetMeta(StateStore.MetaKeys.DeviceId);
            if (token is null || baseUrl is null || deviceId is null) return UploadResult.NoToken;

            var sb = new StringBuilder();
            sb.Append("{\"deviceId\":\"").Append(deviceId).Append("\",\"sentAt\":\"").Append(Time.Utc(_clock.UtcNow)).Append("\",\"events\":[");
            for (int i = 0; i < items.Count; i++) { if (i > 0) sb.Append(','); sb.Append(items[i].Json); }
            sb.Append("]}");

            using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri(baseUrl), "/v1/device/events"))
            {
                Content = new StringContent(sb.ToString(), Encoding.UTF8, "application/json"),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            HttpResponseMessage resp;
            try { resp = await _http.SendAsync(req, ct).ConfigureAwait(false); }
            catch (HttpRequestException e) { _log.LogInformation("event upload failed: {Msg}", e.Message); return UploadResult.Retry; }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return UploadResult.Retry; }
            using (resp)
            {
                if (resp.IsSuccessStatusCode)
                {
                    // {"accepted": n, "rejected": [eventId…]}: rejected events are invalid forever → drop them too
                    await LogRejectedAsync(resp, ct).ConfigureAwait(false);
                    _store.DeleteOutbox(items.Select(x => x.Id));
                    result = UploadResult.Done;
                    continue;
                }
                if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) { _token.Clear(); return UploadResult.Unauthorized; }
                if (resp.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.UnprocessableEntity)
                {
                    // the server will never accept this batch; keep tamper.* events if the batch can be split
                    if (items.Count > 1)
                    {
                        _log.LogError("event batch rejected ({Status}); retrying events one by one", (int)resp.StatusCode);
                        if (!await UploadSinglyAsync(items, token, baseUrl, deviceId, ct).ConfigureAwait(false)) return UploadResult.Retry;
                        result = UploadResult.Done; continue;
                    }
                    _log.LogError("event {Type} rejected by server ({Status}); dropping it", items[0].Type, (int)resp.StatusCode);
                    _store.DeleteOutbox([items[0].Id]);
                    continue;
                }
                return UploadResult.Retry;
            }
        }
    }

    private async Task LogRejectedAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (System.Text.Json.Nodes.JsonNode.Parse(body) is System.Text.Json.Nodes.JsonObject o
                && o["rejected"] is System.Text.Json.Nodes.JsonArray rej && rej.Count > 0)
                _log.LogWarning("server rejected {Count} events (dropped): {Ids}", rej.Count, string.Join(",", rej.Take(20)));
        }
        catch (System.Text.Json.JsonException) { }
    }

    private async Task<bool> UploadSinglyAsync(IReadOnlyList<OutboxItem> items, string token, string baseUrl, string deviceId, CancellationToken ct)
    {
        foreach (var it in items)
        {
            var body = "{\"deviceId\":\"" + deviceId + "\",\"sentAt\":\"" + Time.Utc(_clock.UtcNow) + "\",\"events\":[" + it.Json + "]}";
            using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(new Uri(baseUrl), "/v1/device/events"))
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            try
            {
                using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode || (int)resp.StatusCode is 400 or 413 or 422) _store.DeleteOutbox([it.Id]);
                else return false;
            }
            catch (HttpRequestException) { return false; }
        }
        return true;
    }

    /// <summary>Answers a <c>blob_request</c>: PUT /v1/device/blobs/&lt;key&gt;?reqId=… with the sealed bytes (API.md §9).</summary>
    public async Task<UploadResult> PutBlobAsync(string key, string reqId, byte[] bytes, CancellationToken ct)
    {
        var token = _token.Valid(_clock.UtcNow);
        var baseUrl = _serverUrl();
        if (token is null || baseUrl is null) return UploadResult.NoToken;
        using var req = new HttpRequestMessage(HttpMethod.Put,
            new Uri(new Uri(baseUrl), "/v1/device/blobs/" + key + "?reqId=" + Uri.EscapeDataString(reqId)))
        { Content = new ByteArrayContent(bytes) };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        try
        {
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode) return UploadResult.Done;
            if (resp.StatusCode is HttpStatusCode.Unauthorized) { _token.Clear(); return UploadResult.Unauthorized; }
            _log.LogInformation("blob relay {Key} answered {Status}", key, (int)resp.StatusCode);
            return UploadResult.Retry;
        }
        catch (HttpRequestException e) { _log.LogInformation("blob relay failed: {Msg}", e.Message); return UploadResult.Retry; }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return UploadResult.Retry; }
    }
}
