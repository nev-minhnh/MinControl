using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Commands;
using MinControl.Core.Crypto;
using MinControl.Core.Events;
using MinControl.Core.Policies;
using MinControl.Core.Protocol;
using MinControl.Core.Storage;
using MinControl.Core.Telemetry;
using MinControl.Core.Util;

namespace MinControl.Core.Cloud;

/// <summary>
/// Device ↔ cloud link (API.md §2–3): WebSocket challenge/auth/ready, envelopes (policy first, then commands),
/// acks and policy_applied/rejected, state every 60 s and on change, ping every 30 s, upload token refresh,
/// reconnect forever with exponential backoff + full jitter, <c>tamper.offline_gap</c> after a long gap.
/// Event batches (≤ 500, at least every 60 s) and sealed blobs go over HTTPS with the upload token.
/// </summary>
public sealed class CloudLink : ICloudLink
{
    public static readonly TimeSpan PingInterval = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan StateInterval = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan UploadInterval = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan ReceiveTimeout = TimeSpan.FromSeconds(95);
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(20);
    public const int MaxMessageBytes = 4 * 1024 * 1024;
    public const int CloseBadAuth = 4401;
    public const int MaxConcurrentBlobs = 2;
    public static readonly TimeSpan CleanupInterval = TimeSpan.FromHours(6);

    private readonly StateStore _store;
    private readonly DeviceIdentity _identity;
    private readonly EnvelopeHandler _handler;
    private readonly DeviceStateBuilder _state;
    private readonly CloudUploader _uploader;
    private readonly UploadTokenHolder _token;
    private readonly IEventSink _events;
    private readonly IClock _clock;
    private readonly CoreOptions _options;
    private readonly ILogger _log;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly SemaphoreSlim _stateSignal = new(0, int.MaxValue);
    private readonly SemaphoreSlim _uploadSignal = new(0, int.MaxValue);
    private readonly PolicyProvider _policy;
    private readonly ScreenshotStorage? _screens;
    private readonly SemaphoreSlim _blobSlots = new(MaxConcurrentBlobs, MaxConcurrentBlobs);
    private volatile bool _connected;
    private readonly LiveEventPusher? _live;
    private readonly StateChangeDebouncer? _debouncer;

    public CloudLink(StateStore store, DeviceIdentity identity, EnvelopeHandler handler, DeviceStateBuilder state,
        CloudUploader uploader, UploadTokenHolder token, IEventSink events, IClock clock, CoreOptions options,
        PolicyProvider policy, CommandDispatcher commands, EventSink? concreteSink = null, ScreenshotStorage? screens = null,
        ILogger<CloudLink>? log = null, IStateChangeNotifier? stateNotifier = null, LiveEventPusher? live = null)
    {
        _store = store; _identity = identity; _handler = handler; _state = state; _uploader = uploader; _token = token;
        _events = events; _clock = clock; _options = options; _policy = policy; _screens = screens;
        _log = log ?? (ILogger)NullLogger.Instance;
        _live = live;
        if (live is not null) uploader.InFlight = live.InFlight;
        if (stateNotifier is not null) _debouncer = new StateChangeDebouncer(stateNotifier, SignalState);
        policy.PolicyChanged += (_, _) => SignalState();
        commands.StateChanged += SignalState;
        commands.RefreshRequested += () => { SignalState(); SignalUpload(); };
        uploader.FlushDue += SignalUpload;
        if (concreteSink is not null)
        {
            if (live is not null) concreteSink.Queued += (row, id, json, _) => live.Enqueue(row, id, json);
            concreteSink.Emitted += type =>
            {
                uploader.Nudge(type);
                if (type.StartsWith("tamper.", StringComparison.Ordinal) || type.StartsWith("request.", StringComparison.Ordinal)
                    || type == EventTypes.QuotaExhausted || _store.OutboxCount >= CloudUploader.MaxBatch)
                    SignalUpload();
            };
        }
    }

    public bool Connected => _connected;

    public string? ServerUrl => _options.ServerUrl ?? _store.GetMeta(StateStore.MetaKeys.ServerUrl);

    public void SignalState() => _stateSignal.Release();
    public void SignalUpload() => _uploadSignal.Release();

    public async Task RunAsync(CancellationToken ct)
    {
        var uploads = Task.Run(() => UploadLoopAsync(ct), ct);
        var cleanup = Task.Run(() => CleanupLoopAsync(ct), ct);
        int attempt = 0;
        while (!ct.IsCancellationRequested)
        {
            var deviceId = _store.GetMeta(StateStore.MetaKeys.DeviceId);
            var server = ServerUrl;
            if (deviceId is null || server is null || !_identity.Exists)
            {
                _log.LogWarning("not enrolled; cloud link idle");
                await Delay(TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
                continue;
            }
            var minDelay = TimeSpan.Zero;
            try
            {
                var ready = await SessionAsync(deviceId, server, ct).ConfigureAwait(false);
                if (ready) attempt = 0;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (AuthRejectedException)
            {
                _log.LogError("server rejected device auth (4401); device revoked or key mismatch");
                minDelay = TimeSpan.FromMinutes(5);
            }
            catch (Exception e) when (e is WebSocketException or HttpRequestException or IOException or OperationCanceledException
                                          or JsonException or InvalidOperationException or ProtocolViolationException)
            {
                _log.LogInformation("cloud link dropped: {Msg}", e.Message);
            }
            finally
            {
                _connected = false;
                _token.Clear();
            }
            var delay = Backoff(attempt++);
            await Delay(delay > minDelay ? delay : minDelay, ct).ConfigureAwait(false);
        }
        try { await uploads.ConfigureAwait(false); } catch (OperationCanceledException) { }
        try { await cleanup.ConfigureAwait(false); } catch (OperationCanceledException) { }
    }

    /// <summary>Full-jitter exponential backoff: random in [1 s, min(5 min, 2^attempt s)].</summary>
    public static TimeSpan Backoff(int attempt)
    {
        var capSec = Math.Min(300.0, Math.Pow(2, Math.Min(attempt, 10)));
        return TimeSpan.FromSeconds(1 + Random.Shared.NextDouble() * Math.Max(0, capSec - 1));
    }

    // ------------------------------------------------------------------------------------------ session

    private sealed class AuthRejectedException : Exception;
    private sealed class ProtocolViolationException(string m) : Exception(m);

    /// <returns>true once the session reached <c>ready</c>.</returns>
    private async Task<bool> SessionAsync(string deviceId, string server, CancellationToken ct)
    {
        using var ws = new ClientWebSocket();
        ws.Options.KeepAliveInterval = TimeSpan.Zero; // app-level ping
        var uri = WsUri(server, deviceId);
        using (var hs = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            hs.CancelAfter(HandshakeTimeout);
            await ws.ConnectAsync(uri, hs.Token).ConfigureAwait(false);

            var challenge = await ReceiveAsync(ws, hs.Token).ConfigureAwait(false);
            if (challenge is null || (string?)challenge["t"] != "challenge" || challenge["nonce"]?.GetValue<string>() is not { } nonce)
                throw new ProtocolViolationException("expected challenge");
            var ts = _clock.UtcNow.ToUnixTimeSeconds();
            await SendAsync(ws, new JsonObject
            {
                ["t"] = "auth", ["deviceId"] = deviceId, ["ts"] = ts, ["sig"] = _identity.AuthSignature(nonce, deviceId, ts),
            }, hs.Token).ConfigureAwait(false);

            var ready = await ReceiveAsync(ws, hs.Token).ConfigureAwait(false);
            if (ready is null)
            {
                if (ws.CloseStatus is { } cs && (int)cs == CloseBadAuth) throw new AuthRejectedException();
                throw new ProtocolViolationException("closed before ready");
            }
            if ((string?)ready["t"] != "ready") throw new ProtocolViolationException("expected ready");
            ApplyToken(ready);
        }

        _connected = true;
        _log.LogInformation("cloud link ready");
        ReportOfflineGap();
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var heartbeat = Task.Run(() => HeartbeatAsync(ws, sessionCts.Token), sessionCts.Token);
        SignalUpload();
        _live?.Attach(json => SendRawAsync(ws, json, sessionCts.Token));
        try
        {
            await SendAsync(ws, new JsonObject { ["t"] = "state", ["state"] = _state.Build() }, ct).ConfigureAwait(false);
            while (!ct.IsCancellationRequested)
            {
                using var rcv = CancellationTokenSource.CreateLinkedTokenSource(ct);
                rcv.CancelAfter(ReceiveTimeout);
                var msg = await ReceiveAsync(ws, rcv.Token).ConfigureAwait(false);
                if (msg is null)
                {
                    if (ws.CloseStatus is { } cs && (int)cs == CloseBadAuth) throw new AuthRejectedException();
                    break;
                }
                TouchOnline();
                switch ((string?)msg["t"])
                {
                    case "envelope":
                        var env = msg["envelope"].Deserialize<SignedEnvelope>(PolicyParser.StrictOptions);
                        if (env is null) break;
                        var reply = await _handler.HandleAsync(env, ct).ConfigureAwait(false);
                        if (reply is not null) await SendAsync(ws, reply, ct).ConfigureAwait(false);
                        break;
                    case "token":
                        ApplyToken(msg);
                        SignalUpload();
                        break;
                    case "blob_request":
                        StartBlobRequest(ws, msg, ct);
                        break;
                    case "events_ack":
                        _live?.HandleAck(msg);
                        break;
                    case "ping":
                        await SendAsync(ws, new JsonObject { ["t"] = "pong" }, ct).ConfigureAwait(false);
                        break;
                    case "pong":
                        break;
                    default:
                        _log.LogDebug("ignoring message {T}", (string?)msg["t"]);
                        break;
                }
            }
        }
        finally
        {
            _live?.Detach();
            await sessionCts.CancelAsync().ConfigureAwait(false);
            try { await heartbeat.ConfigureAwait(false); } catch (OperationCanceledException) { } catch (WebSocketException) { }
            if (ws.State == WebSocketState.Open)
            {
                using var close = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                try { await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "bye", close.Token).ConfigureAwait(false); }
                catch (Exception e) when (e is WebSocketException or OperationCanceledException) { }
            }
        }
        return true;
    }

    private async Task HeartbeatAsync(ClientWebSocket ws, CancellationToken ct)
    {
        var lastPing = _clock.MonotonicMs;
        var lastState = _clock.MonotonicMs;
        while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
        {
            var signalled = await _stateSignal.WaitAsync(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            var mono = _clock.MonotonicMs;
            if (mono - lastPing >= PingInterval.TotalMilliseconds)
            {
                await SendAsync(ws, new JsonObject { ["t"] = "ping" }, ct).ConfigureAwait(false);
                lastPing = mono;
                TouchOnline();
            }
            if (signalled || mono - lastState >= StateInterval.TotalMilliseconds)
            {
                while (_stateSignal.CurrentCount > 0) await _stateSignal.WaitAsync(ct).ConfigureAwait(false); // coalesce
                await SendAsync(ws, new JsonObject { ["t"] = "state", ["state"] = _state.Build() }, ct).ConfigureAwait(false);
                lastState = mono;
            }
            // token expired without refresh → reconnect to obtain a new one
            if (_token.ExpiresAt is { } exp && exp < _clock.UtcNow.AddSeconds(-60))
            {
                _log.LogInformation("upload token expired without refresh; reconnecting");
                ws.Abort();
                return;
            }
        }
    }

    private async Task UploadLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await _uploadSignal.WaitAsync(UploadInterval, ct).ConfigureAwait(false);
                while (_uploadSignal.CurrentCount > 0) await _uploadSignal.WaitAsync(ct).ConfigureAwait(false);
                if (_token.Valid(_clock.UtcNow) is null) continue;
                await _uploader.FlushEventsAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception e)
            {
                _log.LogWarning(e, "upload loop error");
                await Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
            }
        }
    }

    // ------------------------------------------------------------------------------------------ screenshots (API.md section 9)

    /// <summary>Retention + 2 GB cap; runs at start and every 6 h.</summary>
    private async Task CleanupLoopAsync(CancellationToken ct)
    {
        if (_screens is null) return;
        while (!ct.IsCancellationRequested)
        {
            try { _screens.Cleanup(_clock.UtcNow, _policy.Current?.RetentionDays.Screenshots, ScreenshotStorage.DefaultCapBytes, _log); }
            catch (Exception e) when (e is not OperationCanceledException) { _log.LogWarning(e, "screenshot cleanup failed"); }
            await Delay(CleanupInterval, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Handles a blob_request off the receive loop; at most <see cref="MaxConcurrentBlobs"/> run at once.</summary>
    private void StartBlobRequest(ClientWebSocket ws, JsonObject msg, CancellationToken ct)
    {
        var reqId = msg["reqId"] is JsonValue rv && rv.TryGetValue<string>(out var r) ? r : null;
        var key = msg["key"] is JsonValue kv && kv.TryGetValue<string>(out var k) ? k : null;
        if (string.IsNullOrEmpty(reqId) || reqId.Length > 64) return;
        if (!_blobSlots.Wait(0))
        {
            _log.LogInformation("blob_request {ReqId} dropped: too many in flight", reqId);
            return; // the server times the master request out (504)
        }
        _ = Task.Run(async () =>
        {
            try { await AnswerBlobRequestAsync(ws, reqId, key, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch (Exception e) { _log.LogInformation("blob_request {ReqId} failed: {Msg}", reqId, e.Message); }
            finally { _blobSlots.Release(); }
        }, ct);
    }

    private async Task AnswerBlobRequestAsync(ClientWebSocket ws, string reqId, string? key, CancellationToken ct)
    {
        var deviceId = _store.GetMeta(StateStore.MetaKeys.DeviceId);
        var bytes = deviceId is null || _screens is null ? null : _screens.TryRead(key, deviceId);
        if (bytes is null)
        {
            await SendAsync(ws, new JsonObject { ["t"] = "blob_missing", ["reqId"] = reqId }, ct).ConfigureAwait(false);
            return;
        }
        var result = await _uploader.PutBlobAsync(key!, reqId, bytes, ct).ConfigureAwait(false);
        if (result != UploadResult.Done) _log.LogInformation("blob_request {ReqId} relay result {Result}", reqId, result);
    }

    // ------------------------------------------------------------------------------------------ helpers

    private void ApplyToken(JsonObject msg)
    {
        var token = msg["uploadToken"]?.GetValue<string>();
        var exp = msg["uploadTokenExpiresAt"]?.GetValue<string>();
        if (token is not null && Time.TryParseUtc(exp, out var e)) _token.Set(token, e);
    }

    private void TouchOnline() => _store.SetMeta(StateStore.MetaKeys.LastOnlineUtc, Time.Utc(_clock.UtcNow));

    private void ReportOfflineGap()
    {
        var now = _clock.UtcNow;
        if (Time.TryParseUtc(_store.GetMeta(StateStore.MetaKeys.LastOnlineUtc), out var last))
        {
            var gap = (long)(now - last).TotalSeconds;
            if (gap >= _options.OfflineGapThresholdSec)
                _events.Emit(EventTypes.TamperOfflineGap, null, new JsonObject { ["gapSec"] = gap, ["detail"] = TamperText.OfflineGap(gap) });
        }
        TouchOnline();
    }

    internal static Uri WsUri(string server, string deviceId)
    {
        var b = new UriBuilder(new Uri(new Uri(server), "/v1/device/ws"))
        {
            Query = "deviceId=" + Uri.EscapeDataString(deviceId),
        };
        b.Scheme = b.Scheme switch { "https" => "wss", "http" => "ws", var s => s };
        b.Port = b.Uri.IsDefaultPort ? -1 : b.Port;
        return b.Uri;
    }

    private Task SendAsync(ClientWebSocket ws, JsonObject msg, CancellationToken ct)
        => SendRawAsync(ws, msg.ToJsonString(ProtocolJson.Options), ct);

    private async Task SendRawAsync(ClientWebSocket ws, string json, CancellationToken ct)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try { await ws.SendAsync(bytes, WebSocketMessageType.Text, true, ct).ConfigureAwait(false); }
        finally { _sendLock.Release(); }
    }

    /// <returns>null when the server closed the socket.</returns>
    private static async Task<JsonObject?> ReceiveAsync(ClientWebSocket ws, CancellationToken ct)
    {
        var buffer = new byte[16 * 1024];
        using var ms = new MemoryStream();
        while (true)
        {
            var r = await ws.ReceiveAsync(buffer, ct).ConfigureAwait(false);
            if (r.MessageType == WebSocketMessageType.Close) return null;
            ms.Write(buffer, 0, r.Count);
            if (ms.Length > MaxMessageBytes) throw new ProtocolViolationException("message too large");
            if (r.EndOfMessage) break;
        }
        return JsonNode.Parse(ms.ToArray()) as JsonObject ?? throw new ProtocolViolationException("message is not an object");
    }

    private static async Task Delay(TimeSpan d, CancellationToken ct)
    {
        try { await Task.Delay(d, ct).ConfigureAwait(false); } catch (OperationCanceledException) { }
    }
}
