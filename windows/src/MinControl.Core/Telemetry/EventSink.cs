using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Protocol;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.Telemetry;

/// <summary>
/// Builds <see cref="TelemetryEvent"/>s (ULID id, deviceId, RFC 3339 ts, monoMs) and appends them to the durable
/// outbox in state.db; <c>CloudLink</c> uploads them. Events emitted before enrolment are dropped.
/// </summary>
public sealed class EventSink : IEventSink
{
    private readonly StateStore _store;
    private readonly IClock _clock;
    private readonly UlidGenerator _ids;
    private readonly ILogger _log;

    public EventSink(StateStore store, IClock clock, UlidGenerator? ids = null, ILogger<EventSink>? log = null)
    {
        _store = store; _clock = clock; _ids = ids ?? UlidGenerator.Shared;
        _log = log ?? (ILogger)NullLogger.Instance;
    }

    /// <summary>Raised after an event was queued (CloudLink uses it to flush early when the batch is full).</summary>
    public event Action<string>? Emitted;

    /// <summary>Raised with (outbox row id, event id, event json, type) right after the event was queued (live WS push).</summary>
    public event Action<long, string, string, string>? Queued;

    public void Emit(string type, string? userSid, JsonObject data) => Emit(type, userSid, data, null);

    /// <summary>Emit with a caller-chosen id (screenshot.taken uses the id inside its blob key). Returns the event, or null if not enrolled.</summary>
    public TelemetryEvent? Emit(string type, string? userSid, JsonObject data, string? id) => EmitCore(type, userSid, data, id, null);

    /// <summary>Emit an event that happened at <paramref name="at"/> (e.g. a browser-history visit read later):
    /// <c>ts</c> is that time, id/monoMs are taken now.</summary>
    public TelemetryEvent? EmitAt(string type, string? userSid, JsonObject data, DateTimeOffset at) => EmitCore(type, userSid, data, null, at);

    private TelemetryEvent? EmitCore(string type, string? userSid, JsonObject data, string? id, DateTimeOffset? at)
    {
        var deviceId = _store.GetMeta(StateStore.MetaKeys.DeviceId);
        if (deviceId is null) { _log.LogDebug("not enrolled; dropping {Type}", type); return null; }
        var now = _clock.UtcNow;
        var ev = new TelemetryEvent(id ?? _ids.New(now), deviceId, userSid, Time.Utc(at ?? now), Math.Max(0, _clock.MonotonicMs), type,
            (JsonObject)data.DeepClone());
        string json; long rowId;
        try
        {
            json = JsonSerializer.Serialize(ev, ProtocolJson.Options);
            rowId = _store.EnqueueOutbox(type, json);
        }
        catch (Exception e)
        {
            _log.LogError(e, "outbox write failed for {Type}", type);
            return null;
        }
        try { Queued?.Invoke(rowId, ev.Id, json, type); }
        catch (Exception e) { _log.LogDebug(e, "live push subscriber failed"); }
        Emitted?.Invoke(type);
        return ev;
    }

    public string NewId() => _ids.New(_clock.UtcNow);
}

/// <summary><see cref="IApprovalStore"/> backed by state.db.</summary>
public sealed class ApprovalStore : IApprovalStore
{
    private readonly StateStore _store;
    private readonly IClock _clock;

    public ApprovalStore(StateStore store, IClock clock) { _store = store; _clock = clock; }

    public string? DecisionFor(string sid, string sha256) => _store.GetApproval(sid, sha256.ToLowerInvariant());

    public void Record(string sid, string sha256, string decision)
    {
        if (decision is not ("allow" or "block")) throw new ArgumentException("decision must be allow or block", nameof(decision));
        _store.SetApproval(sid, sha256.ToLowerInvariant(), decision, Time.Utc(_clock.UtcNow));
    }

    public bool MarkRequested(string sid, string sha256)
        => _store.MarkApprovalRequested(sid, sha256.ToLowerInvariant(), Time.Utc(_clock.UtcNow));
}
