using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Storage;

namespace MinControl.Core.Cloud;

/// <summary>Outbox rows that were sent over the WebSocket and await an <c>events_ack</c>; the HTTP batch uploader
/// skips them until the 30 s timeout expires (API.md section 15).</summary>
public sealed class InFlightEvents
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    private readonly IClock _clock;
    private readonly ConcurrentDictionary<long, long> _rows = new();       // row id -> monotonic ms when sent
    private readonly ConcurrentDictionary<string, long> _eventRows = new(StringComparer.Ordinal); // event id -> row id

    public InFlightEvents(IClock clock) { _clock = clock; }

    public void Mark(long rowId, string eventId)
    {
        _rows[rowId] = _clock.MonotonicMs;
        _eventRows[eventId] = rowId;
    }

    public bool IsInFlight(long rowId) =>
        _rows.TryGetValue(rowId, out var sent) && _clock.MonotonicMs - sent < (long)Timeout.TotalMilliseconds;

    public bool TryTake(string eventId, out long rowId)
    {
        if (_eventRows.TryRemove(eventId, out rowId)) { _rows.TryRemove(rowId, out _); return true; }
        return false;
    }

    public void Clear() { _rows.Clear(); _eventRows.Clear(); }

    public int Count => _rows.Count;
}

/// <summary>While the WebSocket is up, sends every queued event as <c>{"t":"events","events":[...]}</c> (coalesced for
/// 200 ms, at most 50 events / 64 KB per frame) and deletes acked + rejected events from the outbox on
/// <c>events_ack</c>. Anything unacked stays in the outbox for the HTTP batch uploader.</summary>
public sealed class LiveEventPusher
{
    public const int MaxEvents = 50;
    public const int MaxFrameBytes = 64 * 1024;
    public static readonly TimeSpan CoalesceDelay = TimeSpan.FromMilliseconds(200);

    private readonly StateStore _store;
    private readonly ILogger _log;
    private readonly object _gate = new();
    private readonly List<(long Row, string Id, string Json)> _pending = new();
    private Func<string, Task>? _send;
    private bool _timerArmed;

    public InFlightEvents InFlight { get; }
    internal TimeSpan Delay { get; set; } = CoalesceDelay;

    public LiveEventPusher(StateStore store, InFlightEvents inFlight, ILogger? log = null)
    {
        _store = store; InFlight = inFlight; _log = log ?? NullLogger.Instance;
    }

    public bool Attached { get { lock (_gate) return _send is not null; } }

    /// <summary>Called once the WS is authenticated. <paramref name="send"/> writes one text frame.</summary>
    public void Attach(Func<string, Task> send)
    {
        lock (_gate) { _send = send; }
    }

    /// <summary>WS closed: forget in-flight state so the HTTP path re-sends whatever was not acked (idempotent on id).</summary>
    public void Detach()
    {
        lock (_gate) { _send = null; _pending.Clear(); }
        InFlight.Clear();
    }

    public void Enqueue(long rowId, string eventId, string json)
    {
        bool flushNow = false, arm = false;
        lock (_gate)
        {
            if (_send is null || Encoding.UTF8.GetByteCount(json) > MaxFrameBytes - 64) return;
            _pending.Add((rowId, eventId, json));
            if (_pending.Count >= MaxEvents) flushNow = true;
            else if (!_timerArmed) { _timerArmed = true; arm = true; }
        }
        if (flushNow) _ = Task.Run(FlushAsync);
        else if (arm) _ = Task.Delay(Delay).ContinueWith(_ => FlushAsync(), TaskScheduler.Default).Unwrap();
    }

    /// <summary>Sends everything pending, in frames of at most 50 events / 64 KB.</summary>
    public async Task FlushAsync()
    {
        while (true)
        {
            Func<string, Task>? send;
            var batch = new List<(long Row, string Id, string Json)>();
            lock (_gate)
            {
                _timerArmed = false;
                send = _send;
                if (send is null || _pending.Count == 0) return;
                int bytes = 32;
                while (batch.Count < _pending.Count && batch.Count < MaxEvents)
                {
                    var next = _pending[batch.Count];
                    var sz = Encoding.UTF8.GetByteCount(next.Json) + 1;
                    if (batch.Count > 0 && bytes + sz > MaxFrameBytes) break;
                    bytes += sz; batch.Add(next);
                }
                _pending.RemoveRange(0, batch.Count);
            }
            var sb = new StringBuilder("{\"t\":\"events\",\"events\":[");
            for (int i = 0; i < batch.Count; i++) { if (i > 0) sb.Append(','); sb.Append(batch[i].Json); }
            sb.Append("]}");
            foreach (var b in batch) InFlight.Mark(b.Row, b.Id);
            try { await send(sb.ToString()).ConfigureAwait(false); }
            catch (Exception e)
            {
                _log.LogDebug("live event push failed: {Msg}", e.Message);
                foreach (var b in batch) InFlight.TryTake(b.Id, out _); // HTTP path picks them up
                return;
            }
        }
    }

    /// <summary>Handles <c>{"t":"events_ack","ids":[...],"rejected":[...]}</c>: deletes acked + rejected rows.</summary>
    public int HandleAck(JsonObject msg)
    {
        var rows = new List<long>();
        if (msg["ids"] is JsonArray ids)
            foreach (var n in ids)
                if (n is JsonValue v && v.TryGetValue<string>(out var id) && InFlight.TryTake(id, out var row)) rows.Add(row);
        if (msg["rejected"] is JsonArray rej && rej.Count > 0)
        {
            foreach (var n in rej)
                if (n is JsonValue v && v.TryGetValue<string>(out var id) && InFlight.TryTake(id, out var row)) rows.Add(row);
            _log.LogWarning("server rejected {Count} live events (dropped): {Ids}", rej.Count, string.Join(",", rej.Take(20)));
        }
        if (rows.Count > 0) _store.DeleteOutbox(rows);
        return rows.Count;
    }
}

/// <summary>Trailing debounce: the first change starts a timer; changes inside the window are folded into it.</summary>
public sealed class StateChangeDebouncer
{
    public static readonly TimeSpan DefaultDelay = TimeSpan.FromMilliseconds(500);

    private readonly TimeSpan _delay;
    private readonly Action _fire;
    private int _pending;

    public StateChangeDebouncer(IStateChangeNotifier notifier, Action fire, TimeSpan? delay = null)
    {
        _fire = fire; _delay = delay ?? DefaultDelay;
        notifier.Changed += OnChanged;
    }

    private void OnChanged()
    {
        if (Interlocked.Exchange(ref _pending, 1) == 1) return;
        _ = Task.Delay(_delay).ContinueWith(_ =>
        {
            Volatile.Write(ref _pending, 0);
            _fire();
        }, TaskScheduler.Default);
    }
}
