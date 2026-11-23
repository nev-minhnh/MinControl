using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;

namespace MinControl.Core.Telemetry;

/// <summary>
/// Rate limit for block events that never loses an attempt (API.md §17): per key (e.g. sid|host, sid|exe) the first
/// block is emitted at once with <c>count: 1</c>; repeats within <see cref="Period"/> of the last emission are folded
/// into one pending event (the latest attempt's data, <c>count</c> = number of folded attempts) that is emitted when the
/// period has passed. So a key yields at most one event per period and the counts add up to the real attempts.
/// Thread-safe. Call <see cref="Flush"/> periodically (the folder runs its own 1 s timer unless disabled for tests) and
/// <see cref="FlushAll"/> on shutdown.
/// </summary>
public sealed class BlockEventFolder : IDisposable
{
    private sealed class Slot
    {
        public long LastEmitMs;
        public string Type = "";
        public string? Sid;
        public JsonObject? Pending;
        public int PendingCount;
    }

    private readonly IEventSink _sink;
    private readonly IClock _clock;
    private readonly long _periodMs;
    private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly Timer? _timer;

    public BlockEventFolder(IEventSink sink, IClock clock, TimeSpan period, bool autoFlush = true)
    {
        _sink = sink;
        _clock = clock;
        Period = period;
        _periodMs = Math.Max(1, (long)period.TotalMilliseconds);
        if (autoFlush) _timer = new Timer(_ => { try { Flush(); } catch { /* never crash the timer */ } }, null, 1000, 1000);
    }

    public TimeSpan Period { get; }

    /// <summary>Records one blocked attempt. Returns true when the event was emitted now (first in its window: the caller
    /// may show a toast), false when it was folded into the pending event.</summary>
    public bool Record(string type, string? sid, string key, JsonObject data)
    {
        var now = _clock.MonotonicMs;
        JsonObject? emitNow = null;
        lock (_gate)
        {
            if (!_slots.TryGetValue(key, out var slot))
            {
                _slots[key] = slot = new Slot();
                slot.LastEmitMs = long.MinValue / 2;
            }
            if (slot.Pending is null && now - slot.LastEmitMs >= _periodMs)
            {
                slot.LastEmitMs = now;
                emitNow = data;
            }
            else
            {
                slot.Type = type;
                slot.Sid = sid;
                slot.Pending = data;
                slot.PendingCount++;
            }
        }
        if (emitNow is null) return false;
        Emit(type, sid, emitNow, 1);
        return true;
    }

    /// <summary>Emits every pending event whose window has passed; forgets idle keys.</summary>
    public void Flush() => FlushCore(force: false);

    /// <summary>Emits every pending event now (shutdown).</summary>
    public void FlushAll() => FlushCore(force: true);

    private void FlushCore(bool force)
    {
        var now = _clock.MonotonicMs;
        List<(string Type, string? Sid, JsonObject Data, int Count)>? due = null;
        lock (_gate)
        {
            List<string>? idle = null;
            foreach (var (key, slot) in _slots)
            {
                if (slot.Pending is { } data && (force || now - slot.LastEmitMs >= _periodMs))
                {
                    (due ??= []).Add((slot.Type, slot.Sid, data, slot.PendingCount));
                    slot.Pending = null;
                    slot.PendingCount = 0;
                    slot.LastEmitMs = now;
                }
                else if (slot.Pending is null && now - slot.LastEmitMs >= _periodMs)
                    (idle ??= []).Add(key);
            }
            if (idle is not null) foreach (var k in idle) _slots.Remove(k);
        }
        if (due is null) return;
        foreach (var (type, sid, data, count) in due) Emit(type, sid, data, count);
    }

    /// <summary>Number of keys with a pending (folded) event (tests/diagnostics).</summary>
    public int PendingCount
    {
        get { lock (_gate) return _slots.Values.Count(s => s.Pending is not null); }
    }

    private void Emit(string type, string? sid, JsonObject data, int count)
    {
        data["count"] = count;
        _sink.Emit(type, sid, data);
    }

    public void Dispose()
    {
        _timer?.Dispose();
        try { FlushAll(); } catch { /* best effort */ }
    }
}
