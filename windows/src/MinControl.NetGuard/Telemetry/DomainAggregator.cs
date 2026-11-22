using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;

namespace MinControl.NetGuard.Telemetry;

/// <summary>
/// Aggregates proxy connections into <c>net.domain</c> events per (sid, exe, host, allowed, window).
/// A connection is counted in the window in which it opened; its bytes are added when it closes, to the window
/// of closing. If that window has no opened connection yet (long-lived tunnel), it reports connections = 1 to
/// satisfy the schema minimum. Flush emits every window that has ended; <see cref="FlushAll"/> emits everything.
/// </summary>
public sealed class DomainAggregator
{
    private sealed class Counter
    {
        public long Connections, BytesIn, BytesOut;
    }

    private readonly record struct Key(string Sid, string Exe, string Host, bool Allowed, long WindowStartTicks);

    private readonly ConcurrentDictionary<Key, Counter> _counters = new();
    private readonly IEventSink _sink;
    private readonly IClock _clock;
    private readonly long _windowTicks;

    public DomainAggregator(IEventSink sink, IClock clock, NetGuardOptions options)
    {
        _sink = sink;
        _clock = clock;
        _windowTicks = Math.Max(TimeSpan.TicksPerMinute, options.DomainWindow.Ticks);
    }

    public int PendingCount => _counters.Count;

    public void RecordConnection(string sid, string exe, string host, bool allowed)
    {
        var c = _counters.GetOrAdd(KeyFor(sid, exe, host, allowed), static _ => new Counter());
        Interlocked.Increment(ref c.Connections);
    }

    public void RecordBytes(string sid, string exe, string host, bool allowed, long bytesOut, long bytesIn)
    {
        if (bytesIn <= 0 && bytesOut <= 0) return;
        var c = _counters.GetOrAdd(KeyFor(sid, exe, host, allowed), static _ => new Counter());
        Interlocked.Add(ref c.BytesOut, Math.Max(0, bytesOut));
        Interlocked.Add(ref c.BytesIn, Math.Max(0, bytesIn));
    }

    /// <summary>Emits finished windows. Returns number of events emitted.</summary>
    public int Flush() => FlushWhere(k => k.WindowStartTicks + _windowTicks <= _clock.UtcNow.UtcTicks);

    public int FlushAll() => FlushWhere(_ => true);

    private int FlushWhere(Func<Key, bool> due)
    {
        var n = 0;
        foreach (var key in _counters.Keys)
        {
            if (!due(key) || !_counters.TryRemove(key, out var c)) continue;
            var data = new JsonObject
            {
                ["host"] = Truncate(key.Host, 253),
                ["exe"] = Truncate(key.Exe, 260),
                ["windowStart"] = new DateTime(key.WindowStartTicks, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
                ["connections"] = Math.Max(1, Interlocked.Read(ref c.Connections)),
                ["bytesOut"] = Interlocked.Read(ref c.BytesOut),
                ["bytesIn"] = Interlocked.Read(ref c.BytesIn),
                ["allowed"] = key.Allowed,
            };
            _sink.Emit(EventTypes.NetDomain, key.Sid, data);
            n++;
        }
        return n;
    }

    private Key KeyFor(string sid, string exe, string host, bool allowed)
    {
        var t = _clock.UtcNow.UtcTicks;
        return new Key(sid, exe.ToLowerInvariant(), host, allowed, t - t % _windowTicks);
    }

    internal static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}

/// <summary>Suppresses repeated events for the same key within a period (web.blocked, tamper.*).</summary>
public sealed class EventThrottle
{
    private readonly ConcurrentDictionary<string, long> _last = new(StringComparer.Ordinal);
    private readonly IClock _clock;
    private readonly long _periodMs;

    public EventThrottle(IClock clock, TimeSpan period)
    {
        _clock = clock;
        _periodMs = (long)period.TotalMilliseconds;
    }

    public bool ShouldEmit(string key)
    {
        var now = _clock.MonotonicMs;
        while (true)
        {
            if (_last.TryGetValue(key, out var prev))
            {
                if (now - prev < _periodMs) return false;
                if (_last.TryUpdate(key, now, prev)) break;
            }
            else if (_last.TryAdd(key, now)) break;
        }
        if (_last.Count > 10_000)
            foreach (var kv in _last)
                if (now - kv.Value >= _periodMs) _last.TryRemove(kv.Key, out _);
        return true;
    }
}
