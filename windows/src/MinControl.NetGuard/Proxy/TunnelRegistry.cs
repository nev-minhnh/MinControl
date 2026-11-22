using System.Collections.Concurrent;

namespace MinControl.NetGuard.Proxy;

/// <summary>
/// One live proxied connection (CONNECT tunnel or plain-HTTP request) of a known SID. Browsers keep HTTP/2 / keep-alive
/// connections open for minutes to hours, so a decision taken at CONNECT time must be re-checked when the policy changes.
/// </summary>
public sealed class LiveTunnel
{
    private readonly Action _abort;
    private int _closed;

    public LiveTunnel(long id, string sid, string host, string exeName, int port, bool isConnect, string connectHost,
        DateTimeOffset startedUtc, Action abort)
    {
        Id = id; Sid = sid; Host = host; ExeName = exeName; Port = port; IsConnect = isConnect; ConnectHost = connectHost;
        StartedUtc = startedUtc;
        _abort = abort;
    }

    public long Id { get; }
    public string Sid { get; }
    /// <summary>Normalized host the client asked for (what the decision is about).</summary>
    public string Host { get; }
    public string ExeName { get; }
    public int Port { get; }
    public bool IsConnect { get; }
    /// <summary>Host actually connected to (SafeSearch / YouTube restricted rewrite target, else <see cref="Host"/>).</summary>
    public string ConnectHost { get; }
    public DateTimeOffset StartedUtc { get; }
    public bool Closed => Volatile.Read(ref _closed) == 1;

    /// <summary>Aborts both sockets once. Returns false when already closed.</summary>
    public bool TryClose()
    {
        if (Interlocked.Exchange(ref _closed, 1) == 1) return false;
        try { _abort(); } catch { /* sockets already gone */ }
        return true;
    }
}

/// <summary>Thread-safe set of <see cref="LiveTunnel"/>s.</summary>
public sealed class TunnelRegistry
{
    private readonly ConcurrentDictionary<long, LiveTunnel> _live = new();
    private long _nextId;

    public LiveTunnel Register(string sid, string host, string exeName, int port, bool isConnect, string connectHost,
        DateTimeOffset startedUtc, Action abort)
    {
        var t = new LiveTunnel(Interlocked.Increment(ref _nextId), sid, host, exeName, port, isConnect, connectHost, startedUtc, abort);
        _live[t.Id] = t;
        return t;
    }

    public void Remove(LiveTunnel? t)
    {
        if (t is not null) _live.TryRemove(t.Id, out _);
    }

    public int Count => _live.Count;

    public IReadOnlyList<LiveTunnel> Snapshot() => _live.Values.Where(t => !t.Closed).OrderBy(t => t.Id).ToList();
}
