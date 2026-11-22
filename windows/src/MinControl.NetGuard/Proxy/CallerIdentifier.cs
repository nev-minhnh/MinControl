using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using MinControl.Core.Abstractions;
using MinControl.NetGuard.Native;

namespace MinControl.NetGuard.Proxy;

/// <summary>Who opened a proxy connection.</summary>
public sealed record Caller(int Pid, string? Sid, string? ExePath)
{
    public string ExeName => ExePath is null ? "unknown" : Path.GetFileName(ExePath);
}

/// <summary>Maps a loopback client endpoint to PID (TCP table) → SID (IUserDirectory) + image path.</summary>
public sealed class CallerIdentifier
{
    private readonly IUserDirectory _users;
    private readonly IClock _clock;
    private readonly object _tableLock = new();
    private List<TcpRow> _snapshot = [];
    private long _snapshotAtMs = long.MinValue;
    private readonly ConcurrentDictionary<int, (Caller Caller, long AtMs)> _pidCache = new();
    private const long SnapshotTtlMs = 250, PidTtlMs = 30_000;

    public CallerIdentifier(IUserDirectory users, IClock clock)
    {
        _users = users;
        _clock = clock;
    }

    public Caller Identify(IPEndPoint client, int proxyPort)
    {
        var pid = FindPid(client, proxyPort);
        if (pid is null) return new Caller(-1, null, null);
        var now = _clock.MonotonicMs;
        if (_pidCache.TryGetValue(pid.Value, out var c) && now - c.AtMs < PidTtlMs) return c.Caller;
        var caller = new Caller(pid.Value, _users.SidOfProcess(pid.Value), ProcessInfo.ImagePath(pid.Value));
        _pidCache[pid.Value] = (caller, now);
        if (_pidCache.Count > 4096)
            foreach (var kv in _pidCache)
                if (now - kv.Value.AtMs >= PidTtlMs) _pidCache.TryRemove(kv.Key, out _);
        return caller;
    }

    private int? FindPid(IPEndPoint client, int proxyPort)
    {
        lock (_tableLock)
        {
            var now = _clock.MonotonicMs;
            if (now - _snapshotAtMs < SnapshotTtlMs && Lookup(_snapshot, client, proxyPort) is { } cached) return cached;
            _snapshot = TcpTable.Connections(AddressFamily.InterNetwork);
            _snapshotAtMs = now;
            return Lookup(_snapshot, client, proxyPort);
        }
    }

    private static int? Lookup(List<TcpRow> rows, IPEndPoint client, int proxyPort)
    {
        foreach (var r in rows)
            if (r.LocalPort == client.Port && r.RemotePort == proxyPort && IPAddress.IsLoopback(r.LocalAddress)) return r.Pid;
        return null;
    }
}
