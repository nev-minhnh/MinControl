namespace MinControl.Service.Logic;

/// <summary>
/// Rate limit of the "blocked" toast (pure; monotonic milliseconds in): the same (user, key) at most once per
/// <see cref="SameKeyPeriodMs"/>, and at most <see cref="MaxPerWindow"/> toasts per user per <see cref="WindowMs"/>.
/// Rejected notices do not count. Thread-safe.
/// </summary>
public sealed class BlockedNoticeLimiter
{
    public const long SameKeyPeriodMs = 60_000;
    public const long WindowMs = 60_000;
    public const int MaxPerWindow = 3;

    private readonly object _gate = new();
    private readonly Dictionary<string, long> _lastByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Queue<long>> _recentByUser = new(StringComparer.OrdinalIgnoreCase);

    public bool TryAcquire(string sid, string key, long nowMs)
    {
        lock (_gate)
        {
            var k = sid + "\n" + key;
            if (_lastByKey.TryGetValue(k, out var last) && nowMs - last < SameKeyPeriodMs) return false;

            if (!_recentByUser.TryGetValue(sid, out var recent)) _recentByUser[sid] = recent = new Queue<long>();
            while (recent.Count > 0 && nowMs - recent.Peek() >= WindowMs) recent.Dequeue();
            if (recent.Count >= MaxPerWindow) return false;

            recent.Enqueue(nowMs);
            _lastByKey[k] = nowMs;
            if (_lastByKey.Count > 1_000)
                foreach (var kv in _lastByKey.Where(kv => nowMs - kv.Value >= SameKeyPeriodMs).ToList()) _lastByKey.Remove(kv.Key);
            return true;
        }
    }
}
