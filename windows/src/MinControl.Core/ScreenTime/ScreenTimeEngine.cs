using MinControl.Core.Abstractions;
using MinControl.Core.Policies;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.ScreenTime;

/// <summary>
/// Stateful wrapper around <see cref="ScreenTimeCalculator"/>: reads policy/overrides/ledger and records monotonic
/// usage deltas (flushed to state.db every 30 s and on dispose). The caller (Service enforcer) decides whether a
/// second counts (active console session, unlocked, and — when countIdle=false — not idle) and passes only those
/// milliseconds. The engine emits no events: usage.tick and quota.* come from the win-session Enforcer.
/// </summary>
public sealed class ScreenTimeEngine : IScreenTimeEngine, IDisposable
{
    public const long FlushIntervalMs = 30_000;
    public const long MaxDeltaMs = 120_000;   // a single call never adds more than 2 min (guards against clock glitches)
    public const int LedgerKeepDays = 35;

    private readonly StateStore _store;
    private readonly PolicyProvider _policy;
    private readonly IClock _clock;
    private readonly Func<IAppMonitor?> _appMonitor;
    private readonly object _gate = new();
    private readonly Dictionary<(string Sid, string Day, string Bucket), long> _pending = new();
    private long _lastFlushMono;
    private string? _lastPruneDay;

    public ScreenTimeEngine(StateStore store, PolicyProvider policy, IClock clock, Func<IAppMonitor?>? appMonitor = null)
    {
        _store = store; _policy = policy; _clock = clock;
        _appMonitor = appMonitor ?? (() => null);
        _lastFlushMono = clock.MonotonicMs;
    }

    public ScreenTimeState Evaluate(string sid, DateTimeOffset utcNow)
    {
        var user = _policy.ForUser(sid);
        var tz = _policy.TimeZone;
        if (user is null) return ScreenTimeCalculator.Evaluate(null, tz, UserOverrides.None, new Dictionary<string, long>(), utcNow);
        var ov = UserOverrides.FromRows(_store.GetOverrides(sid));
        return ScreenTimeCalculator.Evaluate(user, tz, ov, Ledger(sid, Time.DayKey(utcNow, tz)), utcNow);
    }

    /// <summary>appGroup keys whose quota is used up (empty while paused or for unmanaged users).</summary>
    public IReadOnlyCollection<string> ExhaustedGroups(string sid, DateTimeOffset utcNow)
    {
        var s = Evaluate(sid, utcNow);
        return s.Reason == Reasons.NotManaged ? [] : ScreenTimeCalculator.ExhaustedGroups(s);
    }

    /// <summary>Group of an exe for this user: IAppMonitor (if registered) first, else the simple AppMatch matcher.</summary>
    public string? GroupOf(string sid, string exePath)
    {
        var user = _policy.ForUser(sid);
        if (user is null || string.IsNullOrEmpty(exePath)) return null;
        return _appMonitor()?.GroupOf(sid, exePath) ?? AppMatcher.GroupOf(user, new AppFacts(exePath));
    }

    public void RecordUsage(string sid, string? foregroundExePath, long activeMsDelta)
    {
        if (_policy.ForUser(sid) is null || activeMsDelta <= 0) { MaybeFlush(); return; }
        var delta = Math.Min(activeMsDelta, MaxDeltaMs);
        var day = Time.DayKey(_clock.UtcNow, _policy.TimeZone);
        var group = foregroundExePath is null ? null : GroupOf(sid, foregroundExePath);
        lock (_gate)
        {
            Add((sid, day, ""), delta);
            if (group is not null) Add((sid, day, group), delta);
        }
        MaybeFlush();
    }

    /// <summary>Writes pending ledger deltas now; prunes old ledger rows and expired overrides once per local day.</summary>
    public void Flush()
    {
        List<KeyValuePair<(string Sid, string Day, string Bucket), long>> deltas;
        lock (_gate)
        {
            deltas = _pending.ToList();
            _pending.Clear();
            _lastFlushMono = _clock.MonotonicMs;
        }
        if (deltas.Count > 0) _store.AddLedger(deltas.Select(d => (d.Key.Sid, d.Key.Day, d.Key.Bucket, d.Value)));

        var today = Time.DayKey(_clock.UtcNow, _policy.TimeZone);
        if (_lastPruneDay == today) return;
        _lastPruneDay = today;
        var d0 = DateOnly.ParseExact(today, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        _store.PruneLedger(d0.AddDays(-LedgerKeepDays).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
        _store.PruneOverrides(Time.Utc(_clock.UtcNow), d0.AddDays(-1).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
    }

    public void Dispose() => Flush();

    private void Add((string, string, string) key, long ms) => _pending[key] = _pending.GetValueOrDefault(key) + ms;

    private IReadOnlyDictionary<string, long> Ledger(string sid, string day)
    {
        var stored = _store.GetLedger(sid, day);
        lock (_gate)
        {
            if (_pending.Count == 0) return stored;
            var merged = new Dictionary<string, long>(stored, StringComparer.Ordinal);
            foreach (var ((s, d, b), ms) in _pending)
                if (s == sid && d == day) merged[b] = merged.GetValueOrDefault(b) + ms;
            return merged;
        }
    }

    private void MaybeFlush()
    {
        if (_clock.MonotonicMs - _lastFlushMono >= FlushIntervalMs) Flush();
    }
}
