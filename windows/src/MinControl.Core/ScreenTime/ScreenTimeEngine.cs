using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policies;
using MinControl.Core.Policy;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.ScreenTime;

/// <summary>
/// Stateful wrapper around <see cref="ScreenTimeCalculator"/>: reads policy/overrides/ledger, records monotonic usage
/// deltas (flushed to state.db every 30 s), emits <c>usage.tick</c> (per minute and exe), <c>quota.warning</c> and
/// <c>quota.exhausted</c>. The caller (Service enforcer) decides whether a second counts (active console session,
/// unlocked, and — when countIdle=false — not idle) and passes only those milliseconds.
/// </summary>
public sealed class ScreenTimeEngine : IScreenTimeEngine, IDisposable
{
    public const long FlushIntervalMs = 30_000;
    public const long MaxDeltaMs = 120_000;   // a single call never adds more than 2 min (guards against clock glitches)
    public const int LedgerKeepDays = 35;

    private readonly StateStore _store;
    private readonly PolicyProvider _policy;
    private readonly IClock _clock;
    private readonly IEventSink? _events;
    private readonly Func<IAppMonitor?> _appMonitor;
    private readonly Func<IForegroundTracker?> _foreground;
    private readonly object _gate = new();

    private readonly Dictionary<(string Sid, string Day, string Bucket), long> _pending = new();
    private long _lastFlushMono;
    private string? _lastPruneDay;

    // usage.tick aggregation: per sid, current UTC minute and per-exe active ms
    private readonly Dictionary<string, TickBucket> _ticks = new(StringComparer.Ordinal);
    // emitted quota events, key = sid|day|scope|threshold
    private readonly HashSet<string> _quotaEmitted = new(StringComparer.Ordinal);

    private sealed class TickBucket
    {
        public DateTimeOffset MinuteStart;
        public readonly Dictionary<string, (long Ms, string? Group, string? Title)> Exes = new(StringComparer.OrdinalIgnoreCase);
    }

    public ScreenTimeEngine(StateStore store, PolicyProvider policy, IClock clock, IEventSink? events = null,
        Func<IAppMonitor?>? appMonitor = null, Func<IForegroundTracker?>? foreground = null)
    {
        _store = store; _policy = policy; _clock = clock; _events = events;
        _appMonitor = appMonitor ?? (() => null);
        _foreground = foreground ?? (() => null);
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

    public IReadOnlyCollection<string> ExhaustedGroups(string sid, DateTimeOffset utcNow)
    {
        var s = Evaluate(sid, utcNow);
        return s.Reason == Reasons.NotManaged ? [] : ScreenTimeCalculator.ExhaustedGroups(s);
    }

    public void RecordUsage(string sid, string? foregroundExePath, long activeMsDelta)
    {
        var user = _policy.ForUser(sid);
        if (user is null || activeMsDelta <= 0) { MaybeFlush(); return; }
        var delta = Math.Min(activeMsDelta, MaxDeltaMs);
        var now = _clock.UtcNow;
        var tz = _policy.TimeZone;
        var day = Time.DayKey(now, tz);
        string? group = null;
        if (!string.IsNullOrEmpty(foregroundExePath))
            group = _appMonitor()?.GroupOf(sid, foregroundExePath) ?? AppMatcher.GroupOf(user, new AppFacts(foregroundExePath));

        lock (_gate)
        {
            Add((sid, day, ""), delta);
            if (group is not null) Add((sid, day, group), delta);
            AccumulateTick(sid, user, foregroundExePath, group, delta, now);
        }
        var after = Evaluate(sid, now);
        EmitQuotaEvents(sid, user, day, after);
        MaybeFlush();
    }

    /// <summary>Writes pending ledger deltas and finished usage ticks now.</summary>
    public void Flush()
    {
        List<((string, string, string), long)> deltas;
        lock (_gate)
        {
            deltas = _pending.Select(kv => (kv.Key, kv.Value)).ToList();
            _pending.Clear();
            _lastFlushMono = _clock.MonotonicMs;
        }
        var minuteNow = _clock.UtcNow;
        lock (_gate)
            foreach (var (sid, b) in _ticks.ToList())
                if (b.MinuteStart.AddMinutes(1) <= minuteNow) FlushTicks(sid);
        if (deltas.Count > 0) _store.AddLedger(deltas.Select(d => (d.Item1.Item1, d.Item1.Item2, d.Item1.Item3, d.Item2)));

        var tz = _policy.TimeZone;
        var today = Time.DayKey(_clock.UtcNow, tz);
        if (_lastPruneDay != today)
        {
            _lastPruneDay = today;
            var keepFrom = DateOnly.ParseExact(today, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)
                .AddDays(-LedgerKeepDays).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
            var yesterday = DateOnly.ParseExact(today, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)
                .AddDays(-1).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
            _store.PruneLedger(keepFrom);
            _store.PruneOverrides(Time.Utc(_clock.UtcNow), yesterday);
            lock (_gate) _quotaEmitted.RemoveWhere(k => !k.Contains("|" + today + "|", StringComparison.Ordinal));
        }
    }

    public void Dispose()
    {
        lock (_gate) foreach (var sid in _ticks.Keys.ToList()) FlushTicks(sid);
        Flush();
    }

    // -------------------------------------------------------------------------------------------------

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

    // caller holds _gate
    private void AccumulateTick(string sid, UserPolicy user, string? exePath, string? group, long delta, DateTimeOffset now)
    {
        if (_events is null) return;
        var minute = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0, TimeSpan.Zero);
        if (_ticks.TryGetValue(sid, out var b) && b.MinuteStart != minute) FlushTicks(sid);
        if (!_ticks.TryGetValue(sid, out b)) _ticks[sid] = b = new TickBucket { MinuteStart = minute };
        var exe = string.IsNullOrEmpty(exePath) ? "" : Path.GetFileName(exePath);
        string? title = null;
        if (user.Monitoring.ForegroundTitles && exePath is not null && _foreground()?.Current(sid) is { } fg
            && string.Equals(fg.ExePath, exePath, StringComparison.OrdinalIgnoreCase))
            title = fg.Title;
        var cur = b.Exes.GetValueOrDefault(exe);
        b.Exes[exe] = (cur.Ms + delta, group ?? cur.Group, title ?? cur.Title);
    }

    // caller holds _gate
    private void FlushTicks(string sid)
    {
        if (_events is null || !_ticks.Remove(sid, out var b)) return;
        foreach (var (exe, v) in b.Exes)
        {
            var sec = (int)Math.Min(60, Math.Round(v.Ms / 1000.0));
            if (sec <= 0) continue;
            var data = new JsonObject
            {
                ["minuteStart"] = Time.Utc(b.MinuteStart),
                ["activeSec"] = sec,
                ["exe"] = Truncate(exe, 260),
            };
            if (v.Title is not null) data["title"] = Truncate(v.Title, 512);
            if (v.Group is not null) data["group"] = v.Group;
            _events.Emit(EventTypes.UsageTick, sid, data);
        }
    }

    private void EmitQuotaEvents(string sid, UserPolicy user, string day, ScreenTimeState after)
    {
        if (_events is null) return;
        if (after.Reason is Reasons.Ok or Reasons.QuotaExhausted)
            Check("total", after.Reason == Reasons.Ok ? after.RemainingMin : 0, after.Reason == Reasons.QuotaExhausted);
        foreach (var (name, g) in after.Groups)
            Check("group:" + name, g.RemainingMin, g.RemainingMin is <= 0);

        void Check(string scope, int? cur, bool exhausted)
        {
            if (cur is null) return;
            if (exhausted)
            {
                if (Once($"{sid}|{day}|{scope}|exhausted"))
                    _events!.Emit(EventTypes.QuotaExhausted, sid, new JsonObject { ["scope"] = scope, ["remainingMin"] = 0 });
                return;
            }
            // warn once per threshold; the smallest crossed threshold wins and marks the larger ones as done
            var crossed = user.ScreenTime.WarnAtMin.Where(w => cur <= w).OrderBy(w => w).ToList();
            if (crossed.Count == 0) return;
            var fresh = Once($"{sid}|{day}|{scope}|{crossed[0]}");
            foreach (var w in crossed.Skip(1)) Once($"{sid}|{day}|{scope}|{w}");
            if (fresh)
                _events!.Emit(EventTypes.QuotaWarning, sid, new JsonObject { ["scope"] = scope, ["remainingMin"] = Math.Max(0, cur.Value) });
        }
    }

    private bool Once(string key) { lock (_gate) return _quotaEmitted.Add(key); }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
