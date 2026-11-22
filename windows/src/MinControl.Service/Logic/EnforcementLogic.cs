namespace MinControl.Service.Logic;

// Pure enforcement helpers (no Win32, no DI). Linked into the test project.

/// <summary>Decides when to show a "minutes remaining" warning. Each configured threshold fires once;
/// a threshold re-arms when remaining time rises above it again (add_time, new day).</summary>
public sealed class WarningScheduler
{
    private readonly HashSet<int> _fired = new();

    /// <returns>Minutes to display when a warning must be shown now, otherwise null.</returns>
    public int? Update(IReadOnlyList<int> warnAtMin, int? remainingMin)
    {
        if (remainingMin is not int remaining)
        {
            _fired.Clear(); // unlimited / paused
            return null;
        }
        _fired.RemoveWhere(w => remaining > w);
        var fire = false;
        foreach (var w in warnAtMin)
        {
            if (w <= 0 || remaining > w || !_fired.Add(w)) continue;
            fire = true;
        }
        // At 0 the exhaustion overlay takes over; never show a "0 minutes" toast.
        return fire && remaining > 0 ? remaining : null;
    }

    public void Reset() => _fired.Clear();
}

public enum LockoutKind { None, ShowOverlay, Logoff, ClearOverlay }

public readonly record struct LockoutAction(LockoutKind Kind, string Reason = "", int SecondsLeft = 0);

/// <summary>Per-session lockout state machine: not allowed -> overlay with countdown -> logoff at the deadline
/// (re-issued every <see cref="LogoffRetryMs"/> while the session still exists); allowed again -> clear.</summary>
public sealed class LockoutTracker
{
    public const int LogonNotAllowedGraceSec = 30;
    public const long LogonWindowMs = 15_000;   // "denied at logon" if denied within this time after logon
    public const long LogoffRetryMs = 30_000;

    private long? _deadlineMono;
    private long? _lastLogoffMono;
    private string _reason = "";

    public bool Active => _deadlineMono is not null;

    public LockoutAction Update(bool allowed, string reason, int graceSec, long nowMono, long logonMono)
    {
        if (allowed)
        {
            if (_deadlineMono is null) return default;
            _deadlineMono = null;
            _lastLogoffMono = null;
            _reason = "";
            return new LockoutAction(LockoutKind.ClearOverlay);
        }

        if (_deadlineMono is null)
        {
            var atLogon = nowMono - logonMono <= LogonWindowMs;
            // Logon while not allowed (any reason) -> "not allowed now" overlay, logoff after 30 s (spec 8.2).
            var grace = atLogon ? LogonNotAllowedGraceSec : Math.Clamp(graceSec, 0, 3600);
            _deadlineMono = nowMono + grace * 1000L;
            _reason = reason;
            return new LockoutAction(LockoutKind.ShowOverlay, reason, grace);
        }

        if (nowMono < _deadlineMono.Value)
        {
            if (reason != _reason)
            {
                _reason = reason; // e.g. quota exhausted -> parent locked: refresh text, keep deadline
                return new LockoutAction(LockoutKind.ShowOverlay, reason, SecondsUntilDeadline(nowMono));
            }
            return default;
        }

        if (_lastLogoffMono is null || nowMono - _lastLogoffMono.Value >= LogoffRetryMs)
        {
            _lastLogoffMono = nowMono;
            return new LockoutAction(LockoutKind.Logoff, _reason);
        }
        return default;
    }

    public int SecondsUntilDeadline(long nowMono) =>
        _deadlineMono is long d ? (int)Math.Max(0, (d - nowMono + 999) / 1000) : 0;
}

public sealed record UsageTickRecord(DateTimeOffset MinuteStart, string Exe, string? Title, int ActiveSec);

/// <summary>Aggregates per-second foreground samples into per-minute, per-exe usage.tick records.</summary>
public sealed class UsageAggregator
{
    private DateTimeOffset? _minute;
    private readonly Dictionary<string, (long Ms, string? Title)> _byExe = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Adds a sample; returns the records of the previous minute when the minute rolled over.</summary>
    public IReadOnlyList<UsageTickRecord> Add(DateTimeOffset utcNow, string exe, string? title, long activeMs)
    {
        var minute = MinuteOf(utcNow);
        IReadOnlyList<UsageTickRecord> flushed = Array.Empty<UsageTickRecord>();
        if (_minute is not null && minute != _minute) flushed = Flush();
        _minute ??= minute;
        if (activeMs > 0 && !string.IsNullOrEmpty(exe))
        {
            _byExe.TryGetValue(exe, out var cur);
            _byExe[exe] = (cur.Ms + activeMs, title ?? cur.Title);
        }
        return flushed;
    }

    public IReadOnlyList<UsageTickRecord> Flush()
    {
        var minute = _minute;
        _minute = null;
        if (minute is null || _byExe.Count == 0) { _byExe.Clear(); return Array.Empty<UsageTickRecord>(); }
        var list = new List<UsageTickRecord>(_byExe.Count);
        foreach (var (exe, v) in _byExe)
        {
            var sec = (int)Math.Clamp((v.Ms + 500) / 1000, 0, 60);
            if (sec > 0) list.Add(new UsageTickRecord(minute.Value, exe, v.Title, sec));
        }
        _byExe.Clear();
        return list;
    }

    public static DateTimeOffset MinuteOf(DateTimeOffset utc)
    {
        var u = utc.ToUniversalTime();
        return new DateTimeOffset(u.Year, u.Month, u.Day, u.Hour, u.Minute, 0, TimeSpan.Zero);
    }
}

/// <summary>Detects wall-clock jumps relative to a monotonic clock (I6).</summary>
public sealed class ClockJumpDetector(long thresholdMs = 120_000)
{
    private long? _offset; // wallMs - monoMs at baseline

    /// <returns>Jump in seconds (positive = clock moved forward) since the previous check when it exceeds
    /// the threshold, else null. Call periodically (seconds apart).</returns>
    public long? Check(long wallMs, long monoMs)
    {
        var offset = wallMs - monoMs;
        if (_offset is not long baseline) { _offset = offset; return null; }
        var delta = offset - baseline;
        _offset = offset; // always re-baseline: slow drift / NTP slews never accumulate into a false jump
        return Math.Abs(delta) > thresholdMs ? delta / 1000 : null;
    }
}

/// <summary>"Once per key per day" latch (e.g. tamper.managed_user_is_admin).</summary>
public sealed class DailyLatch
{
    private readonly Dictionary<string, DateOnly> _last = new(StringComparer.OrdinalIgnoreCase);

    public bool TryFire(string key, DateOnly day)
    {
        if (_last.TryGetValue(key, out var d) && d == day) return false;
        _last[key] = day;
        return true;
    }
}
