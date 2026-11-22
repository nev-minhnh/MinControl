using MinControl.Core.Abstractions;
using MinControl.Core.Policies;
using MinControl.Core.Policy;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.ScreenTime;

public sealed record AddTimeGrant(string Day, string? Group, int Minutes);

/// <summary>Active overrides for one user. <see cref="Locked"/> with null <see cref="LockedUntil"/> = until unlock.</summary>
public sealed record UserOverrides(bool Locked, DateTimeOffset? LockedUntil, DateTimeOffset? PausedUntil, IReadOnlyList<AddTimeGrant> Grants)
{
    public static readonly UserOverrides None = new(false, null, null, []);

    public static UserOverrides FromRows(IEnumerable<OverrideRow> rows)
    {
        bool locked = false; DateTimeOffset? lockUntil = null, pauseUntil = null;
        var grants = new List<AddTimeGrant>();
        foreach (var r in rows)
        {
            switch (r.Kind)
            {
                case OverrideKinds.Lock:
                    locked = true;
                    lockUntil = r.Until is not null && Time.TryParseUtc(r.Until, out var lu) ? lu : null;
                    break;
                case OverrideKinds.Pause when r.Until is not null && Time.TryParseUtc(r.Until, out var pu):
                    pauseUntil = pu;
                    break;
                case OverrideKinds.AddTime when r.Day is not null && r.Minutes is not null:
                    grants.Add(new AddTimeGrant(r.Day, r.Scope, r.Minutes.Value));
                    break;
            }
        }
        return new UserOverrides(locked, lockUntil, pauseUntil, grants);
    }
}

public static class Reasons
{
    public const string Ok = "ok", QuotaExhausted = "quota_exhausted", OutsideWindow = "outside_window", Locked = "locked", NotManaged = "not_managed";
}

/// <summary>
/// Pure screen-time accounting (SPEC §8.2): (policy, overrides, ledger of the current local day, now) → state.
/// All schedule math happens in the policy timezone (I6). Rules:
/// <list type="bullet">
/// <item>lock (until unlock or until <c>LockedUntil</c>) beats everything; pause suspends windows and quotas (not filters).</item>
/// <item>A day's quota = dailyQuotaMin[weekday] + add_time grants for that local day (never below 0).</item>
/// <item>An empty allowedWindows list for a weekday means no screen time that day (fail closed).</item>
/// <item>RemainingMin = min(quota left, minutes until the current allowed window ends), rounded up.</item>
/// <item>Groups: same rule with the group's own quota; a group without dailyQuotaMin is tracked but unlimited.</item>
/// </list>
/// </summary>
public static class ScreenTimeCalculator
{
    private static readonly IReadOnlyDictionary<string, GroupState> NoGroups = new Dictionary<string, GroupState>();

    public static ScreenTimeState Evaluate(UserPolicy? user, TimeZoneInfo tz, UserOverrides ov,
        IReadOnlyDictionary<string, long> todayLedgerMs, DateTimeOffset now)
    {
        if (user is null) return new ScreenTimeState(true, Reasons.NotManaged, 0, null, null, null, NoGroups);

        var local = TimeZoneInfo.ConvertTime(now, tz);
        var day = DateOnly.FromDateTime(local.DateTime);
        var dayKey = day.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var paused = ov.PausedUntil is { } pu && pu > now;
        var usedMs = todayLedgerMs.GetValueOrDefault("");
        var usedMin = (int)(usedMs / 60_000);

        // groups
        var groups = new Dictionary<string, GroupState>(StringComparer.Ordinal);
        foreach (var (name, g) in user.AppGroups)
        {
            var gUsed = todayLedgerMs.GetValueOrDefault(name);
            int? gRemaining = null;
            if (g.DailyQuotaMin is not null && !paused)
            {
                var gQuotaMs = Math.Max(0, g.DailyQuotaMin.For(day.DayOfWeek) + GrantMinutes(ov, dayKey, name)) * 60_000L;
                gRemaining = CeilMin(Math.Max(0, gQuotaMs - gUsed));
            }
            groups[name] = new GroupState((int)(gUsed / 60_000), gRemaining);
        }

        if (ov.Locked && (ov.LockedUntil is null || ov.LockedUntil > now))
            return new ScreenTimeState(false, Reasons.Locked, usedMin, 0, ov.LockedUntil, ov.LockedUntil, groups);

        if (paused)
            return new ScreenTimeState(true, Reasons.Ok, usedMin, null, null, ov.PausedUntil, groups);

        var nextMidnightUtc = ToUtc(day.AddDays(1), 0, tz);
        var tod = local.TimeOfDay.TotalMinutes;
        var window = FindWindow(user.ScreenTime, day, tod);
        if (window is null)
        {
            var next = NextWindowStart(user.ScreenTime, day, tod, tz);
            return new ScreenTimeState(false, Reasons.OutsideWindow, usedMin, 0, null, next, groups);
        }

        var quotaMs = Math.Max(0, QuotaFor(user, ov, day, dayKey)) * 60_000L;
        var remainingMs = quotaMs - usedMs;
        if (remainingMs <= 0)
            return new ScreenTimeState(false, Reasons.QuotaExhausted, usedMin, 0, null, nextMidnightUtc, groups);

        var windowEndUtc = EffectiveWindowEnd(user, ov, tz, day, window.Value.End);
        var untilWindowEndMs = (long)Math.Max(0, (windowEndUtc - now).TotalMilliseconds);
        var remaining = Math.Min(CeilMin(remainingMs), CeilMin(untilWindowEndMs));
        var nextChange = Min(Min(windowEndUtc, now.AddMilliseconds(remainingMs)), nextMidnightUtc);
        return new ScreenTimeState(true, Reasons.Ok, usedMin, remaining, null, nextChange, groups);
    }

    /// <summary>Groups whose quota is used up (not while paused). Locked/outside-window users are blocked entirely anyway.</summary>
    public static IReadOnlyCollection<string> ExhaustedGroups(ScreenTimeState s) =>
        s.Groups.Where(kv => kv.Value.RemainingMin is <= 0).Select(kv => kv.Key).ToList();

    internal static int QuotaFor(UserPolicy user, UserOverrides ov, DateOnly day, string dayKey) =>
        user.ScreenTime.DailyQuotaMin.For(day.DayOfWeek) + GrantMinutes(ov, dayKey, null);

    private static int GrantMinutes(UserOverrides ov, string dayKey, string? group) =>
        ov.Grants.Where(g => g.Day == dayKey && g.Group == group).Sum(g => g.Minutes);

    private static int CeilMin(long ms) => (int)((ms + 59_999) / 60_000);

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a <= b ? a : b;

    private static List<(int Start, int End)> Windows(ScreenTimePolicy st, DateOnly day)
    {
        var list = new List<(int, int)>();
        foreach (var raw in st.AllowedWindows.For(day.DayOfWeek))
            if (TimeWindow.TryParse(raw, out var s, out var e) && e > s) list.Add((s, e));
        list.Sort();
        // merge adjacent windows ("15:00-17:00","17:00-18:00") into one
        var merged = new List<(int Start, int End)>();
        foreach (var w in list)
        {
            if (merged.Count > 0 && w.Item1 <= merged[^1].End) merged[^1] = (merged[^1].Start, Math.Max(merged[^1].End, w.Item2));
            else merged.Add(w);
        }
        return merged;
    }

    private static (int Start, int End)? FindWindow(ScreenTimePolicy st, DateOnly day, double tod)
    {
        foreach (var w in Windows(st, day))
            if (tod >= w.Start && tod < w.End) return w;
        return null;
    }

    /// <summary>End of the current window; a window ending at 24:00 continues into a 00:00 window of the next day
    /// when that day has quota (so warnings are not shown at 23:55 for a session that may continue).</summary>
    private static DateTimeOffset EffectiveWindowEnd(UserPolicy user, UserOverrides ov, TimeZoneInfo tz, DateOnly day, int end)
    {
        for (int i = 0; i < 7 && end == 1440; i++)
        {
            var next = day.AddDays(1);
            var nextKey = next.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
            var first = Windows(user.ScreenTime, next).FirstOrDefault();
            if (first.End == 0 || first.Start != 0 || QuotaFor(user, ov, next, nextKey) <= 0) break;
            day = next; end = first.End;
        }
        return ToUtc(day, end, tz);
    }

    private static DateTimeOffset? NextWindowStart(ScreenTimePolicy st, DateOnly day, double tod, TimeZoneInfo tz)
    {
        for (int i = 0; i <= 7; i++)
        {
            var d = day.AddDays(i);
            foreach (var w in Windows(st, d))
                if (i > 0 || w.Start > tod) return ToUtc(d, w.Start, tz);
        }
        return null;
    }

    /// <summary>Local (day, minute-of-day) in <paramref name="tz"/> → UTC. Times inside a DST gap move forward.</summary>
    internal static DateTimeOffset ToUtc(DateOnly day, int minuteOfDay, TimeZoneInfo tz)
    {
        var dt = day.ToDateTime(TimeOnly.MinValue, DateTimeKind.Unspecified).AddMinutes(minuteOfDay);
        for (int i = 0; i < 4 && tz.IsInvalidTime(dt); i++) dt = dt.AddMinutes(30);
        return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(dt, tz), TimeSpan.Zero);
    }
}
