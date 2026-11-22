using System.Collections.Concurrent;
using System.Globalization;
using MinControl.Core.Policy;

namespace MinControl.NetGuard.Web;

/// <summary>Policy-timezone helpers (I6): schedules are evaluated in the policy's IANA zone, never the system zone.</summary>
public static class PolicyTime
{
    public const string DefaultTimezone = "Asia/Ho_Chi_Minh";
    private static readonly ConcurrentDictionary<string, TimeZoneInfo> Cache = new(StringComparer.Ordinal);

    public static TimeZoneInfo Resolve(string? ianaOrWindowsId)
    {
        var id = string.IsNullOrWhiteSpace(ianaOrWindowsId) ? DefaultTimezone : ianaOrWindowsId;
        return Cache.GetOrAdd(id, static key =>
        {
            if (TimeZoneInfo.TryFindSystemTimeZoneById(key, out var tz)) return tz;
            if (TimeZoneInfo.TryConvertIanaIdToWindowsId(key, out var win) && TimeZoneInfo.TryFindSystemTimeZoneById(win, out tz)) return tz;
            // Last resort for the default zone (UTC+7, no DST). Never fall back to the system zone.
            return TimeZoneInfo.CreateCustomTimeZone(key, TimeSpan.FromHours(7), key, key);
        });
    }

    public static DateTime ToLocal(DateTimeOffset utcNow, string? timezone) =>
        TimeZoneInfo.ConvertTime(utcNow, Resolve(timezone)).DateTime;

    /// <summary>True when local time falls inside any "HH:MM-HH:MM" window of that weekday (end exclusive, may be 24:00).</summary>
    public static bool InWindows(WeekdayMap<IReadOnlyList<string>>? map, DateTime local)
    {
        if (map is null) return false;
        var windows = map.For(local.DayOfWeek);
        if (windows is null) return false;
        var minute = local.Hour * 60 + local.Minute;
        foreach (var w in windows)
            if (TryParseWindow(w, out var s, out var e) && minute >= s && minute < e) return true;
        return false;
    }

    public static bool TryParseWindow(string? window, out int startMin, out int endMin)
    {
        startMin = endMin = 0;
        if (string.IsNullOrEmpty(window)) return false;
        var dash = window.IndexOf('-');
        if (dash <= 0) return false;
        if (!TryParseHhmm(window.AsSpan(0, dash), out startMin) || !TryParseHhmm(window.AsSpan(dash + 1), out endMin)) return false;
        return endMin > startMin && endMin <= 1440;
    }

    private static bool TryParseHhmm(ReadOnlySpan<char> s, out int minutes)
    {
        minutes = 0;
        s = s.Trim();
        var colon = s.IndexOf(':');
        if (colon <= 0) return false;
        if (!int.TryParse(s[..colon], NumberStyles.None, CultureInfo.InvariantCulture, out var h) ||
            !int.TryParse(s[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var m)) return false;
        if (m is < 0 or > 59 || h is < 0 or > 24 || (h == 24 && m != 0)) return false;
        minutes = h * 60 + m;
        return true;
    }
}
