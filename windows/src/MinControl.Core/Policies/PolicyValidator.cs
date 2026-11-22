using MinControl.Core.Policy;
using MinControl.Core.Util;

namespace MinControl.Core.Policies;

/// <summary>Semantic rules the JSON schema cannot express. Every rule failure rejects the whole policy.</summary>
public static class PolicyValidator
{
    private static readonly string[] Days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

    public static IReadOnlyList<string> Validate(DevicePolicy p)
    {
        var errors = new List<string>();
        if (TimeZones.TryFind(p.Timezone) is null) errors.Add($"timezone '{p.Timezone}' is unknown on this device");
        foreach (var (sid, u) in p.Users)
        {
            var st = u.ScreenTime;
            CheckWindows(errors, $"{sid}.screenTime.allowedWindows", st.AllowedWindows);
            var quotas = DayValues(st.DailyQuotaMin);
            for (int d = 0; d < 7; d++)
            {
                if (quotas[d] <= 0) continue;   // a day without screen time needs no warning
                foreach (var w in st.WarnAtMin)
                    if (w >= quotas[d]) errors.Add($"{sid}.screenTime.warnAtMin {w} >= dailyQuotaMin.{Days[d]} {quotas[d]}");
            }
            foreach (var r in u.AppRules)
                if (r.Action is not ("block" or "allow")) errors.Add($"{sid}.appRules action '{r.Action}'");

            var web = u.Web;
            if (web.CategorySchedules is not null)
                foreach (var (cat, sched) in web.CategorySchedules)
                {
                    if (web.BlockedCategories.Contains(cat))
                        errors.Add($"{sid}.web category '{cat}' is both blocked and scheduled");
                    CheckWindows(errors, $"{sid}.web.categorySchedules.{cat}", sched);
                }
            foreach (var d in web.BlockDomains.Intersect(web.AllowDomains, StringComparer.OrdinalIgnoreCase))
                errors.Add($"{sid}.web domain '{d}' is both blocked and allowed");
            if (web.Mode == "allowlist" && web.AllowDomains.Count == 0)
                errors.Add($"{sid}.web allowlist mode with no allowDomains blocks every site");
        }
        return errors;
    }

    internal static int[] DayValues(WeekdayMap<int> m) => [m.Mon, m.Tue, m.Wed, m.Thu, m.Fri, m.Sat, m.Sun];

    private static void CheckWindows(List<string> errors, string where, WeekdayMap<IReadOnlyList<string>> map)
    {
        IReadOnlyList<string>[] days = [map.Mon, map.Tue, map.Wed, map.Thu, map.Fri, map.Sat, map.Sun];
        for (int d = 0; d < 7; d++)
        {
            var parsed = new List<(int S, int E, string Raw)>();
            foreach (var raw in days[d])
            {
                if (!TimeWindow.TryParse(raw, out var s, out var e)) { errors.Add($"{where}.{Days[d]} '{raw}' is not HH:MM-HH:MM"); continue; }
                if (e <= s) { errors.Add($"{where}.{Days[d]} '{raw}' ends before it starts (crosses midnight; split it across days)"); continue; }
                parsed.Add((s, e, raw));
            }
            parsed.Sort((a, b) => a.S.CompareTo(b.S));
            for (int i = 1; i < parsed.Count; i++)
                if (parsed[i].S < parsed[i - 1].E)
                    errors.Add($"{where}.{Days[d]} '{parsed[i - 1].Raw}' overlaps '{parsed[i].Raw}'");
        }
    }
}

/// <summary>"HH:MM-HH:MM" (end may be 24:00) → minutes since local midnight.</summary>
public static class TimeWindow
{
    public static bool TryParse(string raw, out int startMin, out int endMin)
    {
        startMin = endMin = 0;
        var parts = raw.Split('-');
        return parts.Length == 2 && TryHm(parts[0], false, out startMin) && TryHm(parts[1], true, out endMin);
    }

    private static bool TryHm(string s, bool allow24, out int min)
    {
        min = 0;
        if (s.Length != 5 || s[2] != ':' || !int.TryParse(s.AsSpan(0, 2), out var h) || !int.TryParse(s.AsSpan(3, 2), out var m)) return false;
        if (m is < 0 or > 59 || h < 0) return false;
        if (h == 24 && m == 0 && allow24) { min = 1440; return true; }
        if (h > 23) return false;
        min = h * 60 + m;
        return true;
    }
}
