using System.Collections.Frozen;
using MinControl.Core.Policy;

namespace MinControl.NetGuard.Categories;

/// <summary>
/// Policy category → UT1 blacklist names (Université Toulouse Capitole, https://dsi.ut-capitole.fr/blacklists/,
/// CC BY-SA 4.0 — see ATTRIBUTION.md). Archives are <c>&lt;BaseUrl&gt;&lt;list&gt;.tar.gz</c> containing
/// <c>&lt;list&gt;/domains</c> (one domain per line), plus urls/usage files we ignore.
/// Verified 2026-11-22: every list below answers 200 with Last-Modified (no ETag) and honours If-Modified-Since (304).
/// Notes: UT1 "malware" is an alias of "phishing" (malware.tar.gz contains <c>phishing/domains</c>), so malware
/// downloads phishing only; "proxy-vpn" merges "vpn" (VPN services) and "redirector" (web proxies / anonymisers);
/// "violence" = "agressif", "drugs" = "drogue", "video" = "audio-video", "social" = "social_networks".
/// </summary>
public static class Ut1Catalog
{
    public const string DefaultBaseUrl = "https://dsi.ut-capitole.fr/blacklists/download/";

    public static FrozenDictionary<string, string[]> Sources { get; } = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["adult"] = ["adult"],
        ["gambling"] = ["gambling"],
        ["proxy-vpn"] = ["vpn", "redirector"],
        ["games"] = ["games"],
        ["social"] = ["social_networks"],
        ["video"] = ["audio-video"],
        ["violence"] = ["agressif"],
        ["drugs"] = ["drogue"],
        ["dating"] = ["dating"],
        ["malware"] = ["phishing"],
    }.ToFrozenDictionary(StringComparer.Ordinal);

    public static Uri UrlOf(string baseUrl, string list) => new(baseUrl.TrimEnd('/') + "/" + Uri.EscapeDataString(list) + ".tar.gz");

    /// <summary>Binary file name of one source of a category: <c>adult.bin</c>, or <c>proxy-vpn.vpn.bin</c> when the
    /// category has several sources. <see cref="Web.CategoryStore.CategoryOfFile"/> maps both back to the category.</summary>
    public static string FileName(string category, string list) =>
        Sources.TryGetValue(category, out var lists) && lists.Length == 1 ? $"{category}.bin" : $"{category}.{list}.bin";

    /// <summary>Known categories referenced by any user of the policy (blockedCategories ∪ categorySchedules keys).</summary>
    public static IReadOnlySet<string> ReferencedCategories(DevicePolicy? policy, Func<string, bool>? isManaged = null)
    {
        var result = new SortedSet<string>(StringComparer.Ordinal);
        if (policy is null) return result;
        foreach (var (sid, user) in policy.Users)
        {
            if (isManaged is not null && !isManaged(sid)) continue;
            var web = user.Web;
            if (web is null) continue;
            foreach (var c in web.BlockedCategories ?? []) Add(c);
            if (web.CategorySchedules is { } schedules)
                foreach (var c in schedules.Keys) Add(c);
        }
        return result;

        void Add(string c)
        {
            var key = c.Trim().ToLowerInvariant();
            if (Sources.ContainsKey(key)) result.Add(key);
        }
    }
}
