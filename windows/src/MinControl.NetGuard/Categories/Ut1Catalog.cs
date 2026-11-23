using System.Collections.Frozen;
using MinControl.Core.Policy;

namespace MinControl.NetGuard.Categories;

/// <summary>
/// Policy category → UT1 blacklist names (Université Toulouse Capitole, https://dsi.ut-capitole.fr/blacklists/,
/// CC BY-SA 4.0 — see ATTRIBUTION.md). Archives are <c>&lt;BaseUrl&gt;&lt;list&gt;.tar.gz</c> containing
/// <c>&lt;list&gt;/domains</c> (one domain per line), plus urls/usage files we ignore.
/// Sources (2026-11-23): primary = the GitHub mirror <c>olbat/ut1-blacklists</c> raw files
/// (<c>&lt;GitHubBase&gt;&lt;list&gt;/domains</c>, ETag + If-None-Match; "adult" is split into <c>domains.0</c>,
/// <c>domains.1</c>, … which are concatenated byte-wise — the split can fall mid-line); fallback = the UT1 tarballs
/// (Last-Modified + If-Modified-Since, slow ~27 KB/s). The installer ships a seed snapshot of all lists.
/// Mapping: adult = adult + mixed_adult; proxy-vpn = vpn + redirector + strict_redirector (VPN services, web proxies,
/// anonymisers); malware = malware + phishing + cryptojacking; "violence" = "agressif", "drugs" = "drogue",
/// "video" = "audio-video", "social" = "social_networks".
/// </summary>
public static class Ut1Catalog
{
    public const string DefaultBaseUrl = "https://dsi.ut-capitole.fr/blacklists/download/";
    public const string DefaultGitHubBaseUrl = "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/";

    public static FrozenDictionary<string, string[]> Sources { get; } = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["adult"] = ["adult", "mixed_adult"],
        ["gambling"] = ["gambling"],
        ["proxy-vpn"] = ["vpn", "redirector", "strict_redirector"],
        ["games"] = ["games"],
        ["social"] = ["social_networks"],
        ["video"] = ["audio-video"],
        ["violence"] = ["agressif"],
        ["drugs"] = ["drogue"],
        ["dating"] = ["dating"],
        ["malware"] = ["malware", "phishing", "cryptojacking"],
    }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>Raw file of a list on the GitHub mirror: <c>&lt;list&gt;/domains</c> (part null) or <c>&lt;list&gt;/domains.&lt;part&gt;</c>.</summary>
    public static Uri GitHubUrlOf(string baseUrl, string list, int? part) =>
        new(baseUrl.TrimEnd('/') + "/" + Uri.EscapeDataString(list) + "/domains" + (part is { } p ? "." + p.ToString(System.Globalization.CultureInfo.InvariantCulture) : ""));

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
