using System.Text.RegularExpressions;

namespace MinControl.NetGuard.Web;

/// <summary>Well-known DNS-over-HTTPS / DNS-over-TLS endpoints. Matched by host suffix (and exact IP literal).</summary>
public static class DohHosts
{
    public static readonly IReadOnlyList<string> Suffixes =
    [
        "dns.google", "dns.google.com", "8888.google",
        "cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "cloudflare-gateway.com",
        "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "dns12.quad9.net",
        "doh.opendns.com", "doh.familyshield.opendns.com", "doh.umbrella.com",
        "dns.adguard.com", "dns.adguard-dns.com", "dns-family.adguard.com", "family.adguard-dns.com", "unfiltered.adguard-dns.com",
        "doh.cleanbrowsing.org", "dns.nextdns.io", "doh.dns.sb", "dns.alidns.com", "doh.pub", "dns.pub",
        "dns.twnic.tw", "doh.mullvad.net", "dns.mullvad.net", "dns.controld.com", "freedns.controld.com",
        "doh.libredns.gr", "dns.switch.ch", "doh.applied-privacy.net", "doh.xfinity.com", "dns.brahma.world",
        "doh.ffmuc.net", "dns0.eu", "doh.360.cn", "dns.bebasid.com",
    ];

    public static readonly IReadOnlySet<string> IpLiterals = new HashSet<string>(StringComparer.Ordinal)
    {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
        "9.9.9.9", "149.112.112.112", "9.9.9.10", "9.9.9.11", "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15", "185.228.168.168", "185.228.168.9", "45.90.28.0", "45.90.30.0",
        "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2620:fe::fe", "2620:fe::9",
    };

    public static bool IsDoh(string normalizedHost)
    {
        if (IpLiterals.Contains(normalizedHost)) return true;
        foreach (var s in Suffixes)
            if (DomainPattern.IsSameOrSubdomain(normalizedHost, s)) return true;
        return false;
    }
}

/// <summary>Maps search/video hosts to their enforced-safe virtual IP hosts (DNS-style forcing, no TLS interception).</summary>
public static partial class SafeSearchMap
{
    public const string GoogleSafe = "forcesafesearch.google.com";
    public const string BingStrict = "strict.bing.com";
    public const string YoutubeStrict = "restrict.youtube.com";
    public const string YoutubeModerate = "restrictmoderate.youtube.com";

    public static readonly IReadOnlySet<string> YoutubeHosts = new HashSet<string>(StringComparer.Ordinal)
    {
        "youtube.com", "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
        "youtube.googleapis.com", "www.youtube-nocookie.com", "youtube-nocookie.com",
    };

    // google.com, www.google.com, google.com.vn, www.google.co.uk, google.de, ... (search hosts only;
    // mail.google.com, docs.google.com etc. are NOT rewritten).
    [GeneratedRegex(@"^(www\.)?google\.(com|[a-z]{2}|co\.[a-z]{2}|com\.[a-z]{2})$", RegexOptions.CultureInvariant)]
    private static partial Regex GoogleSearchHost();

    public static bool IsGoogleSearchHost(string h) => GoogleSearchHost().IsMatch(h);

    public static bool IsBingHost(string h) => h is "bing.com" or "www.bing.com" or "cn.bing.com";

    /// <summary>Returns the host to connect to instead of <paramref name="normalizedHost"/>, or null for no rewrite.</summary>
    public static string? Rewrite(string normalizedHost, bool safeSearch, string? youtube)
    {
        if (safeSearch)
        {
            if (IsGoogleSearchHost(normalizedHost)) return GoogleSafe;
            if (IsBingHost(normalizedHost)) return BingStrict;
        }
        if (YoutubeHosts.Contains(normalizedHost))
        {
            return youtube switch
            {
                "strict" => YoutubeStrict,
                "moderate" => YoutubeModerate,
                _ => null,
            };
        }
        return null;
    }
}
