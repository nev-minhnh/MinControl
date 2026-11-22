// Requires (lead, on merge): MinControl.Core.Tests.csproj -> <TargetFramework>net10.0-windows</TargetFramework>
// and <ProjectReference Include="..\..\src\MinControl.NetGuard\MinControl.NetGuard.csproj" />.
using MinControl.Core.Policy;
using MinControl.NetGuard.Web;
using Xunit;

namespace MinControl.Core.Tests;

public class NetGuardDecisionTests
{
    // 2026-11-23 is a Monday. Asia/Ho_Chi_Minh = UTC+7 (no DST).
    private static readonly DateTimeOffset MonNoonVn = new(2026, 11, 23, 5, 0, 0, TimeSpan.Zero);    // 12:00 local
    private static readonly DateTimeOffset MonEveningVn = new(2026, 11, 23, 13, 0, 0, TimeSpan.Zero); // 20:00 local
    private const string Tz = "Asia/Ho_Chi_Minh";

    private static readonly CategoryIndex Categories = new(
    [
        new("adult", ["adult-example.com", "xxx.test"]),
        new("gambling", ["casino.test"]),
        new("games", ["roblox.com", "minecraft.net"]),
        new("social", ["facebook.com", "tiktok.com"]),
        new("video", ["youtube.com", "netflix.com"]),
    ]);

    private static readonly WeekdayMap<IReadOnlyList<string>> StudyTime = new(
        Mon: ["08:00-17:00"], Tue: ["08:00-17:00"], Wed: ["08:00-17:00"], Thu: ["08:00-17:00"], Fri: ["08:00-17:00"],
        Sat: [], Sun: []);

    private static WebPolicy Web(
        string mode = "blocklist",
        string[]? blockedCategories = null,
        string[]? blockDomains = null,
        string[]? allowDomains = null,
        bool safeSearch = false,
        string youtube = "off",
        Dictionary<string, WeekdayMap<IReadOnlyList<string>>>? schedules = null) =>
        new(mode, blockedCategories ?? [], blockDomains ?? [], allowDomains ?? [], safeSearch, youtube,
            ["msedge.exe"], [], schedules);

    private static WebDecision Decide(WebPolicy web, string host, DateTimeOffset? now = null) =>
        new WebDecisionEngine(Categories).Decide(web, host, now ?? MonNoonVn, Tz);

    // ---------------------------------------------------------------- patterns

    [Theory]
    [InlineData("*.example.com", "example.com", true)]
    [InlineData("*.example.com", "a.b.example.com", true)]
    [InlineData("*.example.com", "badexample.com", false)]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "www.example.com", false)]
    [InlineData("*.edu.vn", "hcmus.edu.vn", true)]
    [InlineData("*.edu.vn", "edu.vn.evil.com", false)]
    public void DomainPattern_matches(string pattern, string host, bool expected) =>
        Assert.Equal(expected, DomainPattern.Matches(pattern, host));

    [Theory]
    [InlineData("WWW.Example.COM.", "www.example.com")]
    [InlineData("[2001:db8::1]", "2001:db8::1")]
    [InlineData("  ", "")]
    public void NormalizeHost(string input, string expected) => Assert.Equal(expected, DomainPattern.NormalizeHost(input));

    [Fact]
    public void BlockDomains_blocks_with_blocklist_reason()
    {
        var d = Decide(Web(blockDomains: ["*.example-bad.com"]), "www.Example-Bad.com");
        Assert.False(d.Allowed);
        Assert.Equal(BlockReasons.Blocklist, d.Reason);
        Assert.Null(d.Category);
    }

    [Fact]
    public void Unlisted_host_allowed_in_blocklist_mode()
    {
        var d = Decide(Web(), "vnexpress.net");
        Assert.True(d.Allowed);
        Assert.Equal("vnexpress.net", d.ConnectHost);
    }

    [Fact]
    public void BlockDomains_beats_allowDomains()
    {
        var d = Decide(Web(blockDomains: ["bad.edu.vn"], allowDomains: ["*.edu.vn"]), "bad.edu.vn");
        Assert.False(d.Allowed);
    }

    [Fact]
    public void Allowlist_mode_blocks_unlisted_and_allows_listed()
    {
        var web = Web(mode: "allowlist", allowDomains: ["*.edu.vn", "wikipedia.org"]);
        Assert.True(Decide(web, "moet.edu.vn").Allowed);
        Assert.True(Decide(web, "wikipedia.org").Allowed);
        var miss = Decide(web, "vi.wikipedia.org");
        Assert.False(miss.Allowed);
        Assert.Equal(BlockReasons.AllowlistMiss, miss.Reason);
    }

    [Fact]
    public void Empty_host_is_blocked() => Assert.False(Decide(Web(), "").Allowed);

    // ---------------------------------------------------------------- categories

    [Fact]
    public void Blocked_category_matches_subdomains()
    {
        var d = Decide(Web(blockedCategories: ["adult", "gambling"]), "cdn.adult-example.com");
        Assert.False(d.Allowed);
        Assert.Equal(BlockReasons.Category, d.Reason);
        Assert.Equal("adult", d.Category);
    }

    [Fact]
    public void Category_not_blocked_when_not_selected() =>
        Assert.True(Decide(Web(blockedCategories: ["gambling"]), "adult-example.com").Allowed);

    [Fact]
    public void AllowDomains_override_category()
    {
        var d = Decide(Web(blockedCategories: ["games"], allowDomains: ["*.minecraft.net"]), "education.minecraft.net");
        Assert.True(d.Allowed);
    }

    [Fact]
    public void Category_suffix_does_not_match_lookalike() =>
        Assert.True(Decide(Web(blockedCategories: ["gambling"]), "notcasino.test").Allowed);

    [Fact]
    public void CategoryIndex_parses_comments_hosts_format_and_wildcards()
    {
        Assert.Null(CategoryIndex.NormalizeListEntry("# comment"));
        Assert.Null(CategoryIndex.NormalizeListEntry("   "));
        Assert.Equal("ads.test", CategoryIndex.NormalizeListEntry("0.0.0.0 ads.test # tracker"));
        Assert.Equal("evil.test", CategoryIndex.NormalizeListEntry("*.Evil.Test"));
        var idx = new CategoryIndex([new("social", ["Facebook.com"]), new("video", ["facebook.com"])]);
        Assert.Equal(new[] { "social", "video" }, idx.CategoriesOf("m.facebook.com").OrderBy(c => c).ToArray());
        Assert.Empty(idx.CategoriesOf("facebook.com.evil.test"));
    }

    // ---------------------------------------------------------------- schedules

    [Fact]
    public void Category_schedule_blocks_inside_window_in_policy_timezone()
    {
        var web = Web(schedules: new() { ["games"] = StudyTime });
        var during = Decide(web, "www.roblox.com", MonNoonVn);
        Assert.False(during.Allowed);
        Assert.Equal(BlockReasons.Schedule, during.Reason);
        Assert.Equal("games", during.Category);
        Assert.True(Decide(web, "www.roblox.com", MonEveningVn).Allowed);
    }

    [Fact]
    public void Category_schedule_uses_policy_timezone_not_utc()
    {
        // 02:00 UTC Monday = 09:00 in Vietnam (inside 08:00-17:00), but outside the window if read as UTC.
        var web = Web(schedules: new() { ["games"] = StudyTime });
        Assert.False(Decide(web, "roblox.com", new DateTimeOffset(2026, 11, 23, 2, 0, 0, TimeSpan.Zero)).Allowed);
        // 10:30 UTC Monday = 17:30 local → window ended (end is exclusive).
        Assert.True(Decide(web, "roblox.com", new DateTimeOffset(2026, 11, 23, 10, 30, 0, TimeSpan.Zero)).Allowed);
    }

    [Fact]
    public void Category_schedule_respects_weekday()
    {
        var web = Web(schedules: new() { ["games"] = StudyTime });
        var saturdayNoon = new DateTimeOffset(2026, 11, 28, 5, 0, 0, TimeSpan.Zero);
        Assert.True(Decide(web, "roblox.com", saturdayNoon).Allowed);
    }

    [Theory]
    [InlineData("08:00-17:00", 8 * 60, true)]
    [InlineData("08:00-17:00", 17 * 60, false)]
    [InlineData("21:00-24:00", 23 * 60 + 59, true)]
    [InlineData("17:00-08:00", 18 * 60, false)]   // end <= start is invalid
    [InlineData("garbage", 0, false)]
    public void Window_parsing(string window, int minuteOfDay, bool inside)
    {
        var map = new WeekdayMap<IReadOnlyList<string>>([window], [window], [window], [window], [window], [window], [window]);
        var local = new DateTime(2026, 11, 23).AddMinutes(minuteOfDay);
        Assert.Equal(inside, PolicyTime.InWindows(map, local));
    }

    // ---------------------------------------------------------------- SafeSearch / YouTube

    [Theory]
    [InlineData("www.google.com", SafeSearchMap.GoogleSafe)]
    [InlineData("google.com", SafeSearchMap.GoogleSafe)]
    [InlineData("www.google.com.vn", SafeSearchMap.GoogleSafe)]
    [InlineData("www.google.co.uk", SafeSearchMap.GoogleSafe)]
    [InlineData("www.google.de", SafeSearchMap.GoogleSafe)]
    [InlineData("www.bing.com", SafeSearchMap.BingStrict)]
    [InlineData("bing.com", SafeSearchMap.BingStrict)]
    public void SafeSearch_rewrites_search_hosts(string host, string expected)
    {
        var d = Decide(Web(safeSearch: true), host);
        Assert.True(d.Allowed);
        Assert.Equal(expected, d.ConnectHost);
        Assert.True(d.Rewritten(host));
    }

    [Theory]
    [InlineData("mail.google.com")]
    [InlineData("docs.google.com")]
    [InlineData("www.google.com.evil.test")]
    [InlineData("googleapis.com")]
    public void SafeSearch_does_not_rewrite_other_google_hosts(string host) =>
        Assert.Equal(host, Decide(Web(safeSearch: true), host).ConnectHost);

    [Fact]
    public void SafeSearch_off_leaves_google_untouched() =>
        Assert.Equal("www.google.com", Decide(Web(safeSearch: false), "www.google.com").ConnectHost);

    [Theory]
    [InlineData("www.youtube.com", "strict", SafeSearchMap.YoutubeStrict)]
    [InlineData("m.youtube.com", "strict", SafeSearchMap.YoutubeStrict)]
    [InlineData("youtubei.googleapis.com", "strict", SafeSearchMap.YoutubeStrict)]
    [InlineData("www.youtube-nocookie.com", "strict", SafeSearchMap.YoutubeStrict)]
    [InlineData("youtube.googleapis.com", "moderate", SafeSearchMap.YoutubeModerate)]
    [InlineData("www.youtube.com", "moderate", SafeSearchMap.YoutubeModerate)]
    [InlineData("www.youtube.com", "off", "www.youtube.com")]
    public void Youtube_restricted_mode_mapping(string host, string mode, string expected) =>
        Assert.Equal(expected, Decide(Web(youtube: mode), host).ConnectHost);

    [Fact]
    public void Youtube_rewrite_does_not_touch_video_cdn() =>
        Assert.Equal("rr3---sn-8qj-i5oe.googlevideo.com", Decide(Web(youtube: "strict"), "rr3---sn-8qj-i5oe.googlevideo.com").ConnectHost);

    [Fact]
    public void Blocked_video_category_wins_over_youtube_rewrite()
    {
        var d = Decide(Web(blockedCategories: ["video"], youtube: "strict"), "www.youtube.com");
        Assert.False(d.Allowed);
        Assert.Equal("video", d.Category);
    }

    [Fact]
    public void Allowlisted_google_is_still_safesearch_rewritten() =>
        Assert.Equal(SafeSearchMap.GoogleSafe,
            Decide(Web(mode: "allowlist", allowDomains: ["*.google.com"], safeSearch: true), "www.google.com").ConnectHost);

    // ---------------------------------------------------------------- DoH / DoT

    [Theory]
    [InlineData("dns.google")]
    [InlineData("cloudflare-dns.com")]
    [InlineData("mozilla.cloudflare-dns.com")]
    [InlineData("chrome.cloudflare-dns.com")]
    [InlineData("one.one.one.one")]
    [InlineData("dns.quad9.net")]
    [InlineData("doh.opendns.com")]
    [InlineData("dns.adguard-dns.com")]
    [InlineData("abc123.dns.nextdns.io")]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("2606:4700:4700::1111")]
    public void Doh_hosts_blocked(string host)
    {
        var d = Decide(Web(), host);
        Assert.False(d.Allowed);
        Assert.Equal(BlockReasons.Blocklist, d.Reason);
        Assert.Equal("doh", d.Category);
    }

    [Fact]
    public void Doh_hosts_blocked_even_if_allowlisted() =>
        Assert.False(Decide(Web(allowDomains: ["*.cloudflare-dns.com"]), "cloudflare-dns.com").Allowed);

    [Theory]
    [InlineData("google.com")]
    [InlineData("cloudflare.com")]
    [InlineData("notdns.google.com.vn")]
    public void Non_doh_lookalikes_allowed(string host) => Assert.True(Decide(Web(), host).Allowed);

    // ---------------------------------------------------------------- IP literals

    [Fact]
    public void Ip_literals_blocked_in_allowlist_mode() =>
        Assert.Equal(BlockReasons.AllowlistMiss, Decide(Web(mode: "allowlist"), "203.0.113.7").Reason);

    [Fact]
    public void Ip_literals_optionally_blocked_in_blocklist_mode()
    {
        var web = Web();
        Assert.True(Decide(web, "203.0.113.7").Allowed);
        var strict = new WebDecisionEngine(Categories, new MinControl.NetGuard.NetGuardOptions { BlockIpLiteralsInBlocklistMode = true });
        var d = strict.Decide(web, "203.0.113.7", MonNoonVn, Tz);
        Assert.False(d.Allowed);
        Assert.Equal("ip", d.Category);
    }
}
