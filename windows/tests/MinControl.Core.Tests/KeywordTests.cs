using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Keywords;
using MinControl.Core.Policy;
using MinControl.Service.Logic;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>API.md §17 keywords: folding, word boundaries, browser title / URL parsing, close + web.blocked.</summary>
public sealed class KeywordTests
{
    private const string Sid = "S-1-5-21-1-2-3-1001";
    private const string Chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
    private const string Edge = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";

    // ------------------------------------------------------------------ matcher

    [Fact]
    public void Matching_is_case_and_diacritics_insensitive_on_word_boundaries()
    {
        var m = new KeywordMatcher(["cờ bạc", "Sex", "đánh nhau", "  "]);
        Assert.Equal("cờ bạc", m.Match("Chơi CỜ BẠC online"));
        Assert.Equal("cờ bạc", m.Match("co bac la gi"));            // typed without accents
        Assert.Equal("cờ bạc", m.Match("cờ-bạc!"));
        Assert.Equal("Sex", m.Match("SEX education"));
        Assert.Equal("đánh nhau", m.Match("video danh nhau o truong"));
        Assert.Null(m.Match("Essex county"));                       // inside a word
        Assert.Null(m.Match("sexy"));
        Assert.Null(m.Match("cờ vua bạc"));                         // not the same word sequence
        Assert.Null(m.Match(""));
        Assert.True(new KeywordMatcher([]).IsEmpty);
        Assert.Equal(" tim co bac ", KeywordMatcher.Tokens("Tìm  CỜ-BẠC!"));
    }

    [Theory]
    [InlineData("cờ bạc - Google Search - Google Chrome", "cờ bạc - Google Search")]
    [InlineData("cờ bạc - Tìm trên Google - Google Chrome", "cờ bạc - Tìm trên Google")]
    [InlineData("cờ bạc - Search and 3 more pages - Personal - Microsoft\u200b Edge", "cờ bạc - Search")]
    [InlineData("cờ bạc - Tìm kiếm và 2 trang khác - Cá nhân - Microsoft\u200b Edge", "cờ bạc - Tìm kiếm")]
    [InlineData("Video hay - YouTube - Cốc Cốc", "Video hay - YouTube")]
    [InlineData("Wikipedia - Mozilla Firefox", "Wikipedia")]
    public void Page_title_strips_browser_suffixes(string window, string page) =>
        Assert.Equal(page, KeywordMatcher.PageTitle(window));

    [Theory]
    [InlineData("cờ bạc - Google Search", "cờ bạc", "google")]
    [InlineData("cờ bạc - Tìm trên Google", "cờ bạc", "google")]
    [InlineData("cờ bạc - Search", "cờ bạc", "bing")]
    [InlineData("cờ bạc at DuckDuckGo", "cờ bạc", "duckduckgo")]
    [InlineData("cờ bạc — Yandex: found 2 thousand results", "cờ bạc", "yandex")]
    [InlineData("cờ bạc - Cốc Cốc", "cờ bạc", "coccoc")]
    [InlineData("(3) Đánh nhau ở trường - YouTube", "Đánh nhau ở trường", "youtube")]
    [InlineData("cờ bạc - Brave Search", "cờ bạc", "brave")]
    public void Search_queries_are_read_from_result_page_titles(string page, string query, string engine)
    {
        Assert.Equal(query, KeywordMatcher.SearchQueryFromTitle(page, out var e));
        Assert.Equal(engine, e);
    }

    [Theory]
    [InlineData("https://www.google.com/search?q=c%E1%BB%9D+b%E1%BA%A1c&oq=x", "cờ bạc")]
    [InlineData("https://www.bing.com/search?form=QBLH&q=co+bac", "co bac")]
    [InlineData("https://search.yahoo.com/search?p=sex", "sex")]
    [InlineData("https://yandex.com/search/?text=danh+nhau", "danh nhau")]
    [InlineData("https://www.youtube.com/results?search_query=danh+nhau", "danh nhau")]
    [InlineData("https://example.com/page?id=3", null)]
    [InlineData("not a url", null)]
    public void Search_queries_are_read_from_urls(string url, string? query) =>
        Assert.Equal(query, KeywordMatcher.SearchQueryFromUrl(url));

    [Fact]
    public void Rules_pick_searches_titles_and_other_windows_per_policy()
    {
        var m = new KeywordMatcher(["cờ bạc"]);
        var both = new KeywordPolicy(["cờ bạc"], true, true);
        var searchOnly = new KeywordPolicy(["cờ bạc"], true, false);
        var titlesOnly = new KeywordPolicy(["cờ bạc"], false, true);

        var s = KeywordRules.Evaluate(searchOnly, m, Chrome, "co bac online - Google Search - Google Chrome")!;
        Assert.Equal((true, "co bac online", "google", "www.google.com"), (s.Browser, s.Query, s.Engine, s.Host));
        Assert.Null(KeywordRules.Evaluate(searchOnly, m, Chrome, "Tin cờ bạc mới - VnExpress - Google Chrome"));   // a page, not a search
        var t = KeywordRules.Evaluate(titlesOnly, m, Edge, "Tin cờ bạc mới - VnExpress - Personal - Microsoft\u200b Edge")!;
        Assert.Equal((true, "Tin cờ bạc mới - VnExpress", (string?)null), (t.Browser, t.Title, t.Query));
        var yt = KeywordRules.Evaluate(titlesOnly, m, Chrome, "Cờ bạc bịp - YouTube - Google Chrome")!;
        Assert.Equal("youtube", yt.Engine);
        var app = KeywordRules.Evaluate(both, m, @"C:\Games\game.exe", "Sòng cờ bạc 2")!;
        Assert.False(app.Browser);
        Assert.Null(KeywordRules.Evaluate(searchOnly, m, @"C:\Games\game.exe", "Sòng cờ bạc 2"));   // other apps: titles only
        Assert.Null(KeywordRules.Evaluate(both, m, Chrome, "Học toán lớp 5 - Google Search - Google Chrome"));
        Assert.Equal("Đã đóng trang vì có từ bị cấm: cờ bạc", KeywordRules.ToastText(s));
        Assert.Equal("Đã đóng cửa sổ vì có từ bị cấm: cờ bạc", KeywordRules.ToastText(app));

        var url = KeywordRules.EvaluateUrl(searchOnly, m, "https://www.bing.com/search?q=co+bac", "x")!;
        Assert.Equal(("co bac", "bing"), (url.Query, url.Engine));
        Assert.Null(KeywordRules.EvaluateUrl(titlesOnly, m, "https://www.bing.com/search?q=co+bac", "x"));
    }

    // ------------------------------------------------------------------ enforcer

    private sealed class Policies(DevicePolicy p) : IPolicyProvider
    {
        public DevicePolicy? Current => p;
        public event EventHandler<DevicePolicy>? PolicyChanged { add { } remove { } }
    }

    private sealed class Sink : IEventSink
    {
        public readonly List<(string Type, string? Sid, JsonObject Data)> Events = [];
        public void Emit(string type, string? userSid, JsonObject data) => Events.Add((type, userSid, data));
    }

    private sealed record CloseCall(int Session, long Hwnd, int Pid, bool Tab, string Title, string Reason);

    private static (KeywordEnforcer E, Sink Sink, List<CloseCall> Closes, FakeClock Clock) Enforcer(
        KeywordPolicy? kw, bool closeOk = true, bool managed = true, ForegroundWindow? foreground = null)
    {
        var user = BlockingV2Tests.User(keywords: kw);
        var policy = new DevicePolicy(1, "Asia/Ho_Chi_Minh", new Dictionary<string, UserPolicy> { [Sid] = user }, new RetentionDays(30, 30, 30));
        var sink = new Sink();
        var closes = new List<CloseCall>();
        var clock = new FakeClock(new DateTimeOffset(2026, 11, 23, 10, 0, 0, TimeSpan.Zero));
        var e = new KeywordEnforcer(new Policies(policy), _ => managed, id => id == 1 ? Sid : null,
            _ => foreground is null ? [] : [(1, foreground)],
            (s, h, p, tab, title, reason) => { closes.Add(new CloseCall(s, h, p, tab, title, reason)); return Task.FromResult(closeOk); },
            sink, clock);
        return (e, sink, closes, clock);
    }

    [Fact]
    public async Task Browser_hit_closes_the_tab_and_emits_one_fully_described_event()
    {
        var (e, sink, closes, clock) = Enforcer(new KeywordPolicy(["cờ bạc"], true, true));
        var fg = new ForegroundWindow(Chrome, "co bac online - Tìm trên Google - Google Chrome", 4242, 0x10A2);

        var hit = await e.CheckForegroundAsync(1, fg);
        Assert.NotNull(hit);
        var close = Assert.Single(closes);
        Assert.Equal(new CloseCall(1, 0x10A2, 4242, true, "Đã đóng trang vì có từ bị cấm: cờ bạc", "co bac online"), close);
        var ev = Assert.Single(sink.Events);
        Assert.Equal(("web.blocked", Sid), (ev.Type, ev.Sid));
        var d = ev.Data;
        Assert.Equal("keyword", (string)d["reason"]!);
        Assert.Equal("closed_tab", (string)d["action"]!);
        Assert.Equal("cờ bạc", (string)d["keyword"]!);
        Assert.Equal("co bac online", (string)d["query"]!);
        Assert.Equal("google", (string)d["engine"]!);
        Assert.Equal("co bac online - Tìm trên Google", (string)d["title"]!);
        Assert.Equal("chrome.exe", (string)d["exe"]!);
        Assert.Equal("Từ khóa: cờ bạc", (string)d["rule"]!);
        Assert.Equal("www.google.com", (string)d["host"]!);
        Assert.Equal(1, (int)d["count"]!);
        BlockingV2Tests.AssertSchemaValidIfV2("web.blocked", d);

        // same window again within 1.5 s: no second Ctrl+W (rate limit per window)
        Assert.Null(await e.CheckForegroundAsync(1, fg));
        Assert.Single(closes);
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.NotNull(await e.CheckForegroundAsync(1, fg with { Title = "Sòng cờ bạc - YouTube - Google Chrome" }));
        Assert.Equal(2, closes.Count);
        Assert.Equal(2, sink.Events.Count);
    }

    [Fact]
    public async Task Other_app_hit_closes_the_window()
    {
        var (e, sink, closes, _) = Enforcer(new KeywordPolicy(["cờ bạc"], false, true));
        Assert.NotNull(await e.CheckForegroundAsync(1, new ForegroundWindow(@"C:\Games\poker.exe", "Cờ bạc Club", 77, 0x20)));
        Assert.False(Assert.Single(closes).Tab);
        var d = Assert.Single(sink.Events).Data;
        Assert.Equal("closed_window", (string)d["action"]!);
        Assert.Equal("", (string)d["host"]!);
        Assert.Null(d["query"]);
    }

    [Fact]
    public async Task Nothing_is_emitted_when_nothing_was_closed_or_nothing_applies()
    {
        var fg = new ForegroundWindow(Chrome, "cờ bạc - Google Search - Google Chrome", 1, 0x10);
        var (e, sink, closes, _) = Enforcer(new KeywordPolicy(["cờ bạc"], true, true), closeOk: false);
        Assert.Null(await e.CheckForegroundAsync(1, fg));
        Assert.Single(closes);
        Assert.Empty(sink.Events);

        (e, sink, closes, _) = Enforcer(new KeywordPolicy(["cờ bạc"], true, true), managed: false);
        Assert.Null(await e.CheckForegroundAsync(1, fg));
        (e, sink, closes, _) = Enforcer(null);
        Assert.Null(await e.CheckForegroundAsync(1, fg));
        (e, sink, closes, _) = Enforcer(new KeywordPolicy(["cờ bạc"], false, false));
        Assert.Null(await e.CheckForegroundAsync(1, fg));
        (e, sink, closes, _) = Enforcer(new KeywordPolicy(["cờ bạc"], true, true));
        Assert.Null(await e.CheckForegroundAsync(2, fg));            // session of nobody we know
        Assert.Null(await e.CheckForegroundAsync(1, fg with { Hwnd = 0 }));
        Assert.Empty(closes);
        Assert.Empty(sink.Events);
    }

    [Fact]
    public async Task Fresh_history_visit_closes_the_matching_foreground_tab_only()
    {
        var fg = new ForegroundWindow(Edge, "Kết quả - Personal - Microsoft\u200b Edge", 9, 0x30);
        var (e, sink, closes, clock) = Enforcer(new KeywordPolicy(["cờ bạc"], true, false), foreground: fg);
        const string url = "https://www.google.com/search?q=co+bac";

        Assert.Null(await e.CheckHistoryAsync(Sid, url, "Something else", clock.UtcNow));    // another page is in front
        Assert.Null(await e.CheckHistoryAsync(Sid, url, "Kết quả", clock.UtcNow.AddMinutes(-5)));   // old visit
        Assert.Empty(closes);
        var hit = await e.CheckHistoryAsync(Sid, url, "Kết quả", clock.UtcNow.AddSeconds(-20));
        Assert.NotNull(hit);
        Assert.True(Assert.Single(closes).Tab);
        Assert.Equal("co bac", (string)Assert.Single(sink.Events).Data["query"]!);
    }
}
