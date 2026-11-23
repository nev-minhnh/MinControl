using MinControl.Core.Catalog;
using MinControl.Core.Policy;
using MinControl.NetGuard.Proxy;
using MinControl.NetGuard.Web;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>API.md §19: with SafeSearch on, only Google and Bing may be used as web search engines.</summary>
public sealed class SafeSearchEnginesTests
{
    private static readonly SearchEngineCatalog Engines = SearchEngineCatalog.Parse("""
    {"version":1,"engines":[
      {"id":"duckduckgo","name":"DuckDuckGo","domains":["*.duckduckgo.com","*.duck.com"]},
      {"id":"yandex","name":"Yandex","domains":["*.yandex.ru","*.yandex.com"]},
      {"id":"yahoo","name":"Yahoo","domains":["search.yahoo.com"]},
      {"id":"bad","name":"Must never block","domains":["*.google.com","*.bing.com","www.youtube.com","*.msn.com","google.com.vn"]}
    ]}
    """);

    private static WebPolicy Web(bool safeSearch, string mode = "blocklist", IReadOnlyList<string>? allow = null) =>
        new(mode, [], [], allow ?? [], safeSearch, "off", ["msedge.exe"], []);

    private static WebDecision Decide(WebPolicy web, string host) =>
        new WebDecisionEngine(CategoryIndex.Empty, null, BlockingV2Tests.Catalog, Engines).Decide(web, host, DateTimeOffset.UtcNow, null);

    [Theory]
    [InlineData("duckduckgo.com", "duckduckgo")]
    [InlineData("html.duckduckgo.com", "duckduckgo")]
    [InlineData("yandex.ru", "yandex")]
    [InlineData("search.yahoo.com", "yahoo")]
    public void SafeSearch_on_blocks_other_engines(string host, string engine)
    {
        var d = Decide(Web(true), host);
        Assert.False(d.Allowed);
        Assert.Equal((BlockReasons.Blocklist, engine), (d.Reason, d.SearchEngine));
        Assert.Equal("SafeSearch: chỉ cho phép Google và Bing", BlockNoticeText.Rule(d));
        Assert.Equal("SafeSearch: chỉ cho phép Google và Bing", FilteringProxy.BlockedData("msedge.exe", host, null, d)["rule"]!.GetValue<string>());
        Assert.Contains("Google", BlockNoticeText.SafeSearchToast);
    }

    [Fact]
    public void SafeSearch_off_leaves_engines_alone()
    {
        Assert.True(Decide(Web(false), "duckduckgo.com").Allowed);
        Assert.True(Decide(Web(true), "mail.yahoo.com").Allowed);   // only the search host is listed
    }

    [Theory]
    [InlineData("www.google.com", "forcesafesearch.google.com")]
    [InlineData("google.com.vn", "forcesafesearch.google.com")]
    [InlineData("www.bing.com", "strict.bing.com")]
    [InlineData("www.youtube.com", "www.youtube.com")]
    [InlineData("www.msn.com", "www.msn.com")]
    public void Google_bing_youtube_msn_are_never_blocked(string host, string connect)
    {
        var d = Decide(Web(true), host);
        Assert.True(d.Allowed);
        Assert.Equal(connect, d.ConnectHost);
    }

    [Fact]
    public void Protected_patterns_are_dropped_from_the_list()
    {
        Assert.DoesNotContain(Engines.Engines, e => e.Id == "bad");
        Assert.True(SearchEngineCatalog.IsProtected("www.google.co.uk"));
        Assert.False(SearchEngineCatalog.IsProtected("duckduckgo.com"));
    }

    [Fact]
    public void Explicit_parent_allow_wins_over_safesearch_engine_block()
    {
        Assert.True(Decide(Web(true, allow: ["*.duckduckgo.com"]), "duckduckgo.com").Allowed);
    }

    [Fact]
    public void Embedded_list_loads_and_blocks_duckduckgo()
    {
        Assert.NotEmpty(SearchEngineCatalog.Shared.Engines);
        Assert.Equal("duckduckgo", SearchEngineCatalog.Shared.Match("duckduckgo.com")?.Id);
        Assert.Null(SearchEngineCatalog.Shared.Match("www.google.com"));
    }
}
