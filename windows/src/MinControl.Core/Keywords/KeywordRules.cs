using MinControl.Core.Policy;

namespace MinControl.Core.Keywords;

/// <summary>A banned word found in a window title, page title or search query.</summary>
/// <param name="Keyword">The word as written in the policy.</param>
/// <param name="Browser">True for a browser window (close the tab), false for another app (close the window).</param>
/// <param name="Title">Page title (browser) or window title (other app).</param>
/// <param name="Query">Search query when the hit came from (or the page is) a search result page.</param>
/// <param name="Engine">event.schema.json engine id: google | bing | youtube | coccoc | other.</param>
public sealed record KeywordHit(string Keyword, bool Browser, string Title, string? Query, string? Engine)
{
    /// <summary>Host of the search engine for <c>web.blocked.host</c> ("" when not a search page).</summary>
    public string Host => KeywordRules.EngineHost(Engine);
}

/// <summary>Pure keyword decisions (API.md §17 <c>userPolicy.keywords</c>).</summary>
public static class KeywordRules
{
    /// <summary>Browser executables whose window title is "&lt;page title&gt; - &lt;browser&gt;" (Cốc Cốc and Yandex ship browser.exe).</summary>
    public static readonly IReadOnlySet<string> BrowserExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "opera_gx.exe", "browser.exe", "coccoc.exe",
        "vivaldi.exe", "iexplore.exe", "chromium.exe", "yandex.exe",
    };

    public static bool IsBrowser(string exePath) => BrowserExes.Contains(Path.GetFileName(exePath));

    /// <summary>Checks a foreground window. Browser: the search query of a result page (<c>matchSearches</c>, incl.
    /// "&lt;q&gt; - Google Search", "&lt;q&gt; - Tìm trên Google", Bing, DuckDuckGo, Yandex, Cốc Cốc, YouTube) and the page
    /// title (<c>matchTitles</c>, incl. YouTube video titles). Other apps: the window title (<c>matchTitles</c>).</summary>
    public static KeywordHit? Evaluate(KeywordPolicy? policy, KeywordMatcher matcher, string exePath, string? windowTitle)
    {
        if (policy is null || matcher.IsEmpty || string.IsNullOrWhiteSpace(windowTitle)) return null;
        if (!policy.MatchSearches && !policy.MatchTitles) return null;
        if (IsBrowser(exePath))
        {
            var page = KeywordMatcher.PageTitle(windowTitle);
            var query = KeywordMatcher.SearchQueryFromTitle(page, out var engine);
            var engineId = query is null ? null : EngineId(engine);
            if (policy.MatchSearches && query is not null && matcher.Match(query) is { } w)
                return new KeywordHit(w, true, page, query, engineId);
            if (policy.MatchTitles && matcher.Match(page) is { } t)
                return new KeywordHit(t, true, page, query, engineId);
            return null;
        }
        if (policy.MatchTitles && matcher.Match(windowTitle) is { } a)
            return new KeywordHit(a, false, windowTitle.Trim(), null, null);
        return null;
    }

    /// <summary>Checks the search query of a visited URL (history reader): q / p / text / search_query parameters.</summary>
    public static KeywordHit? EvaluateUrl(KeywordPolicy? policy, KeywordMatcher matcher, string url, string? pageTitle)
    {
        if (policy is not { MatchSearches: true } || matcher.IsEmpty) return null;
        var query = KeywordMatcher.SearchQueryFromUrl(url);
        if (query is null || matcher.Match(query) is not { } w) return null;
        string? host = Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : null;
        return new KeywordHit(w, true, pageTitle ?? "", query, EngineOfHost(host));
    }

    /// <summary>Title/engine names of <see cref="KeywordMatcher.SearchQueryFromTitle"/> → schema engine ids.</summary>
    public static string EngineId(string? engine) => engine switch
    {
        "google" => "google",
        "bing" => "bing",
        "youtube" => "youtube",
        "coccoc" => "coccoc",
        _ => "other",
    };

    public static string EngineOfHost(string? host)
    {
        var h = host?.ToLowerInvariant() ?? "";
        if (h.Contains("youtube.")) return "youtube";
        if (h.Contains("google.")) return "google";
        if (h.Contains("bing.")) return "bing";
        if (h.Contains("coccoc.")) return "coccoc";
        return "other";
    }

    public static string EngineHost(string? engine) => engine switch
    {
        "google" => "www.google.com",
        "bing" => "www.bing.com",
        "youtube" => "www.youtube.com",
        "coccoc" => "coccoc.com",
        _ => "",
    };

    /// <summary>Vietnamese toast line: "Đã đóng trang vì có từ bị cấm: &lt;word&gt;" (window: "Đã đóng cửa sổ …").</summary>
    public static string ToastText(KeywordHit hit) =>
        (hit.Browser ? "Đã đóng trang vì có từ bị cấm: " : "Đã đóng cửa sổ vì có từ bị cấm: ") + hit.Keyword;

    /// <summary><c>web.blocked.rule</c>: "Từ khóa: &lt;word&gt;".</summary>
    public static string Rule(KeywordHit hit) => "Từ khóa: " + hit.Keyword;
}
