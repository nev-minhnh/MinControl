using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace MinControl.Core.Keywords;

/// <summary>
/// Banned-word matching (API.md §17 <c>userPolicy.keywords</c>): case- and diacritics-insensitive (Vietnamese folded to
/// ASCII, đ → d), on word boundaries (a keyword of several words matches the same word sequence). Pure, thread-safe.
/// </summary>
public sealed partial class KeywordMatcher
{
    // (folded keyword wrapped in spaces, original word)
    private readonly (string Folded, string Original)[] _words;

    public KeywordMatcher(IEnumerable<string>? words)
    {
        _words = (words ?? [])
            .Select(w => (Folded: Tokens(w), Original: w.Trim()))
            .Where(x => x.Folded.Length > 2)
            .GroupBy(x => x.Folded, StringComparer.Ordinal).Select(g => g.First())
            .OrderByDescending(x => x.Folded.Length)   // most specific first
            .ToArray();
    }

    public bool IsEmpty => _words.Length == 0;

    /// <summary>The first banned word (as written in the policy) found in <paramref name="text"/>, or null.</summary>
    public string? Match(string? text)
    {
        if (_words.Length == 0 || string.IsNullOrWhiteSpace(text)) return null;
        var t = Tokens(text);
        foreach (var (folded, original) in _words)
            if (t.Contains(folded, StringComparison.Ordinal)) return original;
        return null;
    }

    /// <summary>Lower-case, diacritics removed (đ → d), every run of non letters/digits → one space, wrapped in spaces:
    /// "Tìm  CỜ-BẠC!" → " tim co bac ".</summary>
    public static string Tokens(string s)
    {
        var folded = Fold(s);
        var sb = new StringBuilder(folded.Length + 2);
        sb.Append(' ');
        bool space = true;
        foreach (var c in folded)
        {
            if (char.IsLetterOrDigit(c)) { sb.Append(c); space = false; }
            else if (!space) { sb.Append(' '); space = true; }
        }
        if (!space) sb.Append(' ');
        return sb.ToString();
    }

    /// <summary>Lower-case and strip combining marks; đ/Đ → d.</summary>
    public static string Fold(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var d = s.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(d.Length);
        foreach (var c in d)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.NonSpacingMark) continue;
            sb.Append(c switch { 'đ' or 'Đ' => 'd', _ => char.ToLowerInvariant(c) });
        }
        return sb.ToString().Normalize(NormalizationForm.FormC);
    }

    // ------------------------------------------------------------------ browser titles

    // " - Google Chrome", " - Microsoft(U+200B) Edge" (Edge puts a zero-width space in its name), " - Cốc Cốc", " - Brave",
    // " - Mozilla Firefox", " — Opera"
    [GeneratedRegex(@"\s+[-—–]\s+(?:Google Chrome|Microsoft[\s\u200b]*Edge|C[oố]c C[oố]c|Brave|Mozilla Firefox|Firefox|Opera|Vivaldi|Chromium)\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BrowserSuffix();

    // Edge profile label before the browser name: " - Personal", " - Cá nhân", " - Work", " - Profile 2", " - Hồ sơ 1"
    [GeneratedRegex(@"\s+[-—–]\s+(?:Personal|Cá nhân|Work|Công việc|Profile \d+|Hồ sơ(?: cá nhân| \d+)?|Default)\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ProfileSuffix();

    // Edge/Chrome tab-count suffix: "… and 3 more pages", "… và 3 trang khác"
    [GeneratedRegex(@"\s+(?:and \d+ more pages?|và \d+ trang khác)\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MorePages();

    /// <summary>The page title inside a browser window title (browser name and tab-count suffix removed).</summary>
    public static string PageTitle(string windowTitle)
    {
        var t = BrowserSuffix().Replace(windowTitle.Trim(), "");
        t = ProfileSuffix().Replace(t, "");
        t = MorePages().Replace(t, "");
        return t.Replace('\u200b', ' ').Replace("  ", " ").Trim();
    }

    private static readonly (string Suffix, string Engine)[] SearchSuffixes =
    [
        (" - Google Search", "google"), (" - Tìm trên Google", "google"), (" - Tìm kiếm trên Google", "google"),
        (" - Google Tìm kiếm", "google"), (" - Tìm kiếm Google", "google"),
        (" - Bing", "bing"), (" - Search", "bing"), (" - Tìm kiếm", "bing"),
        (" at DuckDuckGo", "duckduckgo"), (" tại DuckDuckGo", "duckduckgo"),
        (" - Yahoo Search Results", "yahoo"), (" - Yahoo Search", "yahoo"), (" - Tìm kiếm Yahoo", "yahoo"),
        (" - Cốc Cốc Search", "coccoc"), (" - Tìm kiếm Cốc Cốc", "coccoc"), (" - Cốc Cốc", "coccoc"),
        (" - Brave Search", "brave"),
        (" - YouTube", "youtube"),
    ];

    // Yandex: "<q> — Yandex: 5 thousand results found", "<q> — Яндекс: нашлось …", "<q> — Yandex"
    [GeneratedRegex(@"^(?<q>.+?)\s+[—-]\s+(?:Yandex|Яндекс)(?::.*)?$", RegexOptions.CultureInvariant)]
    private static partial Regex YandexTitle();

    /// <summary>Search query (or YouTube video title) in a page title of a search engine result page:
    /// "<q> - Google Search", "<q> - Tìm trên Google", "<q> - Search" (Bing), "<q> at DuckDuckGo", "<q> — Yandex: …",
    /// "<q> - Cốc Cốc", "<q> - Brave Search", "<title> - YouTube". Null when the title is not one of those.</summary>
    public static string? SearchQueryFromTitle(string pageTitle, out string? engine)
    {
        engine = null;
        var t = pageTitle.Trim();
        // "(3) <title> - YouTube": notification counter
        if (t.StartsWith('(') && t.IndexOf(") ", StringComparison.Ordinal) is > 0 and < 6 and var close) t = t[(close + 2)..];
        foreach (var (suffix, e) in SearchSuffixes)
            if (t.Length > suffix.Length && t.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                engine = e;
                return t[..^suffix.Length].Trim();
            }
        var m = YandexTitle().Match(t);
        if (m.Success) { engine = "yandex"; return m.Groups["q"].Value.Trim(); }
        return null;
    }

    private static readonly string[] QueryParams = ["q", "p", "text", "search_query", "query", "wd"];

    /// <summary>Search query of a URL: the first non-empty of q / p / text / search_query / query / wd.</summary>
    public static string? SearchQueryFromUrl(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
        if (u.Scheme is not ("http" or "https")) return null;
        var query = u.Query;
        if (query.Length <= 1) return null;
        foreach (var part in query[1..].Split('&'))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var name = part[..eq];
            if (!QueryParams.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            string value;
            try { value = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' ')); }
            catch (UriFormatException) { continue; }
            if (!string.IsNullOrWhiteSpace(value)) return value.Trim();
        }
        return null;
    }
}
