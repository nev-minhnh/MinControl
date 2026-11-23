using System.Text.Json;
using MinControl.Core.Protocol;

namespace MinControl.Core.Catalog;

/// <summary>One entry of <c>protocol/search-engines.json</c> (API.md §19).</summary>
public sealed record SearchEngine(string Id, string Name, IReadOnlyList<string> Domains);

/// <summary>
/// Web search engines other than Google and Bing (API.md §19: SafeSearch = Google/Bing only). Embedded at build time
/// from <c>protocol/search-engines.json</c>; a small placeholder is embedded when the file is missing. Domain patterns use
/// the policy <c>domainPattern</c> semantics. Google, Bing, YouTube and MSN hosts are never matched, whatever the file says
/// (Edge and SafeSearch enforcement depend on them).
/// </summary>
public sealed class SearchEngineCatalog
{
    public const string ResourceName = "MinControl.SearchEngines.json";

    /// <summary>Rule text of a SafeSearch engine block (<c>web.blocked.rule</c>).</summary>
    public const string RuleText = "SafeSearch: chỉ cho phép Google và Bing";

    private static readonly string[] NeverBlocked =
    [
        "google", "googleapis.com", "gstatic.com", "bing.com", "bing.net", "youtube.com", "youtu.be", "msn.com", "microsoft.com",
    ];

    public int Version { get; }
    public IReadOnlyList<SearchEngine> Engines { get; }

    private SearchEngineCatalog(int version, IReadOnlyList<SearchEngine> engines)
    {
        Version = version;
        Engines = engines;
    }

    public static SearchEngineCatalog Empty { get; } = new(0, []);

    private static readonly Lazy<SearchEngineCatalog> SharedLazy = new(LoadEmbedded);

    /// <summary>The embedded list (never throws: an unreadable resource yields an empty list).</summary>
    public static SearchEngineCatalog Shared => SharedLazy.Value;

    private sealed record EngineFile(int Version, IReadOnlyList<SearchEngine>? Engines);

    public static SearchEngineCatalog Parse(string json)
    {
        var f = JsonSerializer.Deserialize<EngineFile>(json, ProtocolJson.Options)
            ?? throw new JsonException("empty search engine list");
        var engines = (f.Engines ?? []).Where(e => e is { Id.Length: > 0 })
            .Select(e => e with { Name = e.Name ?? e.Id, Domains = (e.Domains ?? []).Where(d => !IsProtected(ServiceCatalog.BaseDomain(d))).ToList() })
            .Where(e => e.Domains.Count > 0)
            .ToList();
        return new SearchEngineCatalog(f.Version, engines);
    }

    private static SearchEngineCatalog LoadEmbedded()
    {
        try
        {
            using var s = typeof(SearchEngineCatalog).Assembly.GetManifestResourceStream(ResourceName);
            if (s is null) return Empty;
            using var r = new StreamReader(s);
            return Parse(r.ReadToEnd());
        }
        catch (Exception e) when (e is JsonException or IOException or NotSupportedException)
        {
            return Empty;
        }
    }

    /// <summary>True for Google (any google.* label), Bing, YouTube, MSN and Microsoft hosts.</summary>
    public static bool IsProtected(string normalizedHost)
    {
        if (normalizedHost.Length == 0) return false;
        foreach (var p in NeverBlocked)
        {
            if (p == "google")
            {
                // google.com, www.google.com.vn, google.co.uk ...: a "google" label followed only by TLD-ish labels.
                var labels = normalizedHost.Split('.');
                var i = Array.IndexOf(labels, "google");
                if (i >= 0 && labels.Length - i - 1 is >= 1 and <= 2) return true;
                continue;
            }
            if (normalizedHost == p || normalizedHost.EndsWith("." + p, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    /// <summary>The engine owning <paramref name="normalizedHost"/>, or null (always null for protected hosts).</summary>
    public SearchEngine? Match(string normalizedHost)
    {
        if (IsProtected(normalizedHost)) return null;
        foreach (var e in Engines)
            foreach (var d in e.Domains)
                if (HostPattern.Matches(d, normalizedHost)) return e;
        return null;
    }
}
