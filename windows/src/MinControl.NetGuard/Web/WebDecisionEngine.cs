using MinControl.Core.Catalog;
using MinControl.Core.Policy;

namespace MinControl.NetGuard.Web;

/// <summary>Reasons as defined by event.schema.json $defs/webBlocked.reason.</summary>
public static class BlockReasons
{
    public const string Category = "category", Blocklist = "blocklist", AllowlistMiss = "allowlist_miss", Schedule = "schedule",
        Doh = "doh", Port = "port", Keyword = "keyword", Service = "service";
}

/// <param name="Allowed">Connection may proceed.</param>
/// <param name="Reason">One of <see cref="BlockReasons"/> when blocked, null when allowed.</param>
/// <param name="Category">Category that caused the block (also "ip" for the built-in IP-literal rule).</param>
/// <param name="ConnectHost">Host to actually connect to (SafeSearch/YouTube rewrite); equals the request host otherwise.</param>
/// <param name="Service">Catalog service id that caused the block (blockedServices, or a service of a blocked category).</param>
/// <param name="Pattern">blockDomains pattern that matched (reason blocklist).</param>
/// <param name="SearchEngine">Search engine id of a SafeSearch block (API.md §19: only Google and Bing are allowed).</param>
public sealed record WebDecision(bool Allowed, string? Reason, string? Category, string ConnectHost, string? Service = null, string? Pattern = null,
    string? SearchEngine = null)
{
    public bool Rewritten(string host) => !string.Equals(ConnectHost, host, StringComparison.Ordinal);
}

/// <summary>
/// Pure decision engine for the filtering proxy (API.md §17). Order of evaluation:
/// <list type="number">
/// <item>empty host → block (blocklist)</item>
/// <item>built-in DoH/DoT endpoints → block (reason doh) — not overridable, they would bypass all DNS-based filtering</item>
/// <item><c>blockDomains</c> → block (blocklist). A pattern naming a YouTube host (youtube.com, www.youtube.com,
///   *.youtube.com, youtu.be…) blocks every YouTube host of the catalog (ytimg, googlevideo, youtubei.googleapis.com…).</item>
/// <item><c>blockedServices</c> → block (service) on any of the service's domains</item>
/// <item><c>allowDomains</c> / <c>allowedServices</c> → allow (overrides categories and schedules)</item>
/// <item><c>safeSearch</c> on and the host belongs to a search engine of <c>protocol/search-engines.json</c> → block
///   (blocklist, rule "SafeSearch: chỉ cho phép Google và Bing", API.md §19)</item>
/// <item>allowlist mode and not allowed above → block (allowlist_miss)</item>
/// <item>IP literal (blocklist mode, if configured) → block (blocklist, category "ip")</item>
/// <item>category in <c>blockedCategories</c> → block (category): category lists, plus the catalog services of that
///   category (so "video" always covers every YouTube host)</item>
/// <item>category in <c>categorySchedules</c> and now (policy timezone) inside a window → block (schedule)</item>
/// <item>allow, with SafeSearch / YouTube restricted-mode host rewrite</item>
/// </list>
/// </summary>
public sealed class WebDecisionEngine
{
    private readonly ICategoryStore _categories;
    private readonly ServiceCatalog _catalog;
    private readonly SearchEngineCatalog _engines;
    private readonly bool _blockIpLiteralsInBlocklistMode;

    public WebDecisionEngine(ICategoryStore categories, NetGuardOptions? options = null, ServiceCatalog? catalog = null,
        SearchEngineCatalog? searchEngines = null)
    {
        _categories = categories;
        _catalog = catalog ?? ServiceCatalog.Shared;
        _engines = searchEngines ?? SearchEngineCatalog.Shared;
        _blockIpLiteralsInBlocklistMode = options?.BlockIpLiteralsInBlocklistMode ?? false;
    }

    public ServiceCatalog Catalog => _catalog;

    public WebDecision Decide(WebPolicy web, string? host, DateTimeOffset utcNow, string? timezone)
    {
        var h = DomainPattern.NormalizeHost(host);
        if (h.Length == 0) return Block(BlockReasons.Blocklist, null, h);

        if (DohHosts.IsDoh(h)) return Block(BlockReasons.Doh, null, h);

        if (BlockedPattern(web.BlockDomains, h) is { } pattern) return Block(BlockReasons.Blocklist, null, h, pattern: pattern);

        if (ServiceCatalog.MatchHost(_catalog.FindAll(web.BlockedServices), h) is { } blockedService)
            return Block(BlockReasons.Service, null, h, service: blockedService.Id);

        if (DomainPattern.MatchesAny(web.AllowDomains, h) || ServiceCatalog.MatchHost(_catalog.FindAll(web.AllowedServices), h) is not null)
            return Allow(web, h);

        if (web.SafeSearch && _engines.Match(h) is { } engine)
            return Block(BlockReasons.Blocklist, null, h) with { SearchEngine = engine.Id };

        if (string.Equals(web.Mode, "allowlist", StringComparison.OrdinalIgnoreCase))
            return Block(BlockReasons.AllowlistMiss, null, h);

        if (_blockIpLiteralsInBlocklistMode && DomainPattern.IsIpLiteral(h))
            return Block(BlockReasons.Blocklist, "ip", h);

        var cats = _categories.CategoriesOf(h);
        foreach (var c in web.BlockedCategories)
        {
            if (Contains(cats, c)) return Block(BlockReasons.Category, c.ToLowerInvariant(), h, service: CatalogServiceIn(c, h));
            if (CatalogServiceIn(c, h) is { } s) return Block(BlockReasons.Category, c.ToLowerInvariant(), h, service: s);
        }

        if (web.CategorySchedules is { Count: > 0 } schedules)
        {
            DateTime? local = null;
            foreach (var (c, map) in schedules)
            {
                var svc = CatalogServiceIn(c, h);
                if (!Contains(cats, c) && svc is null) continue;
                local ??= PolicyTime.ToLocal(utcNow, timezone);
                if (PolicyTime.InWindows(map, local.Value)) return Block(BlockReasons.Schedule, c.ToLowerInvariant(), h, service: svc);
            }
        }

        return Allow(web, h);
    }

    /// <summary>The blockDomains pattern that blocks <paramref name="h"/>, or null. A pattern naming any YouTube host
    /// stands for the whole YouTube service.</summary>
    private string? BlockedPattern(IReadOnlyList<string> patterns, string h)
    {
        string? youtubePattern = null;
        foreach (var p in patterns)
        {
            if (DomainPattern.Matches(p, h)) return p;
            if (youtubePattern is null && _catalog.IsYoutubeHost(ServiceCatalog.BaseDomain(p))) youtubePattern = p;
        }
        return youtubePattern is not null && _catalog.IsYoutubeHost(h) ? youtubePattern : null;
    }

    /// <summary>Id of a catalog service of policy category <paramref name="category"/> that owns the host, or null.</summary>
    private string? CatalogServiceIn(string category, string h)
    {
        foreach (var s in _catalog.InPolicyCategory(category.ToLowerInvariant()))
            if (ServiceCatalog.HostMatches(s, h)) return s.Id;
        return null;
    }

    private static WebDecision Allow(WebPolicy web, string h) =>
        new(true, null, null, SafeSearchMap.Rewrite(h, web.SafeSearch, web.Youtube) ?? h);

    private static WebDecision Block(string reason, string? category, string h, string? service = null, string? pattern = null) =>
        new(false, reason, category, h, service, pattern);

    private static bool Contains(IEnumerable<string>? list, string value)
    {
        if (list is null) return false;
        foreach (var v in list)
            if (string.Equals(v, value, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
