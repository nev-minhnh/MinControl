using MinControl.Core.Policy;

namespace MinControl.NetGuard.Web;

/// <summary>Reasons as defined by event.schema.json $defs/webBlocked.reason.</summary>
public static class BlockReasons
{
    public const string Category = "category", Blocklist = "blocklist", AllowlistMiss = "allowlist_miss", Schedule = "schedule";
}

/// <param name="Allowed">Connection may proceed.</param>
/// <param name="Reason">One of <see cref="BlockReasons"/> when blocked, null when allowed.</param>
/// <param name="Category">Category that caused the block (also "doh" / "ip" for built-in rules).</param>
/// <param name="ConnectHost">Host to actually connect to (SafeSearch/YouTube rewrite); equals the request host otherwise.</param>
public sealed record WebDecision(bool Allowed, string? Reason, string? Category, string ConnectHost)
{
    public bool Rewritten(string host) => !string.Equals(ConnectHost, host, StringComparison.Ordinal);
}

/// <summary>
/// Pure decision engine for the filtering proxy. Order of evaluation:
/// <list type="number">
/// <item>empty host → block (blocklist)</item>
/// <item>built-in DoH/DoT endpoints → block (blocklist, category "doh") — not overridable, they would bypass all DNS-based filtering</item>
/// <item><c>blockDomains</c> → block (blocklist)</item>
/// <item><c>allowDomains</c> → allow (overrides categories and schedules)</item>
/// <item>allowlist mode and not allowed above → block (allowlist_miss)</item>
/// <item>IP literal (blocklist mode, if configured) → block (blocklist, category "ip")</item>
/// <item>category in <c>blockedCategories</c> → block (category)</item>
/// <item>category in <c>categorySchedules</c> and now (policy timezone) inside a window → block (schedule)</item>
/// <item>allow, with SafeSearch / YouTube restricted-mode host rewrite</item>
/// </list>
/// </summary>
public sealed class WebDecisionEngine
{
    private readonly ICategoryStore _categories;
    private readonly bool _blockIpLiteralsInBlocklistMode;

    public WebDecisionEngine(ICategoryStore categories, NetGuardOptions? options = null)
    {
        _categories = categories;
        _blockIpLiteralsInBlocklistMode = options?.BlockIpLiteralsInBlocklistMode ?? false;
    }

    public WebDecision Decide(WebPolicy web, string? host, DateTimeOffset utcNow, string? timezone)
    {
        var h = DomainPattern.NormalizeHost(host);
        if (h.Length == 0) return Block(BlockReasons.Blocklist, null, h);

        if (DohHosts.IsDoh(h)) return Block(BlockReasons.Blocklist, "doh", h);

        if (DomainPattern.MatchesAny(web.BlockDomains, h)) return Block(BlockReasons.Blocklist, null, h);

        var allowlisted = DomainPattern.MatchesAny(web.AllowDomains, h);
        if (allowlisted) return Allow(web, h);

        if (string.Equals(web.Mode, "allowlist", StringComparison.OrdinalIgnoreCase))
            return Block(BlockReasons.AllowlistMiss, null, h);

        if (_blockIpLiteralsInBlocklistMode && DomainPattern.IsIpLiteral(h))
            return Block(BlockReasons.Blocklist, "ip", h);

        var cats = _categories.CategoriesOf(h);
        if (cats.Count > 0)
        {
            foreach (var c in cats)
                if (Contains(web.BlockedCategories, c)) return Block(BlockReasons.Category, c, h);

            if (web.CategorySchedules is { Count: > 0 } schedules)
            {
                DateTime? local = null;
                foreach (var c in cats)
                {
                    if (!schedules.TryGetValue(c, out var map)) continue;
                    local ??= PolicyTime.ToLocal(utcNow, timezone);
                    if (PolicyTime.InWindows(map, local.Value)) return Block(BlockReasons.Schedule, c, h);
                }
            }
        }

        return Allow(web, h);
    }

    private static WebDecision Allow(WebPolicy web, string h) =>
        new(true, null, null, SafeSearchMap.Rewrite(h, web.SafeSearch, web.Youtube) ?? h);

    private static WebDecision Block(string reason, string? category, string h) => new(false, reason, category, h);

    private static bool Contains(IReadOnlyList<string>? list, string value)
    {
        if (list is null) return false;
        foreach (var v in list)
            if (string.Equals(v, value, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
