using System.Text.Json;
using MinControl.Core.Policy;
using MinControl.Core.Protocol;

namespace MinControl.Core.Catalog;

/// <summary>One entry of <c>protocol/services.json</c> (API.md §17): one switch = the service's apps AND domains.</summary>
public sealed record CatalogService(string Id, string Name, string Category, IReadOnlyList<string> Domains, IReadOnlyList<AppMatch> Apps);

/// <summary>
/// The service catalog shipped with the agent (<c>protocol/services.json</c>, embedded at build time; a tiny placeholder
/// with YouTube only is embedded when the file is missing). Domain patterns use the policy <c>domainPattern</c> semantics:
/// <c>*.x</c> = x and every subdomain, <c>x</c> = exactly x.
/// </summary>
public sealed class ServiceCatalog
{
    public const string ResourceName = "MinControl.Services.json";

    /// <summary>YouTube's hosts, used when the catalog has no "youtube" entry (placeholder / old catalog).</summary>
    public static readonly IReadOnlyList<string> BuiltInYoutubeDomains =
    [
        "*.youtube.com", "*.youtu.be", "*.youtube-nocookie.com", "*.ytimg.com", "*.googlevideo.com",
        "*.youtubei.googleapis.com", "youtube.googleapis.com", "*.yt3.ggpht.com", "*.youtubekids.com",
    ];

    public const string YoutubeId = "youtube";

    private readonly Dictionary<string, CatalogService> _byId;

    public int Version { get; }
    public IReadOnlyList<CatalogService> Services { get; }

    private ServiceCatalog(int version, IReadOnlyList<CatalogService> services)
    {
        Version = version;
        var list = services.ToList();
        // YouTube must always cover all of its hosts (blocking youtube, API.md 17): union with the built-in list.
        var yt = list.FindIndex(s => s.Id == YoutubeId);
        if (yt < 0) list.Add(new CatalogService(YoutubeId, "YouTube", "video", BuiltInYoutubeDomains, []));
        else list[yt] = list[yt] with { Domains = list[yt].Domains.Concat(BuiltInYoutubeDomains).Distinct(StringComparer.OrdinalIgnoreCase).ToList() };
        Services = list;
        _byId = new Dictionary<string, CatalogService>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in list) _byId.TryAdd(s.Id, s);
    }

    private static readonly Lazy<ServiceCatalog> SharedLazy = new(LoadEmbedded);

    /// <summary>The embedded catalog (never throws: an unreadable resource yields the built-in YouTube entry only).</summary>
    public static ServiceCatalog Shared => SharedLazy.Value;

    public static ServiceCatalog Empty { get; } = new(0, []);

    private sealed record CatalogFile(int Version, IReadOnlyList<CatalogService> Services);

    public static ServiceCatalog Parse(string json)
    {
        var f = JsonSerializer.Deserialize<CatalogFile>(json, ProtocolJson.Options)
            ?? throw new JsonException("empty service catalog");
        var services = (f.Services ?? []).Where(s => s is { Id.Length: > 0 })
            .Select(s => s with { Domains = s.Domains ?? [], Apps = s.Apps ?? [], Category = s.Category ?? "other" })
            .ToList();
        return new ServiceCatalog(f.Version, services);
    }

    private static ServiceCatalog LoadEmbedded()
    {
        try
        {
            using var s = typeof(ServiceCatalog).Assembly.GetManifestResourceStream(ResourceName);
            if (s is null) return Empty;
            using var r = new StreamReader(s);
            return Parse(r.ReadToEnd());
        }
        catch (Exception e) when (e is JsonException or IOException or NotSupportedException)
        {
            return Empty;
        }
    }

    public CatalogService? Find(string? id) => id is not null && _byId.TryGetValue(id, out var s) ? s : null;

    /// <summary>Catalog services for the given ids (unknown ids are ignored).</summary>
    public IEnumerable<CatalogService> FindAll(IEnumerable<string>? ids)
    {
        if (ids is null) yield break;
        foreach (var id in ids)
            if (Find(id) is { } s) yield return s;
    }

    /// <summary>Policy web category (blockedCategories id) a catalog service category belongs to, or null.
    /// video→video, social→social, games→games, chat→social, music→video; ai/other → none.</summary>
    public static string? PolicyCategoryOf(string? serviceCategory) => serviceCategory?.ToLowerInvariant() switch
    {
        "video" or "music" => "video",
        "social" or "chat" => "social",
        "games" => "games",
        _ => null,
    };

    /// <summary>Services whose catalog category maps to <paramref name="policyCategory"/>.</summary>
    public IEnumerable<CatalogService> InPolicyCategory(string policyCategory) =>
        Services.Where(s => string.Equals(PolicyCategoryOf(s.Category), policyCategory, StringComparison.OrdinalIgnoreCase));

    /// <summary>Base domains (pattern without "*.") of every service of a policy category: suffix-matched entries for the
    /// category lists (a hashed category set matches a host and its parents).</summary>
    public IEnumerable<string> DomainsOfPolicyCategory(string policyCategory) =>
        InPolicyCategory(policyCategory).SelectMany(s => s.Domains).Select(BaseDomain).Where(d => d.Length > 0).Distinct(StringComparer.Ordinal);

    /// <summary>"*.x.com" → "x.com"; "x.com" → "x.com" (lower-case).</summary>
    public static string BaseDomain(string pattern)
    {
        var p = pattern.Trim().TrimEnd('.').ToLowerInvariant();
        return p.StartsWith("*.", StringComparison.Ordinal) ? p[2..] : p;
    }

    /// <summary>True when <paramref name="normalizedHost"/> matches one of the service's domain patterns.</summary>
    public static bool HostMatches(CatalogService s, string normalizedHost)
    {
        foreach (var d in s.Domains)
            if (HostPattern.Matches(d, normalizedHost)) return true;
        return false;
    }

    /// <summary>First of <paramref name="services"/> whose domains match the host, or null.</summary>
    public static CatalogService? MatchHost(IEnumerable<CatalogService> services, string normalizedHost)
    {
        foreach (var s in services)
            if (HostMatches(s, normalizedHost)) return s;
        return null;
    }

    /// <summary>True when the host is one of YouTube's hosts (catalog entry or built-in list).</summary>
    public bool IsYoutubeHost(string normalizedHost) => Find(YoutubeId) is { } yt && HostMatches(yt, normalizedHost);
}

/// <summary>Policy <c>domainPattern</c> semantics for Core (NetGuard has the same in DomainPattern).</summary>
public static class HostPattern
{
    public static bool Matches(string pattern, string normalizedHost)
    {
        if (string.IsNullOrEmpty(pattern) || normalizedHost.Length == 0) return false;
        var p = pattern.Trim().TrimEnd('.').ToLowerInvariant();
        if (p.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = p[2..];
            return normalizedHost == suffix
                || (normalizedHost.Length > suffix.Length && normalizedHost.EndsWith(suffix, StringComparison.Ordinal)
                    && normalizedHost[normalizedHost.Length - suffix.Length - 1] == '.');
        }
        return string.Equals(p, normalizedHost, StringComparison.Ordinal);
    }
}
