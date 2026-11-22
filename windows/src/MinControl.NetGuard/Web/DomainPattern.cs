using System.Net;

namespace MinControl.NetGuard.Web;

/// <summary>
/// Host normalisation and policy <c>domainPattern</c> matching.
/// Semantics: <c>"example.com"</c> matches exactly that host; <c>"*.example.com"</c> matches
/// <c>example.com</c> itself and every subdomain. Matching is case-insensitive.
/// </summary>
public static class DomainPattern
{
    /// <summary>Lower-case, strip brackets / trailing dot / port-less whitespace. Returns "" for garbage.</summary>
    public static string NormalizeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return "";
        var h = host.Trim();
        if (h.StartsWith('[') && h.EndsWith(']')) h = h[1..^1];
        h = h.TrimEnd('.').ToLowerInvariant();
        return h;
    }

    public static bool IsIpLiteral(string normalizedHost) => IPAddress.TryParse(normalizedHost, out _);

    public static bool Matches(string pattern, string normalizedHost)
    {
        if (string.IsNullOrEmpty(pattern) || normalizedHost.Length == 0) return false;
        var p = pattern.Trim().ToLowerInvariant();
        if (p.StartsWith("*.", StringComparison.Ordinal))
            return IsSameOrSubdomain(normalizedHost, p[2..]);
        return string.Equals(p, normalizedHost, StringComparison.Ordinal);
    }

    public static bool MatchesAny(IEnumerable<string>? patterns, string normalizedHost)
    {
        if (patterns is null) return false;
        foreach (var p in patterns)
            if (Matches(p, normalizedHost)) return true;
        return false;
    }

    /// <summary>True when <paramref name="host"/> equals <paramref name="suffix"/> or ends with "." + suffix.</summary>
    public static bool IsSameOrSubdomain(string host, string suffix)
    {
        if (suffix.Length == 0) return false;
        if (host.Length == suffix.Length) return string.Equals(host, suffix, StringComparison.Ordinal);
        return host.Length > suffix.Length
            && host.EndsWith(suffix, StringComparison.Ordinal)
            && host[host.Length - suffix.Length - 1] == '.';
    }

    /// <summary>Enumerates host, then each parent suffix: a.b.c → a.b.c, b.c, c.</summary>
    public static IEnumerable<string> SelfAndParents(string host)
    {
        var h = host;
        while (h.Length > 0)
        {
            yield return h;
            var dot = h.IndexOf('.');
            if (dot < 0) yield break;
            h = h[(dot + 1)..];
        }
    }
}
