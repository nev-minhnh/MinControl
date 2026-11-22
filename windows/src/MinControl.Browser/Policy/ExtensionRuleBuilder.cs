using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using MinControl.Core.Policy;

namespace MinControl.Browser.Policy;

/// <summary>Builds the {t:"rules"} message sent to the extension (declarativeNetRequest domain lists).
/// Categories and schedules stay with the NetGuard proxy; the extension only handles explicit domains.</summary>
public static partial class ExtensionRuleBuilder
{
    private static readonly IdnMapping Idn = new();

    [GeneratedRegex("^[a-z0-9]([a-z0-9-]{0,62})(\\.[a-z0-9]([a-z0-9-]{0,62}))*$")]
    private static partial Regex HostRx();

    /// <summary>Lower-case ASCII (punycode) host, without "*." / leading or trailing dots; null if invalid.</summary>
    public static string? NormalizeDomain(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        string d = raw.Trim().ToLowerInvariant();
        if (d.StartsWith("*.", StringComparison.Ordinal)) d = d[2..];
        d = d.Trim('.');
        if (d.Length == 0 || d.Length > 253) return null;
        try { d = Idn.GetAscii(d); } catch (ArgumentException) { return null; }
        return HostRx().IsMatch(d) ? d : null;
    }

    public static JsonObject Build(UserPolicy? user)
    {
        var web = user?.Web;
        string mode = web?.Mode == "allowlist" ? "allowlist" : "blocklist";
        return new JsonObject
        {
            ["t"] = "rules",
            ["mode"] = mode,
            ["block"] = ToArray(web?.BlockDomains),
            ["allow"] = ToArray(web?.AllowDomains),
            ["monitoring"] = new JsonObject
            {
                ["history"] = user?.Monitoring.BrowserHistory ?? true,
                ["downloads"] = user?.Monitoring.Downloads ?? true,
            },
        };
    }

    private static JsonArray ToArray(IReadOnlyList<string>? list)
    {
        var arr = new JsonArray();
        if (list is null) return arr;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in list)
            if (NormalizeDomain(raw) is { } d && seen.Add(d)) arr.Add(d);
        return arr;
    }
}
