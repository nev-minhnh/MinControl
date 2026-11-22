using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using MinControl.Core.Events;

namespace MinControl.Browser.Events;

/// <summary>
/// Strict shape check of extension-originated event data against protocol/event.schema.json
/// ($defs webVisit, webSearch, webBlocked, download). Returns a fresh copy containing only known
/// properties, or null when the data does not match (unknown property, wrong type, missing field, too long).
/// The extension is untrusted input from the managed user's session.
/// </summary>
public static partial class BrowserEventValidator
{
    public static readonly IReadOnlySet<string> AcceptedTypes = new HashSet<string>(StringComparer.Ordinal)
    {
        EventTypes.WebVisit, EventTypes.WebSearch, EventTypes.WebBlocked, EventTypes.DownloadCompleted,
    };

    private enum Kind { Str, Int, Enum, Sha256 }

    private sealed record Field(Kind Kind, bool Required, int MaxLength = 0, string[]? Values = null);

    private static readonly Dictionary<string, Dictionary<string, Field>> Shapes = new(StringComparer.Ordinal)
    {
        [EventTypes.WebVisit] = new()
        {
            ["url"] = new(Kind.Str, true, 2048),
            ["title"] = new(Kind.Str, false, 512),
            ["browser"] = new(Kind.Enum, true, Values: ["msedge", "chrome"]),
            ["durationSec"] = new(Kind.Int, false),
            ["transition"] = new(Kind.Str, false, 32),
        },
        [EventTypes.WebSearch] = new()
        {
            ["engine"] = new(Kind.Enum, true, Values: ["google", "bing", "youtube", "coccoc", "other"]),
            ["query"] = new(Kind.Str, true, 512),
        },
        [EventTypes.WebBlocked] = new()
        {
            ["host"] = new(Kind.Str, true, 253),
            ["url"] = new(Kind.Str, false, 2048),
            // Only the extension speaks on this pipe; "proxy" is reserved for NetGuard.
            ["source"] = new(Kind.Enum, true, Values: ["extension"]),
            ["reason"] = new(Kind.Enum, true, Values: ["category", "blocklist", "allowlist_miss", "schedule"]),
            ["category"] = new(Kind.Str, false, 32),
            ["exe"] = new(Kind.Str, false, 260),
        },
        [EventTypes.DownloadCompleted] = new()
        {
            ["url"] = new(Kind.Str, false, 2048),
            ["fileName"] = new(Kind.Str, true, 260),
            ["sizeBytes"] = new(Kind.Int, false),
            ["sha256"] = new(Kind.Sha256, false),
        },
    };

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex Sha256Rx();

    public static JsonObject? Sanitize(string type, JsonObject? data)
    {
        if (data is null || !Shapes.TryGetValue(type, out var shape)) return null;
        var result = new JsonObject();
        foreach (var (name, node) in data)
        {
            if (!shape.TryGetValue(name, out var field)) return null;           // additionalProperties: false
            if (node is not JsonValue v) return null;
            switch (field.Kind)
            {
                case Kind.Str or Kind.Enum or Kind.Sha256:
                {
                    if (v.GetValueKind() != JsonValueKind.String) return null;
                    string s = v.GetValue<string>();
                    if (field.Kind == Kind.Str && s.Length > field.MaxLength) return null;
                    if (field.Kind == Kind.Enum && Array.IndexOf(field.Values!, s) < 0) return null;
                    if (field.Kind == Kind.Sha256 && !Sha256Rx().IsMatch(s)) return null;
                    result[name] = s;
                    break;
                }
                case Kind.Int:
                {
                    if (v.GetValueKind() != JsonValueKind.Number) return null;
                    if (!v.TryGetValue<long>(out long n))
                    {
                        // Accept integral doubles (JS numbers) such as 12.0
                        if (!v.TryGetValue<double>(out double d) || d != Math.Floor(d) || d > long.MaxValue) return null;
                        n = (long)d;
                    }
                    if (n < 0) return null;
                    result[name] = n;
                    break;
                }
            }
        }
        foreach (var (name, field) in shape)
            if (field.Required && !result.ContainsKey(name)) return null;
        return result;
    }
}
