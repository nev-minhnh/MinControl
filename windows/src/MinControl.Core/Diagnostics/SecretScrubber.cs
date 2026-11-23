using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace MinControl.Core.Diagnostics;

/// <summary>
/// Last line of defence for <c>diag.report</c> (API.md §14: no keys, no tokens): drops properties whose name looks like a
/// secret and masks secret-looking text (bearer tokens, key=value pairs, long base64/base64url runs, PEM blocks).
/// Sections must not put secrets in the report in the first place; this only catches mistakes.
/// </summary>
public static partial class SecretScrubber
{
    public const string Redacted = "[redacted]";

    /// <summary>True for property names that must never appear in a report.</summary>
    public static bool IsSecretName(string name) => SecretName().IsMatch(name);

    public static string Scrub(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        var s = Pem().Replace(text, Redacted);
        s = Bearer().Replace(s, m => m.Groups[1].Value + Redacted);
        s = KeyValue().Replace(s, m => m.Groups[1].Value + m.Groups[2].Value + Redacted);
        s = LongBase64().Replace(s, m => LooksLikeSecret(m.Value) ? Redacted : m.Value);
        return s;
    }

    /// <summary>Returns a scrubbed deep copy.</summary>
    public static JsonNode? Scrub(JsonNode? node)
    {
        switch (node)
        {
            case null: return null;
            case JsonObject o:
            {
                var copy = new JsonObject();
                foreach (var (k, v) in o)
                {
                    if (IsSecretName(k)) continue;
                    copy[k] = Scrub(v);
                }
                return copy;
            }
            case JsonArray a:
            {
                var copy = new JsonArray();
                foreach (var v in a) copy.Add(Scrub(v));
                return copy;
            }
            case JsonValue v when v.TryGetValue<string>(out var str):
                return JsonValue.Create(Scrub(str));
            default:
                return node.DeepClone();
        }
    }

    /// <summary>Hex digests (sha256 of an exe) and GUIDs are fine; mixed-case base64 of ≥ 40 chars is not.</summary>
    private static bool LooksLikeSecret(string s)
    {
        bool upper = false, lower = false, digit = false;
        foreach (var c in s)
        {
            if (char.IsAsciiLetterUpper(c)) upper = true;
            else if (char.IsAsciiLetterLower(c)) lower = true;
            else if (char.IsAsciiDigit(c)) digit = true;
        }
        return upper && lower && digit;
    }

    [GeneratedRegex(@"(?i)(token|secret|password|passwd|privatekey|private_key|apikey|api_key|bearer|authorization|cookie|signature|^sig$|^key$|seed|recovery|credential)",
        RegexOptions.CultureInvariant)]
    private static partial Regex SecretName();

    [GeneratedRegex(@"-----BEGIN [A-Z ]+-----[\s\S]*?(-----END [A-Z ]+-----|$)", RegexOptions.CultureInvariant)]
    private static partial Regex Pem();

    [GeneratedRegex(@"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", RegexOptions.CultureInvariant)]
    private static partial Regex Bearer();

    [GeneratedRegex(@"(?i)\b(token|secret|password|passwd|apikey|api_key|private_?key|signature|sig|key|authorization|cookie)(""?\s*[:=]\s*""?)[^\s"",;&]+",
        RegexOptions.CultureInvariant)]
    private static partial Regex KeyValue();

    [GeneratedRegex(@"[A-Za-z0-9+/_-]{40,}={0,2}", RegexOptions.CultureInvariant)]
    private static partial Regex LongBase64();
}
