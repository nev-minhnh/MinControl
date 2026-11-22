namespace MinControl.Core.Util;

/// <summary>RFC 4648 §5 base64url without padding (strict: padding and non-alphabet chars are rejected).</summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool TryDecode(string? s, out byte[] bytes)
    {
        bytes = [];
        if (s is null) return false;
        foreach (var c in s)
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')) return false;
        if (s.Length % 4 == 1) return false;
        var b64 = s.Replace('-', '+').Replace('_', '/');
        b64 += (b64.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        try { bytes = Convert.FromBase64String(b64); return true; }
        catch (FormatException) { return false; }
    }

    public static byte[] Decode(string s) =>
        TryDecode(s, out var b) ? b : throw new FormatException("invalid base64url");
}
