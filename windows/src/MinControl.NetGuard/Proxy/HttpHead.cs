using System.Globalization;
using System.Text;

namespace MinControl.NetGuard.Proxy;

/// <summary>Parsed proxy request head (request line + raw header lines).</summary>
public sealed class HttpHead
{
    public required string Method { get; init; }
    public required string Target { get; init; }
    public required string Version { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    /// <summary>Origin-form path for plain HTTP ("/..."), null for CONNECT.</summary>
    public string? PathAndQuery { get; init; }
    public required IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; }

    public bool IsConnect => Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase);

    /// <summary>Index just past "\r\n\r\n", or -1.</summary>
    public static int FindHeadEnd(ReadOnlySpan<byte> buf) => buf.IndexOf("\r\n\r\n"u8) is var i and >= 0 ? i + 4 : -1;

    public static bool TryParse(ReadOnlySpan<byte> head, out HttpHead? result, out string? error)
    {
        result = null;
        error = null;
        var text = Encoding.Latin1.GetString(head);
        var lines = text.Split("\r\n");
        if (lines.Length == 0) { error = "empty"; return false; }
        var parts = lines[0].Split(' ');
        if (parts.Length != 3 || !parts[2].StartsWith("HTTP/1.", StringComparison.Ordinal)) { error = "bad request line"; return false; }
        var method = parts[0];
        var target = parts[1];

        var headers = new List<KeyValuePair<string, string>>();
        for (var i = 1; i < lines.Length; i++)
        {
            var l = lines[i];
            if (l.Length == 0) continue;
            var colon = l.IndexOf(':');
            if (colon <= 0) { error = "bad header"; return false; }
            headers.Add(new(l[..colon].Trim(), l[(colon + 1)..].Trim()));
        }

        string host;
        int port;
        string? path = null;
        if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            if (!TrySplitHostPort(target, 443, out host, out port)) { error = "bad authority"; return false; }
        }
        else
        {
            const string scheme = "http://";
            if (!target.StartsWith(scheme, StringComparison.OrdinalIgnoreCase)) { error = "not absolute-form http"; return false; }
            var rest = target[scheme.Length..];
            var slash = rest.IndexOfAny(['/', '?', '#']);
            var authority = slash < 0 ? rest : rest[..slash];
            path = slash < 0 ? "/" : rest[slash..];
            if (path.StartsWith('?')) path = "/" + path;
            var hash = path.IndexOf('#');
            if (hash >= 0) path = path[..hash];
            var at = authority.LastIndexOf('@');
            if (at >= 0) authority = authority[(at + 1)..];   // drop userinfo
            if (!TrySplitHostPort(authority, 80, out host, out port)) { error = "bad authority"; return false; }
        }

        result = new HttpHead { Method = method, Target = target, Version = parts[2], Host = host, Port = port, PathAndQuery = path, Headers = headers };
        return true;
    }

    public static bool TrySplitHostPort(string authority, int defaultPort, out string host, out int port)
    {
        host = "";
        port = defaultPort;
        if (string.IsNullOrEmpty(authority)) return false;
        if (authority.StartsWith('['))
        {
            var close = authority.IndexOf(']');
            if (close < 0) return false;
            host = authority[1..close];
            var after = authority[(close + 1)..];
            if (after.Length > 0)
            {
                if (after[0] != ':' || !TryPort(after[1..], out port)) return false;
            }
        }
        else
        {
            var colon = authority.LastIndexOf(':');
            if (colon >= 0 && authority.IndexOf(':') == colon)
            {
                host = authority[..colon];
                if (!TryPort(authority[(colon + 1)..], out port)) return false;
            }
            else if (colon >= 0) return false;   // bare IPv6 without brackets
            else host = authority;
        }
        return host.Length is > 0 and <= 253;
    }

    private static bool TryPort(string s, out int port) =>
        int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is > 0 and < 65536;

    private static readonly HashSet<string> HopByHop = new(StringComparer.OrdinalIgnoreCase)
    {
        "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Connection", "Keep-Alive", "TE", "Trailer", "Upgrade",
    };

    /// <summary>Origin-form request head for the upstream server; forces one request per connection.</summary>
    public byte[] BuildUpstreamHead()
    {
        var sb = new StringBuilder(512);
        sb.Append(Method).Append(' ').Append(PathAndQuery ?? "/").Append(' ').Append(Version).Append("\r\n");
        // Host always comes from the absolute URL that was judged (a spoofed Host header must not reach another vhost).
        var hostValue = Host.Contains(':') ? $"[{Host}]" : Host;
        sb.Append("Host: ").Append(Port == 80 ? hostValue : $"{hostValue}:{Port}").Append("\r\n");
        foreach (var (k, v) in Headers)
        {
            if (HopByHop.Contains(k) || k.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
            sb.Append(k).Append(": ").Append(v).Append("\r\n");
        }
        sb.Append("Connection: close\r\n\r\n");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }
}
