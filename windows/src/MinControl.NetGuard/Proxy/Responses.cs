using System.Net;
using System.Text;

namespace MinControl.NetGuard.Proxy;

/// <summary>Canned proxy responses. All close the connection.</summary>
internal static class Responses
{
    public static readonly byte[] ConnectEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();

    public static byte[] Simple(int code, string reason) =>
        Encoding.ASCII.GetBytes($"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n");

    /// <summary>CONNECT refusal: browsers show their own error page; the extension shows the friendly page.</summary>
    public static readonly byte[] ConnectBlocked =
        "HTTP/1.1 403 Forbidden\r\nX-MinControl: blocked\r\nContent-Length: 0\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n"u8.ToArray();

    public static byte[] BlockPage(string host, string? reason, string? category)
    {
        var why = reason switch
        {
            "category" => $"Trang web thuộc nhóm bị chặn ({Enc(category)}).",
            "schedule" => $"Nhóm trang web này ({Enc(category)}) không được dùng vào giờ này.",
            "allowlist_miss" => "Trang web này không nằm trong danh sách được phép.",
            "doh" => "Máy chủ DNS mã hoá (DoH/DoT) không được dùng trên máy này.",
            "port" => "Kết nối tới cổng này không được phép.",
            _ => "Trang web này đã bị bố mẹ chặn.",
        };
        var html = $$"""
            <!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Trang bị chặn</title><style>body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f8;color:#222;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
            .c{background:#fff;border-radius:12px;padding:32px 40px;max-width:520px;box-shadow:0 2px 12px rgba(0,0,0,.08)}h1{font-size:22px;margin:0 0 12px}code{background:#eef;padding:2px 6px;border-radius:4px}</style></head>
            <body><div class="c"><h1>Trang này đã bị chặn</h1><p><code>{{Enc(host)}}</code></p><p>{{why}}</p>
            <p>Nếu con cần dùng trang này cho việc học, hãy nhờ bố mẹ cho phép.</p></div></body></html>
            """;
        var body = Encoding.UTF8.GetBytes(html);
        var head = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {body.Length}\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n");
        var all = new byte[head.Length + body.Length];
        head.CopyTo(all, 0);
        body.CopyTo(all, head.Length);
        return all;
    }

    private static string Enc(string? s) => WebUtility.HtmlEncode(s ?? "");
}
