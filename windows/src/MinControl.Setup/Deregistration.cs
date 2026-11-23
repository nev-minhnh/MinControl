using System.Globalization;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using MinControl.Core.Crypto;
using MinControl.Core.Util;

namespace MinControl.Setup;

/// <summary>
/// Device deregistration on uninstall (API.md §18.2): <c>POST &lt;server&gt;/v1/device/deregister</c> with
/// <c>{"deviceId","ts","sig"}</c>, sig = b64url (no padding) Ed25519 by the device key over UTF-8
/// <c>"deregister|" + deviceId + "|" + ts</c>, ts = unix seconds (integer). The server then deletes the device and all
/// its data. Best effort: the caller logs a failure and carries on (the PC may be offline).
/// </summary>
public static class Deregistration
{
    public const string Path = "/v1/device/deregister";

    /// <summary>The exact string that is signed.</summary>
    public static string SignatureString(string deviceId, long ts) =>
        "deregister|" + deviceId + "|" + ts.ToString(CultureInfo.InvariantCulture);

    /// <summary>Request body <c>{"deviceId","ts","sig"}</c> (ts is a JSON integer).</summary>
    public static JsonObject BuildBody(DeviceIdentity identity, string deviceId, long ts) => new()
    {
        ["deviceId"] = deviceId,
        ["ts"] = ts,
        ["sig"] = Base64Url.Encode(identity.Sign(Encoding.UTF8.GetBytes(SignatureString(deviceId, ts)))),
    };

    /// <summary>Sends the request with a 10 s timeout. Returns null on success (HTTP 2xx), else a short reason.
    /// Never throws.</summary>
    public static async Task<string?> TrySendAsync(Uri serverBase, DeviceIdentity identity, string deviceId,
        DateTimeOffset now, HttpMessageHandler? handler = null)
    {
        try
        {
            using var http = handler is null
                ? new HttpClient { Timeout = TimeSpan.FromSeconds(10) }
                : new HttpClient(handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(10) };
            using var resp = await http.PostAsync(new Uri(serverBase, Path),
                JsonContent.Create(BuildBody(identity, deviceId, now.ToUnixTimeSeconds())));
            return resp.IsSuccessStatusCode ? null : $"HTTP {(int)resp.StatusCode}";
        }
        catch (Exception e)
        {
            return e is TaskCanceledException ? "timeout" : e.Message;
        }
    }
}
