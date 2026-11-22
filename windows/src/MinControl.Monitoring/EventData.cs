using System.Text.Json.Nodes;

namespace MinControl.Monitoring;

/// <summary>Builders for event <c>data</c> objects, exactly per protocol/event.schema.json $defs
/// (additionalProperties=false, so only schema fields; strings truncated to their maxLength).</summary>
internal static class EventData
{
    public static JsonObject Process(string path, int pid, int? parentPid = null, string? sha256 = null,
        string? publisher = null, bool? signed = null, long? sizeBytes = null, string? rule = null)
    {
        var o = new JsonObject
        {
            ["exe"] = Trunc(System.IO.Path.GetFileName(path), 260),
            ["path"] = Trunc(path, 1024),
            ["pid"] = Math.Max(0, pid),
        };
        if (parentPid is > 0) o["parentPid"] = parentPid.Value;
        if (sha256 is not null) o["sha256"] = sha256;
        if (publisher is not null) o["publisher"] = Trunc(publisher, 256);
        if (signed is not null) o["signed"] = signed.Value;
        if (sizeBytes is >= 0) o["sizeBytes"] = sizeBytes.Value;
        if (rule is not null) o["rule"] = Trunc(rule, 128);
        return o;
    }

    public static JsonObject Install(string product, string? version, string? publisher, string scope)
    {
        var o = new JsonObject { ["product"] = Trunc(product, 256), ["scope"] = scope };
        if (!string.IsNullOrWhiteSpace(version)) o["version"] = Trunc(version, 64);
        if (!string.IsNullOrWhiteSpace(publisher)) o["publisher"] = Trunc(publisher, 256);
        return o;
    }

    public static JsonObject Download(string fileName, long? sizeBytes, string? sha256, string? url = null)
    {
        var o = new JsonObject { ["fileName"] = Trunc(fileName, 260) };
        if (url is not null) o["url"] = Trunc(url, 2048);
        if (sizeBytes is >= 0) o["sizeBytes"] = sizeBytes.Value;
        if (sha256 is not null) o["sha256"] = sha256;
        return o;
    }

    public static JsonObject Usb(string deviceName, string? vendorId, string? productId, string? volumeLabel)
    {
        var o = new JsonObject { ["deviceName"] = Trunc(deviceName, 256) };
        if (IsHex4(vendorId)) o["vendorId"] = vendorId!.ToUpperInvariant();
        if (IsHex4(productId)) o["productId"] = productId!.ToUpperInvariant();
        if (!string.IsNullOrEmpty(volumeLabel)) o["volumeLabel"] = Trunc(volumeLabel, 64);
        return o;
    }

    private static bool IsHex4(string? s) => s is { Length: 4 } && s.All(Uri.IsHexDigit);

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max];
}
