using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MinControl.Service.Logic;

// Pure, platform-neutral: compiled into MinControl.Service, linked into MinControl.Session and the tests.
//
// Wire format on \\.\pipe\MinControl.Session.<sessionId>:
//   [uint32 little-endian payload length][UTF-8 JSON {"type":"...","data":{...}}]
// service -> helper: warning {remainingMin} | lock_overlay {reason, graceSec} | clear_overlay {} |
//                    message {text} | capture {requestId, maxWidth, jpegQuality} | blocked_notice {title, reason} |
//                    close_window {requestId, hwnd, pid, mode: "tab"|"window", title, reason}
// helper -> service: hello {pid} | foreground {exe, title?, pid, hwnd} | idle {idleMs} |
//                    capture_result {requestId, jpeg(base64)?, width, height, error?} | heartbeat {} |
//                    close_result {requestId, ok, error?}

public static class IpcTypes
{
    public const string Warning = "warning", LockOverlay = "lock_overlay", ClearOverlay = "clear_overlay",
        Message = "message", Capture = "capture", BlockedNotice = "blocked_notice", CloseWindow = "close_window";
    public const string Hello = "hello", Foreground = "foreground", Idle = "idle",
        CaptureResult = "capture_result", Heartbeat = "heartbeat", CloseResult = "close_result";
}

/// <summary>One IPC message. <see cref="Data"/> is never null after decoding.</summary>
public sealed record IpcMessage(string Type, JsonObject Data)
{
    public static IpcMessage Of(string type, JsonObject? data = null) => new(type, data ?? new JsonObject());

    public string? Str(string name) => Data[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    public long? Long(string name) => Data[name] is JsonValue v && v.TryGetValue<long>(out var l) ? l
        : Data[name] is JsonValue d && d.TryGetValue<double>(out var dd) ? (long)dd : null;
}

public static class IpcFraming
{
    /// <summary>Upper bound for one frame (a full-resolution multi-monitor JPEG in base64 fits easily).</summary>
    public const int MaxFrameBytes = 16 * 1024 * 1024;

    public static byte[] Encode(IpcMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (string.IsNullOrEmpty(message.Type)) throw new ArgumentException("type required", nameof(message));
        var buffer = new MemoryStream();
        buffer.Write(stackalloc byte[4]); // placeholder for the length prefix
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            w.WriteString("type", message.Type);
            w.WritePropertyName("data");
            message.Data.WriteTo(w);
            w.WriteEndObject();
        }
        var bytes = buffer.ToArray();
        var payloadLength = bytes.Length - 4;
        if (payloadLength > MaxFrameBytes) throw new InvalidDataException($"IPC frame too large: {payloadLength}");
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0, 4), (uint)payloadLength);
        return bytes;
    }

    /// <summary>Decodes one payload (without the length prefix).</summary>
    public static IpcMessage DecodePayload(ReadOnlySpan<byte> payload)
    {
        JsonNode? root;
        try { root = JsonNode.Parse(Encoding.UTF8.GetString(payload)); }
        catch (JsonException e) { throw new InvalidDataException("IPC frame is not JSON", e); }
        if (root is not JsonObject obj || obj["type"] is not JsonValue tv || !tv.TryGetValue<string>(out var type)
            || string.IsNullOrEmpty(type))
            throw new InvalidDataException("IPC frame has no type");
        JsonObject data;
        if (obj["data"] is JsonObject d) { obj.Remove("data"); data = d; }
        else if (obj["data"] is null) data = new JsonObject();
        else throw new InvalidDataException("IPC data must be an object");
        return new IpcMessage(type, data);
    }

    public static async Task WriteAsync(Stream stream, IpcMessage message, CancellationToken ct)
    {
        var frame = Encode(message);
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Reads one frame. Returns null on a clean end of stream at a frame boundary;
    /// throws <see cref="InvalidDataException"/> on truncation, oversize or malformed JSON.</summary>
    public static async Task<IpcMessage?> ReadAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        var got = await ReadFullyAsync(stream, header, ct).ConfigureAwait(false);
        if (got == 0) return null;
        if (got < 4) throw new InvalidDataException("truncated IPC header");
        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length == 0 || length > MaxFrameBytes) throw new InvalidDataException($"bad IPC frame length {length}");
        var payload = new byte[length];
        if (await ReadFullyAsync(stream, payload, ct).ConfigureAwait(false) < length)
            throw new InvalidDataException("truncated IPC payload");
        return DecodePayload(payload);
    }

    private static async Task<int> ReadFullyAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total), ct).ConfigureAwait(false);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    public static string PipeName(int sessionId) => $"MinControl.Session.{sessionId}";
}
