using System.Buffers.Binary;

namespace MinControl.Browser.Ipc;

// Chrome native-messaging framing (uint32 little-endian length + UTF-8 JSON). Used on stdin/stdout by the
// native host and, unchanged, on the service pipe. Compiled into MinControl.NativeHost as a linked file.
internal static class MessageFraming
{
    /// <summary>Largest frame accepted from the extension / native host (Chrome caps host->extension at 1 MB).</summary>
    public const int MaxFrameBytes = 64 * 1024;

    /// <summary>Reads one frame. Returns null on clean end of stream; throws InvalidDataException on oversize.</summary>
    public static async Task<byte[]?> ReadAsync(Stream s, int maxBytes, CancellationToken ct)
    {
        var header = new byte[4];
        if (!await ReadExactAsync(s, header, ct).ConfigureAwait(false)) return null;
        uint len = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (len == 0 || len > (uint)maxBytes) throw new InvalidDataException($"frame length {len} out of range");
        var body = new byte[len];
        if (!await ReadExactAsync(s, body, ct).ConfigureAwait(false)) throw new EndOfStreamException();
        return body;
    }

    public static async Task WriteAsync(Stream s, ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        if (body.Length == 0 || body.Length > 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(body));
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)body.Length);
        body.CopyTo(frame.AsMemory(4));
        await s.WriteAsync(frame, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(off), ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (off == 0) return false;
                throw new EndOfStreamException();
            }
            off += n;
        }
        return true;
    }
}
