using System.Buffers;
using System.Buffers.Binary;
using System.IO.Hashing;
using System.Runtime.InteropServices;
using System.Text;

namespace MinControl.NetGuard.Web;

/// <summary>
/// Compact, immutable domain set for very large category lists (UT1 "adult" has millions of entries): a sorted,
/// de-duplicated array of 64-bit XxHash64 values of the normalised domain (8 bytes per domain instead of a string +
/// dictionary entry). Lookup hashes the host and each parent suffix and binary-searches. A 64-bit collision between
/// a visited host and a listed domain is ~n/2^64 per lookup (n ≈ 5·10^6 → ~3·10^-13): negligible for filtering.
/// <para>File format (<c>&lt;category&gt;[.&lt;part&gt;].bin</c>, little-endian):
/// <c>"MCDH"</c> magic, uint32 version (1), int64 count, then <c>count</c> uint64 hashes in ascending order.</para>
/// </summary>
public sealed class HashedDomainSet
{
    private static readonly byte[] Magic = "MCDH"u8.ToArray();
    private const uint Version = 1;
    private const int HeaderBytes = 16;

    private readonly ulong[] _hashes;

    private HashedDomainSet(ulong[] sortedDistinct) => _hashes = sortedDistinct;

    public static HashedDomainSet Empty { get; } = new([]);

    public int Count => _hashes.Length;

    /// <summary>XxHash64 (seed 0) of the UTF-8 bytes of an already-normalised domain.</summary>
    public static ulong Hash(ReadOnlySpan<char> normalizedDomain)
    {
        var max = Encoding.UTF8.GetMaxByteCount(normalizedDomain.Length);
        byte[]? rented = null;
        Span<byte> buf = max <= 512 ? stackalloc byte[512] : (rented = ArrayPool<byte>.Shared.Rent(max));
        try
        {
            var n = Encoding.UTF8.GetBytes(normalizedDomain, buf);
            return XxHash64.HashToUInt64(buf[..n]);
        }
        finally
        {
            if (rented is not null) ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public bool ContainsHash(ulong hash) => _hashes.Length > 0 && Array.BinarySearch(_hashes, hash) >= 0;

    /// <summary>True when the host or one of its parent domains is in the set (suffix match).</summary>
    public bool MatchesHostOrParent(string normalizedHost)
    {
        if (_hashes.Length == 0 || normalizedHost.Length == 0) return false;
        var span = normalizedHost.AsSpan();
        while (span.Length > 0)
        {
            if (ContainsHash(Hash(span))) return true;
            var dot = span.IndexOf('.');
            if (dot < 0) break;
            span = span[(dot + 1)..];
        }
        return false;
    }

    /// <summary>Sorts and de-duplicates <paramref name="hashes"/> in place (the list is consumed).</summary>
    public static HashedDomainSet FromHashes(List<ulong> hashes)
    {
        var span = CollectionsMarshal.AsSpan(hashes);
        span.Sort();
        var w = 0;
        for (var r = 0; r < span.Length; r++)
            if (w == 0 || span[r] != span[w - 1]) span[w++] = span[r];
        return new HashedDomainSet(span[..w].ToArray());
    }

    public static HashedDomainSet FromDomains(IEnumerable<string> normalizedDomains)
    {
        var list = new List<ulong>();
        foreach (var d in normalizedDomains) list.Add(Hash(d));
        return FromHashes(list);
    }

    public void Write(Stream stream)
    {
        Span<byte> header = stackalloc byte[HeaderBytes];
        Magic.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header[4..], Version);
        BinaryPrimitives.WriteInt64LittleEndian(header[8..], _hashes.Length);
        stream.Write(header);
        if (!BitConverter.IsLittleEndian) throw new PlatformNotSupportedException("big-endian");
        stream.Write(MemoryMarshal.AsBytes(_hashes.AsSpan()));
    }

    /// <summary>Writes to <c>path.tmp</c>, flushes, then atomically replaces <paramref name="path"/>.</summary>
    public void WriteAtomic(string path)
    {
        var tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
        {
            Write(fs);
            fs.Flush(flushToDisk: true);
        }
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>Reads and validates a file written by <see cref="Write"/>; throws <see cref="InvalidDataException"/> on corruption.</summary>
    public static HashedDomainSet Read(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
        Span<byte> header = stackalloc byte[HeaderBytes];
        fs.ReadExactly(header);
        if (!header[..4].SequenceEqual(Magic) || BinaryPrimitives.ReadUInt32LittleEndian(header[4..]) != Version)
            throw new InvalidDataException($"{path}: not a MinControl domain-hash file");
        var count = BinaryPrimitives.ReadInt64LittleEndian(header[8..]);
        if (count < 0 || count > (fs.Length - HeaderBytes) / 8 || HeaderBytes + count * 8 != fs.Length)
            throw new InvalidDataException($"{path}: bad length (count {count}, file {fs.Length})");
        var hashes = GC.AllocateUninitializedArray<ulong>((int)count);
        fs.ReadExactly(MemoryMarshal.AsBytes(hashes.AsSpan()));
        for (var i = 1; i < hashes.Length; i++)
            if (hashes[i] <= hashes[i - 1]) throw new InvalidDataException($"{path}: not sorted");
        return new HashedDomainSet(hashes);
    }
}
