using System.Security.Cryptography;

namespace MinControl.Core.Util;

/// <summary>ULID generator (48-bit ms timestamp + 80-bit randomness, Crockford base32).
/// Monotonic within the same millisecond (randomness incremented) so ids sort in emission order.</summary>
public sealed class UlidGenerator
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private readonly object _gate = new();
    private long _lastMs = -1;
    private readonly byte[] _lastRandom = new byte[10];

    public static UlidGenerator Shared { get; } = new();

    public string New(DateTimeOffset now)
    {
        var ms = Math.Max(0, now.ToUnixTimeMilliseconds());
        Span<byte> rnd = stackalloc byte[10];
        lock (_gate)
        {
            if (ms <= _lastMs)
            {
                ms = _lastMs;
                // increment 80-bit big-endian random part; overflow (practically impossible) bumps the ms
                int i = 9;
                while (i >= 0 && ++_lastRandom[i] == 0) i--;
                if (i < 0) { ms = ++_lastMs; RandomNumberGenerator.Fill(_lastRandom); }
            }
            else
            {
                RandomNumberGenerator.Fill(_lastRandom);
                _lastMs = ms;
            }
            _lastRandom.CopyTo(rnd);
        }
        return Format(ms, rnd);
    }

    internal static string Format(long ms, ReadOnlySpan<byte> random10)
    {
        Span<char> c = stackalloc char[26];
        for (int i = 9; i >= 0; i--) { c[i] = Alphabet[(int)(ms & 31)]; ms >>= 5; }
        // 80 bits -> 16 chars
        UInt128 r = 0;
        foreach (var b in random10) r = (r << 8) | b;
        for (int i = 25; i >= 10; i--) { c[i] = Alphabet[(int)(r & 31)]; r >>= 5; }
        return new string(c);
    }

    public static bool IsValid(string? s)
    {
        if (s is null || s.Length != 26 || s[0] > '7') return false;
        foreach (var ch in s) if (Alphabet.IndexOf(ch) < 0) return false;
        return true;
    }
}
