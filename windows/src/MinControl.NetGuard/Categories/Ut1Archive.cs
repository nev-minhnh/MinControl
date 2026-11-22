using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using MinControl.NetGuard.Web;

namespace MinControl.NetGuard.Categories;

/// <param name="Set">Sorted, de-duplicated hashes of the accepted domains.</param>
/// <param name="EntryName">Tar entry the domains came from (e.g. <c>phishing/domains</c> for the malware alias).</param>
/// <param name="Lines">Non-empty lines read.</param>
/// <param name="Skipped">Lines rejected by <see cref="Ut1Archive.NormalizeDomain"/> (IPs, garbage).</param>
public sealed record Ut1Extract(HashedDomainSet Set, string EntryName, int Lines, int Skipped);

/// <summary>Streams a UT1 <c>.tar.gz</c> (GZipStream → TarReader, nothing written to disk) and hashes its
/// <c>&lt;list&gt;/domains</c> file.</summary>
public static class Ut1Archive
{
    private static readonly HashSet<string> WholeTlds = new(StringComparer.Ordinal) { "xxx", "porn", "sex", "adult", "casino", "poker", "bet" };

    /// <summary>
    /// Reads the first regular entry named <c>&lt;list&gt;/domains</c>; if the archive has none, the first
    /// <c>&lt;dir&gt;/domains</c> (UT1 aliases such as malware → phishing). Throws <see cref="InvalidDataException"/>
    /// when no domains entry exists or it holds no valid domain.
    /// </summary>
    public static async Task<Ut1Extract> ExtractAsync(Stream gzip, string list, int capacityHint, CancellationToken ct)
    {
        await using var gz = new GZipStream(gzip, CompressionMode.Decompress, leaveOpen: true);
        await using var tar = new TarReader(gz, leaveOpen: true);
        while (await tar.GetNextEntryAsync(copyData: false, ct).ConfigureAwait(false) is { } entry)
        {
            if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile)) continue;
            var name = entry.Name.Replace('\\', '/');
            if (name.StartsWith("./", StringComparison.Ordinal)) name = name[2..];
            var slash = name.IndexOf('/');
            if (slash <= 0 || name.IndexOf('/', slash + 1) >= 0 || !name.EndsWith("/domains", StringComparison.Ordinal)) continue;
            // An archive holds one list; prefer the exact name but accept an alias directory.
            if (entry.DataStream is null) throw new InvalidDataException($"{name}: no data");
            return await HashLinesAsync(entry.DataStream, name, capacityHint, ct).ConfigureAwait(false);
        }
        throw new InvalidDataException($"{list}.tar.gz has no <dir>/domains entry");
    }

    private static async Task<Ut1Extract> HashLinesAsync(Stream data, string entryName, int capacityHint, CancellationToken ct)
    {
        var hashes = new List<ulong>(Math.Clamp(capacityHint, 1024, 16_000_000));
        int lines = 0, skipped = 0;
        using var reader = new StreamReader(data, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 1 << 16);
        while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
        {
            if (line.Length == 0) continue;
            lines++;
            var d = NormalizeDomain(line);
            if (d is null) { skipped++; continue; }
            hashes.Add(HashedDomainSet.Hash(d));
        }
        if (hashes.Count == 0) throw new InvalidDataException($"{entryName}: no valid domain in {lines} lines");
        return new Ut1Extract(HashedDomainSet.FromHashes(hashes), entryName, lines, skipped);
    }

    /// <summary>
    /// Lower-case ASCII host name with at least one dot (or one of a few single-purpose TLDs such as "xxx"), labels of [a-z0-9_-] (1..63 chars, no leading/trailing '-'),
    /// ≤ 253 chars. Strips surrounding whitespace, comments, a leading "*." / "." and a trailing dot. Returns null for
    /// IP addresses (v4/v6), URLs, ports and anything else.
    /// </summary>
    public static string? NormalizeDomain(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        var s = line.AsSpan().Trim();
        var hash = s.IndexOf('#');
        if (hash >= 0) s = s[..hash].TrimEnd();
        if (s.StartsWith("*.")) s = s[2..];
        else if (s.StartsWith(".")) s = s[1..];
        if (s.EndsWith(".")) s = s[..^1];
        if (s.Length is 0 or > 253) return null;
        if (s.IndexOf('.') < 0)
        {
            // Whole-TLD entries (UT1 adult lists "xxx", "porn", "sex", "adult"): only these well-known
            // single-purpose TLDs, so a stray "com" in a list can never block the whole web.
            var lower = s.ToString().ToLowerInvariant();
            return WholeTlds.Contains(lower) ? lower : null;
        }

        Span<char> buf = stackalloc char[s.Length];
        var labelLen = 0;
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c is >= 'A' and <= 'Z') c = (char)(c + 32);
            if (c == '.')
            {
                if (labelLen == 0 || buf[i - 1] == '-') return null;
                labelLen = 0;
            }
            else if (c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-')
            {
                if (labelLen == 0 && c == '-') return null;
                if (++labelLen > 63) return null;
            }
            else return null;   // space, '/', ':', non-ASCII, ...
            buf[i] = c;
        }
        if (labelLen == 0 || buf[^1] == '-') return null;
        // IPv4 (incl. short forms like "10.1") and all-numeric TLDs are not host names.
        var tld = buf[(buf.LastIndexOf('.') + 1)..];
        if (!tld.ContainsAnyExceptInRange('0', '9')) return null;
        var result = new string(buf);
        return IPAddress.TryParse(result, out _) ? null : result;
    }
}
