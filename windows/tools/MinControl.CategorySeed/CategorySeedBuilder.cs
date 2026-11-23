using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using MinControl.Core.Catalog;
using MinControl.NetGuard.Categories;
using MinControl.NetGuard.Web;

namespace MinControl.CategorySeed;

/// <summary>Result of one seed run. <see cref="Built"/> / <see cref="Failed"/> hold "category/list" keys.</summary>
public sealed record SeedResult(IReadOnlyList<string> Built, IReadOnlyList<string> Failed, IReadOnlyList<string> Warnings);

/// <summary>
/// Builds the shipped category seed from the local UT1 snapshot zip (layout
/// <c>&lt;root&gt;/blacklists/&lt;list&gt;/domains</c>, or <c>domains.0</c>, <c>domains.1</c>, ... for split lists: concatenated
/// as one byte stream, the split can fall mid-line). For every category/list in <see cref="Ut1Catalog.Sources"/> it
/// hashes the domains, unions the curated catalog domains (<see cref="ServiceCatalog.DomainsOfPolicyCategory"/>) into
/// the FIRST list of the category, writes <c>&lt;out&gt;\&lt;Ut1Catalog.FileName&gt;</c> and <c>seed-state.json</c>
/// (<c>{fileName: Ut1SourceState}</c>, default System.Text.Json = PascalCase; LastModified = zip entry time, ETag null).
/// </summary>
public static class CategorySeedBuilder
{
    public const string StateFileName = "seed-state.json";

    public static async Task<SeedResult> BuildAsync(string zipPath, string outDir, ServiceCatalog catalog,
        IReadOnlyCollection<string>? only = null, Action<string>? log = null, CancellationToken ct = default)
    {
        log ??= _ => { };
        Directory.CreateDirectory(outDir);
        List<string> built = [], failed = [], warnings = [];
        var state = new SortedDictionary<string, Ut1SourceState>(StringComparer.Ordinal);

        using var zip = ZipFile.OpenRead(zipPath);
        foreach (var (category, lists) in Ut1Catalog.Sources.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            if (only is not null && !only.Contains(category)) continue;
            for (var i = 0; i < lists.Length; i++)
            {
                var list = lists[i];
                var key = $"{category}/{list}";
                try
                {
                    var parts = PartsOf(zip, list);
                    if (parts.Count == 0) throw new InvalidDataException($"no blacklists/{list}/domains in {Path.GetFileName(zipPath)}");

                    var hashes = new List<ulong>(1 << 16);
                    await using (var data = new ConcatStream(parts.Select(p => p.Open())))
                        await HashLinesAsync(data, hashes, ct);
                    if (hashes.Count == 0) throw new InvalidDataException($"{key}: no valid domain");

                    if (i == 0)
                        foreach (var d in catalog.DomainsOfPolicyCategory(category))
                            if (Ut1Archive.NormalizeDomain(d) is { } n) hashes.Add(HashedDomainSet.Hash(n));
                    var set = HashedDomainSet.FromHashes(hashes);

                    var file = Ut1Catalog.FileName(category, list);
                    set.WriteAtomic(Path.Combine(outDir, file));
                    state[file] = new Ut1SourceState(null, parts[0].LastWriteTime.ToUniversalTime(), set.Count, DateTimeOffset.UtcNow);
                    built.Add(key);
                    log($"{key}: {set.Count} domains -> {file}");
                }
                catch (Exception e) when (e is InvalidDataException or IOException)
                {
                    failed.Add(key);
                    warnings.Add($"{key}: FAILED: {e.Message}");
                    log($"{key}: FAILED: {e.Message}");
                }
            }
        }

        if (built.Count > 0)
        {
            var tmp = Path.Combine(outDir, StateFileName + ".tmp");
            await File.WriteAllTextAsync(tmp, JsonSerializer.Serialize(state), ct);
            File.Move(tmp, Path.Combine(outDir, StateFileName), overwrite: true);
        }
        return new SeedResult(built, failed, warnings);
    }

    /// <summary>Entries <c>.../blacklists/&lt;list&gt;/domains[.N]</c> in order (plain first, then numeric suffix).</summary>
    private static List<ZipArchiveEntry> PartsOf(ZipArchive zip, string list)
    {
        var rx = new Regex(@"(^|/)blacklists/" + Regex.Escape(list) + @"/domains(\.(?<n>\d+))?$", RegexOptions.CultureInvariant);
        return zip.Entries
            .Select(e => (Entry: e, M: rx.Match(e.FullName.Replace('\\', '/'))))
            .Where(x => x.M.Success && x.Entry.Length > 0)
            .OrderBy(x => x.M.Groups["n"].Success ? int.Parse(x.M.Groups["n"].Value) : -1)
            .Select(x => x.Entry)
            .ToList();
    }

    private static async Task HashLinesAsync(Stream data, List<ulong> hashes, CancellationToken ct)
    {
        using var reader = new StreamReader(data, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 1 << 16);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (line.Length == 0) continue;
            if (Ut1Archive.NormalizeDomain(line) is { } d) hashes.Add(HashedDomainSet.Hash(d));
        }
    }

    /// <summary>Reads several streams as one continuous byte stream (opened lazily, one at a time).</summary>
    private sealed class ConcatStream(IEnumerable<Stream> parts) : Stream
    {
        private readonly IEnumerator<Stream> _it = parts.GetEnumerator();
        private Stream? _cur;

        public override int Read(byte[] buffer, int offset, int count)
        {
            while (true)
            {
                if (_cur is null)
                {
                    if (!_it.MoveNext()) return 0;
                    _cur = _it.Current;
                }
                var n = _cur.Read(buffer, offset, count);
                if (n > 0) return n;
                _cur.Dispose();
                _cur = null;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { _cur?.Dispose(); _it.Dispose(); }
            base.Dispose(disposing);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
