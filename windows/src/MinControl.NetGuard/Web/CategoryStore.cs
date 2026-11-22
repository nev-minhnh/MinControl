using System.Collections.Frozen;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MinControl.NetGuard.Web;

/// <summary>Offline domain → category lookup (suffix match).</summary>
public interface ICategoryStore
{
    /// <summary>Categories whose list contains the host or one of its parent domains. Never null.</summary>
    IReadOnlyCollection<string> CategoriesOf(string normalizedHost);
}

/// <summary>Immutable in-memory category index. Used directly by tests and as the snapshot inside <see cref="CategoryStore"/>.</summary>
public sealed class CategoryIndex : ICategoryStore
{
    private static readonly string[] None = [];
    private readonly FrozenDictionary<string, string[]> _byDomain;

    public CategoryIndex(IEnumerable<KeyValuePair<string, IEnumerable<string>>> categoryDomains)
    {
        var tmp = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var (category, domains) in categoryDomains)
        {
            var cat = category.Trim().ToLowerInvariant();
            foreach (var raw in domains)
            {
                var d = NormalizeListEntry(raw);
                if (d is null) continue;
                if (!tmp.TryGetValue(d, out var set)) tmp[d] = set = new HashSet<string>(StringComparer.Ordinal);
                set.Add(cat);
            }
        }
        _byDomain = tmp.ToFrozenDictionary(kv => kv.Key, kv => kv.Value.ToArray(), StringComparer.Ordinal);
    }

    public static CategoryIndex Empty { get; } = new([]);

    public int DomainCount => _byDomain.Count;

    public IReadOnlyCollection<string> CategoriesOf(string normalizedHost)
    {
        if (normalizedHost.Length == 0 || _byDomain.Count == 0) return None;
        List<string>? result = null;
        foreach (var suffix in DomainPattern.SelfAndParents(normalizedHost))
        {
            if (!_byDomain.TryGetValue(suffix, out var cats)) continue;
            if (result is null) result = new List<string>(cats);
            else foreach (var c in cats) if (!result.Contains(c)) result.Add(c);
        }
        return (IReadOnlyCollection<string>?)result ?? None;
    }

    /// <summary>Accepts "domain", "*.domain", "0.0.0.0 domain" (hosts-file style), ignores comments/blank lines.</summary>
    internal static string? NormalizeListEntry(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        var s = line.Trim();
        var hash = s.IndexOf('#');
        if (hash >= 0) s = s[..hash].Trim();
        if (s.Length == 0) return null;
        var parts = s.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        s = parts[^1];
        if (s.StartsWith("*.", StringComparison.Ordinal)) s = s[2..];
        s = DomainPattern.NormalizeHost(s);
        if (s.Length == 0 || s.Length > 253 || s.Contains('/') || s.Contains(':')) return null;
        return s;
    }
}

/// <summary>
/// Snapshot of all category lists: hashed binary sets (<c>&lt;category&gt;[.&lt;part&gt;].bin</c>, written by
/// <see cref="Categories.CategoryUpdater"/>) plus plain-text lists (<c>&lt;category&gt;.txt</c>, fallback / tests).
/// A category matches when any of its sets or its text list contains the host or a parent domain.
/// </summary>
public sealed class CategorySnapshot : ICategoryStore
{
    private static readonly string[] None = [];
    private readonly CategoryIndex _text;
    private readonly KeyValuePair<string, HashedDomainSet>[] _sets;

    public CategorySnapshot(CategoryIndex text, IEnumerable<KeyValuePair<string, HashedDomainSet>> sets)
    {
        _text = text;
        _sets = sets.Where(kv => kv.Value.Count > 0)
            .Select(kv => new KeyValuePair<string, HashedDomainSet>(kv.Key.Trim().ToLowerInvariant(), kv.Value)).ToArray();
    }

    public static CategorySnapshot Empty { get; } = new(CategoryIndex.Empty, []);

    public int TextDomainCount => _text.DomainCount;
    public long HashedDomainCount => _sets.Sum(kv => (long)kv.Value.Count);

    public IReadOnlyCollection<string> CategoriesOf(string normalizedHost)
    {
        if (normalizedHost.Length == 0) return None;
        var fromText = _text.CategoriesOf(normalizedHost);
        if (_sets.Length == 0) return fromText;

        // Hash each suffix once (a.b.c → a.b.c, b.c, c), then probe every set.
        Span<ulong> hashes = stackalloc ulong[32];
        var n = 0;
        var span = normalizedHost.AsSpan();
        while (span.Length > 0 && n < hashes.Length)
        {
            hashes[n++] = HashedDomainSet.Hash(span);
            var dot = span.IndexOf('.');
            if (dot < 0) break;
            span = span[(dot + 1)..];
        }

        List<string>? result = fromText.Count > 0 ? new List<string>(fromText) : null;
        foreach (var (cat, set) in _sets)
        {
            if (result is not null && result.Contains(cat)) continue;
            for (var i = 0; i < n; i++)
            {
                if (!set.ContainsHash(hashes[i])) continue;
                (result ??= new List<string>(2)).Add(cat);
                break;
            }
        }
        return (IReadOnlyCollection<string>?)result ?? None;
    }
}

/// <summary>
/// Loads <c>%ProgramData%\MinControl\categories\</c>: <c>*.bin</c> hashed sets (category = file name up to the first
/// dot, so <c>proxy-vpn.vpn.bin</c> and <c>proxy-vpn.redirector.bin</c> both feed "proxy-vpn") and <c>*.txt</c>
/// lists (one domain per line, suffix match). Swaps the snapshot atomically on <see cref="Reload"/>.
/// </summary>
public sealed class CategoryStore : ICategoryStore
{
    private readonly string _directory;
    private readonly ILogger _log;
    private volatile CategorySnapshot _snapshot = CategorySnapshot.Empty;
    private string? _fingerprint;
    private readonly object _reloadGate = new();

    public CategoryStore(NetGuardOptions options, ILogger<CategoryStore>? log = null)
    {
        _directory = options.CategoriesDirectory;
        _log = (ILogger?)log ?? NullLogger.Instance;
        Reload();
    }

    public string Directory => _directory;
    public CategorySnapshot Current => _snapshot;

    public IReadOnlyCollection<string> CategoriesOf(string normalizedHost) => _snapshot.CategoriesOf(normalizedHost);

    /// <summary>Category name of a list file: <c>adult.bin</c> / <c>proxy-vpn.vpn.bin</c> / <c>games.txt</c> → adult / proxy-vpn / games.</summary>
    public static string CategoryOfFile(string path)
    {
        var name = Path.GetFileName(path);
        var dot = name.IndexOf('.');
        return (dot > 0 ? name[..dot] : name).ToLowerInvariant();
    }

    /// <summary>Re-reads every *.bin / *.txt file when any of them changed (or <paramref name="force"/>).
    /// A corrupt file is skipped; on any other failure the previous snapshot is kept.</summary>
    public void Reload(bool force = false)
    {
        lock (_reloadGate)
        {
            try
            {
                if (!System.IO.Directory.Exists(_directory))
                {
                    _log.LogWarning("Category directory {Dir} missing; category blocking disabled", _directory);
                    return;
                }
                var files = System.IO.Directory.EnumerateFiles(_directory, "*.bin")
                    .Concat(System.IO.Directory.EnumerateFiles(_directory, "*.txt"))
                    .Select(f => new FileInfo(f)).OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToList();
                var fingerprint = string.Join("|", files.Select(f => $"{f.Name}:{f.Length}:{f.LastWriteTimeUtc.Ticks}"));
                if (!force && fingerprint == _fingerprint) return;

                var sw = System.Diagnostics.Stopwatch.StartNew();
                var lists = new List<KeyValuePair<string, IEnumerable<string>>>();
                var sets = new List<KeyValuePair<string, HashedDomainSet>>();
                foreach (var f in files)
                {
                    var cat = CategoryOfFile(f.FullName);
                    if (f.Extension.Equals(".txt", StringComparison.OrdinalIgnoreCase))
                    {
                        lists.Add(new(cat, File.ReadAllLines(f.FullName)));
                        continue;
                    }
                    try { sets.Add(new(cat, HashedDomainSet.Read(f.FullName))); }
                    catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException)
                    {
                        _log.LogError("Category file {File} is corrupt ({Error}); skipped", f.Name, ex.Message);
                    }
                }
                var snap = new CategorySnapshot(new CategoryIndex(lists), sets);
                _snapshot = snap;
                _fingerprint = fingerprint;
                _log.LogInformation("Loaded categories from {Dir}: {Hashed} hashed + {Text} text domains in {Ms} ms",
                    _directory, snap.HashedDomainCount, snap.TextDomainCount, sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Category reload failed; keeping previous lists");
            }
        }
    }

    /// <summary>Periodic refresh hook (NetGuardService watchdog): reloads only when a list file changed.
    /// Downloads are done by <see cref="Categories.CategoryUpdater"/>, which calls <see cref="Reload"/> itself.</summary>
    public Task RefreshAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Reload();
        return Task.CompletedTask;
    }
}
