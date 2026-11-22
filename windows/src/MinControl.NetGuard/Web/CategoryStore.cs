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
/// Loads <c>%ProgramData%\MinControl\categories\&lt;category&gt;.txt</c> (one domain per line, suffix match)
/// and swaps the index atomically on <see cref="Reload"/>.
/// </summary>
public sealed class CategoryStore : ICategoryStore
{
    private readonly string _directory;
    private readonly ILogger _log;
    private volatile CategoryIndex _index = CategoryIndex.Empty;

    public CategoryStore(NetGuardOptions options, ILogger<CategoryStore>? log = null)
    {
        _directory = options.CategoriesDirectory;
        _log = (ILogger?)log ?? NullLogger.Instance;
        Reload();
    }

    public string Directory => _directory;
    public CategoryIndex Current => _index;

    public IReadOnlyCollection<string> CategoriesOf(string normalizedHost) => _index.CategoriesOf(normalizedHost);

    /// <summary>Re-reads every *.txt file. On any failure the previous index is kept.</summary>
    public void Reload()
    {
        try
        {
            if (!System.IO.Directory.Exists(_directory))
            {
                _log.LogWarning("Category directory {Dir} missing; category blocking disabled", _directory);
                return;
            }
            var lists = new List<KeyValuePair<string, IEnumerable<string>>>();
            foreach (var file in System.IO.Directory.EnumerateFiles(_directory, "*.txt"))
            {
                var cat = Path.GetFileNameWithoutExtension(file);
                lists.Add(new(cat, File.ReadAllLines(file)));
            }
            var idx = new CategoryIndex(lists);
            _index = idx;
            _log.LogInformation("Loaded {Count} category domains from {Dir}", idx.DomainCount, _directory);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Category reload failed; keeping previous lists");
        }
    }

    /// <summary>
    /// Refresh hook. TODO(M6): download signed category lists from the cloud into <see cref="Directory"/>
    /// (contract not yet defined — see docs/contract-requests/netguard.md). For now it only reloads local files.
    /// </summary>
    public Task RefreshAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Reload();
        return Task.CompletedTask;
    }
}
