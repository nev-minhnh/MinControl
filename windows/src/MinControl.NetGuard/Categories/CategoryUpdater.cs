using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.NetGuard.Web;

namespace MinControl.NetGuard.Categories;

/// <summary>Per-source bookkeeping for conditional GET, persisted in <c>categories\.ut1-state.json</c>.
/// <c>ETag</c> is <c>gh:&lt;etag0&gt;|&lt;etag1&gt;…</c> for lists from the GitHub mirror.</summary>
public sealed record Ut1SourceState(string? ETag, DateTimeOffset? LastModified, int Domains, DateTimeOffset UpdatedUtc);

/// <summary>Outcome of one <see cref="CategoryUpdater.UpdateOnceAsync"/> pass (lists are "category/list").</summary>
public sealed record CategoryUpdateResult(
    IReadOnlyList<string> Downloaded, IReadOnlyList<string> NotModified, IReadOnlyList<string> Failed, IReadOnlyList<string> Removed);

/// <summary>
/// Keeps the UT1 lists of the categories referenced by the managed users' policies in
/// <see cref="NetGuardOptions.CategoriesDirectory"/> as hashed <c>.bin</c> sets and reloads <see cref="CategoryStore"/>.
/// <list type="number">
/// <item>Installer seed (API.md §17): <c>categories\seed\</c> holds a snapshot of every list; a referenced list is promoted
///   (copied) into <c>categories\</c> when missing or older than the seed — at service start and on every policy change,
///   before any download, so categories work immediately and offline.</item>
/// <item>Updates: first pass after <see cref="NetGuardOptions.CategoryUpdateInitialDelay"/>, then every
///   <see cref="NetGuardOptions.CategoryUpdateInterval"/> (daily; sooner when a policy references a category without a
///   list, or after a failure). Source: the GitHub mirror raw files (ETag / If-None-Match, split files concatenated),
///   falling back to the UT1 tarballs (If-Modified-Since). Any failure keeps the previous (or seed) file.</item>
/// <item>The store is reloaded after every list that changed (not only at the end of a pass: one slow list must not
///   hold back the others), small lists first and the huge adult list last.</item>
/// </list>
/// Runs inside the service (SYSTEM — not subject to the per-user WFP lock).
/// </summary>
public sealed class CategoryUpdater : BackgroundService
{
    internal const string StateFileName = ".ut1-state.json";
    /// <summary>Installer seed: <c>categories\seed\*.bin</c> + <c>seed-state.json</c> (same shape as the state file).</summary>
    internal const string SeedDirName = "seed", SeedStateFileName = "seed-state.json";
    private const string GitHubTagPrefix = "gh:";
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private readonly NetGuardOptions _options;
    private readonly CategoryStore _store;
    private readonly IPolicyProvider _policy;
    private readonly IUserDirectory? _users;
    private readonly HttpClient _http;
    private readonly ILogger _log;
    private readonly SemaphoreSlim _wake = new(0, 1);
    private readonly SemaphoreSlim _pass = new(1, 1);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _lastErrors = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Time of the last completed update pass (diagnostics).</summary>
    public DateTimeOffset? LastPassUtc { get; private set; }
    /// <summary>"category/list" → error of its last failed download (cleared on success).</summary>
    public IReadOnlyDictionary<string, string> LastErrors => _lastErrors;
    /// <summary>Per list file: ETag/Last-Modified/domains of the last download (diagnostics).</summary>
    public IReadOnlyDictionary<string, Ut1SourceState> SourceStates() => LoadState();

    public CategoryUpdater(NetGuardOptions options, CategoryStore store, IPolicyProvider policy, IUserDirectory users,
        ILogger<CategoryUpdater>? log = null)
        : this(options, store, policy, users, new SocketsHttpHandler
        {
            // GitHub raw files come gzip-encoded; the UT1 .tar.gz carries no Content-Encoding, so it is never touched.
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            UseProxy = false,                                     // never loop through our own filtering proxy
        }, log)
    {
    }

    internal CategoryUpdater(NetGuardOptions options, CategoryStore store, IPolicyProvider policy, IUserDirectory? users,
        HttpMessageHandler handler, ILogger? log)
    {
        _options = options;
        _store = store;
        _policy = policy;
        _users = users;
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = options.CategoryDownloadTimeout };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("MinControl-CategoryUpdater/1.1");
        _log = log ?? NullLogger.Instance;
        _policy.PolicyChanged += OnPolicyChanged;
    }

    private string Dir => _options.CategoriesDirectory;
    private string StatePath => Path.Combine(Dir, StateFileName);
    private string SeedDir => Path.Combine(Dir, SeedDirName);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        // Seed lists work right away (no network): promote them before anything else.
        await Task.Yield();
        try { PromoteSeedsForPolicy(_policy.Current); }
        catch (Exception ex) { _log.LogWarning(ex, "Category seed promotion failed"); }

        if (!_options.CategoryDownloadEnabled) { _log.LogInformation("Category download disabled"); return; }
        try { await Task.Delay(_options.CategoryUpdateInitialDelay, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        while (!ct.IsCancellationRequested)
        {
            var wait = _options.CategoryUpdateInterval;
            try
            {
                var r = await UpdateOnceAsync(ct).ConfigureAwait(false);
                if (r.Failed.Count > 0) wait = _options.CategoryRetryInterval;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                _log.LogError(ex, "Category update pass failed");
                wait = _options.CategoryRetryInterval;
            }
            try { await _wake.WaitAsync(wait, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            // Debounce bursts of policy updates.
            try { await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>A new policy promotes seed lists for its categories right away; one that still references a category
    /// without a list file triggers an early download pass.</summary>
    private void OnPolicyChanged(object? sender, Core.Policy.DevicePolicy policy)
    {
        try { PromoteSeedsForPolicy(policy); }
        catch (Exception ex) { _log.LogWarning(ex, "Category seed promotion failed"); }
        try
        {
            foreach (var cat in Ut1Catalog.ReferencedCategories(policy, IsManaged))
                foreach (var list in Ut1Catalog.Sources[cat])
                    if (!File.Exists(Path.Combine(Dir, Ut1Catalog.FileName(cat, list))))
                    {
                        if (_wake.CurrentCount == 0) _wake.Release();
                        return;
                    }
        }
        catch (Exception ex) when (ex is SemaphoreFullException or IOException) { }
    }

    private bool IsManaged(string sid) => _users is null || _users.IsManaged(sid);

    /// <summary>One pass: seed promotion, conditional GET of every referenced list (store reloaded after each changed
    /// one), drop unreferenced lists (the seed stays). Without a policy nothing is downloaded or removed.</summary>
    public async Task<CategoryUpdateResult> UpdateOnceAsync(CancellationToken ct)
    {
        await _pass.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            List<string> downloaded = [], notModified = [], failed = [], removed = [];
            var policy = _policy.Current;
            if (policy is null) return new(downloaded, notModified, failed, removed);

            Directory.CreateDirectory(Dir);
            var state = LoadState();
            var wanted = Ut1Catalog.ReferencedCategories(policy, IsManaged);
            var sw = Stopwatch.StartNew();
            if (PromoteSeeds(wanted, state) > 0) { SaveState(state); _store.Reload(force: true); }

            // Small lists first, the huge adult list last: one slow download must not delay every other category.
            foreach (var cat in wanted.OrderBy(c => c == "adult" ? 1 : 0).ThenBy(c => c, StringComparer.Ordinal))
                foreach (var list in Ut1Catalog.Sources[cat])
                {
                    var key = $"{cat}/{list}";
                    try
                    {
                        if (await UpdateSourceAsync(cat, list, state, ct).ConfigureAwait(false))
                        {
                            downloaded.Add(key);
                            SaveState(state);
                            _store.Reload(force: true);   // effective now, not only at the end of a long pass
                        }
                        else notModified.Add(key);
                        _lastErrors.TryRemove(key, out _);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex)
                    {
                        failed.Add(key);
                        _lastErrors[key] = ex.Message;
                        _log.LogWarning("Category list {Key} update failed, keeping the previous file: {Error}", key, ex.Message);
                    }
                }

            // Lists of categories no policy references any more only cost memory: remove them (the seed copy stays).
            var keepFiles = wanted.SelectMany(c => Ut1Catalog.Sources[c].Select(l => Ut1Catalog.FileName(c, l)))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var file in Directory.EnumerateFiles(Dir, "*.bin"))
            {
                var name = Path.GetFileName(file);
                if (keepFiles.Contains(name) || !Ut1Catalog.Sources.ContainsKey(CategoryStore.CategoryOfFile(name))) continue;
                try { File.Delete(file); removed.Add(name); }
                catch (IOException ex) { _log.LogWarning("Could not delete {File}: {Error}", name, ex.Message); }
            }
            foreach (var k in state.Keys.Where(k => !keepFiles.Contains(k)).ToList()) state.Remove(k);

            SaveState(state);
            LastPassUtc = DateTimeOffset.UtcNow;
            if (removed.Count > 0) _store.Reload(force: true);
            _log.LogInformation("Category update: {Down} downloaded, {Same} unchanged, {Fail} failed, {Rm} removed in {Ms} ms",
                downloaded.Count, notModified.Count, failed.Count, removed.Count, sw.ElapsedMilliseconds);
            return new(downloaded, notModified, failed, removed);
        }
        finally
        {
            _pass.Release();
        }
    }

    /// <summary>True when a new file was written, false when unchanged. GitHub mirror first, UT1 tarball as fallback.
    /// Throws when both fail (the previous file is kept).</summary>
    private async Task<bool> UpdateSourceAsync(string category, string list, Dictionary<string, Ut1SourceState> state, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(_options.CategoryGitHubBaseUrl))
        {
            try { return await UpdateFromGitHubAsync(category, list, state, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _log.LogInformation("{List}: GitHub mirror failed ({Error}), trying the UT1 tarball", list, ex.Message);
            }
        }
        return await UpdateFromTarballAsync(category, list, state, ct).ConfigureAwait(false);
    }

    /// <summary>GitHub raw files: <c>&lt;list&gt;/domains</c>, or <c>domains.0..N</c> (probed until 404) read as one
    /// stream. Conditional GET per part with If-None-Match.</summary>
    private async Task<bool> UpdateFromGitHubAsync(string category, string list, Dictionary<string, Ut1SourceState> state, CancellationToken ct)
    {
        var fileName = Ut1Catalog.FileName(category, list);
        var path = Path.Combine(Dir, fileName);
        state.TryGetValue(fileName, out var prev);
        string[]? prevTags = prev?.ETag is { } t && t.StartsWith(GitHubTagPrefix, StringComparison.Ordinal) && File.Exists(path)
            ? t[GitHubTagPrefix.Length..].Split('|') : null;
        var baseUrl = _options.CategoryGitHubBaseUrl;
        var sw = Stopwatch.StartNew();

        // single file
        using (var single = await GetAsync(Ut1Catalog.GitHubUrlOf(baseUrl, list, null), prevTags is { Length: 1 } ? prevTags[0] : null, ct).ConfigureAwait(false))
        {
            if (single.StatusCode == HttpStatusCode.NotModified) return false;
            if (single.StatusCode != HttpStatusCode.NotFound)
            {
                single.EnsureSuccessStatusCode();
                await using var body = await single.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                var x = await Ut1Archive.HashDomainLinesAsync(body, list + "/domains", prev?.Domains ?? 0, ct).ConfigureAwait(false);
                Write(x, GitHubTagPrefix + (single.Headers.ETag?.ToString() ?? ""), single.Content.Headers.LastModified);
                return true;
            }
        }

        // split file: domains.0, domains.1, … until 404; parts land in temp files, then are hashed as one stream
        var tmpDir = Path.Combine(Dir, ".dl");
        Directory.CreateDirectory(tmpDir);
        var parts = new List<string>();
        var tags = new List<string>();
        var stale = new List<int>();   // 304 parts whose bytes we do not have
        try
        {
            for (var i = 0; i < 64; i++)
            {
                var prevTag = prevTags is { Length: > 1 } && i < prevTags.Length ? prevTags[i] : null;
                using var resp = await GetAsync(Ut1Catalog.GitHubUrlOf(baseUrl, list, i), prevTag, ct).ConfigureAwait(false);
                if (resp.StatusCode == HttpStatusCode.NotFound) break;
                var partPath = Path.Combine(tmpDir, $"{list}.{i}");
                parts.Add(partPath);
                if (resp.StatusCode == HttpStatusCode.NotModified) { stale.Add(i); tags.Add(prevTag ?? ""); continue; }
                resp.EnsureSuccessStatusCode();
                await SaveAsync(resp, partPath, ct).ConfigureAwait(false);
                tags.Add(resp.Headers.ETag?.ToString() ?? "");
            }
            if (parts.Count == 0) throw new HttpRequestException($"{list}: not on the GitHub mirror");
            if (stale.Count == parts.Count && prevTags is not null && prevTags.Length == parts.Count) return false;
            foreach (var i in stale)
            {
                using var resp = await GetAsync(Ut1Catalog.GitHubUrlOf(baseUrl, list, i), null, ct).ConfigureAwait(false);
                resp.EnsureSuccessStatusCode();
                await SaveAsync(resp, parts[i], ct).ConfigureAwait(false);
                tags[i] = resp.Headers.ETag?.ToString() ?? "";
            }
            Ut1Extract x;
            await using (var concat = new ConcatenatedFileStream(parts))
                x = await Ut1Archive.HashDomainLinesAsync(concat, list + "/domains.*", prev?.Domains ?? 0, ct).ConfigureAwait(false);
            Write(x, GitHubTagPrefix + string.Join("|", tags), null);
            return true;
        }
        finally
        {
            foreach (var p in parts)
            {
                try { File.Delete(p); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }

        void Write(Ut1Extract x, string etag, DateTimeOffset? lastModified)
        {
            x.Set.WriteAtomic(path);
            state[fileName] = new Ut1SourceState(etag, lastModified, x.Set.Count, DateTimeOffset.UtcNow);
            _log.LogInformation("{Category}/{List} (GitHub): {Domains} domains ({Skipped} skipped of {Lines} lines) → {File} in {Ms} ms",
                category, list, x.Set.Count, x.Skipped, x.Lines, fileName, sw.ElapsedMilliseconds);
        }
    }

    private async Task<HttpResponseMessage> GetAsync(Uri url, string? etag, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (etag is { Length: > 0 } && EntityTagHeaderValue.TryParse(etag, out var tag)) req.Headers.IfNoneMatch.Add(tag);
        return await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
    }

    private static async Task SaveAsync(HttpResponseMessage resp, string path, CancellationToken ct)
    {
        await using var body = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true);
        await body.CopyToAsync(fs, ct).ConfigureAwait(false);
    }

    /// <summary>UT1 tarball with If-None-Match / If-Modified-Since. True when a new file was written, false on 304.</summary>
    private async Task<bool> UpdateFromTarballAsync(string category, string list, Dictionary<string, Ut1SourceState> state, CancellationToken ct)
    {
        var fileName = Ut1Catalog.FileName(category, list);
        var path = Path.Combine(Dir, fileName);
        var url = Ut1Catalog.UrlOf(_options.CategorySourceBaseUrl, list);
        state.TryGetValue(fileName, out var prev);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (prev is not null && File.Exists(path))
        {
            if (prev.ETag is { Length: > 0 } etag && !etag.StartsWith(GitHubTagPrefix, StringComparison.Ordinal)
                && EntityTagHeaderValue.TryParse(etag, out var tag)) req.Headers.IfNoneMatch.Add(tag);
            if (prev.LastModified is { } lm) req.Headers.IfModifiedSince = lm;
        }

        var sw = Stopwatch.StartNew();
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotModified)
        {
            _log.LogDebug("{List}: not modified", list);
            return false;
        }
        resp.EnsureSuccessStatusCode();

        var length = resp.Content.Headers.ContentLength;
        await using var body = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var extract = await Ut1Archive.ExtractAsync(body, list, prev?.Domains ?? 0, ct).ConfigureAwait(false);
        var downloadMs = sw.ElapsedMilliseconds;

        extract.Set.WriteAtomic(path);
        state[fileName] = new Ut1SourceState(resp.Headers.ETag?.ToString(), resp.Content.Headers.LastModified,
            extract.Set.Count, DateTimeOffset.UtcNow);
        _log.LogInformation(
            "{Category}/{List}: {Bytes} bytes → {Domains} domains ({Skipped} skipped of {Lines} lines, entry {Entry}) → {File} {BinBytes} bytes; download+extract {Ms} ms, total {Total} ms",
            category, list, length, extract.Set.Count, extract.Skipped, extract.Lines, extract.EntryName, fileName,
            new FileInfo(path).Length, downloadMs, sw.ElapsedMilliseconds);
        return true;
    }

    // ------------------------------------------------------------------ installer seed

    /// <summary>Promotes the seed lists of the categories <paramref name="policy"/> references and reloads the store when
    /// anything was copied. Returns the number of promoted files.</summary>
    internal int PromoteSeedsForPolicy(Core.Policy.DevicePolicy? policy)
    {
        if (policy is null || !Directory.Exists(SeedDir)) return 0;
        _pass.Wait();
        try
        {
            var state = LoadState();
            var n = PromoteSeeds(Ut1Catalog.ReferencedCategories(policy, IsManaged), state);
            if (n > 0) { SaveState(state); _store.Reload(force: true); }
            return n;
        }
        finally { _pass.Release(); }
    }

    /// <summary>Copies <c>seed\&lt;file&gt;</c> to <c>&lt;file&gt;</c> when the live list is missing or the seed is newer
    /// (seed LastModified vs the live list's LastModified, else its download time) and adopts the seed's state entry, so
    /// the next conditional GET starts from it. Caller holds the pass lock.</summary>
    private int PromoteSeeds(IEnumerable<string> categories, Dictionary<string, Ut1SourceState> state)
    {
        if (!Directory.Exists(SeedDir)) return 0;
        Dictionary<string, Ut1SourceState> seedState;
        try
        {
            var sp = Path.Combine(SeedDir, SeedStateFileName);
            seedState = File.Exists(sp) && JsonSerializer.Deserialize<Dictionary<string, Ut1SourceState>>(File.ReadAllText(sp), Json) is { } d
                ? new(d, StringComparer.OrdinalIgnoreCase) : new(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _log.LogWarning("Category seed state unreadable: {Error}", ex.Message);
            seedState = new(StringComparer.OrdinalIgnoreCase);
        }
        Directory.CreateDirectory(Dir);
        var promoted = 0;
        foreach (var cat in categories)
        {
            if (!Ut1Catalog.Sources.TryGetValue(cat, out var lists)) continue;
            foreach (var list in lists)
            {
                var fileName = Ut1Catalog.FileName(cat, list);
                var seedFile = Path.Combine(SeedDir, fileName);
                if (!File.Exists(seedFile)) continue;
                var live = Path.Combine(Dir, fileName);
                seedState.TryGetValue(fileName, out var seed);
                state.TryGetValue(fileName, out var cur);
                if (File.Exists(live) && cur is not null)
                {
                    var seedAt = seed?.LastModified ?? seed?.UpdatedUtc ?? File.GetLastWriteTimeUtc(seedFile);
                    var liveAt = cur.LastModified ?? cur.UpdatedUtc;
                    if (seedAt <= liveAt) continue;
                }
                try
                {
                    HashedDomainSet.Read(seedFile);   // never promote a corrupt file over a good one
                    File.Copy(seedFile, live + ".tmp", overwrite: true);
                    File.Move(live + ".tmp", live, overwrite: true);
                    state[fileName] = seed ?? new Ut1SourceState(null, null, 0, File.GetLastWriteTimeUtc(seedFile));
                    promoted++;
                    _log.LogInformation("Category {File}: installed the seed list", fileName);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
                {
                    _log.LogWarning("Category seed {File} not promoted: {Error}", fileName, ex.Message);
                }
            }
        }
        return promoted;
    }

    // ------------------------------------------------------------------ state

    internal Dictionary<string, Ut1SourceState> LoadState()
    {
        try
        {
            if (File.Exists(StatePath))
                return JsonSerializer.Deserialize<Dictionary<string, Ut1SourceState>>(File.ReadAllText(StatePath), Json)
                    is { } d ? new(d, StringComparer.OrdinalIgnoreCase) : new(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _log.LogWarning("Category state unreadable, next pass downloads everything: {Error}", ex.Message);
        }
        return new(StringComparer.OrdinalIgnoreCase);
    }

    private void SaveState(Dictionary<string, Ut1SourceState> state)
    {
        try
        {
            Directory.CreateDirectory(Dir);
            var tmp = StatePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(state, Json));
            File.Move(tmp, StatePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.LogWarning("Could not save category state: {Error}", ex.Message);
        }
    }

    public override void Dispose()
    {
        _policy.PolicyChanged -= OnPolicyChanged;
        _http.Dispose();
        _wake.Dispose();
        _pass.Dispose();
        base.Dispose();
    }
}
