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

/// <summary>Per-source bookkeeping for conditional GET, persisted in <c>categories\.ut1-state.json</c>.</summary>
public sealed record Ut1SourceState(string? ETag, DateTimeOffset? LastModified, int Domains, DateTimeOffset UpdatedUtc);

/// <summary>Outcome of one <see cref="CategoryUpdater.UpdateOnceAsync"/> pass (lists are "category/list").</summary>
public sealed record CategoryUpdateResult(
    IReadOnlyList<string> Downloaded, IReadOnlyList<string> NotModified, IReadOnlyList<string> Failed, IReadOnlyList<string> Removed);

/// <summary>
/// Downloads the UT1 lists of the categories referenced by the managed users' policies into
/// <see cref="NetGuardOptions.CategoriesDirectory"/> as hashed <c>.bin</c> sets, then reloads <see cref="CategoryStore"/>.
/// Runs inside the service (SYSTEM — not subject to the per-user WFP lock): first pass after
/// <see cref="NetGuardOptions.CategoryUpdateInitialDelay"/>, then every <see cref="NetGuardOptions.CategoryUpdateInterval"/>
/// (sooner when a policy starts referencing a category that has no list yet, or after a failure).
/// Conditional GET (If-None-Match / If-Modified-Since) keeps daily checks cheap; any failure keeps the previous file.
/// </summary>
public sealed class CategoryUpdater : BackgroundService
{
    internal const string StateFileName = ".ut1-state.json";
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private readonly NetGuardOptions _options;
    private readonly CategoryStore _store;
    private readonly IPolicyProvider _policy;
    private readonly IUserDirectory? _users;
    private readonly HttpClient _http;
    private readonly ILogger _log;
    private readonly SemaphoreSlim _wake = new(0, 1);
    private readonly SemaphoreSlim _pass = new(1, 1);

    public CategoryUpdater(NetGuardOptions options, CategoryStore store, IPolicyProvider policy, IUserDirectory users,
        ILogger<CategoryUpdater>? log = null)
        : this(options, store, policy, users, new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.None,   // the .tar.gz is the payload, not a transfer encoding
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
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("MinControl-CategoryUpdater/1.0");
        _log = log ?? NullLogger.Instance;
        _policy.PolicyChanged += OnPolicyChanged;
    }

    private string Dir => _options.CategoriesDirectory;
    private string StatePath => Path.Combine(Dir, StateFileName);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
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

    /// <summary>A new policy that references a category without a list file triggers an early pass.</summary>
    private void OnPolicyChanged(object? sender, Core.Policy.DevicePolicy policy)
    {
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

    /// <summary>One pass: conditional GET of every referenced list, rebuild changed ones, drop unreferenced ones,
    /// reload the store when anything changed. Without a policy nothing is downloaded or removed.</summary>
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

            foreach (var cat in wanted)
                foreach (var list in Ut1Catalog.Sources[cat])
                {
                    var key = $"{cat}/{list}";
                    try
                    {
                        if (await UpdateSourceAsync(cat, list, state, ct).ConfigureAwait(false)) downloaded.Add(key);
                        else notModified.Add(key);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex)
                    {
                        failed.Add(key);
                        _log.LogWarning("Category list {Key} update failed, keeping the previous file: {Error}", key, ex.Message);
                    }
                }

            // Lists of categories no policy references any more only cost memory: remove them.
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
            if (downloaded.Count > 0 || removed.Count > 0) _store.Reload(force: true);
            _log.LogInformation("Category update: {Down} downloaded, {Same} unchanged, {Fail} failed, {Rm} removed in {Ms} ms",
                downloaded.Count, notModified.Count, failed.Count, removed.Count, sw.ElapsedMilliseconds);
            return new(downloaded, notModified, failed, removed);
        }
        finally
        {
            _pass.Release();
        }
    }

    /// <summary>Returns true when a new file was written, false on 304. Throws on any failure (file untouched).</summary>
    private async Task<bool> UpdateSourceAsync(string category, string list, Dictionary<string, Ut1SourceState> state, CancellationToken ct)
    {
        var fileName = Ut1Catalog.FileName(category, list);
        var path = Path.Combine(Dir, fileName);
        var url = Ut1Catalog.UrlOf(_options.CategorySourceBaseUrl, list);
        state.TryGetValue(fileName, out var prev);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (prev is not null && File.Exists(path))
        {
            if (prev.ETag is { Length: > 0 } etag && EntityTagHeaderValue.TryParse(etag, out var tag)) req.Headers.IfNoneMatch.Add(tag);
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
