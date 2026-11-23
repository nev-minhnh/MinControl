using System.Text.Json.Nodes;
using MinControl.Browser.Events;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Telemetry;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MinControl.Browser.History;

/// <summary>Emits events carrying their own timestamp (<c>ts</c> = when the visit happened).</summary>
public interface IHistoryEventSink
{
    void Emit(string type, string sid, JsonObject data, DateTimeOffset at);
}

/// <summary>Routes to <see cref="EventSink.EmitAt"/> when the concrete Core sink is used, else plain Emit.</summary>
public sealed class HistoryEventSink(IEventSink sink) : IHistoryEventSink
{
    public void Emit(string type, string sid, JsonObject data, DateTimeOffset at)
    {
        if (sink is EventSink concrete) concrete.EmitAt(type, sid, data, at);
        else sink.Emit(type, sid, data);
    }
}

/// <summary>
/// Reads web history from the browsers' own History databases (Chrome/Edge refuse force-installed off-store
/// extensions on non-domain PCs). Every <see cref="BrowserOptions.HistoryPollInterval"/>, for each managed user
/// with <c>monitoring.browserHistory</c>: when a profile's History (size, mtime) changed, copies it (+ journal)
/// into the restricted temp dir, reads <c>visits JOIN urls</c> past the persisted cursor (≤ 500 per poll) and
/// emits <c>web.visit</c> / <c>web.search</c>. A cursor going backwards or a sharply shrunken DB means history
/// was cleared → <c>tamper.state_tampered</c> once, cursor reset.
/// </summary>
public sealed class BrowserHistoryReader : BackgroundService
{
    /// <summary>A file at least this big shrinking below a quarter of its size counts as "history cleared".</summary>
    internal const long ShrinkMinBytes = 1L << 20;

    private readonly IUserDirectory _users;
    private readonly IPolicyProvider? _policy;
    private readonly IHistoryEventSink _sink;
    private readonly IClock _clock;
    private readonly IHistoryFileLocator _locator;
    private readonly HistoryCursorStore _cursors;
    private readonly string _tempRoot;
    private readonly BrowserOptions _options;
    private readonly ILogger _log;

    // key -> (size, mtime, journal mtime) at the last complete read; absent/null forces a read
    private readonly Dictionary<string, (long, long, long)> _seen = new(StringComparer.Ordinal);
    // sids whose monitoring was off at the last poll: when it turns on, import only from that moment
    private readonly Dictionary<string, DateTimeOffset> _resumedAt = new(StringComparer.Ordinal);
    private readonly HashSet<string> _disabled = new(StringComparer.Ordinal);

    public BrowserHistoryReader(IUserDirectory users, IPolicyProvider? policy, IHistoryEventSink sink, IClock clock,
        IHistoryFileLocator locator, HistoryCursorStore cursors, string tempRoot, BrowserOptions options, ILogger log)
    {
        _users = users; _policy = policy; _sink = sink; _clock = clock; _locator = locator; _cursors = cursors;
        _tempRoot = tempRoot; _options = options; _log = log;
    }

    /// <summary>Banned-word check of fresh visits (search query in the URL); resolved lazily, may return null.</summary>
    public Func<IKeywordGuard?>? KeywordGuard { get; init; }

    /// <summary>Read positions (diagnostics).</summary>
    public HistoryCursorStore Cursors => _cursors;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        PurgeTemp();
        using var timer = new PeriodicTimer(_options.HistoryPollInterval);
        do
        {
            try { await Task.Run(PollOnce, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "browser history poll failed"); }
        } while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }

    /// <summary>One pass over every managed user's profiles (tests call this directly).</summary>
    internal void PollOnce()
    {
        var policy = _policy?.Current;
        if (policy is null) return;
        foreach (var sid in _users.ManagedSids)
        {
            if (!_users.IsManaged(sid) || !policy.Users.TryGetValue(sid, out var user)) continue;
            if (!user.Monitoring.BrowserHistory) { _disabled.Add(sid); continue; }
            if (_disabled.Remove(sid)) _resumedAt[sid] = _clock.UtcNow;
            string? profile = _users.ProfilePath(sid);
            if (string.IsNullOrEmpty(profile)) continue;
            foreach (var file in _locator.Locate(sid, profile))
            {
                try { PollFile(sid, user.Label, file); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or SqliteException or InvalidOperationException)
                {
                    _log.LogInformation("history read {Browser}/{Profile} of {Sid} failed: {Msg}", file.Browser, file.Profile, sid, e.Message);
                }
            }
        }
    }

    private void PollFile(string sid, string label, HistoryFile file)
    {
        string key = HistoryCursorStore.Key(sid, file.Browser, file.Profile);
        var info = new FileInfo(file.Path);
        if (!info.Exists) return;
        var journal = new FileInfo(file.Path + "-journal");
        var sig = (info.Length, info.LastWriteTimeUtc.Ticks, journal.Exists ? journal.LastWriteTimeUtc.Ticks : 0L);
        if (_seen.TryGetValue(key, out var last) && last == sig) return;

        string dir = Path.Combine(_tempRoot, "hist-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(dir);
            string copy = Path.Combine(dir, "History");
            CopyShared(file.Path, copy);
            bool hasJournal = journal.Exists && TryCopyShared(journal.FullName, copy + "-journal");
            bool truncated = Process(sid, label, file, copy, info.Length, readWrite: hasJournal);
            // more than one batch waiting → read again next poll even if the file does not change
            if (truncated) _seen.Remove(key); else _seen[key] = sig;
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { _log.LogDebug("temp cleanup failed: {Msg}", e.Message); }
        }
    }

    /// <summary>Reads the copied DB and emits; returns true when the per-poll cap was hit.</summary>
    internal bool Process(string sid, string label, HistoryFile file, string dbPath, long size, bool readWrite = false)
    {
        string key = HistoryCursorStore.Key(sid, file.Browser, file.Profile);
        var cursor = _cursors.Get(key);
        var now = _clock.UtcNow;
        long after, minTime;
        if (cursor is null)
        {
            after = 0;
            minTime = ChromiumHistory.ToWebKit(now - _options.HistoryFirstImportWindow);
        }
        else
        {
            after = cursor.LastVisitId;
            minTime = 0;
        }
        if (_resumedAt.Remove(sid, out var resumed)) minTime = Math.Max(minTime, ChromiumHistory.ToWebKit(resumed));

        int limit = _options.HistoryMaxVisitsPerPoll;
        var result = ChromiumHistory.Read(dbPath, after, minTime, limit, readWrite);

        bool shrank = cursor is not null && cursor.Size >= ShrinkMinBytes && size < cursor.Size / 4;
        if (cursor is not null && (result.MaxVisitId < cursor.LastVisitId || shrank))
        {
            string browserName = file.Browser == "msedge" ? "Edge" : "Chrome";
            _log.LogWarning("{Browser} history of {Sid} was cleared (max id {Max} < cursor {Cursor}, size {Old} -> {New})",
                browserName, sid, result.MaxVisitId, cursor.LastVisitId, cursor.Size, size);
            _sink.Emit(EventTypes.TamperStateTampered, sid, new JsonObject
            {
                ["detail"] = $"Lịch sử {browserName} của {(string.IsNullOrWhiteSpace(label) ? sid : label)} bị xoá",
            }, now);
            // start over, but never re-emit what was already sent: only visits newer than the last emitted one
            result = ChromiumHistory.Read(dbPath, 0, cursor.LastVisitTime + 1, limit, readWrite);
            cursor = cursor with { LastVisitId = 0 };
        }

        long lastTime = cursor?.LastVisitTime ?? 0;
        foreach (var v in result.Visits)
        {
            if (Emit(sid, file.Browser, v)) lastTime = Math.Max(lastTime, v.VisitTime);
        }
        _cursors.Set(key, new HistoryCursor(result.LastScannedId, lastTime, size));
        return result.Truncated;
    }

    private bool Emit(string sid, string browser, HistoryVisit v)
    {
        if (!ChromiumHistory.IsHttp(v.Url)) return false;
        long core = v.Transition & 0xFF;
        if (core == 3) return false;                                   // auto_subframe: ads/iframes, not a page view
        if (ChromiumHistory.FromWebKit(v.VisitTime) is not { } at) return false;

        var data = new JsonObject
        {
            ["url"] = Truncate(v.Url, 2048),
            ["browser"] = browser,
            ["transition"] = ChromiumHistory.TransitionName(v.Transition),
        };
        if (!string.IsNullOrEmpty(v.Title)) data["title"] = Truncate(v.Title, 512);
        if (v.DurationUs >= 1_000_000) data["durationSec"] = v.DurationUs / 1_000_000;
        var clean = BrowserEventValidator.Sanitize(EventTypes.WebVisit, data);
        if (clean is null) return false;
        _sink.Emit(EventTypes.WebVisit, sid, clean, at);
        try { KeywordGuard?.Invoke()?.OnHistoryVisit(sid, browser, v.Url, v.Title, at); }
        catch (Exception ex) { _log.LogDebug(ex, "keyword check of a visit failed"); }

        if (!string.IsNullOrWhiteSpace(v.SearchTerm) && core != 8)    // a reload of a results page is not a new search
        {
            var search = BrowserEventValidator.Sanitize(EventTypes.WebSearch, new JsonObject
            {
                ["engine"] = ChromiumHistory.SearchEngine(v.Url),
                ["query"] = Truncate(v.SearchTerm.Trim(), 512),
            });
            if (search is not null) _sink.Emit(EventTypes.WebSearch, sid, search, at);
        }
        return true;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    private static void CopyShared(string source, string dest)
    {
        using var src = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
        using var dst = new FileStream(dest, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16);
        src.CopyTo(dst);
    }

    private static bool TryCopyShared(string source, string dest)
    {
        try { CopyShared(source, dest); return true; }
        catch (FileNotFoundException) { return false; }      // journal vanished between stat and copy
    }

    private void PurgeTemp()
    {
        try
        {
            if (!Directory.Exists(_tempRoot)) return;
            foreach (var d in Directory.EnumerateDirectories(_tempRoot, "hist-*"))
                try { Directory.Delete(d, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { _log.LogDebug("temp purge failed: {Msg}", e.Message); }
    }
}
