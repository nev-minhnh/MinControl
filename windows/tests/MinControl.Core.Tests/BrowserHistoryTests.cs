using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Browser;
using MinControl.Browser.Events;
using MinControl.Browser.History;
using MinControl.Core.Abstractions;
using MinControl.Core.Cloud;
using MinControl.Core.Events;
using MinControl.Core.Policies;
using MinControl.Core.Policy;
using MinControl.Core.Util;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace MinControl.Core.Tests;

public sealed class BrowserHistoryTests : IDisposable
{
    private const string Sid = TestData.Sid;
    private static readonly DateTimeOffset Now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    private readonly string _dir;
    private readonly string _history;
    private readonly FakeClock _clock = new(Now);
    private readonly RecordingSink _sink = new();
    private readonly Users _users = new();
    private readonly Policies _policy = new();
    private readonly BrowserOptions _options = new();
    private BrowserHistoryReader? _reader;

    public BrowserHistoryTests()
    {
        // under bin/ (inside the repo), never %TEMP%
        _dir = Path.Combine(AppContext.BaseDirectory, "history-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(_dir, "profile"));
        _history = Path.Combine(_dir, "profile", "History");
        _users.Profiles[Sid] = Path.Combine(_dir, "profile");
        _policy.Set(browserHistory: true);
        CreateDb(_history);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private BrowserHistoryReader Reader => _reader ??= new BrowserHistoryReader(_users, _policy, _sink, _clock,
        new OneFile(new HistoryFile("msedge", "Default", _history)),
        new HistoryCursorStore(Path.Combine(_dir, "data", "browser-history.json")), Path.Combine(_dir, "data", "tmp"),
        _options, NullLogger.Instance);

    // ------------------------------------------------------------------------------------------------ pure mapping

    [Fact]
    public void WebKit_time_converts_to_utc()
    {
        Assert.Equal(DateTimeOffset.UnixEpoch, ChromiumHistory.FromWebKit(11_644_473_600_000_000));
        var t = new DateTimeOffset(2026, 11, 20, 8, 30, 15, TimeSpan.Zero);
        Assert.Equal(t, ChromiumHistory.FromWebKit(ChromiumHistory.ToWebKit(t)));
        Assert.Equal("2026-11-20T08:30:15Z", Time.Utc(ChromiumHistory.FromWebKit(ChromiumHistory.ToWebKit(t) + 999)!.Value));
        Assert.Null(ChromiumHistory.FromWebKit(0));
        Assert.Null(ChromiumHistory.FromWebKit(-5));
        Assert.Null(ChromiumHistory.FromWebKit(long.MaxValue));
    }

    [Theory]
    [InlineData(0, "link")]
    [InlineData(0x30000001, "typed")]            // CHAIN_START|CHAIN_END qualifiers are ignored
    [InlineData(2, "auto_bookmark")]
    [InlineData(0x10000005, "generated")]
    [InlineData(0x30000008, "reload")]
    [InlineData(7, "form_submit")]
    [InlineData(9, "keyword")]
    [InlineData(10, "keyword_generated")]
    [InlineData(0x2000006, "auto_toplevel")]
    [InlineData(0x3F, "other")]
    public void Core_transition_maps_to_name(long transition, string expected) =>
        Assert.Equal(expected, ChromiumHistory.TransitionName(transition));

    [Theory]
    [InlineData("https://www.google.com/search?q=a", "google")]
    [InlineData("https://www.google.com.vn/search?q=a", "google")]
    [InlineData("https://google.co.uk/search?q=a", "google")]
    [InlineData("https://google.evil.com/search?q=a", "other")]
    [InlineData("https://googleusercontent.com/x", "other")]
    [InlineData("https://www.bing.com/search?q=a", "bing")]
    [InlineData("https://m.youtube.com/results?search_query=a", "youtube")]
    [InlineData("https://coccoc.com/search?query=a", "coccoc")]
    [InlineData("https://duckduckgo.com/?q=a", "other")]
    [InlineData("not a url", "other")]
    public void Search_engine_from_host(string url, string expected) =>
        Assert.Equal(expected, ChromiumHistory.SearchEngine(url));

    // ------------------------------------------------------------------------------------------------ reader

    [Fact]
    public void First_poll_imports_last_24h_http_visits_with_exact_shapes()
    {
        AddUrl(1, "https://old.example/", "Old");
        AddUrl(2, "https://news.example/a", "Tin tức");
        AddUrl(3, "chrome://settings/", "Settings");
        AddUrl(4, "https://ads.example/frame", null);
        AddUrl(5, "https://www.google.com.vn/search?q=meo", "meo - Google");
        AddVisit(1, 1, Now.AddHours(-30), 0, 1);
        AddVisit(2, 2, Now.AddMinutes(-10), 5_500_000, 0x30000001);
        AddVisit(3, 3, Now.AddMinutes(-9), 0, 1);
        AddVisit(4, 4, Now.AddMinutes(-8), 0, 3);                  // auto_subframe
        AddVisit(5, 5, Now.AddMinutes(-7), 0, 0x30000000);
        AddTerm(5, "mèo con");

        Reader.PollOnce();

        Assert.Collection(_sink.Events,
            e =>
            {
                Assert.Equal(("web.visit", Sid, Now.AddMinutes(-10)), (e.Type, e.Sid, e.At));
                Assert.Equal("""{"url":"https://news.example/a","browser":"msedge","transition":"typed","title":"Tin tức","durationSec":5}""",
                    e.Data.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
            },
            e =>
            {
                Assert.Equal("web.visit", e.Type);
                Assert.Equal("link", (string?)e.Data["transition"]);
                Assert.False(e.Data.ContainsKey("durationSec"));
            },
            e =>
            {
                Assert.Equal(("web.search", Now.AddMinutes(-7)), (e.Type, e.At));
                Assert.Equal("google", (string?)e.Data["engine"]);
                Assert.Equal("mèo con", (string?)e.Data["query"]);
            });
        foreach (var e in _sink.Events) AssertSchemaValid(e);
        Assert.Empty(Directory.EnumerateDirectories(Path.Combine(_dir, "data", "tmp")));   // copies deleted
    }

    [Fact]
    public void Unchanged_file_is_not_reread_and_new_visits_follow_cursor()
    {
        AddUrl(1, "https://a.example/", "A");
        AddVisit(1, 1, Now.AddMinutes(-5), 0, 0);
        Reader.PollOnce();
        Assert.Single(_sink.Events);

        Reader.PollOnce();
        Assert.Single(_sink.Events);

        AddVisit(2, 1, Now.AddMinutes(-1), 0, 8);
        Touch();
        Reader.PollOnce();
        Assert.Equal(2, _sink.Events.Count);
        Assert.Equal("reload", (string?)_sink.Events[1].Data["transition"]);

        // a new reader (service restart) resumes from the persisted cursor: nothing re-emitted
        _reader = null;
        Reader.PollOnce();
        Assert.Equal(2, _sink.Events.Count);
    }

    [Fact]
    public void One_poll_is_capped_and_the_rest_follows_without_file_change()
    {
        _options.HistoryMaxVisitsPerPoll = 500;
        AddUrl(1, "https://a.example/", "A");
        using (var db = Open(_history))
        using (var tx = db.BeginTransaction())
        {
            for (int i = 1; i <= 1200; i++) Exec(db, "INSERT INTO visits VALUES($a,1,$b,0,0)", ("$a", i), ("$b", ChromiumHistory.ToWebKit(Now.AddSeconds(-2000 + i))));
            tx.Commit();
        }
        Reader.PollOnce();
        Assert.Equal(500, _sink.Events.Count);
        Reader.PollOnce();
        Assert.Equal(1000, _sink.Events.Count);
        Reader.PollOnce();
        Assert.Equal(1200, _sink.Events.Count);
        Reader.PollOnce();
        Assert.Equal(1200, _sink.Events.Count);
    }

    [Fact]
    public void Cleared_history_emits_tamper_once_and_resets_cursor()
    {
        AddUrl(1, "https://a.example/", "A");
        for (int i = 1; i <= 10; i++) AddVisit(i, 1, Now.AddMinutes(-60 + i), 0, 0);
        Reader.PollOnce();
        Assert.Equal(10, _sink.Events.Count);
        _sink.Events.Clear();

        // user cleared history: table emptied, ids restart at 1
        Exec("DELETE FROM visits");
        AddVisit(1, 1, Now.AddMinutes(-1), 0, 1);
        Touch();
        _clock.Advance(TimeSpan.FromSeconds(10));
        Reader.PollOnce();

        Assert.Equal(2, _sink.Events.Count);
        Assert.Equal(EventTypes.TamperStateTampered, _sink.Events[0].Type);
        Assert.Equal("Lịch sử Edge của Bin bị xoá", (string?)_sink.Events[0].Data["detail"]);
        AssertSchemaValid(_sink.Events[0]);
        Assert.Equal("web.visit", _sink.Events[1].Type);
        Assert.Equal(Now.AddMinutes(-1), _sink.Events[1].At);

        AddVisit(2, 1, Now, 0, 0);
        Touch();
        Reader.PollOnce();
        Assert.Equal(3, _sink.Events.Count);
        Assert.Equal("web.visit", _sink.Events[2].Type);       // no second tamper
    }

    [Fact]
    public void Monitoring_off_reads_nothing_and_resume_skips_the_paused_period()
    {
        _policy.Set(browserHistory: false);
        AddUrl(1, "https://a.example/", "A");
        AddVisit(1, 1, Now.AddMinutes(-5), 0, 0);
        Reader.PollOnce();
        Assert.Empty(_sink.Events);

        _clock.Advance(TimeSpan.FromMinutes(1));
        _policy.Set(browserHistory: true);
        AddVisit(2, 1, Now.AddMinutes(2), 0, 0);
        Touch();
        Reader.PollOnce();
        Assert.Single(_sink.Events);
        Assert.Equal(Now.AddMinutes(2), _sink.Events[0].At);
    }

    [Fact]
    public void Profile_dirs_are_default_or_numbered()
    {
        Assert.True(HistoryFileLocator.IsProfileDir("Default"));
        Assert.True(HistoryFileLocator.IsProfileDir("Profile 3"));
        Assert.False(HistoryFileLocator.IsProfileDir("Guest Profile"));
        Assert.False(HistoryFileLocator.IsProfileDir("System Profile"));
        Assert.False(HistoryFileLocator.IsProfileDir("Profile x"));
    }

    // ------------------------------------------------------------------------------------------------ heartbeat (bug fix)

    [Fact]
    public void Heartbeat_is_a_noop_without_configured_extension_ids()
    {
        var sink = new PlainSink();
        var mon = Monitor(new BrowserOptions(), sink);
        mon.RunningProbe = () => [(Sid, "msedge"), (Sid, "chrome")];
        mon.Check();
        _clock.Advance(TimeSpan.FromMinutes(10));
        mon.Check();
        Assert.Empty(sink.Types);
        Assert.False(mon.IsExtensionMissing(Sid, "msedge"));
        Assert.False(mon.IsExtensionMissing(Sid, "chrome"));
    }

    [Fact]
    public void Heartbeat_monitors_only_browsers_with_an_id()
    {
        var sink = new PlainSink();
        var mon = Monitor(new BrowserOptions { EdgeExtensionId = new string('a', 32), ChromeExtensionId = "not-an-id" }, sink);
        mon.RunningProbe = () => [(Sid, "msedge"), (Sid, "chrome")];
        mon.Check();
        _clock.Advance(TimeSpan.FromMinutes(4));
        mon.Check();
        Assert.Equal([EventTypes.TamperExtensionMissing], sink.Types);
        Assert.True(mon.IsExtensionMissing(Sid, "msedge"));
        Assert.False(mon.IsExtensionMissing(Sid, "chrome"));
    }

    private ExtensionHeartbeatMonitor Monitor(BrowserOptions o, IEventSink sink) =>
        new(new ExtensionHeartbeatTracker(_clock), _users, sink, _clock, Options.Create(o), NullLogger<ExtensionHeartbeatMonitor>.Instance);

    // ------------------------------------------------------------------------------------------------ uploader nudge

    [Fact]
    public async Task Web_events_nudge_one_early_flush()
    {
        using var http = new HttpClient();
        using var store = new MinControl.Core.Storage.StateStore(Path.Combine(_dir, "state.db"));
        var up = new CloudUploader(http, store, new UploadTokenHolder(), _clock, () => null) { NudgeDelay = TimeSpan.FromMilliseconds(50) };
        int fired = 0;
        var done = new TaskCompletionSource();
        up.FlushDue += () => { Interlocked.Increment(ref fired); done.TrySetResult(); };

        up.Nudge("process.started");
        up.Nudge("web.visit");
        up.Nudge("web.visit");
        up.Nudge("web.search");
        await done.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(150);
        Assert.Equal(1, fired);

        up.Nudge("web.visit");                                    // next window
        await Task.Delay(300);
        Assert.Equal(2, fired);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private static void AssertSchemaValid(Recorded e)
    {
        var ev = new JsonObject
        {
            ["id"] = "01JDQ3Z8K4M2N6P8R0S2T4V6W8",
            ["deviceId"] = TestData.DeviceId,
            ["userSid"] = e.Sid,
            ["ts"] = Time.Utc(e.At),
            ["monoMs"] = 1,
            ["type"] = e.Type,
            ["data"] = e.Data.DeepClone(),
        };
        Assert.True(SchemaValidator.Shared.IsValid("event", JsonSerializer.SerializeToElement(ev)), ev.ToJsonString());
    }

    private void Touch() => File.SetLastWriteTimeUtc(_history, File.GetLastWriteTimeUtc(_history).AddSeconds(1));

    private static SqliteConnection Open(string path)
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        db.Open();
        return db;
    }

    private static void CreateDb(string path)
    {
        using var db = Open(path);
        Exec(db, """
            CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR);
            CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
                visit_duration INTEGER DEFAULT 0 NOT NULL, transition INTEGER DEFAULT 0 NOT NULL);
            CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL, term LONGVARCHAR NOT NULL);
            """);
    }

    private void Exec(string sql) { using var db = Open(_history); Exec(db, sql); }

    private static void Exec(SqliteConnection db, string sql, params (string, object?)[] args)
    {
        using var cmd = db.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    private void AddUrl(long id, string url, string? title)
    {
        using var db = Open(_history);
        Exec(db, "INSERT INTO urls VALUES($i,$u,$t)", ("$i", id), ("$u", url), ("$t", title));
    }

    private void AddVisit(long id, long urlId, DateTimeOffset at, long durationUs, long transition)
    {
        using var db = Open(_history);
        Exec(db, "INSERT INTO visits VALUES($i,$u,$t,$d,$x)", ("$i", id), ("$u", urlId), ("$t", ChromiumHistory.ToWebKit(at)), ("$d", durationUs), ("$x", transition));
    }

    private void AddTerm(long urlId, string term)
    {
        using var db = Open(_history);
        Exec(db, "INSERT INTO keyword_search_terms VALUES(2,$u,$t)", ("$u", urlId), ("$t", term));
    }

    private sealed record Recorded(string Type, string Sid, JsonObject Data, DateTimeOffset At);

    private sealed class RecordingSink : IHistoryEventSink
    {
        public List<Recorded> Events { get; } = [];
        public void Emit(string type, string sid, JsonObject data, DateTimeOffset at) => Events.Add(new(type, sid, data, at));
    }

    private sealed class PlainSink : IEventSink
    {
        public List<string> Types { get; } = [];
        public void Emit(string type, string? userSid, JsonObject data) => Types.Add(type);
    }

    private sealed class OneFile(HistoryFile file) : IHistoryFileLocator
    {
        public IReadOnlyList<HistoryFile> Locate(string sid, string profilePath) => [file];
    }

    private sealed class Users : IUserDirectory
    {
        public Dictionary<string, string> Profiles { get; } = new();
        public bool IsManaged(string sid) => Profiles.ContainsKey(sid);
        public bool IsAdministrator(string sid) => false;
        public IReadOnlyCollection<string> ManagedSids => Profiles.Keys;
        public string? SidOfProcess(int pid) => null;
        public string? ProfilePath(string sid) => Profiles.GetValueOrDefault(sid);
    }

    private sealed class Policies : IPolicyProvider
    {
        public DevicePolicy? Current { get; private set; }
        public event EventHandler<DevicePolicy>? PolicyChanged;

        private static WeekdayMap<T> All<T>(T v) => new(v, v, v, v, v, v, v);

        public void Set(bool browserHistory)
        {
            var user = new UserPolicy("Bin",
                new ScreenTimePolicy(All(120), All<IReadOnlyList<string>>(["00:00-23:59"]), [5], 60, false, 300),
                new Dictionary<string, AppGroup>(), [], "allow",
                new WebPolicy("blocklist", [], [], [], true, "strict", ["msedge.exe", "chrome.exe"], []),
                new MonitoringPolicy(true, browserHistory, true, true, true, new ScreenshotPolicy(5, true, 1280, 60)));
            Current = new DevicePolicy(1, "Asia/Ho_Chi_Minh", new Dictionary<string, UserPolicy> { [Sid] = user }, new RetentionDays(90, 30, 7));
            PolicyChanged?.Invoke(this, Current);
        }
    }
}
