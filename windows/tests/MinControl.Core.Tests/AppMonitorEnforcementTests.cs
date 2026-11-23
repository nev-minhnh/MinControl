using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policy;
using MinControl.Monitoring;
using MinControl.Monitoring.Processes;
using MinControl.Monitoring.Rules;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>Policy → AppMonitor → kill, through fake process sources (no ETW, no real processes).</summary>
public class AppMonitorEnforcementTests
{
    private const string Kid = TestData.Sid;
    private const string Admin = TestData.AdminSid;
    private const string Game = @"C:\Games\Game\game.exe";
    private const string Roblox = @"C:\Program Files (x86)\Roblox\RobloxPlayerBeta.exe";
    private const string Notepad = @"C:\Program Files\Notepad++\notepad++.exe";

    private sealed class FakeSource : IProcessEventSource
    {
        public bool FailStart { get; init; }
        public bool Started_ { get; private set; }
        public bool Disposed { get; private set; }
        public event Action<ProcessStarted>? Started;
        public event Action<int>? Stopped;
        public event Action<Exception?>? Faulted;
        public void Start() { if (FailStart) throw new InvalidOperationException("no ETW for you"); Started_ = true; }
        public void Dispose() => Disposed = true;
        public void RaiseStart(int pid, string? path = null) => Started?.Invoke(new ProcessStarted(pid, 1, path));
        public void RaiseStop(int pid) => Stopped?.Invoke(pid);
        public void RaiseFault() => Faulted?.Invoke(new Exception("session stopped"));
    }

    private sealed class Users : IUserDirectory
    {
        public ConcurrentDictionary<int, string> Pids { get; } = new();
        public bool IsManaged(string sid) => sid == Kid;
        public bool IsAdministrator(string sid) => sid == Admin;
        public IReadOnlyCollection<string> ManagedSids => [Kid];
        public string? SidOfProcess(int pid) => Pids.GetValueOrDefault(pid);
        public string? ProfilePath(string sid) => @"C:\Users\kid";
    }

    private sealed class Control : IProcessControl
    {
        public ConcurrentDictionary<int, string> Paths { get; } = new();
        public ConcurrentQueue<(int Pid, string Path)> Kills { get; } = new();
        public string? ImagePath(int pid) => Paths.GetValueOrDefault(pid);
        public bool Terminate(int pid, string expectedPath) { Kills.Enqueue((pid, expectedPath)); return true; }
    }

    private sealed class Facts : IFileFacts
    {
        public string? Sha256(string path) => path == Game ? new string('a', 64) : null;
        public SignatureInfo Signature(string path) => SignatureInfo.Unsigned;
        public long? SizeBytes(string path) => 1;
    }

    private sealed class Policies(DevicePolicy p) : IPolicyProvider
    {
        public DevicePolicy? Current { get; set; } = p;
        public event EventHandler<DevicePolicy>? PolicyChanged;
        public void Change(DevicePolicy next) { Current = next; PolicyChanged?.Invoke(this, next); }
    }

    private sealed class Sink : IEventSink
    {
        public ConcurrentQueue<(string Type, string? Sid, JsonObject Data)> Events { get; } = new();
        public void Emit(string type, string? userSid, JsonObject data) => Events.Enqueue((type, userSid, data));
    }

    private sealed class Approvals : IApprovalStore
    {
        public string? DecisionFor(string sid, string sha256) => null;
        public void Record(string sid, string sha256, string decision) { }
        public bool MarkRequested(string sid, string sha256) => true;
    }

    private sealed class Engine : IScreenTimeEngine
    {
        public volatile string[] Exhausted = [];
        public ScreenTimeState Evaluate(string sid, DateTimeOffset utcNow) => throw new NotSupportedException();
        public void RecordUsage(string sid, string? foregroundExePath, long activeMsDelta) { }
        public IReadOnlyCollection<string> ExhaustedGroups(string sid, DateTimeOffset utcNow) => Exhausted;
    }

    private static WeekdayMap<T> All<T>(T v) => new(v, v, v, v, v, v, v);

    private static DevicePolicy Policy(IReadOnlyList<AppRule> rules, IReadOnlyDictionary<string, AppGroup>? groups = null) =>
        new(6, "Asia/Ho_Chi_Minh", new Dictionary<string, UserPolicy>
        {
            [Kid] = new UserPolicy("Kid",
                new ScreenTimePolicy(All(120), All<IReadOnlyList<string>>(["00:00-23:59"]), [5], 60, false, 300),
                groups ?? new Dictionary<string, AppGroup>(), rules, "allow",
                new WebPolicy("blocklist", [], [], [], false, "off", ["msedge.exe"], []),
                new MonitoringPolicy(false, false, false, false, false, new ScreenshotPolicy(5, true, 1280, 60))),
        }, new RetentionDays(30, 30, 7));

    // allow-rules first so no ACL probing happens for the allowed test exes
    private static readonly AppRule AllowNotepad = new("allow", new AppMatch(Exe: "notepad++.exe"));
    private static readonly AppRule AllowRoblox = new("allow", new AppMatch(Exe: "RobloxPlayerBeta.exe"));

    private sealed class Fixture : IDisposable
    {
        public Users Users { get; } = new();
        public Control Control { get; } = new();
        public Sink Sink { get; } = new();
        public Engine Engine { get; } = new();
        public FakeSessionActions Session { get; } = new();
        public Policies Policy { get; }
        public FakeSource Primary { get; }
        public FakeSource Poll { get; } = new();
        public int PollInterval { get; private set; }
        public AppMonitor Monitor { get; }

        public Fixture(DevicePolicy policy, bool etwFails = false)
        {
            Policy = new Policies(policy);
            Primary = new FakeSource { FailStart = etwFails };
            var services = new ServiceCollection()
                .AddSingleton<IScreenTimeEngine>(Engine)
                .AddSingleton<ISessionActions>(Session)
                .BuildServiceProvider();
            var options = new MonitoringOptions { GroupSweepInterval = TimeSpan.FromMilliseconds(50), StateDirectory = Path.GetTempPath() };
            Monitor = new AppMonitor(Users, Policy, Sink, new Approvals(), new FakeClock(DateTimeOffset.UtcNow), services, new Facts(),
                Control, options, NullLoggerFactory.Instance, aclLayer: null, components: [])
            {
                PrimarySourceFactory = () => Primary,
                PollSourceFactory = ms => { PollInterval = ms; return Poll; },
                ProcessIds = () => Control.Paths.Keys.ToList(),   // "running" = spawned by the test
            };
            Monitor.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        public void Spawn(int pid, string path, string sid = Kid, FakeSource? via = null)
        {
            Users.Pids[pid] = sid;
            Control.Paths[pid] = path;
            (via ?? Primary).RaiseStart(pid, path);
        }

        public async Task<bool> WaitKill(int pid, int ms = 3000)
        {
            for (var i = 0; i < ms / 10; i++)
            {
                if (Control.Kills.Any(k => k.Pid == pid)) return true;
                await Task.Delay(10);
            }
            return false;
        }

        public void Dispose() => Monitor.Dispose();
    }

    [Fact]
    public async Task Block_rule_by_exe_kills_managed_process_and_reports()
    {
        using var f = new Fixture(Policy([new AppRule("block", new AppMatch(Exe: "game.exe")), AllowNotepad]));
        Assert.Equal("etw+poll", f.Monitor.SourceMode);
        Assert.True(f.PollInterval is > 0 and <= 1000);

        f.Spawn(101, Game);
        f.Spawn(102, Notepad);
        f.Spawn(103, Game, sid: Admin);   // administrator: never touched (I1/I2)

        Assert.True(await f.WaitKill(101));
        await Task.Delay(100);
        Assert.DoesNotContain(f.Control.Kills, k => k.Pid is 102 or 103);
        var blocked = Assert.Single(f.Sink.Events, e => e.Type == EventTypes.ProcessBlocked);
        Assert.Equal(Kid, blocked.Sid);
        Assert.Equal("appRules[0]", (string?)blocked.Data["rule"]);
        Assert.Contains(f.Session.Calls, c => c.StartsWith($"blocked {Kid}", StringComparison.Ordinal) && c.Contains("game.exe"));
        Assert.Equal(1, f.Monitor.BlockCount);
        Assert.Equal("appRules[0]", Assert.Single(f.Monitor.RecentBlocks()).Rule);
    }

    [Theory]
    [InlineData("path")]
    [InlineData("sha256")]
    public async Task Block_rule_by_path_or_sha256(string kind)
    {
        var match = kind == "path" ? new AppMatch(Path: @"C:\Games\**") : new AppMatch(Sha256: new string('A', 64));
        using var f = new Fixture(Policy([new AppRule("block", match), AllowNotepad]));
        f.Spawn(201, Game);
        Assert.True(await f.WaitKill(201));
    }

    [Fact]
    public async Task Pid_reported_by_both_sources_is_evaluated_once()
    {
        using var f = new Fixture(Policy([new AppRule("block", new AppMatch(Exe: "game.exe"))]));
        f.Spawn(301, Game);
        f.Poll.RaiseStart(301);
        Assert.True(await f.WaitKill(301));
        await Task.Delay(150);
        Assert.Single(f.Control.Kills, k => k.Pid == 301);

        // after the process stopped, the pid may be reused and is evaluated again
        f.Primary.RaiseStop(301);
        f.Spawn(301, Game, via: f.Poll);
        for (var i = 0; i < 300 && f.Control.Kills.Count(k => k.Pid == 301) < 2; i++) await Task.Delay(10);
        Assert.Equal(2, f.Control.Kills.Count(k => k.Pid == 301));
    }

    [Fact]
    public async Task Etw_unavailable_falls_back_to_polling_at_most_one_second_and_still_enforces()
    {
        using var f = new Fixture(Policy([new AppRule("block", new AppMatch(Exe: "game.exe"))]), etwFails: true);
        Assert.Equal("poll", f.Monitor.SourceMode);
        Assert.True(f.Primary.Disposed);
        Assert.True(f.PollInterval is > 0 and <= 1000);
        f.Spawn(401, Game, via: f.Poll);
        Assert.True(await f.WaitKill(401));
    }

    [Fact]
    public async Task Etw_dying_later_keeps_enforcing_through_the_poll()
    {
        using var f = new Fixture(Policy([new AppRule("block", new AppMatch(Exe: "game.exe"))]));
        f.Primary.RaiseFault();
        Assert.Equal("poll (etw stopped)", f.Monitor.SourceMode);
        f.Spawn(501, Game, via: f.Poll);
        Assert.True(await f.WaitKill(501));
    }

    [Fact]
    public async Task Exhausted_group_kills_on_start_and_running_members_on_sweep()
    {
        var groups = new Dictionary<string, AppGroup>
        {
            ["games"] = new("Games", [new AppMatch(Exe: "RobloxPlayerBeta.exe")], All(60)),
        };
        using var f = new Fixture(Policy([AllowRoblox, AllowNotepad], groups));

        // running and within quota: tracked, not killed
        f.Spawn(601, Roblox);
        await Task.Delay(150);
        Assert.Empty(f.Control.Kills);

        // quota runs out: the sweep kills the running member, a new start is killed immediately
        f.Engine.Exhausted = ["games"];
        Assert.True(await f.WaitKill(601));
        f.Spawn(602, Roblox);
        Assert.True(await f.WaitKill(602));
        Assert.DoesNotContain(f.Control.Kills, k => k.Path == Notepad);
        Assert.All(f.Sink.Events.Where(e => e.Type == EventTypes.ProcessBlocked), e => Assert.Equal("group:games", (string?)e.Data["rule"]));
    }

    [Fact]
    public async Task Policy_change_re_evaluates_running_processes()
    {
        using var f = new Fixture(Policy([AllowNotepad, new AppRule("allow", new AppMatch(Exe: "game.exe"))]));
        f.Spawn(701, Game);
        await Task.Delay(150);
        Assert.Empty(f.Control.Kills);

        f.Policy.Change(Policy([new AppRule("block", new AppMatch(Exe: "game.exe"))]));
        Assert.True(await f.WaitKill(701));
    }

    [Fact]
    public void Monitor_diagnostics_section_reports_source_and_rules()
    {
        using var f = new Fixture(Policy([new AppRule("block", new AppMatch(Exe: "game.exe")), AllowNotepad]));
        var section = new MonitorDiagnostics(f.Monitor, f.Policy, f.Users, new MonitoringOptions()).Collect();
        Assert.Equal("etw+poll", (string?)section["source"]);
        Assert.True((bool)section["etwRunning"]!);
        Assert.Equal(2, (int)section["rules"]![Kid]!["appRules"]!);
        Assert.Equal(1, (int)section["rules"]![Kid]!["blockRules"]!);
    }
}
