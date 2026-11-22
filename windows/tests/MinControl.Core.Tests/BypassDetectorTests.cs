using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.NetGuard;
using MinControl.NetGuard.Bypass;
using MinControl.NetGuard.Native;
using MinControl.NetGuard.Wfp;
using Xunit;

namespace MinControl.Core.Tests;

public class BypassDetectorTests
{
    private const string Kid = "S-1-5-21-1-2-3-1001";
    private const string Other = "S-1-5-21-1-2-3-1002";
    private const string Edge = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
    private const string Zalo = @"C:\Users\CK\AppData\Local\Programs\Zalo\Zalo.exe";
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 3, 0, 0, TimeSpan.Zero);

    private sealed class Users : IUserDirectory
    {
        public Dictionary<int, string> Pids { get; } = [];
        public bool IsManaged(string sid) => sid is Kid or Other;
        public bool IsAdministrator(string sid) => false;
        public IReadOnlyCollection<string> ManagedSids => [Kid, Other];
        public string? SidOfProcess(int pid) => Pids.GetValueOrDefault(pid);
        public string? ProfilePath(string sid) => null;
    }

    private sealed class Sink : IEventSink
    {
        public List<(string Type, string? Sid, JsonObject Data)> Events { get; } = [];
        public void Emit(string type, string? userSid, JsonObject data) => Events.Add((type, userSid, data));
    }

    private sealed class Table : ITcpTableSource
    {
        public List<TcpRow> Rows { get; } = [];
        public Dictionary<int, string> Paths { get; } = [];
        public List<TcpRow> Resets { get; } = [];
        public IReadOnlyList<TcpRow> Read(AddressFamily family) => Rows.Where(r => r.LocalAddress.AddressFamily == family).ToList();
        public bool TryReset(TcpRow row) { Resets.Add(row); Rows.Remove(row); return true; }
        public string? ImagePath(int pid) => Paths.GetValueOrDefault(pid);
    }

    private sealed class Fixture
    {
        public FakeClock Clock { get; } = new(T0);
        public Users Users { get; } = new();
        public Sink Sink { get; } = new();
        public Table Table { get; } = new();
        public BypassDetector Detector { get; }
        public Dictionary<string, IReadOnlyList<string>> Exempt { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Fixture()
        {
            Detector = new BypassDetector(Users, Sink, Clock, tcp: Table);
            Users.Pids[100] = Kid; Table.Paths[100] = Edge;
            Users.Pids[200] = Kid; Table.Paths[200] = Zalo;
            Users.Pids[300] = Other; Table.Paths[300] = Edge;
        }

        public void Apply(params string[] sids) =>
            Detector.OnFiltersApplied(sids.Select(s => new WfpUserRule(s, Exempt.GetValueOrDefault(s) ?? [])).ToList());

        public void Scan(Func<string, bool>? present = null) => Detector.Scan(3129, Exempt, present);

        public IEnumerable<string> Details => Sink.Events.Select(e => (string)e.Data["detail"]!);
    }

    private static TcpRow V4(string remote, int port, int pid, DateTimeOffset? created, int localPort = 50000) =>
        new(IPAddress.Parse("192.168.1.10"), localPort, IPAddress.Parse(remote), port, TcpRow.StateEstablished, pid, created);

    private static TcpRow V6(string remote, int port, int pid, DateTimeOffset? created) =>
        new(IPAddress.Parse("2001:db8::10"), 50001, IPAddress.Parse(remote), port, TcpRow.StateEstablished, pid, created);

    // ------------------------------------------------------------------ enforcement

    [Fact]
    public void Apply_resets_only_that_sids_blockable_ipv4_connections()
    {
        var f = new Fixture();
        f.Exempt[Kid] = [Zalo];
        f.Table.Rows.Add(V4("4.150.223.99", 443, 100, T0.AddMinutes(-5)));                  // kid, edge: reset
        f.Table.Rows.Add(V4("52.110.8.129", 443, 200, T0.AddMinutes(-5), 50010));           // kid, exempt app: keep
        f.Table.Rows.Add(V4("162.159.61.3", 443, 300, T0.AddMinutes(-5), 50020));           // other SID: never touched
        f.Table.Rows.Add(new TcpRow(IPAddress.Loopback, 50030, IPAddress.Loopback, 3129, TcpRow.StateEstablished, 100, T0)); // loopback
        f.Table.Rows.Add(V6("2620:1ec:c11::200", 443, 100, T0.AddMinutes(-5)));             // IPv6: cannot reset

        var r = f.Detector.OnFiltersApplied([new WfpUserRule(Kid, [Zalo])]);

        Assert.Equal(1, r.Reset);
        Assert.Equal(0, r.ResetFailed);
        Assert.Equal(1, r.Ipv6Left);
        var reset = Assert.Single(f.Table.Resets);
        Assert.Equal("4.150.223.99", reset.RemoteAddress.ToString());
    }

    [Fact]
    public void ChangedRules_are_new_sids_or_changed_exempt_sets()
    {
        var prev = new List<WfpUserRule> { new(Kid, [Zalo]), new(Other, []) };
        var next = new List<WfpUserRule> { new(Kid, [Zalo.ToUpperInvariant()]), new(Other, [Edge]), new("S-1-5-21-9", []) };
        var changed = NetGuardService.ChangedRules(prev, next).Select(r => r.Sid).ToList();
        Assert.Equal(new[] { Other, "S-1-5-21-9" }, changed);
        Assert.Equal(3, NetGuardService.ChangedRules(null, next).Count);
    }

    // ------------------------------------------------------------------ creation-time filtering

    [Fact]
    public void Startup_quiet_period_reports_nothing()
    {
        var f = new Fixture();
        f.Apply(Kid);
        f.Table.Rows.Add(V4("4.150.223.99", 443, 100, T0.AddSeconds(20)));
        f.Clock.Advance(TimeSpan.FromSeconds(30));
        f.Scan();
        Assert.Empty(f.Sink.Events);
        f.Clock.Advance(TimeSpan.FromSeconds(31));
        f.Scan();
        Assert.Single(f.Sink.Events);
    }

    [Fact]
    public void Connections_created_before_apply_or_within_grace_are_ignored()
    {
        var f = new Fixture();
        f.Apply(Kid);
        f.Table.Rows.Add(V6("2620:1ec:c11::200", 443, 100, T0.AddMinutes(-3)));        // pre-existing IPv6, left open
        f.Table.Rows.Add(V4("150.171.28.11", 443, 100, T0.AddSeconds(9), 50002));       // inside 10 s grace
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        f.Scan();
        Assert.Empty(f.Sink.Events);

        f.Table.Rows.Add(V4("4.150.223.99", 443, 100, T0.AddSeconds(11), 50003));       // after grace: real
        f.Scan();
        var e = Assert.Single(f.Sink.Events);
        Assert.Equal(EventTypes.TamperProxyBypassAttempt, e.Type);
        Assert.Equal(Kid, e.Sid);
        Assert.Equal("msedge.exe", (string)e.Data["exe"]!);
        Assert.Equal("Kết nối thẳng ra Internet không qua bộ lọc: msedge.exe → 4.150.223.99:443", (string)e.Data["detail"]!);
    }

    [Fact]
    public void Reapply_moves_the_cutoff()
    {
        var f = new Fixture();
        f.Apply(Kid);
        f.Clock.Advance(TimeSpan.FromMinutes(5));
        f.Table.Rows.Add(V6("2620:1ec:c11::200", 443, 100, f.Clock.UtcNow.AddSeconds(-1)));
        f.Apply(Kid);                                   // e.g. exempt apps changed
        f.Clock.Advance(TimeSpan.FromMinutes(1));
        f.Scan();
        Assert.Empty(f.Sink.Events);
    }

    [Fact]
    public void Sid_without_applied_filters_is_never_reported()
    {
        var f = new Fixture();
        f.Apply(Kid);
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        f.Table.Rows.Add(V4("4.150.223.99", 443, 300, f.Clock.UtcNow));   // Other: no filters of ours
        f.Scan();
        Assert.Empty(f.Sink.Events);
    }

    [Fact]
    public void Fallback_without_creation_time_uses_first_seen()
    {
        var f = new Fixture();
        f.Table.Rows.Add(V6("2620:1ec:c11::200", 443, 100, null));    // open before the lock, no timestamp
        f.Apply(Kid);
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        f.Scan();
        Assert.Empty(f.Sink.Events);

        f.Table.Rows.Add(V4("4.150.223.99", 443, 100, null, 50009));  // first seen now (> apply + grace)
        f.Scan();
        Assert.Single(f.Sink.Events);
        Assert.Contains("4.150.223.99:443", f.Details.Single());
    }

    // ------------------------------------------------------------------ verify before accusing

    [Fact]
    public void Missing_filters_are_not_reported_as_bypass()
    {
        var f = new Fixture();
        f.Apply(Kid);
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        f.Table.Rows.Add(V4("4.150.223.99", 443, 100, f.Clock.UtcNow));
        var asked = 0;
        f.Scan(sid => { asked++; return false; });
        Assert.Empty(f.Sink.Events);
        Assert.Equal(1, asked);
        f.Scan(_ => true);
        Assert.Single(f.Sink.Events);
    }

    [Fact]
    public void Verify_is_not_called_when_there_is_nothing_to_report()
    {
        var f = new Fixture();
        f.Apply(Kid);
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        f.Scan(_ => throw new InvalidOperationException("must not verify"));
        Assert.Empty(f.Sink.Events);
    }

    // ------------------------------------------------------------------ aggregation

    [Fact]
    public void Burst_is_aggregated_per_sid_and_exe_with_count()
    {
        var f = new Fixture();
        f.Apply(Kid);
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        var t = f.Clock.UtcNow;
        f.Table.Rows.Add(V4("4.150.223.99", 443, 100, t, 50100));
        f.Table.Rows.Add(V4("52.110.8.129", 443, 100, t, 50101));
        f.Table.Rows.Add(V4("162.159.61.3", 443, 100, t, 50102));
        f.Table.Rows.Add(V6("2620:1ec:c11::200", 443, 100, t));
        f.Table.Rows.Add(V4("150.171.28.11", 443, 200, t, 50103));    // different exe -> own event
        f.Scan();

        Assert.Equal(2, f.Sink.Events.Count);
        Assert.Contains("Kết nối thẳng ra Internet không qua bộ lọc: msedge.exe → 4.150.223.99:443 (+3 kết nối khác)", f.Details);
        Assert.Contains("Kết nối thẳng ra Internet không qua bộ lọc: Zalo.exe → 150.171.28.11:443", f.Details);
    }

    [Fact]
    public void Repeats_within_window_are_suppressed_and_counted_into_the_next_event()
    {
        var f = new Fixture();
        f.Apply(Kid);
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        f.Table.Rows.Add(V4("4.150.223.99", 443, 100, f.Clock.UtcNow, 50100));
        f.Scan();
        Assert.Single(f.Sink.Events);

        // Same connection still open + 2 new ones within 10 minutes: no new event.
        for (var i = 0; i < 2; i++)
        {
            f.Clock.Advance(TimeSpan.FromSeconds(30));
            f.Table.Rows.Add(V4("52.110.8.129", 443, 100, f.Clock.UtcNow, 50200 + i));
            f.Scan();
        }
        Assert.Single(f.Sink.Events);

        // Unchanged after the window: still-open, already counted connections are not re-reported...
        f.Clock.Advance(TimeSpan.FromMinutes(10));
        f.Table.Rows.Add(V4("162.159.61.3", 443, 100, f.Clock.UtcNow, 50300));
        f.Scan();
        Assert.Equal(2, f.Sink.Events.Count);
        // ...the next event carries the new one plus the 2 suppressed ones.
        Assert.Equal("Kết nối thẳng ra Internet không qua bộ lọc: msedge.exe → 162.159.61.3:443 (+2 kết nối khác)", f.Details.Last());

        f.Clock.Advance(TimeSpan.FromMinutes(11));
        f.Scan();
        Assert.Equal(2, f.Sink.Events.Count);   // nothing new
    }

    // ------------------------------------------------------------------ formatting

    [Fact]
    public void Messages_are_vietnamese_and_human()
    {
        Assert.Equal("Kết nối thẳng ra Internet không qua bộ lọc: msedge.exe → 4.150.223.99:443 (+3 kết nối khác)",
            BypassDetector.FormatDirect("msedge.exe", "4.150.223.99:443", 3));
        Assert.Equal("Kết nối thẳng ra Internet không qua bộ lọc: a.exe → 1.2.3.4:80", BypassDetector.FormatDirect("a.exe", "1.2.3.4:80", 0));
        Assert.Equal("[2620:1ec:c11::200]:443", BypassDetector.Endpoint(IPAddress.Parse("2620:1ec:c11::200"), 443));
        Assert.Equal("4.150.223.99:443", BypassDetector.Endpoint(IPAddress.Parse("::ffff:4.150.223.99"), 443));
        Assert.StartsWith("Phát hiện proxy/VPN cục bộ: clash.exe đang mở cổng 7890", BypassDetector.FormatListener("clash.exe", 7890));
        Assert.Equal("Xuất hiện card mạng VPN/đường hầm mới: WireGuard Tunnel (wg0)", BypassDetector.FormatAdapter("WireGuard Tunnel", "wg0"));
    }

    [Fact]
    public void Listener_report_is_vietnamese_with_exe_and_deduped()
    {
        var f = new Fixture();
        f.Table.Rows.Add(new TcpRow(IPAddress.Any, 7890, IPAddress.Any, 0, TcpRow.StateListen, 200));
        f.Table.Rows.Add(new TcpRow(IPAddress.Loopback, 3129, IPAddress.Any, 0, TcpRow.StateListen, 200));   // our proxy port
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        f.Scan();
        f.Scan();
        var e = Assert.Single(f.Sink.Events);
        Assert.Equal("Zalo.exe", (string)e.Data["exe"]!);
        Assert.StartsWith("Phát hiện proxy/VPN cục bộ: Zalo.exe đang mở cổng 7890", (string)e.Data["detail"]!);
    }
}
