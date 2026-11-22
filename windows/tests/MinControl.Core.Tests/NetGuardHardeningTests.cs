using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policy;
using MinControl.NetGuard;
using MinControl.NetGuard.Proxy;
using MinControl.NetGuard.Telemetry;
using MinControl.NetGuard.Web;
using MinControl.NetGuard.Wfp;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>Live tunnel re-evaluation in <see cref="FilteringProxy"/> and the WFP filter plan as data.</summary>
public class NetGuardHardeningTests
{
    private const string Kid = TestData.Sid;
    private const string Admin = TestData.AdminSid;
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 5, 0, 0, TimeSpan.Zero);

    // ================================================================== live tunnels

    private sealed class Policies : IPolicyProvider
    {
        public DevicePolicy? Current { get; set; }
        public event EventHandler<DevicePolicy>? PolicyChanged;
        public void Change(DevicePolicy p) { Current = p; PolicyChanged?.Invoke(this, p); }
    }

    private sealed class Sink : IEventSink
    {
        public List<(string Type, string? Sid, JsonObject Data)> Events { get; } = [];
        public void Emit(string type, string? userSid, JsonObject data) { lock (Events) Events.Add((type, userSid, data)); }
    }

    private sealed class Notifier : IBlockNotifier
    {
        public List<string> Hosts { get; } = [];
        public void NotifyWebBlocked(string sid, string host, WebDecision decision) { lock (Hosts) Hosts.Add($"{sid}|{host}"); }
    }

    private static WeekdayMap<T> All<T>(T v) => new(v, v, v, v, v, v, v);

    private static DevicePolicy Policy(string[]? blockDomains = null, string youtube = "off", string[]? blockedCategories = null) =>
        new(6, "Asia/Ho_Chi_Minh", new Dictionary<string, UserPolicy>
        {
            [Kid] = new UserPolicy("Kid",
                new ScreenTimePolicy(All(120), All<IReadOnlyList<string>>(["00:00-23:59"]), [5], 60, false, 300),
                new Dictionary<string, AppGroup>(), [], "allow",
                new WebPolicy("blocklist", blockedCategories ?? [], blockDomains ?? [], [], false, youtube, ["msedge.exe"], []),
                new MonitoringPolicy(false, false, true, false, false, new ScreenshotPolicy(5, true, 1280, 60))),
        }, new RetentionDays(30, 30, 7));

    private sealed class ProxyFixture
    {
        public FakeClock Clock { get; } = new(T0);
        public FakeUserDirectory Users { get; } = new();
        public Policies Policy { get; } = new();
        public Sink Sink { get; } = new();
        public Notifier Notifier { get; } = new();
        public FilteringProxy Proxy { get; }
        public Dictionary<long, int> Aborts { get; } = [];

        public ProxyFixture()
        {
            Users.Admins.Add(Admin);
            var options = new NetGuardOptions { CategoriesDirectory = Path.Combine(Path.GetTempPath(), "mc-none-" + Guid.NewGuid().ToString("N")) };
            var categories = new CategoryIndex([new("video", ["youtube.com"]), new("games", ["roblox.com"])]);
            Proxy = new FilteringProxy(options, Users, Policy, Sink, Clock, new WebDecisionEngine(categories, options),
                new CallerIdentifier(Users, Clock), new DomainAggregator(Sink, Clock, options), notifier: Notifier);
        }

        public LiveTunnel Open(string sid, string host, string exe = "msedge.exe", string? connectHost = null)
        {
            LiveTunnel? t = null;
            t = Proxy.Tunnels.Register(sid, host, exe, 443, true, connectHost ?? host, Clock.UtcNow, () =>
            {
                lock (Aborts) Aborts[t!.Id] = Aborts.GetValueOrDefault(t!.Id) + 1;
            });
            return t;
        }

        public int AbortCount(LiveTunnel t) { lock (Aborts) return Aborts.GetValueOrDefault(t.Id); }
    }

    [Fact]
    public void Policy_change_closes_live_tunnels_that_are_now_blocked_and_only_those()
    {
        var f = new ProxyFixture();
        f.Policy.Current = Policy();
        var yt = f.Open(Kid, "www.youtube.com");
        var video = f.Open(Kid, "rr3---sn-8qj-nbo6.googlevideo.com");
        var news = f.Open(Kid, "vnexpress.net");
        var adminYt = f.Open(Admin, "www.youtube.com");   // not managed: never touched (I1)

        Assert.Equal((0, 0), f.Proxy.ReevaluateTunnels());
        Assert.Equal(0, f.AbortCount(yt));

        f.Policy.Current = Policy(blockDomains: ["*.youtube.com", "*.googlevideo.com"]);
        var (blocked, rerouted) = f.Proxy.ReevaluateTunnels("policy");

        Assert.Equal(2, blocked);
        Assert.Equal(0, rerouted);
        Assert.Equal(1, f.AbortCount(yt));
        Assert.Equal(1, f.AbortCount(video));
        Assert.Equal(0, f.AbortCount(news));
        Assert.Equal(0, f.AbortCount(adminYt));
        Assert.True(yt.Closed);

        var webBlocked = f.Sink.Events.Where(e => e.Type == EventTypes.WebBlocked).ToList();
        Assert.Equal(2, webBlocked.Count);
        Assert.All(webBlocked, e => Assert.Equal(Kid, e.Sid));
        Assert.Contains(webBlocked, e => (string?)e.Data["host"] == "www.youtube.com" && (string?)e.Data["reason"] == BlockReasons.Blocklist
                                          && (string?)e.Data["source"] == "proxy" && e.Data["url"] is null);
        Assert.Contains($"{Kid}|www.youtube.com", f.Notifier.Hosts);

        // closed tunnels are not closed (nor reported) twice
        Assert.Equal((0, 0), f.Proxy.ReevaluateTunnels("periodic"));
        Assert.Equal(1, f.AbortCount(yt));
    }

    [Fact]
    public async Task PolicyChanged_event_triggers_re_evaluation()
    {
        var f = new ProxyFixture();
        f.Policy.Current = Policy();
        var game = f.Open(Kid, "www.roblox.com");
        f.Policy.Change(Policy(blockedCategories: ["games"]));

        for (var i = 0; i < 200 && f.AbortCount(game) == 0; i++) await Task.Delay(10);
        Assert.Equal(1, f.AbortCount(game));
        var e = Assert.Single(f.Sink.Events, e => e.Type == EventTypes.WebBlocked);
        Assert.Equal("category", (string?)e.Data["reason"]);
        Assert.Equal("games", (string?)e.Data["category"]);
    }

    [Fact]
    public void Rewrite_target_change_closes_tunnel_without_web_blocked()
    {
        var f = new ProxyFixture();
        f.Policy.Current = Policy();
        var yt = f.Open(Kid, "www.youtube.com");
        f.Policy.Current = Policy(youtube: "strict");

        Assert.Equal((0, 1), f.Proxy.ReevaluateTunnels());
        Assert.Equal(1, f.AbortCount(yt));
        Assert.DoesNotContain(f.Sink.Events, e => e.Type == EventTypes.WebBlocked);

        // a tunnel already connected to the strict host stays
        var strict = f.Open(Kid, "www.youtube.com", connectHost: SafeSearchMap.YoutubeStrict);
        Assert.Equal((0, 0), f.Proxy.ReevaluateTunnels());
        Assert.Equal(0, f.AbortCount(strict));
    }

    [Fact]
    public void No_policy_fails_closed_for_managed_tunnels()
    {
        var f = new ProxyFixture();
        var t = f.Open(Kid, "example.org");
        var admin = f.Open(Admin, "example.org");
        f.Policy.Current = null;
        Assert.Equal(1, f.Proxy.ReevaluateTunnels().Blocked);
        Assert.Equal(1, f.AbortCount(t));
        Assert.Equal(0, f.AbortCount(admin));
    }

    [Fact]
    public void Registry_snapshot_skips_removed_and_closed()
    {
        var reg = new TunnelRegistry();
        var a = reg.Register(Kid, "a.com", "x.exe", 443, true, "a.com", T0, () => { });
        var b = reg.Register(Kid, "b.com", "x.exe", 443, true, "b.com", T0, () => { });
        reg.Register(Kid, "c.com", "x.exe", 443, true, "c.com", T0, () => throw new InvalidOperationException("socket gone"));
        reg.Remove(a);
        Assert.True(b.TryClose());
        Assert.False(b.TryClose());
        Assert.Equal(["c.com"], reg.Snapshot().Select(t => t.Host));
        Assert.True(reg.Snapshot()[0].TryClose());   // a throwing abort is swallowed
    }

    // ================================================================== WFP filter plan

    private static readonly Guid[] AllLayers =
    [
        FwpGuids.LayerAleAuthConnectV4, FwpGuids.LayerAleAuthConnectV6, FwpGuids.LayerAleAuthRecvAcceptV4, FwpGuids.LayerAleAuthRecvAcceptV6,
    ];

    [Fact]
    public void Plan_has_loopback_permit_app_permit_and_hard_block_on_every_ale_layer()
    {
        const string app = @"C:\Program Files\Zoom\bin\Zoom.exe";
        var plan = WfpFilterPlan.Build(new WfpUserRule(Kid, [app]));

        Assert.Equal(12, plan.Count);
        Assert.Equal(AllLayers.OrderBy(g => g), plan.Select(f => f.Layer).Distinct().OrderBy(g => g));
        Assert.Equal(plan.Count, plan.Select(f => f.Key).Distinct().Count());

        foreach (var layer in AllLayers)
        {
            var onLayer = plan.Where(f => f.Layer == layer).ToList();
            var block = Assert.Single(onLayer, f => f.Kind == "block");
            Assert.Equal(FwpConst.FWP_ACTION_BLOCK, block.Action);
            Assert.Equal(0x1001u, block.Action);
            Assert.Equal(0, block.Weight);
            Assert.Equal(FwpConst.FWPM_FILTER_FLAG_PERSISTENT | FwpConst.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, block.Flags);
            var user = Assert.Single(block.Conditions);   // nothing but the user: every protocol, every port, every address
            AssertUserCondition(user);

            var loop = Assert.Single(onLayer, f => f.Kind == "loopback");
            Assert.Equal(FwpConst.FWP_ACTION_PERMIT, loop.Action);
            Assert.Equal(15, loop.Weight);
            Assert.Equal(FwpConst.FWPM_FILTER_FLAG_PERSISTENT, loop.Flags);   // soft permit: other providers may still block
            Assert.Equal(2, loop.Conditions.Count);
            AssertUserCondition(loop.Conditions[0]);
            Assert.Equal(FwpGuids.ConditionFlags, loop.Conditions[1].FieldKey);
            Assert.Equal(FwpConst.FWP_MATCH_FLAGS_ALL_SET, loop.Conditions[1].MatchType);
            Assert.Equal(FwpConst.FWP_UINT32, loop.Conditions[1].ValueType);
            Assert.Equal("1", loop.Conditions[1].Value);   // FWP_CONDITION_FLAG_IS_LOOPBACK

            var permitApp = Assert.Single(onLayer, f => f.Kind == "app");
            Assert.Equal(14, permitApp.Weight);
            Assert.Equal(app, permitApp.AppPath);
            Assert.Equal(FwpGuids.ConditionAleAppId, permitApp.Conditions[1].FieldKey);
            Assert.Equal(FwpConst.FWP_BYTE_BLOB_TYPE, permitApp.Conditions[1].ValueType);
            AssertUserCondition(permitApp.Conditions[0]);
        }

        // the only permits are loopback and the exempt app
        Assert.All(plan.Where(f => !f.IsBlock), f => Assert.Contains(f.Kind, new[] { "loopback", "app" }));
        Assert.Equal(WfpManager.ExpectedKeys(new WfpUserRule(Kid, [app])), plan.Select(f => f.Key));
    }

    private static void AssertUserCondition(WfpConditionSpec c)
    {
        Assert.Equal(FwpGuids.ConditionAleUserId, c.FieldKey);
        Assert.Equal(new Guid("af043a0a-b34d-4f86-979c-c90371af6e66"), c.FieldKey);
        Assert.Equal(FwpConst.FWP_MATCH_EQUAL, c.MatchType);
        Assert.Equal(FwpConst.FWP_SECURITY_DESCRIPTOR_TYPE, c.ValueType);
        Assert.Equal(14u, c.ValueType);
        Assert.Equal(WfpFilterPlan.UserSddl(Kid), c.Value);
    }

    [Fact]
    public void User_sd_grants_match_to_the_sid_and_to_appcontainer_and_restricted_token_passes()
    {
        var sddl = WfpFilterPlan.UserSddl(Kid);
        Assert.StartsWith("O:SYG:SYD:", sddl);
        Assert.Contains($"(A;;CC;;;{Kid})", sddl);           // pass 1: the managed user's token
        Assert.Contains("(A;;CC;;;AC)", sddl);               // AppContainer pass (ALL APPLICATION PACKAGES)
        Assert.Contains("(A;;CC;;;S-1-15-2-2)", sddl);       // LPAC pass (ALL RESTRICTED APPLICATION PACKAGES)
        Assert.Contains("(A;;CC;;;RC)", sddl);               // restricted-token pass
        Assert.Contains("(A;;CC;;;WR)", sddl);               // write-restricted token
        Assert.DoesNotContain(";;;WD)", sddl);               // never Everyone / Users / Authenticated Users
        Assert.DoesNotContain(";;;BU)", sddl);
        Assert.DoesNotContain(";;;AU)", sddl);
        Assert.Equal(Kid, WfpManager.FirstAceSid(sddl));

        // The SDDL must parse (advapi32 string → SD conversion only, no WFP call).
        Assert.True(WfpNative.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var sd, out var size));
        try { Assert.True(size > 40); }
        finally { WfpNative.LocalFree(sd); }
    }

    [Theory]
    [InlineData("")]
    [InlineData("S-1-5-21-1)(A;;CC;;;WD")]
    [InlineData("WD")]
    [InlineData("S-1-5-21-1;2")]
    public void Plan_rejects_invalid_sid(string sid) =>
        Assert.Throws<ArgumentException>(() => WfpFilterPlan.Build(new WfpUserRule(sid, [])));

    [Fact]
    public void Plan_skips_exempt_apps_without_app_id_and_keys_are_revisioned()
    {
        var rule = new WfpUserRule(Kid, [@"C:\a.exe", @"C:\b.exe"]);
        var plan = WfpFilterPlan.Build(rule, usableApps: [@"C:\b.exe"]);
        Assert.Equal(4, plan.Count(f => f.Kind == "app"));
        Assert.All(plan.Where(f => f.Kind == "app"), f => Assert.Equal(@"C:\b.exe", f.AppPath));

        // keys are case-insensitive in SID/app and differ per layer/kind
        Assert.Equal(WfpFilterPlan.FilterKey(Kid, AllLayers[0], "block", null), WfpFilterPlan.FilterKey(Kid.ToLowerInvariant(), AllLayers[0], "block", null));
        Assert.NotEqual(WfpFilterPlan.FilterKey(Kid, AllLayers[0], "block", null), WfpFilterPlan.FilterKey(Kid, AllLayers[1], "block", null));
        Assert.Equal("v2", WfpFilterPlan.Revision);
    }

    [Fact]
    public void Wfp_native_layouts_match_the_x64_c_definitions()
    {
        if (IntPtr.Size != 8) return;
        Assert.Equal(16, Marshal.SizeOf<FWP_VALUE0>());
        Assert.Equal(8, (int)Marshal.OffsetOf<FWP_VALUE0>(nameof(FWP_VALUE0.uint64)));
        Assert.Equal(16, Marshal.SizeOf<FWP_BYTE_BLOB>());
        Assert.Equal(40, Marshal.SizeOf<FWPM_FILTER_CONDITION0>());
        Assert.Equal(24, (int)Marshal.OffsetOf<FWPM_FILTER_CONDITION0>(nameof(FWPM_FILTER_CONDITION0.conditionValue)));
        Assert.Equal(20, Marshal.SizeOf<FWPM_ACTION0>());
        Assert.Equal(64, Marshal.SizeOf<FWPM_PROVIDER0>());
        Assert.Equal(72, Marshal.SizeOf<FWPM_SUBLAYER0>());
        Assert.Equal(64, (int)Marshal.OffsetOf<FWPM_SUBLAYER0>(nameof(FWPM_SUBLAYER0.weight)));

        Assert.Equal(200, Marshal.SizeOf<FWPM_FILTER0>());
        (string Field, int Offset)[] expected =
        [
            ("filterKey", 0), ("displayData", 16), ("flags", 32), ("providerKey", 40), ("providerData", 48), ("layerKey", 64),
            ("subLayerKey", 80), ("weight", 96), ("numFilterConditions", 112), ("filterCondition", 120), ("action", 128),
            ("context", 152), ("reserved", 168), ("filterId", 176), ("effectiveWeight", 184),
        ];
        foreach (var (field, offset) in expected)
            Assert.True(offset == (int)Marshal.OffsetOf<FWPM_FILTER0>(field), $"{field}: {Marshal.OffsetOf<FWPM_FILTER0>(field)} != {offset}");

        // WFP enum / flag values
        Assert.Equal(12u, FwpConst.FWP_BYTE_BLOB_TYPE);
        Assert.Equal(3u, FwpConst.FWP_UINT32);
        Assert.Equal(6u, FwpConst.FWP_MATCH_FLAGS_ALL_SET);
        Assert.Equal(0x1002u, FwpConst.FWP_ACTION_PERMIT);
        Assert.Equal(0x8u, FwpConst.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT);
        Assert.Equal(new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), FwpGuids.LayerAleAuthConnectV4);
        Assert.Equal(new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), FwpGuids.LayerAleAuthRecvAcceptV4);
        Assert.Equal(new Guid("632ce23b-5167-435c-86d7-e903684aa80c"), FwpGuids.ConditionFlags);
        Assert.Equal(new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971"), FwpGuids.ConditionAleAppId);
    }
}
