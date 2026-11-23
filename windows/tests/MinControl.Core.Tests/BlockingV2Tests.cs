using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Browser.Policy;
using MinControl.Core.Abstractions;
using MinControl.Core.Catalog;
using MinControl.Core.Events;
using MinControl.Core.Policies;
using MinControl.Core.Policy;
using MinControl.Core.Storage;
using MinControl.Core.Telemetry;
using MinControl.Monitoring.Rules;
using MinControl.NetGuard.Proxy;
using MinControl.NetGuard.Web;
using MinControl.Service.Logic;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>API.md §17: app allowlist mode, services, YouTube coverage, folded block events, expected service stops.</summary>
public sealed class BlockingV2Tests
{
    private const string Sid = "S-1-5-21-1-2-3-1001";
    private const string Win = @"C:\Windows";

    internal static readonly ServiceCatalog Catalog = ServiceCatalog.Parse("""
    {"version":3,"services":[
      {"id":"youtube","name":"YouTube","category":"video","domains":["*.youtube.com","*.youtu.be","*.ytimg.com","*.googlevideo.com","*.youtubei.googleapis.com","*.youtube-nocookie.com"],"apps":[]},
      {"id":"tiktok","name":"TikTok","category":"video","domains":["*.tiktok.com","*.tiktokcdn.com"],"apps":[{"exe":"TikTok.exe"}]},
      {"id":"zalo","name":"Zalo","category":"chat","domains":["*.zalo.me","*.zadn.vn"],"apps":[{"exe":"Zalo.exe"}]},
      {"id":"roblox","name":"Roblox","category":"games","domains":["*.roblox.com","*.rbxcdn.com"],"apps":[{"exe":"RobloxPlayerBeta.exe"}]},
      {"id":"steam","name":"Steam","category":"games","domains":["*.steampowered.com"],"apps":[{"exe":"steam.exe"},{"publisher":"Valve*"}]}
    ]}
    """);

    private sealed class Facts : IFileFacts
    {
        public readonly Dictionary<string, SignatureInfo> Sig = new(StringComparer.OrdinalIgnoreCase);
        public string? Sha256(string path) => null;
        public SignatureInfo Signature(string path) => Sig.GetValueOrDefault(path) ?? SignatureInfo.Unsigned;
        public long? SizeBytes(string path) => 1;
    }

    private sealed class Sink : IEventSink
    {
        public readonly List<(string Type, string? Sid, JsonObject Data)> Events = [];
        public void Emit(string type, string? userSid, JsonObject data) { lock (Events) Events.Add((type, userSid, data)); }
    }

    private static WeekdayMap<T> All<T>(T v) => new(v, v, v, v, v, v, v);

    internal static UserPolicy User(string appMode = "blocklist", IReadOnlyList<AppRule>? rules = null, string webMode = "blocklist",
        string[]? blockedCategories = null, string[]? blockDomains = null, string[]? allowDomains = null,
        string[]? blockedServices = null, string[]? allowedServices = null, string youtube = "off", KeywordPolicy? keywords = null,
        string newExecutable = "allow") =>
        new("Bin",
            new ScreenTimePolicy(All(120), All<IReadOnlyList<string>>(["00:00-23:59"]), [5], 60, false, 300),
            new Dictionary<string, AppGroup>(), rules ?? [], newExecutable,
            new WebPolicy(webMode, blockedCategories ?? [], blockDomains ?? [], allowDomains ?? [], false, youtube,
                ["msedge.exe", "chrome.exe"], [], null, blockedServices, allowedServices),
            new MonitoringPolicy(true, true, true, true, true, new ScreenshotPolicy(5, true, 1280, 60)),
            appMode, keywords);

    private static EvaluationContext Ctx() => new()
    {
        Sid = Sid,
        ProfilePath = @"C:\Users\bin",
        ExtraUserWritableRoots = [@"C:\Windows\Temp", @"C:\Users\Public"],
        WindowsDir = Win,
        OwnInstallDir = @"C:\Program Files\MinControl",
        ProgramFilesDir = @"C:\Program Files",
        IsUserWritableByAcl = p => p.StartsWith(@"C:\Windows\Tasks\", StringComparison.OrdinalIgnoreCase),
    };

    // ------------------------------------------------------------------ 1. app allowlist mode

    [Fact]
    public void Allowlist_mode_runs_the_system_set_and_allowed_apps_only()
    {
        var facts = new Facts();
        const string search = @"C:\Program Files\WindowsApps\MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy\SearchHost.exe";
        const string fakeShell = @"C:\Program Files\WindowsApps\MicrosoftWindows.Client.CBS_1000.26100.1.0_x64__cw5n1h2txyewy\evil.exe";
        facts.Sig[search] = new SignatureInfo(true, "Microsoft Windows");
        var ev = new AppRuleEvaluator(facts, Catalog);
        var user = User("allowlist", rules: [new AppRule("allow", new AppMatch(Exe: "chrome.exe"))], allowedServices: ["steam"],
            newExecutable: "allow");
        var ctx = Ctx();

        Assert.Equal(new RuleDecision(Verdict.Allow, "system"), ev.Evaluate(user, @"C:\Windows\System32\notepad.exe", ctx));
        Assert.Equal(new RuleDecision(Verdict.Allow, "system"), ev.Evaluate(user, @"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe", ctx));
        Assert.Equal(new RuleDecision(Verdict.Allow, "system"), ev.Evaluate(user, @"C:\Windows\WinSxS\amd64_x\tool.exe", ctx));
        Assert.Equal(new RuleDecision(Verdict.Allow, "system"), ev.Evaluate(user, @"C:\Program Files\MinControl\MinControl.Session.exe", ctx));
        Assert.Equal(new RuleDecision(Verdict.Allow, "system"), ev.Evaluate(user, search, ctx));
        Assert.Equal("appRules", ev.Evaluate(user, @"C:\Program Files\Google\Chrome\Application\chrome.exe", ctx).Rule);
        var steam = ev.Evaluate(user, @"C:\Program Files (x86)\Steam\steam.exe", ctx);
        Assert.Equal((Verdict.Allow, "service:steam", "steam"), (steam.Verdict, steam.Rule, steam.Service));

        // everything else is blocked, including user-writable corners of %windir% and unsigned exes in shell packages
        Assert.Equal(new RuleDecision(Verdict.Block, "appMode:allowlist"), ev.Evaluate(user, @"C:\Games\game.exe", ctx));
        Assert.Equal(new RuleDecision(Verdict.Block, "appMode:allowlist"), ev.Evaluate(user, @"C:\Windows\Temp\game.exe", ctx));
        Assert.Equal(new RuleDecision(Verdict.Block, "appMode:allowlist"), ev.Evaluate(user, @"C:\Windows\Tasks\game.exe", ctx));
        Assert.Equal(new RuleDecision(Verdict.Block, "appMode:allowlist"), ev.Evaluate(user, fakeShell, ctx));
        Assert.Equal(new RuleDecision(Verdict.Block, "appMode:allowlist"), ev.Evaluate(user, @"C:\Users\bin\Downloads\x.exe", ctx));
        Assert.Equal(new RuleDecision(Verdict.Block, "appMode:allowlist"), ev.Evaluate(user, @"C:\Program Files\WindowsApps\SpotifyAB.SpotifyMusic_1.0_x64__zpdnekdrzrea0\Spotify.exe", ctx));
    }

    [Fact]
    public void Blocklist_mode_is_unchanged_and_newExecutable_only_applies_there()
    {
        var ev = new AppRuleEvaluator(new Facts(), Catalog);
        var block = User("blocklist", newExecutable: "block");
        Assert.Equal(RuleDecision.DefaultAllow, ev.Evaluate(block, @"C:\Games\game.exe", Ctx()));
        Assert.Equal("newExecutable", ev.Evaluate(block, @"C:\Users\bin\Downloads\x.exe", Ctx()).Rule);
        var allow = User("allowlist", rules: [new AppRule("allow", new AppMatch(Path: @"C:\Users\bin\Downloads\x.exe"))], newExecutable: "block");
        Assert.Equal(Verdict.Allow, allow.IsAppAllowlist ? ev.Evaluate(allow, @"C:\Users\bin\Downloads\x.exe", Ctx()).Verdict : Verdict.Block);
    }

    [Fact]
    public void Policy_validator_rules_for_allowlist_and_services()
    {
        var dp = (UserPolicy u) => new DevicePolicy(1, "Asia/Ho_Chi_Minh", new Dictionary<string, UserPolicy> { [Sid] = u }, new RetentionDays(30, 30, 30));
        Assert.Contains(PolicyValidator.Validate(dp(User("allowlist"))), e => e.Contains("appMode allowlist"));
        Assert.Empty(PolicyValidator.Validate(dp(User("allowlist", allowedServices: ["steam"]))));
        Assert.Contains(PolicyValidator.Validate(dp(User(blockedServices: ["tiktok", "youtube"], allowedServices: ["youtube"]))),
            e => e.Contains("both blocked and allowed"));
        Assert.Empty(PolicyValidator.Validate(dp(User(webMode: "allowlist", allowedServices: ["youtube"]))));
    }

    [Fact]
    public void Policy_v2_fields_round_trip_through_the_strict_parser_options()
    {
        var u = User("allowlist", rules: [new AppRule("allow", new AppMatch(Exe: "chrome.exe"))], blockedServices: ["tiktok"],
            keywords: new KeywordPolicy(["cờ bạc"], true, false));
        var json = JsonSerializer.Serialize(u, Protocol.ProtocolJson.Options);
        var back = JsonSerializer.Deserialize<UserPolicy>(json, PolicyParser.StrictOptions)!;
        Assert.Equal("allowlist", back.AppMode);
        Assert.Equal(["tiktok"], back.Web.BlockedServices!);
        Assert.Equal("cờ bạc", back.Keywords!.Words[0]);
        // a v1 policy (no appMode / keywords / services) still parses: defaults
        var v1 = JsonNode.Parse(json)!.AsObject();
        v1.Remove("appMode"); v1.Remove("keywords"); v1["web"]!.AsObject().Remove("blockedServices");
        var old = JsonSerializer.Deserialize<UserPolicy>(v1.ToJsonString(), PolicyParser.StrictOptions)!;
        Assert.False(old.IsAppAllowlist);
        Assert.Null(old.Keywords);
        Assert.Null(old.Web.BlockedServices);
    }

    // ------------------------------------------------------------------ 2. services

    [Fact]
    public void Blocked_service_blocks_its_apps_and_domains()
    {
        var ev = new AppRuleEvaluator(new Facts(), Catalog);
        var user = User(blockedServices: ["zalo", "tiktok"]);
        var d = ev.Evaluate(user, @"C:\Users\bin\AppData\Local\Programs\Zalo\Zalo.exe", Ctx());
        Assert.Equal((Verdict.Block, "service:zalo", "zalo"), (d.Verdict, d.Rule, d.Service));
        // an explicit allow rule of the parent wins over the service switch
        var allowed = User(blockedServices: ["zalo"], rules: [new AppRule("allow", new AppMatch(Exe: "Zalo.exe"))]);
        Assert.Equal(Verdict.Allow, ev.Evaluate(allowed, @"C:\Zalo\Zalo.exe", Ctx()).Verdict);

        var engine = new WebDecisionEngine(CategoryIndex.Empty, null, Catalog);
        var w = engine.Decide(user.Web, "chat.zalo.me", DateTimeOffset.UtcNow, null);
        Assert.Equal((false, BlockReasons.Service, "zalo"), (w.Allowed, w.Reason, w.Service));
        Assert.Equal("tiktok", engine.Decide(user.Web, "v16.tiktokcdn.com", DateTimeOffset.UtcNow, null).Service);
        Assert.True(engine.Decide(user.Web, "zalo.me.evil.test", DateTimeOffset.UtcNow, null).Allowed);
    }

    [Fact]
    public void Allowed_service_opens_web_allowlist_mode()
    {
        var engine = new WebDecisionEngine(CategoryIndex.Empty, null, Catalog);
        var web = User(webMode: "allowlist", allowedServices: ["roblox"]).Web;
        Assert.True(engine.Decide(web, "www.roblox.com", DateTimeOffset.UtcNow, null).Allowed);
        Assert.True(engine.Decide(web, "tr.rbxcdn.com", DateTimeOffset.UtcNow, null).Allowed);
        Assert.Equal(BlockReasons.AllowlistMiss, engine.Decide(web, "www.tiktok.com", DateTimeOffset.UtcNow, null).Reason);
    }

    [Fact]
    public void Curated_service_domains_belong_to_their_policy_category()
    {
        Assert.Equal("video", ServiceCatalog.PolicyCategoryOf("music"));
        Assert.Equal("social", ServiceCatalog.PolicyCategoryOf("chat"));
        Assert.Equal("ai", ServiceCatalog.PolicyCategoryOf("ai"));
        Assert.Null(ServiceCatalog.PolicyCategoryOf("other"));
        var engine = new WebDecisionEngine(CategoryIndex.Empty, null, Catalog);
        var web = User(blockedCategories: ["games", "social"]).Web;
        var d = engine.Decide(web, "www.roblox.com", DateTimeOffset.UtcNow, null);
        Assert.Equal((BlockReasons.Category, "games", "roblox"), (d.Reason, d.Category, d.Service));
        Assert.Equal("social", engine.Decide(web, "chat.zalo.me", DateTimeOffset.UtcNow, null).Category);
        Assert.Contains("roblox.com", Catalog.DomainsOfPolicyCategory("games"));
    }

    // ------------------------------------------------------------------ 6. YouTube

    public static TheoryData<string> YoutubeHosts => new()
    {
        "youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be", "i.ytimg.com",
        "rr4---sn-8pxuuxa-nbo6.googlevideo.com", "youtubei.googleapis.com", "www.youtube-nocookie.com",
    };

    [Theory]
    [MemberData(nameof(YoutubeHosts))]
    public void Blocking_youtube_by_domain_service_or_category_covers_every_youtube_host(string host)
    {
        var engine = new WebDecisionEngine(CategoryIndex.Empty, null, Catalog);
        var now = DateTimeOffset.UtcNow;
        foreach (var pattern in new[] { "youtube.com", "www.youtube.com", "*.youtube.com", "youtu.be" })
        {
            var d = engine.Decide(User(blockDomains: [pattern]).Web, host, now, null);
            Assert.False(d.Allowed, $"{pattern} must block {host}");
            Assert.Equal(pattern, d.Pattern);
        }
        Assert.Equal(BlockReasons.Service, engine.Decide(User(blockedServices: ["youtube"]).Web, host, now, null).Reason);
        var cat = engine.Decide(User(blockedCategories: ["video"]).Web, host, now, null);
        Assert.Equal((BlockReasons.Category, "video"), (cat.Reason, cat.Category));
        // unrelated Google hosts stay reachable
        Assert.True(engine.Decide(User(blockDomains: ["youtube.com"]).Web, "www.googleapis.com", now, null).Allowed);
        Assert.True(engine.Decide(User(blockDomains: ["youtube.com"]).Web, "mail.google.com", now, null).Allowed);
    }

    [Theory]
    [InlineData("www.youtube.com"), InlineData("m.youtube.com"), InlineData("youtubei.googleapis.com"),
     InlineData("youtube.googleapis.com"), InlineData("www.youtube-nocookie.com"), InlineData("youtube.com")]
    public void Youtube_restricted_mode_rewrites_every_api_host_and_matches_the_browser_policy(string host)
    {
        var engine = new WebDecisionEngine(CategoryIndex.Empty, null, Catalog);
        Assert.Equal(SafeSearchMap.YoutubeStrict, engine.Decide(User(youtube: "strict").Web, host, DateTimeOffset.UtcNow, null).ConnectHost);
        Assert.Equal(SafeSearchMap.YoutubeModerate, engine.Decide(User(youtube: "moderate").Web, host, DateTimeOffset.UtcNow, null).ConnectHost);
        Assert.Equal(host, engine.Decide(User(youtube: "off").Web, host, DateTimeOffset.UtcNow, null).ConnectHost);
        // allowed through an allowlist entry or service: still restricted
        Assert.Equal(SafeSearchMap.YoutubeStrict, engine.Decide(User(webMode: "allowlist", allowedServices: ["youtube"], youtube: "strict").Web,
            host, DateTimeOffset.UtcNow, null).ConnectHost);
        Assert.Equal(2, BrowserPolicyMapper.YouTubeRestrictValue("strict"));
        Assert.Equal(1, BrowserPolicyMapper.YouTubeRestrictValue("moderate"));
        Assert.Equal(0, BrowserPolicyMapper.YouTubeRestrictValue("off"));
    }

    // ------------------------------------------------------------------ 4. block events: every attempt, folded counts

    [Fact]
    public void Folder_emits_first_attempt_then_folds_repeats_into_one_event_per_window()
    {
        var clock = new FakeClock(DateTimeOffset.UtcNow);
        var sink = new Sink();
        using var folder = new BlockEventFolder(sink, clock, TimeSpan.FromSeconds(10), autoFlush: false);
        JsonObject D(int i) => new() { ["host"] = "tiktok.com", ["i"] = i };

        Assert.True(folder.Record("web.blocked", Sid, "a", D(1)));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.False(folder.Record("web.blocked", Sid, "a", D(2)));
        Assert.False(folder.Record("web.blocked", Sid, "a", D(3)));
        Assert.True(folder.Record("web.blocked", Sid, "b", D(9)));   // other key: own window
        folder.Flush();
        Assert.Equal(2, sink.Events.Count);                          // window not over yet
        clock.Advance(TimeSpan.FromSeconds(9));
        folder.Flush();
        Assert.Equal(3, sink.Events.Count);
        var folded = sink.Events[2].Data;
        Assert.Equal(2, (int)folded["count"]!);
        Assert.Equal(3, (int)folded["i"]!);                          // latest attempt's details
        Assert.Equal(1, (int)sink.Events[0].Data["count"]!);

        // next attempt right after a flush is folded again (≤ 1 event per 10 s per key), counts add up
        Assert.False(folder.Record("web.blocked", Sid, "a", D(4)));
        clock.Advance(TimeSpan.FromSeconds(10));
        folder.Flush();
        Assert.Equal(4, sink.Events.Count);
        Assert.Equal(4, sink.Events.Where(e => (string)e.Data["host"]! == "tiktok.com" && e.Data["i"]!.GetValue<int>() != 9)
            .Sum(e => (int)e.Data["count"]!));

        // quiet period: the key is forgotten and the next attempt is immediate again
        clock.Advance(TimeSpan.FromSeconds(30));
        folder.Flush();
        Assert.True(folder.Record("web.blocked", Sid, "a", D(5)));
        Assert.False(folder.Record("web.blocked", Sid, "a", D(6)));
        folder.FlushAll();
        Assert.Equal(1, (int)sink.Events[^1].Data["count"]!);
        Assert.Equal(0, folder.PendingCount);
    }

    [Fact]
    public void Proxy_block_events_carry_action_rule_service_and_category()
    {
        var d = new WebDecision(false, BlockReasons.Category, "social", "www.tiktok.com", Service: "tiktok");
        var data = FilteringProxy.BlockedData("chrome.exe", "www.tiktok.com", null, d, Catalog);
        Assert.Equal("refused", (string)data["action"]!);
        Assert.Equal("Danh mục: Mạng xã hội (TikTok)", (string)data["rule"]!);
        Assert.Equal("tiktok", (string)data["service"]!);
        Assert.Equal("social", (string)data["category"]!);
        Assert.Equal("chrome.exe", (string)data["exe"]!);

        Assert.Equal("Dịch vụ: TikTok", BlockNoticeText.Rule(new WebDecision(false, BlockReasons.Service, null, "h", "tiktok"), Catalog));
        Assert.Equal("Danh sách chặn: *.youtube.com", BlockNoticeText.Rule(new WebDecision(false, BlockReasons.Blocklist, null, "h", Pattern: "*.youtube.com")));
        Assert.Equal("Ngoài giờ cho phép · Trò chơi", BlockNoticeText.Rule(new WebDecision(false, BlockReasons.Schedule, "games", "h")));
        Assert.Equal("Chế độ chỉ cho phép", BlockNoticeText.Rule(new WebDecision(false, BlockReasons.AllowlistMiss, null, "h")));
        Assert.Equal("Danh mục: Mạng xã hội", BlockNoticeText.Rule(new WebDecision(false, BlockReasons.Category, "social", "h")));
        AssertSchemaValidIfV2("web.blocked", data);
    }

    [Fact]
    public void Process_block_events_carry_action_rule_service_and_title()
    {
        var data = MinControl.Monitoring.AppMonitor.BlockedData(@"C:\Zalo\Zalo.exe", 4242, 100,
            new RuleDecision(Verdict.Block, "service:zalo", Service: "zalo"), null, null, false, 10, "Zalo - Tin nhắn");
        Assert.Equal("killed", (string)data["action"]!);
        Assert.Equal("service:zalo", (string)data["rule"]!);
        Assert.Equal("zalo", (string)data["service"]!);
        Assert.Equal("Zalo - Tin nhắn", (string)data["title"]!);
        Assert.Equal("Dịch vụ bị chặn: Zalo", MinControl.Monitoring.AppMonitor.BlockedReasonText("service:zalo")
            .Replace(ServiceCatalog.Shared.Find("zalo")?.Name ?? "zalo", "Zalo"));
        Assert.Equal("Chỉ được dùng các ứng dụng bố mẹ cho phép", MinControl.Monitoring.AppMonitor.BlockedReasonText("appMode:allowlist"));
        data["count"] = 1;
        AssertSchemaValidIfV2("process.blocked", data);
    }

    /// <summary>Validates against protocol/event.schema.json once it has the §17 block fields (r15-protocol).</summary>
    internal static void AssertSchemaValidIfV2(string type, JsonObject data)
    {
        if (!SchemaValidator.Shared.IsValid("event", JsonSerializer.SerializeToElement(new JsonObject
            {
                ["id"] = "01JD0000000000000000000000", ["deviceId"] = "01JD0000000000000000000001", ["userSid"] = Sid,
                ["ts"] = "2026-11-23T10:00:00Z", ["monoMs"] = 1, ["type"] = "web.blocked",
                ["data"] = new JsonObject { ["host"] = "x", ["source"] = "proxy", ["reason"] = "keyword", ["action"] = "closed_tab", ["count"] = 1 },
            })))
            return;   // schema without the v2 fields yet
        var ev = new JsonObject
        {
            ["id"] = "01JD0000000000000000000000", ["deviceId"] = "01JD0000000000000000000001", ["userSid"] = Sid,
            ["ts"] = "2026-11-23T10:00:00Z", ["monoMs"] = 1, ["type"] = type, ["data"] = data.DeepClone(),
        };
        Assert.True(SchemaValidator.Shared.IsValid("event", JsonSerializer.SerializeToElement(ev)), ev.ToJsonString());
    }

    // ------------------------------------------------------------------ 7. expected service stops

    [Fact]
    public void Service_stop_is_reported_only_when_unexpected()
    {
        Assert.True(StopClassifier.ShouldReport(osShuttingDown: false, expectedStopMarkerFresh: false));
        Assert.False(StopClassifier.ShouldReport(osShuttingDown: true, expectedStopMarkerFresh: false));
        Assert.False(StopClassifier.ShouldReport(osShuttingDown: false, expectedStopMarkerFresh: true));

        var dir = Path.Combine(Path.GetTempPath(), "mc-stop-" + Guid.NewGuid().ToString("N"));
        try
        {
            var paths = new DataPaths(dir);
            var now = new DateTimeOffset(2026, 11, 23, 10, 0, 0, TimeSpan.Zero);
            Assert.False(ExpectedStopMarker.IsFresh(paths.ExpectedStop, now));                 // no marker
            Assert.True(ExpectedStopMarker.Write(paths.ExpectedStop, "msi", now));
            Assert.Contains("\"by\":\"msi\"", File.ReadAllText(paths.ExpectedStop));
            Assert.True(ExpectedStopMarker.IsFresh(paths.ExpectedStop, now.AddMinutes(3)));
            Assert.False(ExpectedStopMarker.IsFresh(paths.ExpectedStop, now.AddMinutes(11)));  // stale
            Assert.False(ExpectedStopMarker.IsFresh(paths.ExpectedStop, now.AddMinutes(-5)));  // from the future
            File.WriteAllText(paths.ExpectedStop, "garbage");
            Assert.False(ExpectedStopMarker.IsFresh(paths.ExpectedStop, now));
            ExpectedStopMarker.Delete(paths.ExpectedStop);
            Assert.False(File.Exists(paths.ExpectedStop));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void Tamper_details_are_vietnamese()
    {
        Assert.Equal("Dịch vụ MinControl bị dừng bất thường", TamperText.ServiceStopped);
        Assert.Equal("Đồng hồ máy bị chỉnh nhanh 2 giờ 5 phút", TamperText.ClockJump(7500));
        Assert.Equal("Máy mất kết nối với MinControl trong 45 giây", TamperText.OfflineGap(45));
        Assert.Equal("Tiện ích MinControl trong Google Chrome không hoạt động (3 phút)", TamperText.ExtensionMissing("chrome", 180));
    }
}
