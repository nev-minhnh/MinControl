using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Text;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
using MinControl.NetGuard;
using MinControl.NetGuard.Categories;
using MinControl.NetGuard.Web;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>blockedCategories → CategoryUpdater (UT1 archives) → files on disk → CategoryStore → WebDecisionEngine.</summary>
public sealed class CategoryEndToEndTests : IDisposable
{
    private const string Sid = "S-1-5-21-1-2-3-1001";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mc-cat-e2e-" + Guid.NewGuid().ToString("N"));

    public CategoryEndToEndTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private static byte[] TarGz(string list, string domains)
    {
        var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gz, TarEntryFormat.Ustar, leaveOpen: true))
        {
            tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, list + "/urls") { DataStream = new MemoryStream("x.com/a\n"u8.ToArray()) });
            tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, list + "/domains") { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(domains)) });
        }
        return ms.ToArray();
    }

    private static WeekdayMap<T> All<T>(T v) => new(v, v, v, v, v, v, v);

    private static DevicePolicy PolicyWith(params string[] blocked)
    {
        var user = new UserPolicy("Bin",
            new ScreenTimePolicy(All(120), All<IReadOnlyList<string>>(["00:00-23:59"]), [5], 60, false, 300),
            new Dictionary<string, AppGroup>(), [], "allow",
            new WebPolicy("blocklist", blocked, [], [], true, "off", ["msedge.exe"], []),
            new MonitoringPolicy(true, true, true, true, true, new ScreenshotPolicy(5, true, 1280, 60)));
        return new DevicePolicy(1, "Asia/Ho_Chi_Minh", new Dictionary<string, UserPolicy> { [Sid] = user }, new RetentionDays(30, 30, 30));
    }

    private sealed class Policies(DevicePolicy? p) : IPolicyProvider
    {
        public DevicePolicy? Current { get; set; } = p;
        public event EventHandler<DevicePolicy>? PolicyChanged;
        public void Raise() => PolicyChanged?.Invoke(this, Current!);
    }

    private sealed class FakeUt1 : HttpMessageHandler
    {
        public Dictionary<string, byte[]> Archives { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var list = Path.GetFileName(request.RequestUri!.AbsolutePath).Replace(".tar.gz", "");
            if (!Archives.TryGetValue(list, out var body)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
            resp.Content.Headers.LastModified = new DateTimeOffset(2026, 11, 21, 0, 0, 0, TimeSpan.Zero);
            return Task.FromResult(resp);
        }
    }

    [Fact]
    public async Task Updater_files_feed_store_and_engine_blocks_social_and_video()
    {
        var server = new FakeUt1();
        server.Archives["social_networks"] = TarGz("social_networks", "tiktok.com\nfacebook.com\n");
        server.Archives["audio-video"] = TarGz("audio-video", "youtube.com\nnetflix.com\n");
        server.Archives["games"] = TarGz("games", "roblox.com\n");
        var policies = new Policies(PolicyWith("social", "video", "games"));
        var options = new NetGuardOptions { CategoriesDirectory = _dir, CategorySourceBaseUrl = "https://ut1.test/blacklists/download/" };
        var store = new CategoryStore(options);
        using var updater = new CategoryUpdater(options, store, policies, null, server, null);

        var r = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Empty(r.Failed);
        Assert.True(File.Exists(Path.Combine(_dir, "social.bin")));
        Assert.True(File.Exists(Path.Combine(_dir, "video.bin")));

        var engine = new WebDecisionEngine(store);
        var web = policies.Current!.Users[Sid].Web;
        var now = DateTimeOffset.UtcNow;
        AssertBlocked(engine.Decide(web, "www.tiktok.com", now, "Asia/Ho_Chi_Minh"), "social");
        AssertBlocked(engine.Decide(web, "m.facebook.com", now, "Asia/Ho_Chi_Minh"), "social");
        AssertBlocked(engine.Decide(web, "m.youtube.com", now, "Asia/Ho_Chi_Minh"), "video");
        AssertBlocked(engine.Decide(web, "www.roblox.com", now, "Asia/Ho_Chi_Minh"), "games");
        Assert.True(engine.Decide(web, "www.wikipedia.org", now, "Asia/Ho_Chi_Minh").Allowed);
    }

    [Fact]
    public void Curated_service_domains_are_in_their_category_before_any_download()
    {
        // empty categories folder: UT1 has not arrived yet
        var store = new CategoryStore(new NetGuardOptions { CategoriesDirectory = _dir });
        var engine = new WebDecisionEngine(store);
        var web = PolicyWith("social", "video", "games").Users[Sid].Web;
        var now = DateTimeOffset.UtcNow;
        AssertBlocked(engine.Decide(web, "rr3---sn-8qj-i5oe.googlevideo.com", now, null), "video");
        AssertBlocked(engine.Decide(web, "i.ytimg.com", now, null), "video");
        Assert.True(engine.Decide(web, "www.wikipedia.org", now, null).Allowed);
    }

    /// <summary>GitHub mirror: <c>/blacklists/&lt;list&gt;/domains[.N]</c> with ETags and If-None-Match.</summary>
    private sealed class FakeGitHub : HttpMessageHandler
    {
        public Dictionary<string, string> Files { get; } = new();   // "list/domains.0" → content
        public List<string> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            var key = path[(path.IndexOf("/blacklists/", StringComparison.Ordinal) + "/blacklists/".Length)..];
            var inm = request.Headers.IfNoneMatch.FirstOrDefault()?.Tag;
            Requests.Add(key + (inm is null ? "" : " inm"));
            if (!Files.TryGetValue(key, out var content)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            var etag = "\"" + content.GetHashCode().ToString("x") + "\"";
            if (inm == etag) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotModified));
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(content) };
            resp.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue(etag);
            return Task.FromResult(resp);
        }
    }

    [Fact]
    public async Task GitHub_mirror_split_files_are_concatenated_and_conditional()
    {
        var gh = new FakeGitHub();
        // the split falls in the middle of "pornhub.com"
        gh.Files["adult/domains.0"] = "xvideos.com\nporn";
        gh.Files["adult/domains.1"] = "hub.com\nxnxx.com\n";
        gh.Files["mixed_adult/domains"] = "mixed.test\n";
        var policies = new Policies(PolicyWith("adult"));
        var options = new NetGuardOptions { CategoriesDirectory = _dir, CategoryGitHubBaseUrl = "https://gh.test/olbat/ut1-blacklists/master/blacklists/",
            CategorySourceBaseUrl = "https://ut1.test/" };
        var store = new CategoryStore(options);
        using var updater = new CategoryUpdater(options, store, policies, null, gh, null);

        var r = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Equal(["adult/adult", "adult/mixed_adult"], r.Downloaded);
        Assert.Equal(["adult"], store.CategoriesOf("www.pornhub.com"));
        Assert.Equal(["adult"], store.CategoriesOf("xnxx.com"));
        Assert.Empty(store.CategoriesOf("porn"));
        Assert.Contains("adult/domains.2", gh.Requests);   // probed until 404

        gh.Requests.Clear();
        var r2 = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Empty(r2.Downloaded);
        Assert.Equal(["adult/adult", "adult/mixed_adult"], r2.NotModified);
        Assert.Contains("adult/domains.0 inm", gh.Requests);
        Assert.Contains("mixed_adult/domains inm", gh.Requests);
    }

    [Fact]
    public async Task GitHub_failure_falls_back_to_the_tarball()
    {
        var both = new Both(new FakeGitHub(), new FakeUt1());
        both.Ut1.Archives["social_networks"] = TarGz("social_networks", "tiktok.com\n");
        var policies = new Policies(PolicyWith("social"));
        var options = new NetGuardOptions { CategoriesDirectory = _dir, CategoryGitHubBaseUrl = "https://gh.test/blacklists/",
            CategorySourceBaseUrl = "https://ut1.test/blacklists/download/" };
        var store = new CategoryStore(options);
        using var updater = new CategoryUpdater(options, store, policies, null, both, null);
        var r = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Equal(["social/social_networks"], r.Downloaded);
        Assert.Contains("social", store.CategoriesOf("www.tiktok.com"));
    }

    private sealed class Both(FakeGitHub gh, FakeUt1 ut1) : HttpMessageHandler
    {
        public FakeUt1 Ut1 => ut1;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var invoker = new HttpMessageInvoker(request.RequestUri!.Host == "gh.test" ? gh : ut1, disposeHandler: false);
            return invoker.SendAsync(request, ct);
        }
    }

    [Fact]
    public void Seed_lists_are_promoted_when_missing_or_newer_and_never_over_a_newer_download()
    {
        var seed = Path.Combine(_dir, "seed");
        Directory.CreateDirectory(seed);
        HashedDomainSet.FromDomains(["seed-social.test"]).WriteAtomic(Path.Combine(seed, "social.bin"));
        HashedDomainSet.FromDomains(["seed-video.test"]).WriteAtomic(Path.Combine(seed, "video.bin"));
        var seedAt = new DateTimeOffset(2026, 10, 12, 7, 10, 0, TimeSpan.Zero);
        File.WriteAllText(Path.Combine(seed, "seed-state.json"), System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, Ut1SourceState>
        {
            ["social.bin"] = new(null, seedAt, 1, seedAt),
            ["video.bin"] = new(null, seedAt, 1, seedAt),
        }));
        // video already has a list downloaded after the seed was built: keep it
        HashedDomainSet.FromDomains(["live-video.test"]).WriteAtomic(Path.Combine(_dir, "video.bin"));
        File.WriteAllText(Path.Combine(_dir, ".ut1-state.json"), System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, Ut1SourceState>
        {
            ["video.bin"] = new("gh:\"x\"", null, 1, seedAt.AddDays(20)),
        }));

        var policies = new Policies(PolicyWith("social", "video"));
        var options = new NetGuardOptions { CategoriesDirectory = _dir };
        var store = new CategoryStore(options);
        using var updater = new CategoryUpdater(options, store, policies, null, new FakeUt1(), null);
        Assert.Equal(1, updater.PromoteSeedsForPolicy(policies.Current));
        Assert.Equal(["social"], store.CategoriesOf("a.seed-social.test"));
        Assert.Equal(["video"], store.CategoriesOf("live-video.test"));
        Assert.Empty(store.CategoriesOf("seed-video.test"));
        Assert.Equal(seedAt, updater.LoadState()["social.bin"].LastModified);   // conditional GET continues from the seed
        Assert.Equal(0, updater.PromoteSeedsForPolicy(policies.Current));       // idempotent
    }

    private static void AssertBlocked(WebDecision d, string category)
    {
        Assert.False(d.Allowed);
        Assert.Equal(BlockReasons.Category, d.Reason);
        Assert.Equal(category, d.Category);
    }
}
