using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Text;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
using MinControl.NetGuard;
using MinControl.NetGuard.Categories;
using MinControl.NetGuard.Web;
using MinControl.Service.Logic;
using Xunit;

namespace MinControl.Core.Tests;

public sealed class CategoryUpdaterTests : IDisposable
{
    private const string Sid = "S-1-5-21-1-2-3-1001";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mc-cat-" + Guid.NewGuid().ToString("N"));

    public CategoryUpdaterTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] TarGz(params (string Name, string Content)[] entries)
    {
        var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gz, TarEntryFormat.Ustar, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var e = new UstarTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)) };
                tar.WriteEntry(e);
            }
        }
        return ms.ToArray();
    }

    private static WeekdayMap<T> All<T>(T v) => new(v, v, v, v, v, v, v);

    private static DevicePolicy PolicyWith(string[] blocked, string[]? scheduled = null)
    {
        var schedules = scheduled?.ToDictionary(c => c, _ => All<IReadOnlyList<string>>(["08:00-17:00"]));
        var user = new UserPolicy("Bin",
            new ScreenTimePolicy(All(120), All<IReadOnlyList<string>>(["00:00-23:59"]), [5], 60, false, 300),
            new Dictionary<string, AppGroup>(), [], "allow",
            new WebPolicy("blocklist", blocked, [], [], true, "strict", ["msedge.exe"], [], schedules),
            new MonitoringPolicy(true, true, true, true, true, new ScreenshotPolicy(5, true, 1280, 60)));
        return new DevicePolicy(1, "Asia/Ho_Chi_Minh", new Dictionary<string, UserPolicy> { [Sid] = user }, new RetentionDays(30, 30, 30));
    }

    private sealed class Policies(DevicePolicy? p) : IPolicyProvider
    {
        public DevicePolicy? Current { get; set; } = p;
        public event EventHandler<DevicePolicy>? PolicyChanged;
        public void Raise() => PolicyChanged?.Invoke(this, Current!);
    }

    /// <summary>Fake UT1 server: serves archives by list name with a Last-Modified/ETag and honours conditionals.</summary>
    private sealed class FakeUt1 : HttpMessageHandler
    {
        public Dictionary<string, byte[]> Archives { get; } = new();
        public List<HttpRequestMessage> Requests { get; } = [];
        public DateTimeOffset LastModified { get; set; } = new(2026, 11, 21, 21, 50, 17, TimeSpan.Zero);
        public string ETag { get; set; } = "\"v1\"";
        public HttpStatusCode? Force { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            if (Force is { } f) return Task.FromResult(new HttpResponseMessage(f));
            var list = Path.GetFileName(request.RequestUri!.AbsolutePath).Replace(".tar.gz", "");
            if (!Archives.TryGetValue(list, out var body)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            var inm = request.Headers.IfNoneMatch.FirstOrDefault()?.Tag;
            var ims = request.Headers.IfModifiedSince;
            if (inm == ETag || (inm is null && ims is { } d && d >= LastModified))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotModified));
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
            resp.Content.Headers.LastModified = LastModified;
            resp.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue(ETag);
            return Task.FromResult(resp);
        }
    }

    private (CategoryUpdater Updater, CategoryStore Store) Create(FakeUt1 server, Policies policies)
    {
        var options = new NetGuardOptions { CategoriesDirectory = _dir, CategorySourceBaseUrl = "https://ut1.test/blacklists/download/", CategoryGitHubBaseUrl = "" };
        var store = new CategoryStore(options);
        return (new CategoryUpdater(options, store, policies, null, server, null), store);
    }

    // ------------------------------------------------------------------ archive + normalisation

    [Fact]
    public async Task Extract_reads_only_the_domains_entry_and_skips_garbage()
    {
        var archive = TarGz(
            ("games/urls", "roblox.com/games\n"),
            ("games/domains", "Roblox.COM\n\n*.minecraft.net\n10.0.0.1\n2001:db8::1\nbad domain.com\nhttp://x.com/\nfoo\nexample.com.\n"),
            ("games/usage", "black\n"));
        var r = await Ut1Archive.ExtractAsync(new MemoryStream(archive), "games", 0, CancellationToken.None);
        Assert.Equal("games/domains", r.EntryName);
        Assert.Equal(3, r.Set.Count);       // roblox.com, minecraft.net, example.com
        Assert.Equal(5, r.Skipped);
        Assert.True(r.Set.MatchesHostOrParent("www.roblox.com"));
        Assert.True(r.Set.MatchesHostOrParent("minecraft.net"));
        Assert.False(r.Set.MatchesHostOrParent("notroblox.com"));
    }

    [Fact]
    public async Task Extract_accepts_alias_directory_and_rejects_archive_without_domains()
    {
        var alias = TarGz(("phishing/domains", "evil.test\n"));
        var r = await Ut1Archive.ExtractAsync(new MemoryStream(alias), "malware", 0, CancellationToken.None);
        Assert.Equal("phishing/domains", r.EntryName);

        var none = TarGz(("games/urls", "x.com/a\n"));
        await Assert.ThrowsAsync<InvalidDataException>(() => Ut1Archive.ExtractAsync(new MemoryStream(none), "games", 0, CancellationToken.None));
        var empty = TarGz(("games/domains", "1.2.3.4\n#c\n"));
        await Assert.ThrowsAsync<InvalidDataException>(() => Ut1Archive.ExtractAsync(new MemoryStream(empty), "games", 0, CancellationToken.None));
    }

    [Theory]
    [InlineData("  WWW.Example.com.  ", "www.example.com")]
    [InlineData("*.casino.test", "casino.test")]
    [InlineData("xn--bcher-kva.example", "xn--bcher-kva.example")]
    [InlineData("a_b.example.org # note", "a_b.example.org")]
    [InlineData("192.168.1.1", null)]
    [InlineData("10.1", null)]
    [InlineData("::1", null)]
    [InlineData("localhost", null)]
    [InlineData("XXX", "xxx")]
    [InlineData("com", null)]
    [InlineData("-bad.com", null)]
    [InlineData("bad-.com", null)]
    [InlineData("a..b.com", null)]
    [InlineData("example.com:8080", null)]
    [InlineData("bücher.de", null)]
    public void NormalizeDomain(string input, string? expected) => Assert.Equal(expected, Ut1Archive.NormalizeDomain(input));

    // ------------------------------------------------------------------ hashed sets

    [Fact]
    public void HashedSet_suffix_matching_and_roundtrip()
    {
        var set = HashedDomainSet.FromDomains(["example.com", "b.test.org", "example.com"]);
        Assert.Equal(2, set.Count);
        Assert.True(set.MatchesHostOrParent("example.com"));
        Assert.True(set.MatchesHostOrParent("a.b.example.com"));
        Assert.True(set.MatchesHostOrParent("x.b.test.org"));
        Assert.False(set.MatchesHostOrParent("test.org"));
        Assert.False(set.MatchesHostOrParent("myexample.com"));
        Assert.False(set.MatchesHostOrParent("com"));

        var path = Path.Combine(_dir, "games.bin");
        set.WriteAtomic(path);
        Assert.Equal(16 + 2 * 8, new FileInfo(path).Length);
        var back = HashedDomainSet.Read(path);
        Assert.True(back.MatchesHostOrParent("www.example.com"));

        File.WriteAllBytes(Path.Combine(_dir, "adult.bin"), [1, 2, 3]);
        Assert.ThrowsAny<Exception>(() => HashedDomainSet.Read(Path.Combine(_dir, "adult.bin")));
    }

    [Fact]
    public void Store_merges_bin_parts_and_txt_and_skips_corrupt_files()
    {
        HashedDomainSet.FromDomains(["nordvpn.com"]).WriteAtomic(Path.Combine(_dir, "proxy-vpn.vpn.bin"));
        HashedDomainSet.FromDomains(["hidemyass.com"]).WriteAtomic(Path.Combine(_dir, "proxy-vpn.redirector.bin"));
        HashedDomainSet.FromDomains(["roblox.com"]).WriteAtomic(Path.Combine(_dir, "games.bin"));
        File.WriteAllLines(Path.Combine(_dir, "social.txt"), ["facebook.com"]);
        File.WriteAllBytes(Path.Combine(_dir, "adult.bin"), "garbage"u8.ToArray());

        var store = new CategoryStore(new NetGuardOptions { CategoriesDirectory = _dir });
        Assert.Equal(["proxy-vpn"], store.CategoriesOf("www.nordvpn.com"));
        Assert.Equal(["proxy-vpn"], store.CategoriesOf("hidemyass.com"));
        Assert.Equal(["games"], store.CategoriesOf("web.roblox.com"));
        Assert.Equal(["social"], store.CategoriesOf("m.facebook.com"));
        Assert.Empty(store.CategoriesOf("example.com"));
        Assert.Equal("proxy-vpn", CategoryStore.CategoryOfFile(@"C:\x\proxy-vpn.vpn.bin"));

        // Decision engine sees hashed categories like text ones.
        var web = new WebPolicy("blocklist", ["games"], [], [], false, "off", ["msedge.exe"], []);
        var d = new WebDecisionEngine(store).Decide(web, "www.roblox.com", DateTimeOffset.UtcNow, "UTC");
        Assert.Equal((false, BlockReasons.Category, "games"), (d.Allowed, d.Reason, d.Category));
    }

    // ------------------------------------------------------------------ mapping

    [Fact]
    public void Mapping_covers_every_policy_category()
    {
        string[] policyCats = ["adult", "gambling", "proxy-vpn", "games", "social", "video", "violence", "drugs", "dating", "malware"];
        Assert.Equal(policyCats.Order(), Ut1Catalog.Sources.Keys.Order());
        Assert.Equal(["vpn", "redirector", "strict_redirector"], Ut1Catalog.Sources["proxy-vpn"]);
        Assert.Equal(["malware", "phishing", "cryptojacking"], Ut1Catalog.Sources["malware"]);
        Assert.Equal(["adult", "mixed_adult"], Ut1Catalog.Sources["adult"]);
        Assert.Equal(["agressif"], Ut1Catalog.Sources["violence"]);
        Assert.Equal(["social_networks"], Ut1Catalog.Sources["social"]);
        Assert.Equal("adult.adult.bin", Ut1Catalog.FileName("adult", "adult"));
        Assert.Equal("games.bin", Ut1Catalog.FileName("games", "games"));
        Assert.Equal("https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/adult/domains.1",
            Ut1Catalog.GitHubUrlOf(Ut1Catalog.DefaultGitHubBaseUrl, "adult", 1).ToString());
        Assert.Equal("proxy-vpn.redirector.bin", Ut1Catalog.FileName("proxy-vpn", "redirector"));
        Assert.Equal("https://dsi.ut-capitole.fr/blacklists/download/audio-video.tar.gz",
            Ut1Catalog.UrlOf(Ut1Catalog.DefaultBaseUrl, "audio-video").ToString());

        var referenced = Ut1Catalog.ReferencedCategories(PolicyWith(["adult", "Games", "unknown"], scheduled: ["social"]));
        Assert.Equal(["adult", "games", "social"], referenced.Order());
        Assert.Empty(Ut1Catalog.ReferencedCategories(PolicyWith(["games"]), isManaged: _ => false));
        Assert.Empty(Ut1Catalog.ReferencedCategories(null));
    }

    [Fact]
    public void Vietnamese_notice_texts()
    {
        Assert.Equal("MinControl đã chặn poki.com", BlockNoticeText.Title("poki.com"));
        Assert.Equal("Danh mục: Trò chơi · đang trong giờ học", BlockNoticeText.Reason(BlockReasons.Schedule, "games"));
        Assert.Equal("Danh mục: Người lớn", BlockNoticeText.Reason(BlockReasons.Category, "adult"));
        Assert.Equal("Trang nằm trong danh sách chặn", BlockNoticeText.Reason(BlockReasons.Blocklist, null));
        Assert.Equal("Chỉ được vào các trang cho phép", BlockNoticeText.Reason(BlockReasons.AllowlistMiss, null));
        Assert.Equal("Chặn DNS mã hoá", BlockNoticeText.Reason(BlockReasons.Doh, null));
        Assert.Equal("Cổng không được phép", BlockNoticeText.Reason(BlockReasons.Port, null));
        Assert.Equal("Mã độc", BlockNoticeText.CategoryName("malware"));
        Assert.Equal("VPN/Proxy", BlockNoticeText.CategoryName("proxy-vpn"));
    }

    // ------------------------------------------------------------------ updater (conditional GET bookkeeping)

    [Fact]
    public async Task Updater_downloads_referenced_lists_then_uses_conditional_get()
    {
        var server = new FakeUt1();
        server.Archives["games"] = TarGz(("games/domains", "poki.com\nroblox.com\n"));
        server.Archives["vpn"] = TarGz(("vpn/domains", "nordvpn.com\n"));
        server.Archives["redirector"] = TarGz(("redirector/domains", "hidemyass.com\n"));
        server.Archives["strict_redirector"] = TarGz(("strict_redirector/domains", "translate-proxy.test\n"));
        server.Archives["adult"] = TarGz(("adult/domains", "xxx.test\n"));
        var policies = new Policies(PolicyWith(["proxy-vpn"], scheduled: ["games"]));
        var (updater, store) = Create(server, policies);
        using var _ = updater;

        var r1 = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Equal(["games/games", "proxy-vpn/vpn", "proxy-vpn/redirector", "proxy-vpn/strict_redirector"], r1.Downloaded);
        Assert.Empty(r1.Failed);
        Assert.All(server.Requests, q => Assert.True(q.Headers.IfNoneMatch.Count == 0 && q.Headers.IfModifiedSince is null));
        Assert.True(File.Exists(Path.Combine(_dir, "games.bin")));
        Assert.True(File.Exists(Path.Combine(_dir, "proxy-vpn.vpn.bin")));
        Assert.False(File.Exists(Path.Combine(_dir, "adult.bin")));   // not referenced → not downloaded
        Assert.Equal(["games"], store.CategoriesOf("www.poki.com"));
        Assert.Equal(["proxy-vpn"], store.CategoriesOf("hidemyass.com"));

        var state = updater.LoadState();
        Assert.Equal("\"v1\"", state["games.bin"].ETag);
        Assert.Equal(server.LastModified, state["games.bin"].LastModified);
        Assert.Equal(2, state["games.bin"].Domains);

        // Second pass: conditional headers sent, 304 → nothing rewritten.
        server.Requests.Clear();
        var before = File.GetLastWriteTimeUtc(Path.Combine(_dir, "games.bin"));
        var r2 = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Empty(r2.Downloaded);
        Assert.Equal(4, r2.NotModified.Count);
        Assert.All(server.Requests, q =>
        {
            Assert.Equal("\"v1\"", q.Headers.IfNoneMatch.Single().Tag);
            Assert.Equal(server.LastModified, q.Headers.IfModifiedSince);
        });
        Assert.Equal(before, File.GetLastWriteTimeUtc(Path.Combine(_dir, "games.bin")));

        // New version on the server → re-downloaded.
        server.ETag = "\"v2\"";
        server.Archives["games"] = TarGz(("games/domains", "poki.com\nroblox.com\ny8.com\n"));
        var r3 = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Equal(["games/games", "proxy-vpn/vpn", "proxy-vpn/redirector", "proxy-vpn/strict_redirector"], r3.Downloaded);
        Assert.Equal(["games"], store.CategoriesOf("y8.com"));

        // Policy drops proxy-vpn → its files are removed and the store forgets them.
        policies.Current = PolicyWith([], scheduled: ["games"]);
        var r4 = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Equal(["proxy-vpn.redirector.bin", "proxy-vpn.strict_redirector.bin", "proxy-vpn.vpn.bin"], r4.Removed.Order());
        Assert.Empty(store.CategoriesOf("nordvpn.com"));
        Assert.False(updater.LoadState().ContainsKey("proxy-vpn.vpn.bin"));
    }

    [Fact]
    public async Task Updater_keeps_previous_file_on_failure()
    {
        var server = new FakeUt1();
        server.Archives["games"] = TarGz(("games/domains", "poki.com\n"));
        var (updater, store) = Create(server, new Policies(PolicyWith(["games"])));
        using var _ = updater;
        Assert.Single((await updater.UpdateOnceAsync(CancellationToken.None)).Downloaded);
        var path = Path.Combine(_dir, "games.bin");
        var bytes = File.ReadAllBytes(path);

        // Server error.
        server.Force = HttpStatusCode.ServiceUnavailable;
        var r = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Equal(["games/games"], r.Failed);
        Assert.Equal(bytes, File.ReadAllBytes(path));

        // Broken archive (new version announced, body is not a tar.gz).
        server.Force = null;
        server.ETag = "\"v2\"";
        server.Archives["games"] = "not a gzip"u8.ToArray();
        r = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Equal(["games/games"], r.Failed);
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.Equal(["games"], store.CategoriesOf("poki.com"));
        Assert.False(File.Exists(path + ".tmp"));

        // Missing file → unconditional GET even though state exists.
        server.Archives["games"] = TarGz(("games/domains", "poki.com\n"));
        File.Delete(path);
        server.Requests.Clear();
        r = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Equal(["games/games"], r.Downloaded);
        Assert.Empty(server.Requests[0].Headers.IfNoneMatch);
    }

    [Fact]
    public async Task Updater_does_nothing_without_policy()
    {
        var server = new FakeUt1();
        var (updater, _) = Create(server, new Policies(null));
        using var __ = updater;
        var r = await updater.UpdateOnceAsync(CancellationToken.None);
        Assert.Empty(r.Downloaded);
        Assert.Empty(server.Requests);
    }

    // ------------------------------------------------------------------ toast rate limit (Service logic)

    [Fact]
    public void Notice_limiter_same_key_60s_and_three_per_minute_per_user()
    {
        var l = new BlockedNoticeLimiter();
        Assert.True(l.TryAcquire("u1", "poki.com", 0));
        Assert.False(l.TryAcquire("u1", "poki.com", 59_999));       // same host within 60 s
        Assert.True(l.TryAcquire("u2", "poki.com", 1_000));         // other user unaffected
        Assert.True(l.TryAcquire("u1", "a.com", 1_000));
        Assert.True(l.TryAcquire("u1", "b.com", 2_000));
        Assert.False(l.TryAcquire("u1", "c.com", 3_000));           // 4th in a minute
        Assert.True(l.TryAcquire("u1", "c.com", 60_000));           // first one aged out
        Assert.False(l.TryAcquire("u1", "d.com", 60_500));
        Assert.True(l.TryAcquire("u1", "poki.com", 120_000));
    }
}
