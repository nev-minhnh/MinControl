using System.Text;
using MinControl.Core.Cloud;
using MinControl.Core.Commands;
using MinControl.Core.Crypto;
using MinControl.Core.Storage;
using MinControl.Core.Telemetry;
using MinControl.Core.Util;
using NSec.Cryptography;
using Xunit;

namespace MinControl.Core.Tests;

public class UtilAndStoreTests
{
    [Fact]
    public void Ulid_is_valid_and_monotonic()
    {
        var gen = new UlidGenerator();
        var t = new DateTimeOffset(2026, 11, 22, 8, 50, 0, TimeSpan.Zero);
        var ids = Enumerable.Range(0, 1000).Select(_ => gen.New(t)).ToList();
        Assert.All(ids, id => Assert.True(UlidGenerator.IsValid(id), id));
        Assert.Equal(ids.OrderBy(x => x, StringComparer.Ordinal), ids);
        Assert.Equal(1000, ids.Distinct().Count());
    }

    [Theory]
    [InlineData("eyJkZXZpY2VJZCI6IjAxIn0", true)]
    [InlineData("eyJkZXZpY2VJZCI6IjAxIn0=", false)]
    [InlineData("a+b/", false)]
    public void Base64Url_is_strict(string s, bool ok) => Assert.Equal(ok, Base64Url.TryDecode(s, out _));

    [Fact]
    public void Time_formats_rfc3339_utc()
    {
        var t = new DateTimeOffset(2026, 11, 22, 15, 50, 7, TimeSpan.FromHours(7));
        Assert.Equal("2026-11-22T08:50:07Z", Time.Utc(t));
        Assert.True(Time.TryParseUtc("2026-11-22T08:50:07Z", out var back));
        Assert.Equal(t, back);
        Assert.False(Time.TryParseUtc("2026-11-22T15:50:07+07:00", out _));
    }

    [Theory]
    [InlineData("Minecraft*.exe", "MinecraftLauncher.EXE", true)]
    [InlineData("firefox?.exe", "firefox1.exe", true)]
    [InlineData("firefox?.exe", "firefox.exe", false)]
    [InlineData("*.exe", "a.dll", false)]
    public void Glob_matches_case_insensitively(string pattern, string text, bool expected) =>
        Assert.Equal(expected, Glob.IsMatch(pattern, text));

    [Fact]
    public void Device_identity_signs_ws_auth_with_unix_seconds()
    {
        var dir = Path.Combine(Path.GetTempPath(), "mc-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var id = new DeviceIdentity(Path.Combine(dir, "device.key"), new NoopKeyProtector());
            var pub = id.CreateNew();
            var sig = Base64Url.Decode(id.AuthSignature("bm9uY2U", TestData.DeviceId, 1795337400));
            var pk = PublicKey.Import(SignatureAlgorithm.Ed25519, pub, KeyBlobFormat.RawPublicKey);
            Assert.True(SignatureAlgorithm.Ed25519.Verify(pk, Encoding.UTF8.GetBytes($"bm9uY2U|{TestData.DeviceId}|1795337400"), sig));

            using var reloaded = new DeviceIdentity(Path.Combine(dir, "device.key"), new NoopKeyProtector());
            Assert.Equal(pub, reloaded.PublicKey);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Outbox_cap_drops_usage_ticks_first_and_never_tamper()
    {
        using var store = new StateStore(":memory:") { OutboxCapBytes = 2_000 };
        var pad = new string('x', 180);
        for (int i = 0; i < 5; i++) store.EnqueueOutbox("tamper.clock_jump", $"{{\"t\":\"{pad}\"}}");
        for (int i = 0; i < 20; i++) store.EnqueueOutbox("usage.tick", $"{{\"u\":\"{pad}\"}}");
        for (int i = 0; i < 20; i++) store.EnqueueOutbox("process.start", $"{{\"p\":\"{pad}\"}}");
        var all = store.PeekOutbox(1000);
        Assert.Equal(5, all.Count(x => x.Type == "tamper.clock_jump"));
        Assert.DoesNotContain(all, x => x.Type == "usage.tick");
        Assert.True(store.OutboxBytes <= 2_000);
    }

    [Fact]
    public void Outbox_delete_updates_size()
    {
        using var store = new StateStore(":memory:");
        store.EnqueueOutbox("usage.tick", "{}");
        store.EnqueueOutbox("usage.tick", "{\"a\":1}");
        var items = store.PeekOutbox(10);
        store.DeleteOutbox(items.Select(i => i.Id));
        Assert.Equal(0, store.OutboxCount);
        Assert.Equal(0, store.OutboxBytes);
    }

    [Fact]
    public void Seq_only_advances()
    {
        using var store = new StateStore(":memory:");
        Assert.True(store.TryAdvanceSeq("policy", 3));
        Assert.False(store.TryAdvanceSeq("policy", 3));
        Assert.False(store.TryAdvanceSeq("policy", 2));
        Assert.True(store.TryAdvanceSeq("command", 1));
        Assert.Equal(3, store.GetSeq("policy"));
    }

    [Fact]
    public void Approval_request_is_marked_once_and_persisted()
    {
        var path = Path.Combine(Path.GetTempPath(), "mc-test-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var clock = new FakeClock(new DateTimeOffset(2026, 11, 22, 8, 0, 0, TimeSpan.Zero));
            using (var store = new StateStore(path))
            {
                var approvals = new ApprovalStore(store, clock);
                Assert.True(approvals.MarkRequested("S-1-5-21-1", "ABCDEF"));
                Assert.False(approvals.MarkRequested("S-1-5-21-1", "abcdef"));
                Assert.True(approvals.MarkRequested("S-1-5-21-2", "abcdef"));
            }
            using (var reopened = new StateStore(path))
                Assert.False(new ApprovalStore(reopened, clock).MarkRequested("S-1-5-21-1", "abcdef"));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            foreach (var f in new[] { path, path + "-wal", path + "-shm" }) try { File.Delete(f); } catch (IOException) { }
        }
    }

    [Fact]
    public void Ws_uri_uses_wss_and_device_query() =>
        Assert.Equal("wss://mc.example.org/v1/device/ws?deviceId=" + TestData.DeviceId,
            CloudLink.WsUri("https://mc.example.org", TestData.DeviceId).ToString());

    [Fact]
    public void Sealed_box_adds_overhead() =>
        Assert.Equal(10 + SealedBox.Overhead, SealedBox.Seal(new byte[10], Sodium.PublicKeyBox.GenerateKeyPair().PublicKey).Length);
}
