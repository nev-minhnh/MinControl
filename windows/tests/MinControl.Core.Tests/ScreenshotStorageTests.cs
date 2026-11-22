using System.Text.Json.Nodes;
using MinControl.Core.Cloud;
using MinControl.Core.Crypto;
using MinControl.Core.Storage;
using MinControl.Core.Telemetry;
using MinControl.Core.Util;
using NSec.Cryptography;
using Xunit;

namespace MinControl.Core.Tests;

public class ScreenshotStorageTests
{
    private const string Dev = TestData.DeviceId;
    private const string Id = "01JDQ3Z8K4M2N6P8R0S2T4V6W1";

    [Theory]
    [InlineData("screens/" + Dev + "/2026-11-22/" + Id + ".bin", true)]
    [InlineData("screens/" + TestData.OtherDeviceId + "/2026-11-22/" + Id + ".bin", false)]   // someone else's device
    [InlineData("screens/" + Dev + "/../" + Dev + "/2026-11-22/" + Id + ".bin", false)]        // traversal
    [InlineData("screens/" + Dev + "/2026-11-22/../" + Id + ".bin", false)]
    [InlineData("screens/" + Dev + "/2026-11-22/..\\" + Id + ".bin", false)]
    [InlineData("screens/" + Dev + "/2026-11-22/" + Id + ".bin/", false)]
    [InlineData("screens/" + Dev + "/2026-13-40/" + Id + ".bin", false)]                       // bad date
    [InlineData("screens/" + Dev + "/2026-1-2/" + Id + ".bin", false)]
    [InlineData("screens/" + Dev + "/2026-11-22/" + Id + ".png", false)]
    [InlineData("screens/" + Dev + "/2026-11-22/notaulid.bin", false)]
    [InlineData("screens/" + Dev + "/2026-11-22/" + Id + ".bin.bin", false)]
    [InlineData("/screens/" + Dev + "/2026-11-22/" + Id + ".bin", false)]
    [InlineData("C:/screens/" + Dev + "/2026-11-22/" + Id + ".bin", false)]
    [InlineData("screens/" + Dev + "/2026-11-22", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Key_validation(string? key, bool ok)
    {
        Assert.Equal(ok, ScreenshotStorage.TryParseKey(key, Dev, out var day, out var id));
        if (ok) { Assert.Equal(new DateOnly(2026, 11, 22), day); Assert.Equal(Id, id); }
    }

    [Fact]
    public void KeyFor_round_trips()
    {
        var key = ScreenshotStorage.KeyFor(Dev, new DateOnly(2026, 1, 5), Id);
        Assert.Equal($"screens/{Dev}/2026-01-05/{Id}.bin", key);
        Assert.True(ScreenshotStorage.TryParseKey(key, Dev, out _, out _));
    }

    private static ScreenFile F(string day, string id, long size) => new(DateOnly.Parse(day), id, size, id);

    [Fact]
    public void Retention_deletes_only_days_older_than_cutoff()
    {
        var files = new[] { F("2026-11-10", "A", 10), F("2026-11-14", "B", 10), F("2026-11-15", "C", 10), F("2026-11-22", "D", 10) };
        var doomed = ScreenshotStorage.SelectForDeletion(files, new DateOnly(2026, 11, 22), 7, 1000);
        Assert.Equal(["A", "B"], doomed.Select(f => f.EventId).OrderBy(x => x));
    }

    [Fact]
    public void Cap_removes_oldest_first_until_under_limit()
    {
        var files = new[] { F("2026-11-21", "B", 40), F("2026-11-20", "A", 40), F("2026-11-22", "D", 40), F("2026-11-21", "C", 40) };
        var doomed = ScreenshotStorage.SelectForDeletion(files, new DateOnly(2026, 11, 22), 30, 100);
        Assert.Equal(["A", "B"], doomed.Select(f => f.EventId));   // 160 -> 80 after the two oldest
        Assert.Empty(ScreenshotStorage.SelectForDeletion(files, new DateOnly(2026, 11, 22), 30, 160));
    }

    [Fact]
    public void Cleanup_removes_files_and_empty_day_folders()
    {
        var root = Path.Combine(Path.GetTempPath(), "mc-shots-" + Guid.NewGuid().ToString("N"));
        try
        {
            var st = new ScreenshotStorage(root);
            st.Write(new DateOnly(2026, 11, 1), Id, [1, 2, 3]);
            st.Write(new DateOnly(2026, 11, 22), "01JDQ3Z8K4M2N6P8R0S2T4V6W2", [4, 5, 6]);
            var removed = st.Cleanup(new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero), 7);
            Assert.Equal(1, removed);
            Assert.False(Directory.Exists(Path.Combine(root, "2026-11-01")));
            Assert.Single(st.List());
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public void TryRead_returns_null_for_missing_or_foreign_keys()
    {
        var root = Path.Combine(Path.GetTempPath(), "mc-shots-" + Guid.NewGuid().ToString("N"));
        try
        {
            var st = new ScreenshotStorage(root);
            st.Write(new DateOnly(2026, 11, 22), Id, [9, 9]);
            Assert.Equal([9, 9], st.TryRead(ScreenshotStorage.KeyFor(Dev, new DateOnly(2026, 11, 22), Id), Dev));
            Assert.Null(st.TryRead(ScreenshotStorage.KeyFor(Dev, new DateOnly(2026, 11, 21), Id), Dev));
            Assert.Null(st.TryRead(ScreenshotStorage.KeyFor(TestData.OtherDeviceId, new DateOnly(2026, 11, 22), Id), Dev));
            Assert.Null(st.TryRead("screens/" + Dev + "/../../x.bin", Dev));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public async Task Uploader_writes_sealed_file_to_injected_root_and_emits_event()
    {
        var root = Path.Combine(Path.GetTempPath(), "mc-shots-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var store = new StateStore(":memory:");
            var clock = new FakeClock(new DateTimeOffset(2026, 11, 22, 8, 0, 0, TimeSpan.Zero));
            store.SetMeta(StateStore.MetaKeys.DeviceId, Dev);
            using var recipient = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            store.SetMeta(StateStore.MetaKeys.MasterSealPubKey, Base64Url.Encode(recipient.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
            var sink = new EventSink(store, clock);
            var up = new ScreenshotUploader(store, sink, clock, new ScreenshotStorage(root));

            await up.UploadAsync(TestData.Sid, [0xFF, 0xD8, 0xFF], 10, 10, "interval", null, "a.exe", CancellationToken.None);

            var evt = JsonNode.Parse(store.PeekOutbox(10).Single(x => x.Type == "screenshot.taken").Json)!;
            var key = (string)evt["data"]!["blobKey"]!;
            Assert.True(ScreenshotStorage.TryParseKey(key, Dev, out var day, out var id));
            Assert.Equal((string)evt["id"]!, id);
            var path = Path.Combine(root, "2026-11-22", id + ".bin");
            Assert.True(File.Exists(path));
            Assert.Equal(3 + SealedBox.Overhead, new FileInfo(path).Length);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
