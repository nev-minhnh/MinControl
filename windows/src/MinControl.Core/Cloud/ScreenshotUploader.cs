using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Crypto;
using MinControl.Core.Events;
using MinControl.Core.Storage;
using MinControl.Core.Telemetry;
using MinControl.Core.Util;

namespace MinControl.Core.Cloud;

/// <summary>
/// Seals a JPEG to the master seal key (only the phone can open it), writes the sealed bytes to the local screenshot
/// store (API.md section 9; nothing is uploaded) and emits <c>screenshot.taken</c> with
/// <c>blobKey = screens/&lt;deviceId&gt;/&lt;yyyy-mm-dd&gt;/&lt;eventId&gt;.bin</c>. The cloud link serves the file on demand.
/// </summary>
public sealed class ScreenshotUploader : IScreenshotUploader
{
    public const int MaxBlobBytes = 2 * 1024 * 1024;

    private readonly StateStore _store;
    private readonly EventSink _events;
    private readonly IClock _clock;
    private readonly ScreenshotStorage _storage;

    public ScreenshotUploader(StateStore store, EventSink events, IClock clock, ScreenshotStorage storage)
    {
        _store = store; _events = events; _clock = clock; _storage = storage;
    }

    public Task UploadAsync(string? sid, byte[] jpeg, int width, int height, string reason, string? commandId, string? foregroundExe, CancellationToken ct)
    {
        if (sid is null) throw new ArgumentException("screenshot.taken requires the user's SID", nameof(sid));
        if (reason is not ("interval" or "command")) throw new ArgumentException("reason must be interval or command", nameof(reason));
        var deviceId = _store.GetMeta(StateStore.MetaKeys.DeviceId) ?? throw new InvalidOperationException("device is not enrolled");
        var sealKey = _store.GetMeta(StateStore.MetaKeys.MasterSealPubKey) is { } k && Base64Url.TryDecode(k, out var kb) && kb.Length == 32
            ? kb : throw new InvalidOperationException("master seal key missing");
        if (jpeg.Length + SealedBox.Overhead > MaxBlobBytes) throw new ArgumentException("screenshot exceeds 2 MB; lower maxWidth/jpegQuality", nameof(jpeg));

        var now = _clock.UtcNow;
        var eventId = _events.NewId();
        var day = DateOnly.FromDateTime(now.UtcDateTime);
        var key = ScreenshotStorage.KeyFor(deviceId, day, eventId);
        _storage.Write(day, eventId, SealedBox.Seal(jpeg, sealKey));

        var data = new JsonObject { ["blobKey"] = key, ["width"] = width, ["height"] = height, ["reason"] = reason };
        if (commandId is not null) data["commandId"] = commandId;
        if (foregroundExe is not null) data["foregroundExe"] = foregroundExe.Length <= 260 ? foregroundExe : foregroundExe[..260];
        _events.Emit(EventTypes.ScreenshotTaken, sid, data, eventId);
        return Task.CompletedTask;
    }
}
