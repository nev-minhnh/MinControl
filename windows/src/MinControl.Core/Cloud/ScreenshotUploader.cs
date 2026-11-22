using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Crypto;
using MinControl.Core.Events;
using MinControl.Core.Storage;
using MinControl.Core.Telemetry;
using MinControl.Core.Util;

namespace MinControl.Core.Cloud;

/// <summary>
/// Seals a JPEG to the master seal key (only the phone can open it), queues the blob under
/// <c>screens/&lt;deviceId&gt;/&lt;yyyy-mm-dd&gt;/&lt;eventId&gt;.bin</c> and emits <c>screenshot.taken</c> with the same event id.
/// The cloud link uploads queued blobs as soon as it holds an upload token (works offline, I3).
/// </summary>
public sealed class ScreenshotUploader : IScreenshotUploader
{
    public const int MaxBlobBytes = 2 * 1024 * 1024;

    private readonly StateStore _store;
    private readonly EventSink _events;
    private readonly IClock _clock;

    public ScreenshotUploader(StateStore store, EventSink events, IClock clock)
    {
        _store = store; _events = events; _clock = clock;
    }

    /// <summary>Raised after a blob was queued (CloudLink uploads right away when connected).</summary>
    public event Action? BlobQueued;

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
        var key = $"screens/{deviceId}/{now.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)}/{eventId}.bin";
        _store.EnqueueBlob(key, SealedBox.Seal(jpeg, sealKey), Time.Utc(now));

        var data = new JsonObject { ["blobKey"] = key, ["width"] = width, ["height"] = height, ["reason"] = reason };
        if (commandId is not null) data["commandId"] = commandId;
        if (foregroundExe is not null) data["foregroundExe"] = foregroundExe.Length <= 260 ? foregroundExe : foregroundExe[..260];
        _events.Emit(EventTypes.ScreenshotTaken, sid, data, eventId);
        BlobQueued?.Invoke();
        return Task.CompletedTask;
    }
}
