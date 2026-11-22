using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using MinControl.Core.Abstractions;
using MinControl.Core.Cloud;
using MinControl.Core.Commands;
using MinControl.Core.Util;
using MinControl.Monitoring.Rules;

namespace MinControl.Monitoring.Inventory;

/// <summary>
/// App inventory (API.md §11): collects per managed SID, uploads with PUT /v1/device/inventory at start (+60 s),
/// every 6 h, after install.detected (<see cref="Trigger"/>) and when a refresh command is applied.
/// Also feeds <see cref="UsageLedger"/> from the foreground tracker (active minutes per exe).
/// </summary>
internal sealed class InventoryService : IDisposable
{
    public static readonly TimeSpan StartDelay = TimeSpan.FromSeconds(60), Interval = TimeSpan.FromHours(6),
        RetryDelay = TimeSpan.FromMinutes(2), Debounce = TimeSpan.FromSeconds(15), SampleEvery = TimeSpan.FromSeconds(15);

    private readonly IUserDirectory _users;
    private readonly IClock _clock;
    private readonly UsageLedger _ledger;
    private readonly IFileFacts _facts;
    private readonly IInventorySources _sources;
    private readonly Func<InventoryUploader?> _uploader;
    private readonly Func<IForegroundTracker?> _foreground;
    private readonly ILogger _log;
    private readonly SemaphoreSlim _signal = new(0, int.MaxValue);
    private CancellationTokenSource? _cts;
    private Timer? _sampler;
    private long _lastSampleMs;
    private int _saveTick;

    public InventoryService(IUserDirectory users, IClock clock, UsageLedger ledger, IFileFacts facts, IInventorySources sources,
        Func<InventoryUploader?> uploader, Func<IForegroundTracker?> foreground, ILogger log)
    {
        _users = users; _clock = clock; _ledger = ledger; _facts = facts; _sources = sources;
        _uploader = uploader; _foreground = foreground; _log = log;
    }

    public UsageLedger Ledger => _ledger;

    public void Start(CommandDispatcher? commands)
    {
        if (_cts is not null) return;
        _cts = new CancellationTokenSource();
        if (commands is not null) commands.RefreshRequested += Trigger;
        _lastSampleMs = _clock.MonotonicMs;
        _sampler = new Timer(_ => Sample(), null, SampleEvery, SampleEvery);
        var ct = _cts.Token;
        _ = Task.Run(() => LoopAsync(ct), ct);
    }

    public void Stop()
    {
        _sampler?.Dispose(); _sampler = null;
        _cts?.Cancel(); _cts = null;
        _ledger.Save();
    }

    public void Dispose() => Stop();

    /// <summary>install.detected / refresh: send soon (debounced).</summary>
    public void Trigger() { try { _signal.Release(); } catch (ObjectDisposedException) { } }

    private void Sample()
    {
        try
        {
            long now = _clock.MonotonicMs;
            double secs = Math.Min((now - _lastSampleMs) / 1000.0, 60);
            _lastSampleMs = now;
            var fg = _foreground();
            if (fg is not null)
                foreach (var sid in _users.ManagedSids)
                    if (fg.Current(sid) is { Idle: false } c && !string.IsNullOrEmpty(c.ExePath))
                        _ledger.AddActive(sid, c.ExePath, secs, _clock.UtcNow);
            if (++_saveTick % 20 == 0) _ledger.Save();   // ~5 min
        }
        catch (Exception ex) { _log.LogDebug(ex, "inventory usage sampling"); }
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        var wait = StartDelay;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (await _signal.WaitAsync(wait, ct).ConfigureAwait(false))
                {
                    await Task.Delay(Debounce, ct).ConfigureAwait(false);   // coalesce bursts
                    while (_signal.Wait(0)) { }
                }
                var result = await SendOnceAsync(ct).ConfigureAwait(false);
                wait = result is UploadResult.Done or UploadResult.NothingToDo ? Interval : RetryDelay;
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "inventory cycle failed"); wait = RetryDelay; }
        }
    }

    internal async Task<UploadResult> SendOnceAsync(CancellationToken ct)
    {
        var uploader = _uploader();
        var deviceId = uploader?.DeviceId;
        if (uploader is null || deviceId is null) return UploadResult.NoToken;
        var json = await Task.Run(() => BuildJson(deviceId), ct).ConfigureAwait(false);
        _ledger.Save();
        return await uploader.PutAsync(json, ct).ConfigureAwait(false);
    }

    internal string BuildJson(string deviceId)
    {
        var now = _clock.UtcNow;
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var sids = _users.ManagedSids.ToList();
        int cap = 3000;
        while (true)
        {
            var users = new JsonObject();
            foreach (var sid in sids)
            {
                IReadOnlyList<AppEntry> apps;
                try
                {
                    apps = InventoryMerger.Merge(_sources.Uninstalls(sid), _sources.Shortcuts(sid), _sources.Appx(sid),
                        _ledger.Snapshot(sid, now), p => _facts.Signature(p).Publisher, winDir);
                }
                catch (Exception ex) { _log.LogWarning(ex, "inventory collect failed for {Sid}", sid); apps = []; }
                users[sid] = new JsonObject { ["apps"] = new JsonArray(apps.Take(cap).Select(ToJson).ToArray<JsonNode?>()) };
            }
            var root = new JsonObject { ["deviceId"] = deviceId, ["generatedAt"] = Time.Utc(now), ["users"] = users };
            var text = root.ToJsonString();
            if (System.Text.Encoding.UTF8.GetByteCount(text) <= InventoryUploader.MaxBytes || cap <= 50) return text;
            cap = cap * 2 / 3;   // apps are sorted by usage, so the tail is dropped first
        }
    }

    internal static JsonObject ToJson(AppEntry a)
    {
        var o = new JsonObject { ["id"] = a.Id, ["name"] = a.Name, ["kind"] = a.Kind };
        void Put(string k, string? v) { if (!string.IsNullOrEmpty(v)) o[k] = v; }
        Put("publisher", a.Publisher); Put("version", a.Version); Put("installDir", a.InstallDir);
        Put("exe", a.Exe); Put("exePath", a.ExePath);
        if (a.LastUsed is { } lu) o["lastUsed"] = Time.Utc(lu);
        if (a.Minutes7d is { } m) o["minutes7d"] = m;
        o["category"] = a.Category;
        return o;
    }
}
