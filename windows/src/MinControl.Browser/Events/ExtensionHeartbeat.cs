using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MinControl.Browser.Events;

/// <summary>Last heartbeat per (SID, browser), monotonic clock.</summary>
public sealed class ExtensionHeartbeatTracker
{
    private readonly ConcurrentDictionary<(string Sid, string Browser), long> _last = new();
    private readonly IClock _clock;

    public ExtensionHeartbeatTracker(IClock clock) => _clock = clock;

    public void Record(string sid, string browser) => _last[(sid, browser)] = _clock.MonotonicMs;

    public long? LastMs(string sid, string browser) => _last.TryGetValue((sid, browser), out var ms) ? ms : null;
}

/// <summary>
/// Every <see cref="BrowserOptions.HeartbeatCheckInterval"/> looks for msedge.exe / chrome.exe processes owned by
/// managed users. A browser running longer than <see cref="BrowserOptions.HeartbeatTimeout"/> with no heartbeat in
/// that window emits tamper.extension_missing once per episode. Only browsers whose extension id is configured in
/// <see cref="BrowserOptions"/> are monitored; with no id the extension is not expected (history comes from the
/// History database) and this is a no-op.
/// </summary>
public sealed class ExtensionHeartbeatMonitor : BackgroundService, IExtensionHealth
{
    private static readonly (string Process, string Browser)[] Browsers = [("msedge", "msedge"), ("chrome", "chrome")];

    private readonly ExtensionHeartbeatTracker _tracker;
    private readonly IUserDirectory _users;
    private readonly IEventSink _sink;
    private readonly IClock _clock;
    private readonly BrowserOptions _options;
    private readonly ILogger<ExtensionHeartbeatMonitor> _log;

    // (sid, browser) -> monotonic ms when we first saw it running in the current run
    private readonly ConcurrentDictionary<(string, string), long> _runningSince = new();
    private readonly ConcurrentDictionary<(string, string), bool> _alerted = new();

    public ExtensionHeartbeatMonitor(ExtensionHeartbeatTracker tracker, IUserDirectory users, IEventSink sink, IClock clock,
        IOptions<BrowserOptions> options, ILogger<ExtensionHeartbeatMonitor> log)
    {
        _tracker = tracker; _users = users; _sink = sink; _clock = clock; _options = options.Value; _log = log;
    }

    /// <summary>Always false for a browser without a configured extension id (the extension is optional).</summary>
    public bool IsExtensionMissing(string sid, string browser) =>
        _options.ExtensionConfigured(browser) && _alerted.TryGetValue((sid, browser), out var a) && a;

    /// <summary>Test seam: replaces the process scan.</summary>
    internal Func<IReadOnlyCollection<(string Sid, string Browser)>>? RunningProbe { get; set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(_options.HeartbeatCheckInterval);
        do
        {
            try { Check(); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "heartbeat check failed"); }
        } while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }

    internal void Check()
    {
        long now = _clock.MonotonicMs;
        long timeoutMs = (long)_options.HeartbeatTimeout.TotalMilliseconds;
        var running = RunningBrowsers();
        running.RemoveWhere(k => !_options.ExtensionConfigured(k.Browser));   // no id configured → nothing to monitor

        foreach (var key in _runningSince.Keys)
            if (!running.Contains(key)) { _runningSince.TryRemove(key, out _); _alerted.TryRemove(key, out _); }

        foreach (var key in running)
        {
            long since = _runningSince.GetOrAdd(key, now);
            long? last = _tracker.LastMs(key.Sid, key.Browser);
            bool fresh = last is { } l && now - l <= timeoutMs;
            if (fresh) { _alerted[key] = false; continue; }
            if (now - since <= timeoutMs) continue;                 // give the extension time to start
            if (_alerted.TryGetValue(key, out var done) && done) continue;
            _alerted[key] = true;
            long silentSec = (now - Math.Max(since, last ?? since)) / 1000;
            _log.LogWarning("no extension heartbeat from {Browser} of {Sid} for {Sec}s", key.Browser, key.Sid, silentSec);
            _sink.Emit(EventTypes.TamperExtensionMissing, key.Sid, new JsonObject
            {
                ["detail"] = TamperText.ExtensionMissing(key.Browser, silentSec),
                ["exe"] = key.Browser + ".exe",
            });
        }
    }

    private HashSet<(string Sid, string Browser)> RunningBrowsers()
    {
        if (RunningProbe is not null) return new HashSet<(string, string)>(RunningProbe());
        var set = new HashSet<(string, string)>();
        if (!Browsers.Any(b => _options.ExtensionConfigured(b.Browser))) return set;
        var managed = _users.ManagedSids;
        if (managed.Count == 0) return set;
        foreach (var (proc, browser) in Browsers)
        {
            if (!_options.ExtensionConfigured(browser)) continue;
            foreach (var p in Process.GetProcessesByName(proc))
            {
                using (p)
                {
                    string? sid = _users.SidOfProcess(p.Id);
                    if (sid is not null && managed.Contains(sid) && _users.IsManaged(sid)) set.Add((sid, browser));
                }
            }
        }
        return set;
    }
}
