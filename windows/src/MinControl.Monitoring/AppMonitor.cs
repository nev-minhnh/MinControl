using System.Collections.Concurrent;
using System.Diagnostics;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policy;
using MinControl.Core.Telemetry;
using MinControl.Monitoring.Acl;
using MinControl.Monitoring.Processes;
using MinControl.Monitoring.Rules;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MinControl.Monitoring;

/// <summary>Internal start/stop contract for the side monitors (installs, USB, downloads, ACL layer).</summary>
internal interface IMonitorComponent
{
    void Start();
    void Stop();
}

/// <summary>
/// <see cref="IAppMonitor"/>: watches process starts (ETW, polling fallback), enforces appRules / groups /
/// browsers / newExecutable for managed SIDs only (I1), emits process.* and request.exe_approval, and runs
/// the install / USB / download monitors.
/// </summary>
internal sealed class AppMonitor : IAppMonitor, IDisposable
{
    private sealed record Tracked(int Pid, int ParentPid, string Sid, string Path, bool Emitted, long SeenAtMs);

    private readonly IUserDirectory _users;
    private readonly IPolicyProvider _policy;
    private readonly IEventSink _sink;
    private readonly IApprovalStore _approvals;
    private readonly IClock _clock;
    private readonly IServiceProvider _services;
    private readonly IFileFacts _facts;
    private readonly IProcessControl _control;
    private readonly MonitoringOptions _options;
    private readonly ILogger<AppMonitor> _log;
    private readonly ILoggerFactory _loggerFactory;
    private readonly AppRuleEvaluator _evaluator;
    private readonly IReadOnlyList<IMonitorComponent> _components;

    private readonly ConcurrentDictionary<int, Tracked> _tracked = new();
    // Every pid already evaluated once (ETW and the backup poll both report starts; evaluate each pid once).
    private readonly ConcurrentDictionary<int, byte> _handled = new();
    // pid → monotonic ms of its kill (de-duplicates racing evaluations of one process)
    private readonly ConcurrentDictionary<int, long> _killedPids = new();
    private readonly Queue<BlockRecord> _recentBlocks = new();
    /// <summary>process.blocked: at most one event per (sid, exe) per 10 s, repeats folded into <c>count</c> (API.md §17).</summary>
    private readonly BlockEventFolder _blockedEvents;
    private static readonly string? OwnInstallDir = NullIfEmpty(AppContext.BaseDirectory.TrimEnd('\\'));
    private static readonly string? ProgramFilesDir = NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
    private long _blockCount;

    /// <summary>One enforcement (diagnostics).</summary>
    internal sealed record BlockRecord(DateTimeOffset At, string Sid, string Exe, int Pid, string Rule, bool Killed);
    private readonly ConcurrentDictionary<(string Sid, string Path), string?> _groupCache = new();
    private readonly ConcurrentDictionary<char, (bool Removable, long At)> _driveTypes = new();

    private readonly List<IProcessEventSource> _sources = [];
    private Timer? _sweep;

    /// <summary>"etw+poll" (ETW with the 1 s backup poll), "poll" (ETW unavailable), "poll (etw stopped)", "stopped".</summary>
    internal string SourceMode { get; private set; } = "stopped";
    internal string? SourceError { get; private set; }
    internal int PollIntervalMs { get; private set; }

    // Test seams (internal): process sources and the process list used by the rescan.
    internal Func<IProcessEventSource>? PrimarySourceFactory { get; set; }
    internal Func<int, IProcessEventSource>? PollSourceFactory { get; set; }
    internal Func<IEnumerable<int>>? ProcessIds { get; set; }
    private int _started;
    private readonly string? _windowsDir = NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    private readonly string[] _extraWritableRoots;
    private readonly UserWritableProbe _writable;

    public AppMonitor(IUserDirectory users, IPolicyProvider policy, IEventSink sink, IApprovalStore approvals,
        IClock clock, IServiceProvider services, IFileFacts facts, IProcessControl control, MonitoringOptions options,
        ILoggerFactory loggerFactory, ExecuteDenyAclLayer aclLayer)
        : this(users, policy, sink, approvals, clock, services, facts, control, options, loggerFactory, aclLayer, null)
    {
    }

    /// <summary>Tests pass <paramref name="components"/> (usually empty) instead of the real install/USB/download/ACL monitors.</summary>
    internal AppMonitor(IUserDirectory users, IPolicyProvider policy, IEventSink sink, IApprovalStore approvals,
        IClock clock, IServiceProvider services, IFileFacts facts, IProcessControl control, MonitoringOptions options,
        ILoggerFactory loggerFactory, ExecuteDenyAclLayer? aclLayer, IReadOnlyList<IMonitorComponent>? components)
    {
        _users = users;
        _policy = policy;
        _sink = sink;
        _approvals = approvals;
        _clock = clock;
        _services = services;
        _facts = facts;
        _control = control;
        _options = options;
        _loggerFactory = loggerFactory;
        _log = loggerFactory.CreateLogger<AppMonitor>();
        _evaluator = new AppRuleEvaluator(facts);
        _blockedEvents = new BlockEventFolder(sink, clock, options.BlockedEventPeriod);
        _writable = new UserWritableProbe(_log);

        var roots = new List<string>();
        if (_windowsDir is not null) roots.Add(Path.Combine(_windowsDir, "Temp"));
        var pub = NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments));
        if (pub is not null && Path.GetDirectoryName(pub) is { } publicRoot) roots.Add(publicRoot); // C:\Users\Public
        _extraWritableRoots = [.. roots];

        _components = components ??
        [
            new Installs.InstallWatcher(users, sink, options, loggerFactory.CreateLogger<Installs.InstallWatcher>(),
                onInstall: () => { try { _services.GetService<Inventory.InventoryService>()?.Trigger(); } catch { } }),
            new Usb.UsbWatcher(users, policy, sink, loggerFactory.CreateLogger<Usb.UsbWatcher>()),
            new Downloads.DownloadWatcher(users, policy, sink, options, loggerFactory.CreateLogger<Downloads.DownloadWatcher>()),
            aclLayer ?? throw new ArgumentNullException(nameof(aclLayer)),
        ];
    }

    // ------------------------------------------------------------------ lifecycle

    public Task StartAsync(CancellationToken ct)
    {
        if (Interlocked.Exchange(ref _started, 1) == 1) return Task.CompletedTask;

        _policy.PolicyChanged += OnPolicyChanged;
        StartSources();

        // Processes that were already running (service restart, user logged on before us).
        ThreadPool.UnsafeQueueUserWorkItem(_ => RescanAll(), null);

        _sweep = new Timer(_ => Sweep(), null, _options.GroupSweepInterval, _options.GroupSweepInterval);

        try { _services.GetService<Inventory.InventoryService>()?.Start(_services.GetService<MinControl.Core.Commands.CommandDispatcher>()); }
        catch (Exception ex) { _log.LogWarning(ex, "Inventory service failed to start"); }

        foreach (var c in _components)
        {
            try { c.Start(); }
            catch (Exception ex) { _log.LogError(ex, "Monitor component {Component} failed to start", c.GetType().Name); }
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// ETW (Kernel-Process, ~200 ms) as the primary source plus a process-list poll as a safety net: at
    /// <see cref="MonitoringOptions.BackupPollIntervalMs"/> (≤ 1 s) while ETW runs, at <see cref="MonitoringOptions.PollIntervalMs"/>
    /// when ETW cannot start. A pid reported by both is evaluated once. If the ETW session dies later the poll keeps going.
    /// </summary>
    private void StartSources()
    {
        var etwOk = false;
        var primary = PrimarySourceFactory?.Invoke() ?? new EtwProcessEventSource(_options, _loggerFactory.CreateLogger<EtwProcessEventSource>());
        try
        {
            Wire(primary);
            primary.Faulted += OnPrimaryFaulted;
            primary.Start();
            _sources.Add(primary);
            etwOk = true;
        }
        catch (Exception ex)
        {
            primary.Dispose();
            SourceError = ex.Message;
            _log.LogWarning(ex, "ETW process session unavailable, falling back to polling every {Ms} ms", _options.PollIntervalMs);
        }

        var interval = etwOk ? Math.Min(1000, Math.Max(100, _options.BackupPollIntervalMs)) : Math.Min(1000, Math.Max(100, _options.PollIntervalMs));
        var poll = PollSourceFactory?.Invoke(interval) ?? new PollingProcessEventSource(interval);
        try
        {
            Wire(poll);
            poll.Start();
            _sources.Add(poll);
            PollIntervalMs = interval;
        }
        catch (Exception ex)
        {
            poll.Dispose();
            _log.LogError(ex, "Process polling failed to start");
        }
        SourceMode = etwOk ? "etw+poll" : "poll";
        _log.LogInformation("Process monitor started: {Mode}, poll every {Ms} ms", SourceMode, PollIntervalMs);
    }

    private void Wire(IProcessEventSource source)
    {
        source.Started += s => ThreadPool.UnsafeQueueUserWorkItem(_ => SafeHandleStart(s, initial: false), null);
        source.Stopped += OnStopped;
    }

    private void OnPrimaryFaulted(Exception? ex)
    {
        SourceMode = "poll (etw stopped)";
        SourceError = ex?.Message ?? "ETW session ended";
    }

    public Task StopAsync()
    {
        if (Interlocked.Exchange(ref _started, 0) == 0) return Task.CompletedTask;
        _policy.PolicyChanged -= OnPolicyChanged;
        _sweep?.Dispose();
        try { _services.GetService<Inventory.InventoryService>()?.Stop(); } catch { }
        foreach (var s in _sources)
        {
            try { s.Dispose(); } catch (Exception ex) { _log.LogDebug(ex, "Disposing process source"); }
        }
        _sources.Clear();
        SourceMode = "stopped";
        try { _blockedEvents.FlushAll(); } catch (Exception ex) { _log.LogDebug(ex, "flush process.blocked"); }
        foreach (var c in _components)
        {
            try { c.Stop(); } catch (Exception ex) { _log.LogWarning(ex, "Stopping {Component}", c.GetType().Name); }
        }
        return Task.CompletedTask;
    }

    public void Dispose() => StopAsync().GetAwaiter().GetResult();

    // ------------------------------------------------------------------ IAppMonitor.GroupOf

    public string? GroupOf(string sid, string exePath)
    {
        if (string.IsNullOrEmpty(exePath)) return null;
        var up = UserPolicyFor(sid);
        if (up is null || up.AppGroups.Count == 0) return null;
        if (_groupCache.Count > 4096) _groupCache.Clear();
        return _groupCache.GetOrAdd((sid, exePath.ToUpperInvariant()),
            _ => _evaluator.GroupOf(up, exePath, Context(sid, withExhausted: false, pidHint: 0)));
    }

    // ------------------------------------------------------------------ process handling

    private void SafeHandleStart(ProcessStarted s, bool initial)
    {
        try { HandleStart(s, initial); }
        catch (Exception ex) { _log.LogWarning(ex, "Handling process {Pid}", s.Pid); }
    }

    private void HandleStart(ProcessStarted s, bool initial)
    {
        if (s.Pid <= 4) return;
        if (initial) _handled[s.Pid] = 0;
        else if (!_handled.TryAdd(s.Pid, 0)) return;   // already evaluated (the other source reported it first)
        var sid = _users.SidOfProcess(s.Pid);
        if (sid is null || !_users.IsManaged(sid)) return;          // I1: never touch other SIDs
        var up = UserPolicyFor(sid);
        if (up is null) return;

        var path = s.ImagePath ?? _control.ImagePath(s.Pid);
        if (string.IsNullOrEmpty(path)) return;

        var decision = _evaluator.Evaluate(up, path, Context(sid, withExhausted: true, pidHint: s.Pid));
        if (decision.IsBlock)
        {
            Block(s.Pid, s.ParentPid, sid, path, decision);
            return;
        }

        if (!_options.QuietExes.Contains(Path.GetFileName(path)))
            try { _services.GetService<Inventory.UsageLedger>()?.Touch(sid, path, _clock.UtcNow); } catch { /* inventory is best effort */ }

        bool emit = !initial && ShouldEmit(s.ParentPid, path);
        if (_tracked.TryAdd(s.Pid, new Tracked(s.Pid, s.ParentPid, sid, path, emit, _clock.MonotonicMs)) && emit)
            EmitProcess(EventTypes.ProcessStart, sid, path, s.Pid, s.ParentPid, rule: null, enrich: true);
    }

    /// <summary>Skip quiet system helpers and children with the same image as the parent
    /// (browser renderers, Electron helpers...) so process.* stays readable.</summary>
    private bool ShouldEmit(int parentPid, string path)
    {
        var exe = Path.GetFileName(path);
        if (_options.QuietExes.Contains(exe)) return false;
        if (parentPid > 0 && _tracked.TryGetValue(parentPid, out var parent)
            && string.Equals(Path.GetFileName(parent.Path), exe, StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    private void OnStopped(int pid)
    {
        _handled.TryRemove(pid, out _);
        _killedPids.TryRemove(pid, out _);
        if (_tracked.TryRemove(pid, out var t) && t.Emitted)
        {
            try { _sink.Emit(EventTypes.ProcessStop, t.Sid, EventData.Process(t.Path, t.Pid, t.ParentPid)); }
            catch (Exception ex) { _log.LogWarning(ex, "Emit process.stop"); }
        }
    }

    private void Block(int pid, int parentPid, string sid, string path, RuleDecision decision)
    {
        // The startup/policy rescan and the process sources can race on the same new pid: one kill (and one event) per
        // process. Cleared when the pid stops, so a reused pid is judged again.
        var nowMs = _clock.MonotonicMs;
        if (_killedPids.TryGetValue(pid, out var at) && nowMs - at < 5_000) return;
        _killedPids[pid] = nowMs;
        if (_killedPids.Count > 4096)
            foreach (var kv in _killedPids)
                if (nowMs - kv.Value > 60_000) _killedPids.TryRemove(kv.Key, out _);
        var sw = Stopwatch.StartNew();
        bool killed = _control.Terminate(pid, path);
        _tracked.TryRemove(pid, out _);
        _log.LogInformation("Blocked {Path} (pid {Pid}, rule {Rule}) for {Sid} killed={Killed} in {Ms} ms",
            path, pid, decision.Rule, sid, killed, sw.ElapsedMilliseconds);
        RecordBlock(sid, path, pid, decision.Rule ?? "unknown", killed);

        bool first = EmitBlocked(sid, path, pid, parentPid, decision, killed);

        if (decision.RequestApproval && decision.Sha256 is { } sha && MarkRequested(sid, sha))
            EmitProcess(EventTypes.RequestExeApproval, sid, path, pid, parentPid, rule: null, enrich: true);

        if (first) NotifyUser(sid, $"MinControl đã chặn {Path.GetFileName(path)}", BlockedReasonText(decision.Rule));
    }

    /// <summary>process.blocked (folded per sid+exe): action killed, rule (Vietnamese + machine id), service, window
    /// title when the blocked exe owns the foreground window. Never emitted when nothing was killed.
    /// Returns true when emitted now (first in its window).</summary>
    private bool EmitBlocked(string sid, string path, int pid, int parentPid, RuleDecision decision, bool killed)
    {
        if (!killed) return false;
        try
        {
            var sig = _facts.Signature(path);
            var data = BlockedData(path, pid, parentPid, decision, _facts.Sha256(path), sig.Publisher, sig.Signed, _facts.SizeBytes(path),
                ForegroundTitleOf(sid, path));
            return _blockedEvents.Record(EventTypes.ProcessBlocked, sid, sid + "|" + path.ToUpperInvariant(), data);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Emit process.blocked");
            return false;
        }
    }

    internal static System.Text.Json.Nodes.JsonObject BlockedData(string path, int pid, int parentPid, RuleDecision decision,
        string? sha, string? publisher, bool? signed, long? size, string? title)
    {
        var rule = decision.Rule ?? "unknown";
        var data = EventData.Process(path, pid, parentPid, sha, publisher, signed, size, rule);
        data["action"] = "killed";
        if (decision.Service is { } svc) data["service"] = svc;
        if (!string.IsNullOrWhiteSpace(title)) data["title"] = title.Length <= 256 ? title : title[..256];
        return data;
    }

    private string? ForegroundTitleOf(string sid, string path)
    {
        try
        {
            var fg = _services.GetService<IForegroundTracker>()?.Current(sid);
            return fg is { } f && string.Equals(f.ExePath, path, StringComparison.OrdinalIgnoreCase) ? f.Title : null;
        }
        catch { return null; }
    }

    /// <summary>Vietnamese reason line of the "blocked" toast for an app rule (<see cref="RuleDecision.Rule"/>).</summary>
    internal static string BlockedReasonText(string? rule) => rule switch
    {
        ExtensionMissingRule => "Tiện ích MinControl trong trình duyệt không chạy · hãy mở lại trình duyệt",
        "allowedBrowsers" => "Trình duyệt này không được phép",
        "approval" => "Bố mẹ không cho phép ứng dụng này",
        "newExecutable:ask" => "Ứng dụng mới · đang chờ bố mẹ duyệt",
        "newExecutable" => "Không được chạy ứng dụng mới",
        "appMode:allowlist" => "Chỉ được dùng các ứng dụng bố mẹ cho phép",
        { } r when r.StartsWith("service:", StringComparison.Ordinal) =>
            "Dịch vụ bị chặn: " + (MinControl.Core.Catalog.ServiceCatalog.Shared.Find(r["service:".Length..])?.Name ?? r["service:".Length..]),
        { } r when r.StartsWith("group:", StringComparison.Ordinal) => "Đã hết giờ dùng nhóm ứng dụng này hôm nay",
        _ => "Ứng dụng nằm trong danh sách chặn",
    };

    /// <summary>Persisted "request once per (sid, sha256)" (IApprovalStore.MarkRequested). On a store failure the
    /// request is sent anyway (a lost request would strand the child; the master de-duplicates alerts).</summary>
    private bool MarkRequested(string sid, string sha)
    {
        try { return _approvals.MarkRequested(sid, sha); }
        catch (Exception ex) { _log.LogWarning(ex, "MarkRequested failed"); return true; }
    }

    private void EmitProcess(string type, string sid, string path, int pid, int parentPid, string? rule, bool enrich)
    {
        try
        {
            string? sha = null, publisher = null;
            bool? signed = null;
            long? size = null;
            if (enrich)
            {
                size = _facts.SizeBytes(path);
                sha = _facts.Sha256(path);
                var sig = _facts.Signature(path);
                signed = sig.Signed;
                publisher = sig.Publisher;
            }
            _sink.Emit(type, sid, EventData.Process(path, pid, parentPid, sha, publisher, signed, size, rule));
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Emit {Type}", type);
        }
    }

    private void NotifyUser(string sid, string title, string reason)
    {
        var actions = _services.GetService<ISessionActions>();
        if (actions is null) return;
        _ = Task.Run(async () =>
        {
            try { await actions.ShowBlockedNoticeAsync(sid, title, reason, CancellationToken.None); }
            catch { /* best effort */ }
        });
    }

    // ------------------------------------------------------------------ periodic / policy re-evaluation

    private void Sweep()
    {
        SweepExhaustedGroups();
        SweepMissingExtension();
    }

    internal const string ExtensionMissingRule = "extensionMissing";

    /// <summary>SPEC §8.5 / ROUND2 B.3: while the MinControl extension is missing in a managed user's msedge/chrome
    /// (no heartbeat, <see cref="IExtensionHealth"/>), that browser is blocked for the user. Grace: the browser may run
    /// <see cref="MonitoringOptions.ExtensionMissingGrace"/> after its oldest tracked process appeared, so every fresh
    /// start gets time for the extension to load.</summary>
    private void SweepMissingExtension()
    {
        try
        {
            var health = _services.GetService<IExtensionHealth>();
            if (health is null) return;
            long now = _clock.MonotonicMs;
            long graceMs = (long)_options.ExtensionMissingGrace.TotalMilliseconds;
            var groups = _tracked.Values
                .Select(t => (Tracked: t, Browser: BrowserKey(t.Path)))
                .Where(x => x.Browser is not null)
                .GroupBy(x => (x.Tracked.Sid, Browser: x.Browser!))
                .ToList();
            foreach (var group in groups)
            {
                var (sid, browser) = group.Key;
                if (!_users.IsManaged(sid)) continue;
                if (now - group.Min(x => x.Tracked.SeenAtMs) < graceMs) continue;
                if (!health.IsExtensionMissing(sid, browser)) continue;
                var decision = new RuleDecision(Verdict.Block, ExtensionMissingRule);
                bool notified = false;
                // oldest (the browser main process) first: killing it takes its children with it
                foreach (var x in group.OrderBy(x => x.Tracked.SeenAtMs))
                {
                    if (!_tracked.ContainsKey(x.Tracked.Pid)) continue;
                    BlockQuiet(x.Tracked, decision, notify: !notified);
                    notified = true;
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Extension sweep failed");
        }
    }

    private void BlockQuiet(Tracked t, RuleDecision decision, bool notify)
    {
        if (notify) { Block(t.Pid, t.ParentPid, t.Sid, t.Path, decision); return; }
        var killed = _control.Terminate(t.Pid, t.Path);
        _tracked.TryRemove(t.Pid, out _);
        RecordBlock(t.Sid, t.Path, t.Pid, decision.Rule ?? "unknown", killed);
        EmitBlocked(t.Sid, t.Path, t.Pid, t.ParentPid, decision, killed);   // folded with the main process event
    }

    private void RecordBlock(string sid, string path, int pid, string rule, bool killed)
    {
        Interlocked.Increment(ref _blockCount);
        lock (_recentBlocks)
        {
            _recentBlocks.Enqueue(new BlockRecord(_clock.UtcNow, sid, Path.GetFileName(path), pid, rule, killed));
            while (_recentBlocks.Count > 50) _recentBlocks.Dequeue();
        }
    }

    /// <summary>Most recent first (diagnostics).</summary>
    internal IReadOnlyList<BlockRecord> RecentBlocks()
    {
        lock (_recentBlocks) return _recentBlocks.Reverse().ToList();
    }

    internal long BlockCount => Interlocked.Read(ref _blockCount);

    /// <summary>Tracked (allowed, running) managed processes per SID (diagnostics).</summary>
    internal IReadOnlyDictionary<string, int> TrackedPerSid() =>
        _tracked.Values.GroupBy(t => t.Sid).ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

    /// <summary>"msedge" / "chrome" for those images, else null (browser names used by IExtensionHealth).</summary>
    internal static string? BrowserKey(string path) => Path.GetFileName(path).ToLowerInvariant() switch
    {
        "msedge.exe" => "msedge",
        "chrome.exe" => "chrome",
        _ => null,
    };

    private void SweepExhaustedGroups()
    {
        try
        {
            var engine = _services.GetService<IScreenTimeEngine>();
            if (engine is null) return;
            var now = _clock.UtcNow;
            foreach (var bySid in _tracked.Values.GroupBy(t => t.Sid))
            {
                if (!_users.IsManaged(bySid.Key)) continue;
                var exhausted = engine.ExhaustedGroups(bySid.Key, now);
                if (exhausted.Count == 0) continue;
                foreach (var t in bySid)
                {
                    var g = GroupOf(t.Sid, t.Path);
                    if (g is not null && exhausted.Contains(g))
                        Block(t.Pid, t.ParentPid, t.Sid, t.Path, new RuleDecision(Verdict.Block, "group:" + g));
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Group sweep failed");
        }
    }

    private void OnPolicyChanged(object? sender, DevicePolicy policy)
    {
        _groupCache.Clear();
        _writable.Invalidate();
        ThreadPool.UnsafeQueueUserWorkItem(_ => RescanAll(), null);
    }

    /// <summary>Evaluates every running process (startup, policy change, user newly managed).</summary>
    private void RescanAll()
    {
        List<int> pids;
        try { pids = (ProcessIds ?? AllProcessIds)().ToList(); }
        catch (Exception ex) { _log.LogWarning(ex, "Process enumeration failed"); return; }

        foreach (var pid in pids)
        {
            if (_tracked.TryGetValue(pid, out var t))
            {
                // re-evaluate already tracked processes against the new rules
                if (!_users.IsManaged(t.Sid)) { _tracked.TryRemove(pid, out _); continue; }
                var up = UserPolicyFor(t.Sid);
                if (up is null) continue;
                var d = _evaluator.Evaluate(up, t.Path, Context(t.Sid, withExhausted: true, pidHint: t.Pid));
                if (d.IsBlock) Block(t.Pid, t.ParentPid, t.Sid, t.Path, d);
                continue;
            }
            SafeHandleStart(new ProcessStarted(pid, 0, null), initial: true);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static IEnumerable<int> AllProcessIds()
    {
        var procs = Process.GetProcesses();
        var ids = new List<int>(procs.Length);
        foreach (var p in procs) { ids.Add(p.Id); p.Dispose(); }
        return ids;
    }

    private UserPolicy? UserPolicyFor(string sid)
        => _policy.Current?.Users is { } users && users.TryGetValue(sid, out var up) ? up : null;

    private EvaluationContext Context(string sid, bool withExhausted, int pidHint)
    {
        IReadOnlyCollection<string> exhausted = [];
        if (withExhausted)
        {
            try { exhausted = _services.GetService<IScreenTimeEngine>()?.ExhaustedGroups(sid, _clock.UtcNow) ?? []; }
            catch (Exception ex) { _log.LogDebug(ex, "ExhaustedGroups failed"); }
        }
        return new EvaluationContext
        {
            Sid = sid,
            ProfilePath = _users.ProfilePath(sid),
            ExhaustedGroups = exhausted,
            ExtraUserWritableRoots = _extraWritableRoots,
            IsRemovableOrNetwork = IsRemovableOrNetwork,
            IsUserWritableByAcl = path => _writable.IsUserWritable(sid, path, pidHint),
            ApprovalFor = sha => _approvals.DecisionFor(sid, sha),
            WindowsDir = _windowsDir,
            OwnInstallDir = OwnInstallDir,
            ProgramFilesDir = ProgramFilesDir,
        };
    }

    private bool IsRemovableOrNetwork(string path)
    {
        if (path.Length < 3 || path[1] != ':') return false;
        char letter = char.ToUpperInvariant(path[0]);
        long now = Environment.TickCount64;
        if (_driveTypes.TryGetValue(letter, out var c) && now - c.At < 30_000) return c.Removable;
        bool removable;
        try
        {
            var type = new DriveInfo(letter + ":\\").DriveType;
            removable = type is DriveType.Removable or DriveType.Network or DriveType.CDRom;
        }
        catch { removable = false; }
        _driveTypes[letter] = (removable, now);
        return removable;
    }

    private static string? NullIfEmpty(string s) => string.IsNullOrEmpty(s) ? null : s;
}
