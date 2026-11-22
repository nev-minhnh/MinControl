using System.Collections.Concurrent;
using System.Diagnostics;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policy;
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
    private readonly ConcurrentDictionary<(string Sid, string Path), string?> _groupCache = new();
    private readonly ConcurrentDictionary<char, (bool Removable, long At)> _driveTypes = new();

    private IProcessEventSource? _source;
    private Timer? _sweep;
    private int _started;
    private readonly string? _windowsDir = NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    private readonly string[] _extraWritableRoots;
    private readonly UserWritableProbe _writable;

    public AppMonitor(IUserDirectory users, IPolicyProvider policy, IEventSink sink, IApprovalStore approvals,
        IClock clock, IServiceProvider services, IFileFacts facts, IProcessControl control, MonitoringOptions options,
        ILoggerFactory loggerFactory, ExecuteDenyAclLayer aclLayer)
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
        _writable = new UserWritableProbe(_log);

        var roots = new List<string>();
        if (_windowsDir is not null) roots.Add(Path.Combine(_windowsDir, "Temp"));
        var pub = NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments));
        if (pub is not null && Path.GetDirectoryName(pub) is { } publicRoot) roots.Add(publicRoot); // C:\Users\Public
        _extraWritableRoots = [.. roots];

        _components =
        [
            new Installs.InstallWatcher(users, sink, options, loggerFactory.CreateLogger<Installs.InstallWatcher>(),
                onInstall: () => { try { _services.GetService<Inventory.InventoryService>()?.Trigger(); } catch { } }),
            new Usb.UsbWatcher(users, policy, sink, loggerFactory.CreateLogger<Usb.UsbWatcher>()),
            new Downloads.DownloadWatcher(users, policy, sink, options, loggerFactory.CreateLogger<Downloads.DownloadWatcher>()),
            aclLayer,
        ];
    }

    // ------------------------------------------------------------------ lifecycle

    public Task StartAsync(CancellationToken ct)
    {
        if (Interlocked.Exchange(ref _started, 1) == 1) return Task.CompletedTask;

        _policy.PolicyChanged += OnPolicyChanged;
        _source = CreateSource();
        _source.Started += s => ThreadPool.UnsafeQueueUserWorkItem(_ => SafeHandleStart(s, initial: false), null);
        _source.Stopped += OnStopped;

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

    private IProcessEventSource CreateSource()
    {
        var etw = new EtwProcessEventSource(_options, _loggerFactory.CreateLogger<EtwProcessEventSource>());
        try
        {
            etw.Start();
            return etw;
        }
        catch (Exception ex)
        {
            etw.Dispose();
            _log.LogWarning(ex, "ETW process session unavailable, falling back to polling");
            var poll = new PollingProcessEventSource(_options);
            poll.Start();
            return poll;
        }
    }

    public Task StopAsync()
    {
        if (Interlocked.Exchange(ref _started, 0) == 0) return Task.CompletedTask;
        _policy.PolicyChanged -= OnPolicyChanged;
        _sweep?.Dispose();
        try { _services.GetService<Inventory.InventoryService>()?.Stop(); } catch { }
        _source?.Dispose();
        _source = null;
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
        if (_tracked.TryRemove(pid, out var t) && t.Emitted)
        {
            try { _sink.Emit(EventTypes.ProcessStop, t.Sid, EventData.Process(t.Path, t.Pid, t.ParentPid)); }
            catch (Exception ex) { _log.LogWarning(ex, "Emit process.stop"); }
        }
    }

    private void Block(int pid, int parentPid, string sid, string path, RuleDecision decision)
    {
        var sw = Stopwatch.StartNew();
        bool killed = _control.Terminate(pid, path);
        _tracked.TryRemove(pid, out _);
        _log.LogInformation("Blocked {Path} (pid {Pid}, rule {Rule}) killed={Killed} in {Ms} ms",
            path, pid, decision.Rule, killed, sw.ElapsedMilliseconds);

        EmitProcess(EventTypes.ProcessBlocked, sid, path, pid, parentPid, decision.Rule ?? "unknown", enrich: true);

        if (decision.RequestApproval && decision.Sha256 is { } sha && MarkRequested(sid, sha))
            EmitProcess(EventTypes.RequestExeApproval, sid, path, pid, parentPid, rule: null, enrich: true);

        var exe = Path.GetFileName(path);
        NotifyUser(sid, decision.Rule == ExtensionMissingRule
            ? $"\"{exe}\" bị chặn vì tiện ích MinControl trong trình duyệt không hoạt động. Hãy mở lại trình duyệt; nếu vẫn bị chặn, hãy báo bố mẹ."
            : $"\"{exe}\" bị chặn bởi MinControl.");
    }

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

    private void NotifyUser(string sid, string text)
    {
        var actions = _services.GetService<ISessionActions>();
        if (actions is null) return;
        _ = Task.Run(async () =>
        {
            try { await actions.ShowMessageAsync(sid, text, CancellationToken.None); }
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
        _control.Terminate(t.Pid, t.Path);
        _tracked.TryRemove(t.Pid, out _);
    }

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
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch (Exception ex) { _log.LogWarning(ex, "Process enumeration failed"); return; }

        foreach (var p in procs)
        {
            int pid = p.Id;
            p.Dispose();
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
