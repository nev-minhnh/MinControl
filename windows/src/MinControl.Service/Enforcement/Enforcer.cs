using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policy;
using MinControl.Service.Ipc;
using MinControl.Service.Logic;
using MinControl.Service.Native;
using MinControl.Service.Sessions;
using MinControl.Service.Users;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MinControl.Service.Enforcement;

/// <summary>1 s enforcement loop (spec 8.2): usage accounting for the active, unlocked console session of a
/// managed user, warnings, quota events, overlay + logoff, exhausted-group process kills, usage.tick and
/// interval screenshots. Only managed SIDs are ever looked at (I1/I2).</summary>
internal sealed class Enforcer(
    SessionTracker sessions,
    UserDirectory users,
    SessionChannelRegistry channels,
    SessionActions actions,
    IForegroundTracker foreground,
    IPolicyProvider policyProvider,
    IScreenTimeEngine engine,
    IEventSink events,
    IClock clock,
    IServiceProvider services,
    ILogger<Enforcer> log,
    IStateChangeNotifier? stateNotifier = null) : BackgroundService
{
    private const long GroupCheckMs = 5_000, OverlayRefreshMs = 5_000, MaxTickDeltaMs = 2_000;

    private sealed class UserState
    {
        public readonly WarningScheduler Warnings = new();
        public readonly UsageAggregator Usage = new();
        public bool TotalExhaustedSent;
        public string? LastForegroundExe;
        public HashSet<string> ExhaustedGroups = new(StringComparer.Ordinal);
        public long LastGroupCheckMono = long.MinValue / 2;
        public long LastScreenshotMono;
        public int ScreenshotInFlight;
    }

    private sealed class SessionState
    {
        public readonly LockoutTracker Lockout = new();
        public long LastOverlayMono;
        public string Reason = "";
    }

    private readonly Dictionary<string, UserState> _users = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, SessionState> _sessions = new();
    private long _lastTickMono;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Yield();
        sessions.EnsureInitialized();
        _lastTickMono = clock.MonotonicMs;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try { await TickAsync(ct).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { log.LogError(e, "enforcer tick failed"); }
        }
    }

    private async Task TickAsync(CancellationToken ct)
    {
        var now = clock.MonotonicMs;
        var delta = Math.Clamp(now - _lastTickMono, 0, MaxTickDeltaMs); // sleep/hibernate never counts
        _lastTickMono = now;
        var utc = clock.UtcNow;
        var policy = policyProvider.Current;
        var live = new HashSet<int>();
        if (policy is null) { _sessions.Clear(); return; }

        var console = sessions.ActiveConsoleSessionId;
        var countedSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in sessions.Sessions)
        {
            if (s.Sid is not { } sid || !users.IsManaged(sid) || !policy.Users.TryGetValue(sid, out var user)) continue;
            live.Add(s.SessionId);
            if (!_users.TryGetValue(sid, out var us)) _users[sid] = us = new UserState { LastScreenshotMono = now };
            if (!_sessions.TryGetValue(s.SessionId, out var ss)) _sessions[s.SessionId] = ss = new SessionState();

            (string ExePath, string? Title, bool Idle)? fg = null;
            if (s.SessionId == console && !s.Locked && countedSids.Add(sid))
            {
                fg = foreground.Current(sid);
                if (!string.Equals(us.LastForegroundExe, fg?.ExePath, StringComparison.OrdinalIgnoreCase))
                {
                    us.LastForegroundExe = fg?.ExePath;
                    stateNotifier?.Notify(); // foreground app changed
                }
                // Helper silent => count anyway (fail closed); idle => count only when countIdle.
                var counting = fg is null || user.ScreenTime.CountIdle || !fg.Value.Idle;
                if (counting && delta > 0) engine.RecordUsage(sid, fg?.ExePath, delta);
                if (fg is { Idle: false } f)
                    EmitUsage(sid, us.Usage.Add(utc, Path.GetFileName(f.ExePath),
                        user.Monitoring.ForegroundTitles ? f.Title : null, delta), user);
                MaybeScreenshot(sid, user, us, fg, now, ct);
            }
            EmitUsage(sid, us.Usage.Add(utc, "", null, 0), user); // flushes on minute rollover

            var state = engine.Evaluate(sid, utc);
            await HandleQuotaAsync(sid, user, us, state, ct).ConfigureAwait(false);
            await HandleLockoutAsync(s, sid, user, ss, state, now, ct).ConfigureAwait(false);
            if (now - us.LastGroupCheckMono >= GroupCheckMs)
            {
                us.LastGroupCheckMono = now;
                HandleGroups(s.SessionId, sid, us, utc, ct);
            }
        }

        foreach (var id in _sessions.Keys.Where(id => !live.Contains(id)).ToList()) _sessions.Remove(id);
        var liveSids = sessions.Sessions.Select(s => s.Sid).Where(x => x is not null).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var sid in _users.Keys.Where(k => !liveSids.Contains(k)).ToList())
        {
            if (policy.Users.TryGetValue(sid, out var u)) EmitUsage(sid, _users[sid].Usage.Flush(), u);
            _users.Remove(sid);
        }
    }

    private async Task HandleQuotaAsync(string sid, UserPolicy user, UserState us, ScreenTimeState state, CancellationToken ct)
    {
        var warn = us.Warnings.Update(user.ScreenTime.WarnAtMin, state.Allowed ? state.RemainingMin : null);
        if (warn is int remaining)
        {
            stateNotifier?.Notify(); // quota threshold crossed
            await actions.ShowWarningAsync(sid, remaining, ct).ConfigureAwait(false);
            events.Emit(EventTypes.QuotaWarning, sid, new JsonObject { ["scope"] = "total", ["remainingMin"] = remaining });
        }
        var exhausted = state.Reason == "quota_exhausted";
        if (exhausted != us.TotalExhaustedSent) stateNotifier?.Notify();
        if (exhausted && !us.TotalExhaustedSent)
            events.Emit(EventTypes.QuotaExhausted, sid, new JsonObject { ["scope"] = "total", ["remainingMin"] = 0 });
        us.TotalExhaustedSent = exhausted;
    }

    private async Task HandleLockoutAsync(SessionSnapshot s, string sid, UserPolicy user, SessionState ss,
        ScreenTimeState state, long now, CancellationToken ct)
    {
        var action = ss.Lockout.Update(state.Allowed, state.Reason, user.ScreenTime.GraceSec, now, s.LogonMono);
        var channel = channels.TryGet(s.SessionId);
        switch (action.Kind)
        {
            case LockoutKind.ShowOverlay:
                ss.Reason = action.Reason;
                ss.LastOverlayMono = now;
                log.LogInformation("session {Session}: not allowed ({Reason}), logoff in {Sec}s", s.SessionId, action.Reason, action.SecondsLeft);
                if (channel is not null) await channel.SendAsync(Overlay(action.Reason, action.SecondsLeft), ct).ConfigureAwait(false);
                break;
            case LockoutKind.ClearOverlay:
                ss.Reason = "";
                if (channel is not null) await channel.SendAsync(IpcMessage.Of(IpcTypes.ClearOverlay), ct).ConfigureAwait(false);
                break;
            case LockoutKind.Logoff:
                if (!users.IsManaged(sid)) break; // re-check right before acting (I2)
                log.LogInformation("session {Session}: logoff ({Reason})", s.SessionId, action.Reason);
                if (!Wts.Logoff(s.SessionId))
                    log.LogError("WTSLogoffSession({Session}) failed: {Err}", s.SessionId, Marshal.GetLastWin32Error());
                break;
            default:
                // Re-send while active so a restarted helper shows the overlay again with the right countdown.
                if (ss.Lockout.Active && channel is not null && now - ss.LastOverlayMono >= OverlayRefreshMs)
                {
                    ss.LastOverlayMono = now;
                    await channel.SendAsync(Overlay(ss.Reason, ss.Lockout.SecondsUntilDeadline(now)), ct).ConfigureAwait(false);
                }
                break;
        }
    }

    private static IpcMessage Overlay(string reason, int seconds) =>
        IpcMessage.Of(IpcTypes.LockOverlay, new JsonObject { ["reason"] = reason, ["graceSec"] = seconds });

    private void HandleGroups(int sessionId, string sid, UserState us, DateTimeOffset utc, CancellationToken ct)
    {
        var exhausted = engine.ExhaustedGroups(sid, utc).ToHashSet(StringComparer.Ordinal);
        foreach (var g in exhausted.Where(g => !us.ExhaustedGroups.Contains(g)))
            events.Emit(EventTypes.QuotaExhausted, sid, new JsonObject { ["scope"] = $"group:{g}", ["remainingMin"] = 0 });
        us.ExhaustedGroups = exhausted;
        if (exhausted.Count == 0) return;

        // Group membership is decided by Monitoring (publisher/hash/path rules); without it we cannot match.
        var monitor = services.GetService<IAppMonitor>();
        if (monitor is null) return;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.SessionId != sessionId) continue;
                using var h = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, p.Id);
                if (h.IsInvalid) continue;
                var path = Win32.ImagePath(h);
                if (path is null || monitor.GroupOf(sid, path) is not { } group || !exhausted.Contains(group)) continue;
                _ = actions.KillProcessAsync(sid, p.Id, path, ct); // verifies owner SID on the same handle
            }
        }
    }

    private void EmitUsage(string sid, IReadOnlyList<UsageTickRecord> ticks, UserPolicy user)
    {
        if (ticks.Count == 0) return;
        var monitor = services.GetService<IAppMonitor>();
        foreach (var t in ticks)
        {
            var data = new JsonObject
            {
                ["minuteStart"] = t.MinuteStart.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture),
                ["activeSec"] = t.ActiveSec,
                ["exe"] = t.Exe.Length > 260 ? t.Exe[..260] : t.Exe,
            };
            if (user.Monitoring.ForegroundTitles && !string.IsNullOrEmpty(t.Title))
                data["title"] = t.Title.Length > 512 ? t.Title[..512] : t.Title;
            if (monitor?.GroupOf(sid, t.Exe) is { } group) data["group"] = group;
            events.Emit(EventTypes.UsageTick, sid, data);
        }
    }

    private void MaybeScreenshot(string sid, UserPolicy user, UserState us,
        (string ExePath, string? Title, bool Idle)? fg, long now, CancellationToken ct)
    {
        var shots = user.Monitoring.Screenshots;
        if (shots.IntervalMin <= 0 || now - us.LastScreenshotMono < shots.IntervalMin * 60_000L) return;
        if (shots.OnlyWhenActive && fg is not { Idle: false }) return;
        if (services.GetService<IScreenshotUploader>() is not { } uploader) return;
        if (Interlocked.CompareExchange(ref us.ScreenshotInFlight, 1, 0) != 0) return;
        us.LastScreenshotMono = now;
        _ = Task.Run(async () =>
        {
            try
            {
                var frame = await actions.CaptureFrameAsync(sid, shots.MaxWidth, shots.JpegQuality, ct).ConfigureAwait(false);
                if (frame is not null)
                    await uploader.UploadAsync(sid, frame.Jpeg, frame.Width, frame.Height, "interval", null,
                        fg is { } f ? Path.GetFileName(f.ExePath) : null, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is not OperationCanceledException) { log.LogWarning(e, "interval screenshot failed"); }
            finally { Interlocked.Exchange(ref us.ScreenshotInFlight, 0); }
        }, ct);
    }
}
