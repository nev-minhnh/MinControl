using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Cloud;
using MinControl.Service.Ipc;
using MinControl.Service.Logic;
using MinControl.Service.Native;
using MinControl.Service.Users;
using Microsoft.Extensions.Logging;

namespace MinControl.Service.Sessions;

/// <summary>ISessionActions on top of WTS + the session-helper pipes. Every action is refused for SIDs that
/// are not managed (I1/I2), so commands or bugs can never touch an administrator or another user.</summary>
internal sealed class SessionActions(
    SessionTracker sessions,
    UserDirectory users,
    SessionChannelRegistry channels,
    ILogger<SessionActions> log) : ISessionActions
{
    public static readonly TimeSpan CaptureTimeout = TimeSpan.FromSeconds(15);

    public Task LogoffAsync(string sid, string reason, CancellationToken ct)
    {
        if (!Guard(sid, "logoff")) return Task.CompletedTask;
        foreach (var id in sessions.SessionsOf(sid))
        {
            log.LogInformation("logoff session {Session} ({Reason})", id, reason);
            if (!Wts.Logoff(id)) log.LogError("WTSLogoffSession({Session}) failed: {Err}", id, Marshal.GetLastWin32Error());
        }
        return Task.CompletedTask;
    }

    public Task ShowWarningAsync(string sid, int remainingMin, CancellationToken ct) =>
        Broadcast(sid, IpcMessage.Of(IpcTypes.Warning, new JsonObject { ["remainingMin"] = Math.Max(0, remainingMin) }), ct);

    public Task ShowLockOverlayAsync(string sid, string reason, int graceSec, CancellationToken ct) =>
        Broadcast(sid, IpcMessage.Of(IpcTypes.LockOverlay, new JsonObject { ["reason"] = reason, ["graceSec"] = Math.Max(0, graceSec) }), ct);

    public Task ClearOverlayAsync(string sid, CancellationToken ct) => Broadcast(sid, IpcMessage.Of(IpcTypes.ClearOverlay), ct);

    public Task ShowMessageAsync(string sid, string text, CancellationToken ct) =>
        Broadcast(sid, IpcMessage.Of(IpcTypes.Message, new JsonObject { ["text"] = text.Length > 2000 ? text[..2000] : text }), ct);

    public Task<bool> KillProcessAsync(string sid, int pid, string? expectedExe, CancellationToken ct)
    {
        if (!Guard(sid, "kill")) return Task.FromResult(false);
        // One handle for check + kill: no PID-reuse race between verifying the owner and terminating.
        using var h = Win32.OpenProcess(Win32.PROCESS_TERMINATE | Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return Task.FromResult(false);
        if (!string.Equals(UserDirectory.SidOfProcess(h), sid, StringComparison.OrdinalIgnoreCase))
        {
            log.LogWarning("kill refused: pid {Pid} does not belong to {Sid}", pid, sid);
            return Task.FromResult(false);
        }
        var path = Win32.ImagePath(h);
        if (expectedExe is not null && !ExeMatches(path, expectedExe))
        {
            log.LogWarning("kill refused: pid {Pid} is {Path}, expected {Exe}", pid, path, expectedExe);
            return Task.FromResult(false);
        }
        var ok = Win32.TerminateProcess(h, 1);
        log.LogInformation("kill pid {Pid} ({Path}) of {Sid}: {Ok}", pid, path, sid, ok);
        return Task.FromResult(ok);
    }

    public static bool ExeMatches(string? path, string expected) =>
        path is not null && (string.Equals(path, expected, StringComparison.OrdinalIgnoreCase)
            || string.Equals(Path.GetFileName(path), Path.GetFileName(expected), StringComparison.OrdinalIgnoreCase));

    public async Task<ScreenCapture?> CaptureScreenAsync(string? sid, int maxWidth, int jpegQuality, CancellationToken ct) =>
        await CaptureFrameAsync(sid, maxWidth, jpegQuality, ct).ConfigureAwait(false) is { } f
            ? new ScreenCapture(f.Jpeg, f.Width, f.Height) : null;

    /// <summary>Captures the managed user's session (null sid = the active console session, only if it is managed).</summary>
    public async Task<CaptureFrame?> CaptureFrameAsync(string? sid, int maxWidth, int jpegQuality, CancellationToken ct)
    {
        var sessionId = ResolveCaptureSession(sid);
        if (sessionId is null) return null;
        var channel = channels.TryGet(sessionId.Value);
        return channel is null ? null : await channel.CaptureAsync(maxWidth, jpegQuality, CaptureTimeout, ct).ConfigureAwait(false);
    }

    private int? ResolveCaptureSession(string? sid)
    {
        var console = sessions.ActiveConsoleSessionId;
        if (sid is null)
        {
            var s = sessions.Get(console);
            return s?.Sid is not null && users.IsManaged(s.Sid) ? console : null;
        }
        if (!Guard(sid, "capture")) return null;
        var ids = sessions.SessionsOf(sid);
        return ids.Contains(console) ? console : ids.Count > 0 ? ids[0] : null;
    }

    private async Task Broadcast(string sid, IpcMessage message, CancellationToken ct)
    {
        if (!Guard(sid, message.Type)) return;
        foreach (var id in sessions.SessionsOf(sid))
        {
            var channel = channels.TryGet(id);
            if (channel is null || !await channel.SendAsync(message, ct).ConfigureAwait(false))
                log.LogDebug("{Type} not delivered to session {Session}", message.Type, id);
        }
    }

    private bool Guard(string sid, string action)
    {
        if (users.IsManaged(sid)) return true;
        log.LogWarning("{Action} refused for unmanaged/admin SID {Sid}", action, sid);
        return false;
    }
}

/// <summary>IForegroundTracker fed by the helper pipe of the user's (preferably console) session.</summary>
internal sealed class ForegroundTracker(
    SessionTracker sessions,
    SessionChannelRegistry channels,
    IPolicyProvider policy,
    IClock clock) : IForegroundTracker, IForegroundSince
{
    public (string ExePath, string? Title, bool Idle)? Current(string sid) =>
        Snapshot(sid) is { } s ? (s.Info.ExePath, s.Info.Title, s.Idle) : null;

    public DateTimeOffset? ForegroundStartedAt(string sid) => Snapshot(sid)?.Info.StartedUtc;

    private (ForegroundInfo Info, bool Idle)? Snapshot(string sid)
    {
        var ids = sessions.SessionsOf(sid);
        if (ids.Count == 0) return null;
        var console = sessions.ActiveConsoleSessionId;
        var channel = channels.TryGet(ids.Contains(console) ? console : ids[0]);
        if (channel is null || !channel.Connected || clock.MonotonicMs - channel.LastSeenMono > HelperSupervisor.StaleMs)
            return null;
        var fg = channel.Foreground;
        if (fg is null) return null;
        var thresholdSec = policy.Current?.Users.GetValueOrDefault(sid)?.ScreenTime.IdleThresholdSec ?? 300;
        var idle = channel.IdleMs >= Math.Max(1, thresholdSec) * 1000L;
        return (fg, idle);
    }
}
