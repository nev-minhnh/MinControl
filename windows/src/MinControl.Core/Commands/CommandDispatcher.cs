using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Crypto;
using MinControl.Core.Diagnostics;
using MinControl.Core.Policies;
using MinControl.Core.Protocol;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.Commands;

/// <summary>
/// Executes verified command envelopes (SPEC §6) and returns the <see cref="CommandAck"/> (command-ack.schema.json).
/// Overrides (lock/unlock/add_time/pause) are written to state.db and picked up by the screen-time engine; the
/// Service enforcer turns the resulting state into overlays/logoff. Commands naming an unmanaged or admin SID are
/// rejected with <c>unmanaged_user</c> (I1/I2).
/// </summary>
public sealed class CommandDispatcher
{
    private readonly StateStore _store;
    private readonly PolicyProvider _policy;
    private readonly IClock _clock;
    private readonly IApprovalStore _approvals;
    private readonly Func<ISessionActions?> _session;
    private readonly Func<IScreenshotUploader?> _uploader;
    private readonly Func<IUserDirectory?> _users;
    private readonly Func<IForegroundTracker?> _foreground;
    private readonly Func<DiagnosticsCollector?> _diagnostics;
    private readonly ILogger _log;

    public CommandDispatcher(StateStore store, PolicyProvider policy, IClock clock, IApprovalStore approvals,
        Func<ISessionActions?>? session = null, Func<IScreenshotUploader?>? uploader = null,
        Func<IUserDirectory?>? users = null, Func<IForegroundTracker?>? foreground = null, ILogger<CommandDispatcher>? log = null,
        Func<DiagnosticsCollector?>? diagnostics = null)
    {
        _store = store; _policy = policy; _clock = clock; _approvals = approvals;
        _session = session ?? (() => null);
        _uploader = uploader ?? (() => null);
        _users = users ?? (() => null);
        _foreground = foreground ?? (() => null);
        _diagnostics = diagnostics ?? (() => null);
        _log = log ?? (ILogger)NullLogger.Instance;
    }

    /// <summary>A <c>refresh</c> command arrived: flush the outbox and send state now.</summary>
    public event Action? RefreshRequested;
    /// <summary>Overrides changed (lock/unlock/add_time/pause): device state should be re-sent.</summary>
    public event Action? StateChanged;

    public CommandAck Reject(string commandId, string status, string error, string? detail = null) =>
        new(commandId, status, Time.Utc(_clock.UtcNow), error, detail is null ? null : PolicyParser.Trim(detail));

    public CommandAck Applied(string commandId) => new(commandId, "applied", Time.Utc(_clock.UtcNow));

    public async Task<CommandAck> DispatchAsync(VerifiedEnvelope env, CancellationToken ct)
    {
        Command? cmd;
        try { cmd = env.Body.Body.Deserialize<Command>(PolicyParser.StrictOptions); }
        catch (Exception e) when (e is JsonException or NotSupportedException)
        {
            var id = env.Body.Body.TryGetProperty("commandId", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString()! : "";
            return Reject(id, "rejected", VerifyErrors.InvalidBody, e.Message);
        }
        if (cmd is null) return Reject("", "rejected", VerifyErrors.InvalidBody, "empty command");

        try
        {
            return await ExecuteAsync(cmd, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception e)
        {
            _log.LogError(e, "command {Type} {Id} failed", cmd.GetType().Name, cmd.CommandId);
            return Reject(cmd.CommandId, "failed", VerifyErrors.Internal, e.Message);
        }
    }

    private bool IsManaged(string sid)
    {
        if (_policy.ForUser(sid) is null) return false;
        var dir = _users();
        return dir is null || (dir.IsManaged(sid) && !dir.IsAdministrator(sid));
    }

    private async Task<CommandAck> ExecuteAsync(Command cmd, CancellationToken ct)
    {
        var now = _clock.UtcNow;
        string? sid = cmd switch
        {
            LockNowCommand c => c.UserSid, UnlockCommand c => c.UserSid, AddTimeCommand c => c.UserSid,
            PauseLimitsCommand c => c.UserSid, ScreenshotCommand c => c.UserSid, MessageCommand c => c.UserSid,
            ApproveExeCommand c => c.UserSid, KillProcessCommand c => c.UserSid, LogoffCommand c => c.UserSid,
            _ => null,
        };
        if (sid is not null && !IsManaged(sid)) return Reject(cmd.CommandId, "rejected", VerifyErrors.UnmanagedUser);

        switch (cmd)
        {
            case LockNowCommand c:
            {
                DateTimeOffset? until = null;
                if (c.Until is not null)
                {
                    if (!Time.TryParseUtc(c.Until, out var u) || u <= now) return Reject(c.CommandId, "rejected", VerifyErrors.InvalidBody, "until is in the past");
                    until = u;
                }
                _store.ClearLockAndPause(c.UserSid);
                _store.AddOverride(new OverrideRow(0, c.UserSid, OverrideKinds.Lock, until is null ? null : Time.Utc(until.Value), null, null, null, c.CommandId));
                StateChanged?.Invoke();
                var grace = _policy.ForUser(c.UserSid)!.ScreenTime.GraceSec;
                if (_session() is { } s)
                {
                    try { await s.ShowLockOverlayAsync(c.UserSid, "locked", grace, ct).ConfigureAwait(false); }
                    catch (Exception e) when (e is not OperationCanceledException)
                    { _log.LogWarning(e, "lock overlay failed; enforcer will apply the lock"); }
                }
                return Applied(c.CommandId);
            }
            case UnlockCommand c:
                _store.ClearOverride(c.UserSid, OverrideKinds.Lock);
                StateChanged?.Invoke();
                return Applied(c.CommandId);

            case AddTimeCommand c:
            {
                if (c.Group is not null && !_policy.ForUser(c.UserSid)!.AppGroups.ContainsKey(c.Group))
                    return Reject(c.CommandId, "rejected", VerifyErrors.NotFound, $"group '{c.Group}' not in policy");
                var day = Time.DayKey(now, _policy.TimeZone);
                _store.AddOverride(new OverrideRow(0, c.UserSid, OverrideKinds.AddTime, null, day, c.Group, c.Minutes, c.CommandId));
                StateChanged?.Invoke();
                return Applied(c.CommandId);
            }
            case PauseLimitsCommand c:
            {
                if (!Time.TryParseUtc(c.Until, out var until) || until <= now)
                    return Reject(c.CommandId, "rejected", VerifyErrors.InvalidBody, "until is in the past");
                _store.ClearLockAndPause(c.UserSid);
                _store.AddOverride(new OverrideRow(0, c.UserSid, OverrideKinds.Pause, Time.Utc(until), null, null, null, c.CommandId));
                StateChanged?.Invoke();
                return Applied(c.CommandId);
            }
            case ScreenshotCommand c:
                return await ScreenshotAsync(c, ct).ConfigureAwait(false);

            case MessageCommand c:
            {
                if (_session() is not { } s) return Reject(c.CommandId, "failed", VerifyErrors.Internal, "session host unavailable");
                await s.ShowMessageAsync(c.UserSid, c.Text, ct).ConfigureAwait(false);
                return Applied(c.CommandId);
            }
            case ApproveExeCommand c:
                _approvals.Record(c.UserSid, c.Sha256, c.Decision);
                return Applied(c.CommandId);

            case KillProcessCommand c:
            {
                if (_session() is not { } s) return Reject(c.CommandId, "failed", VerifyErrors.Internal, "session host unavailable");
                return await s.KillProcessAsync(c.UserSid, c.Pid, c.Exe, ct).ConfigureAwait(false)
                    ? Applied(c.CommandId)
                    : Reject(c.CommandId, "failed", VerifyErrors.NotFound, "process not found for that user");
            }
            case LogoffCommand c:
            {
                if (_session() is not { } s) return Reject(c.CommandId, "failed", VerifyErrors.Internal, "session host unavailable");
                await s.LogoffAsync(c.UserSid, "command", ct).ConfigureAwait(false);
                return Applied(c.CommandId);
            }
            case RefreshCommand c:
                RefreshRequested?.Invoke();
                return Applied(c.CommandId);

            case DiagnoseCommand c:
            {
                if (_diagnostics() is not { } diag) return Reject(c.CommandId, "failed", VerifyErrors.Internal, "diagnostics unavailable");
                await diag.ReportAsync(c.CommandId, ct).ConfigureAwait(false);
                RefreshRequested?.Invoke();   // upload the report now
                return Applied(c.CommandId);
            }

            default:
                return Reject(cmd.CommandId, "rejected", VerifyErrors.InvalidBody, "unsupported command");
        }
    }

    private async Task<CommandAck> ScreenshotAsync(ScreenshotCommand c, CancellationToken ct)
    {
        if (_session() is not { } s || _uploader() is not { } up)
            return Reject(c.CommandId, "failed", VerifyErrors.Internal, "screenshot pipeline unavailable");
        // Without a SID, capture the managed user that currently has the foreground (never an admin session, I1).
        var sid = c.UserSid ?? _policy.Current?.Users.Keys.FirstOrDefault(u => IsManaged(u) && _foreground()?.Current(u) is not null);
        if (sid is null) return Reject(c.CommandId, "failed", VerifyErrors.NotFound, "no active managed session");
        var shots = _policy.ForUser(sid)!.Monitoring.Screenshots;
        var cap = await CaptureAsync(s, sid, shots.MaxWidth, shots.JpegQuality, ct).ConfigureAwait(false);
        if (cap is null) return Reject(c.CommandId, "failed", VerifyErrors.NotFound, "user has no session");
        var fg = _foreground()?.Current(sid);
        await up.UploadAsync(sid, cap.Value.Jpeg, cap.Value.Width, cap.Value.Height, "command", c.CommandId,
            fg is { } f ? Path.GetFileName(f.ExePath) : null, ct).ConfigureAwait(false);
        return Applied(c.CommandId);
    }

    private static async Task<(byte[] Jpeg, int Width, int Height)?> CaptureAsync(ISessionActions s, string sid, int maxWidth, int quality, CancellationToken ct)
    {
        var c = await s.CaptureScreenAsync(sid, maxWidth, quality, ct).ConfigureAwait(false);
        return c is null || c.Jpeg.Length == 0 || c.Width <= 0 || c.Height <= 0 ? null : (c.Jpeg, c.Width, c.Height);
    }
}

