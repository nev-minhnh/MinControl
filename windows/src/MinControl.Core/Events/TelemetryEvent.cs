using System.Text.Json.Nodes;

namespace MinControl.Core.Events;

// C# mirror of protocol/event.schema.json. `Data` must match the $defs for `Type`.
public sealed record TelemetryEvent(
    string Id,          // ULID
    string DeviceId,
    string? UserSid,
    string Ts,          // RFC 3339 UTC with Z — use Time.Utc(...)
    long MonoMs,
    string Type,
    JsonObject Data);

public sealed record EventBatch(string DeviceId, string SentAt, IReadOnlyList<TelemetryEvent> Events);

public static class EventTypes
{
    public const string SessionLogon = "session.logon", SessionLogoff = "session.logoff",
        SessionLock = "session.lock", SessionUnlock = "session.unlock";
    public const string UsageTick = "usage.tick";
    public const string ProcessStart = "process.start", ProcessStop = "process.stop", ProcessBlocked = "process.blocked";
    public const string WebVisit = "web.visit", WebSearch = "web.search", WebBlocked = "web.blocked";
    public const string NetDomain = "net.domain";
    public const string InstallDetected = "install.detected", DownloadCompleted = "download.completed";
    public const string UsbAttached = "usb.attached", UsbDetached = "usb.detached";
    public const string ScreenshotTaken = "screenshot.taken";
    public const string QuotaWarning = "quota.warning", QuotaExhausted = "quota.exhausted";
    public const string RequestExeApproval = "request.exe_approval";
    public const string DiagReport = "diag.report";
    public const string TamperAgentKilled = "tamper.agent_killed", TamperServiceStopped = "tamper.service_stopped",
        TamperWfpFilterMissing = "tamper.wfp_filter_missing", TamperProxyBypassAttempt = "tamper.proxy_bypass_attempt",
        TamperTimezoneChanged = "tamper.timezone_changed", TamperClockJump = "tamper.clock_jump",
        TamperManagedUserIsAdmin = "tamper.managed_user_is_admin", TamperExtensionMissing = "tamper.extension_missing",
        TamperOfflineGap = "tamper.offline_gap", TamperStateTampered = "tamper.state_tampered";
}
