using MinControl.Core.Policy;

namespace MinControl.Core.Abstractions;

// Integration seams between the Windows components. Owned by the lead: implementers may ADD members
// in their own project only through new interfaces; changing these signatures needs the lead.
// Every component is registered in MinControl.Service's DI container (owned by the win-core stream).

/// <summary>Wall clock + monotonic clock. Never use DateTime.Now in enforcement code.</summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }
    long MonotonicMs { get; }
}

/// <summary>Creates ids/timestamps and queues events into the durable outbox (uploaded by the cloud link).</summary>
public interface IEventSink
{
    void Emit(string type, string? userSid, System.Text.Json.Nodes.JsonObject data);
}

/// <summary>Current verified policy. Raised after a new signed policy has been verified and stored.</summary>
public interface IPolicyProvider
{
    DevicePolicy? Current { get; }
    event EventHandler<DevicePolicy>? PolicyChanged;
}

/// <summary>Local accounts and which of them are managed (I1/I2).</summary>
public interface IUserDirectory
{
    bool IsManaged(string sid);                 // in policy AND not an administrator
    bool IsAdministrator(string sid);
    IReadOnlyCollection<string> ManagedSids { get; }
    string? SidOfProcess(int pid);              // token user of a process, null if gone/inaccessible
    string? ProfilePath(string sid);
}

/// <summary>Per-user temporary decisions taken at runtime (approvals from the master).</summary>
public interface IApprovalStore
{
    string? DecisionFor(string sid, string sha256);   // allow | block | null
    void Record(string sid, string sha256, string decision);
    /// <summary>Marks that request.exe_approval was sent for (sid, sha256). Persisted; true only the first time,
    /// so a still-pending exe is requested once even across service restarts.</summary>
    bool MarkRequested(string sid, string sha256);
}

/// <summary>Watches process starts for managed users, enforces appRules/newExecutable, emits process.* /
/// install.* / usb.* / download.* events. Implemented in MinControl.Monitoring.</summary>
public interface IAppMonitor
{
    Task StartAsync(CancellationToken ct);
    Task StopAsync();
    /// <summary>Foreground-independent group lookup used by screen-time accounting.</summary>
    string? GroupOf(string sid, string exePath);
}

/// <summary>Per-user network lock (persistent WFP) + filtering proxy. Implemented in MinControl.NetGuard.</summary>
public interface INetGuard
{
    Task ApplyAsync(DevicePolicy policy, IReadOnlyCollection<string> managedSids, CancellationToken ct);
    Task<bool> VerifyAsync(CancellationToken ct);           // filters present & proxy listening
    Task RemoveAllAsync(CancellationToken ct);               // uninstall only
    int ProxyPort { get; }
}

/// <summary>Writes Edge/Chrome policies + proxy settings into HKU\&lt;SID&gt; and registers the native host.
/// Implemented in MinControl.Browser.</summary>
public interface IBrowserPolicyWriter
{
    Task ApplyAsync(string sid, WebPolicy web, int proxyPort, CancellationToken ct);
    Task RemoveAsync(string sid, CancellationToken ct);
    /// <summary>Uninstall only: removes the HKLM native-messaging host registration and its manifest.</summary>
    Task UnregisterNativeHostAsync(CancellationToken ct);
}

/// <summary>Whether the MinControl browser extension is alive in a managed user's browser (MinControl.Browser).
/// App control blocks a browser whose extension is missing (SPEC §8.5).</summary>
public interface IExtensionHealth
{
    /// <summary>True when <paramref name="browser"/> (<c>msedge</c> | <c>chrome</c>) runs for the user and no heartbeat
    /// arrived within the timeout (grace after browser start).</summary>
    bool IsExtensionMissing(string sid, string browser);
}

/// <summary>Receives web.* events from the native-messaging host (validated to come from the managed SID).</summary>
public interface IBrowserEventIngress
{
    void OnBrowserEvent(string sid, string type, System.Text.Json.Nodes.JsonObject data);
    void OnHeartbeat(string sid, string browser);
}

// ---- Seams between the win-core stream (Core engine, cloud link) and the win-session stream (Service host, Session app)

public sealed record GroupState(int UsedMin, int? RemainingMin);

/// <summary>Result of screen-time evaluation for one managed user at one instant.</summary>
public sealed record ScreenTimeState(
    bool Allowed,                 // false => must not be logged on (logoff after grace)
    string Reason,                // ok | quota_exhausted | outside_window | locked | not_managed
    int UsedMin,
    int? RemainingMin,            // null when unlimited / paused
    DateTimeOffset? LockedUntil,
    DateTimeOffset? NextChangeUtc,
    IReadOnlyDictionary<string, GroupState> Groups);

/// <summary>Pure-ish screen-time engine (implemented in Core by win-core). Persists its ledger itself.</summary>
public interface IScreenTimeEngine
{
    ScreenTimeState Evaluate(string sid, DateTimeOffset utcNow);
    /// <summary>Called by the Service ~every second for the active managed session.</summary>
    void RecordUsage(string sid, string? foregroundExePath, long activeMsDelta);
    /// <summary>Groups currently over quota for this user (exe paths of those groups must be blocked).</summary>
    IReadOnlyCollection<string> ExhaustedGroups(string sid, DateTimeOffset utcNow);
}

/// <summary>One JPEG screen capture of a user session.</summary>
public sealed record ScreenCapture(byte[] Jpeg, int Width, int Height);

/// <summary>Session-side actions requested by commands or the enforcer (implemented by win-session).</summary>
public interface ISessionActions
{
    Task LogoffAsync(string sid, string reason, CancellationToken ct);
    Task ShowWarningAsync(string sid, int remainingMin, CancellationToken ct);
    Task ShowLockOverlayAsync(string sid, string reason, int graceSec, CancellationToken ct);
    Task ShowMessageAsync(string sid, string text, CancellationToken ct);
    /// <summary>Non-activating corner toast "<paramref name="title"/>" + "<paramref name="reason"/>" in the user's
    /// session(s) when something was blocked (web host or app). Rate limited by the implementation
    /// (same title once per 60 s, at most 3 per minute per user); excess notices are dropped silently.</summary>
    Task ShowBlockedNoticeAsync(string sid, string title, string reason, CancellationToken ct);
    Task<bool> KillProcessAsync(string sid, int pid, string? expectedExe, CancellationToken ct);
    /// <summary>Capture the screen of the user's session; null if no session.</summary>
    Task<ScreenCapture?> CaptureScreenAsync(string? sid, int maxWidth, int jpegQuality, CancellationToken ct);
}

/// <summary>What the user is doing right now (implemented by win-session from the Session helper).</summary>
public interface IForegroundTracker
{
    (string ExePath, string? Title, bool Idle)? Current(string sid);
}

/// <summary>Seals a screenshot with the master key, uploads it and emits screenshot.taken (win-core).</summary>
public interface IScreenshotUploader
{
    Task UploadAsync(string? sid, byte[] jpeg, int width, int height, string reason, string? commandId, string? foregroundExe, CancellationToken ct);
}

/// <summary>Cloud connection status (win-core).</summary>
public interface ICloudLink
{
    bool Connected { get; }
    Task RunAsync(CancellationToken ct);   // connect, auth, receive envelopes, send acks/state; reconnect forever
}

/// <summary>Banned-word enforcement (API.md §17 keywords), implemented by the Service. The history reader reports fresh
/// visits so search queries hidden from the window title (URL q / p / text / search_query) are caught too.</summary>
public interface IKeywordGuard
{
    void OnHistoryVisit(string sid, string browser, string url, string? title, DateTimeOffset visitedAt);
}
