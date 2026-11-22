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
}

/// <summary>Receives web.* events from the native-messaging host (validated to come from the managed SID).</summary>
public interface IBrowserEventIngress
{
    void OnBrowserEvent(string sid, string type, System.Text.Json.Nodes.JsonObject data);
    void OnHeartbeat(string sid, string browser);
}
