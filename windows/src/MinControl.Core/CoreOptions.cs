using MinControl.Core.Crypto;

namespace MinControl.Core;

/// <summary>Options for <see cref="ServiceCollectionExtensions.AddMinControlCore"/>.</summary>
public sealed class CoreOptions
{
    /// <summary>State directory; default %ProgramData%\MinControl (I7).</summary>
    public string? DataDirectory { get; set; }

    /// <summary>Cloud base URL (https://…). Default: the URL saved by <c>MinControl.Setup enroll</c>.</summary>
    public string? ServerUrl { get; set; }

    public string AgentVersion { get; set; } = "0.1.0";

    public long OutboxCapBytes { get; set; } = 500L * 1024 * 1024;

    /// <summary>Reconnect after an offline period at least this long emits <c>tamper.offline_gap</c>.</summary>
    public int OfflineGapThresholdSec { get; set; } = 300;

    /// <summary>Register a hosted service that runs <c>ICloudLink.RunAsync</c> and flushes the ledger on stop.
    /// Set false if the host calls RunAsync itself.</summary>
    public bool RunCloudLinkAsHostedService { get; set; } = true;

    /// <summary>Key protector for device.key; default DPAPI LocalMachine. Tests may supply their own.</summary>
    public IKeyProtector? KeyProtector { get; set; }
}
