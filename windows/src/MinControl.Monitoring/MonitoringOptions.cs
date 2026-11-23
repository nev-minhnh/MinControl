namespace MinControl.Monitoring;

public sealed class MonitoringOptions
{
    /// <summary>process.blocked: same (sid, exe) at most once per period, repeats folded into count (API.md 17).</summary>
    public TimeSpan BlockedEventPeriod { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Kernel-enforced layer: deny-Execute ACE for the managed SID on exes of block rules under
    /// %ProgramFiles% / %ProgramFiles(x86)% only (never %windir%, never user-writable paths). Off by default.</summary>
    public bool EnableAclLayer { get; set; }

    /// <summary>ETW real-time session name (a stale session with this name is replaced on start).</summary>
    public string EtwSessionName { get; set; } = "MinControl-Process";

    /// <summary>ETW buffers are force-flushed this often to keep start→kill latency well under 1 s.</summary>
    public int EtwFlushIntervalMs { get; set; } = 200;

    /// <summary>Fallback when the ETW session cannot be started: process list polling interval.</summary>
    public int PollIntervalMs { get; set; } = 500;

    /// <summary>Backup process-list poll that runs even while ETW works (an ETW session that silently delivers nothing
    /// must not disable app control). Must stay ≤ 1000 ms.</summary>
    public int BackupPollIntervalMs { get; set; } = 1000;

    /// <summary>Re-check of running managed processes against exhausted groups.</summary>
    public TimeSpan GroupSweepInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>A managed user's msedge/chrome may run this long before it is blocked for a missing MinControl
    /// extension (IExtensionHealth). Matches the browser stream's heartbeat timeout.</summary>
    public TimeSpan ExtensionMissingGrace { get; set; } = TimeSpan.FromMinutes(3);

    /// <summary>Installs / AppX periodic rescan (registry notifications trigger earlier scans).</summary>
    public TimeSpan InstallRescanInterval { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>A download is "completed" once its size and mtime are unchanged for this long.</summary>
    public TimeSpan DownloadStableAfter { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>Directory for small state files (ACL ledger). Must be the SYSTEM/Admins-only ProgramData dir (I7).</summary>
    public string StateDirectory { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinControl", "monitoring");

    /// <summary>Do not emit process.start/stop for these images (still evaluated against rules).</summary>
    public HashSet<string> QuietExes { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "conhost.exe", "werfault.exe", "werfaultsecure.exe", "backgroundtaskhost.exe", "runtimebroker.exe",
        "dllhost.exe", "smartscreen.exe", "taskhostw.exe", "svchost.exe", "searchprotocolhost.exe",
        "searchfilterhost.exe", "compPkgSrv.exe", "ctfmon.exe", "sihost.exe", "msedgewebview2.exe",
        "crashpad_handler.exe", "rundll32.exe", "consent.exe", "audiodg.exe", "wmiprvse.exe",
        "textinputhost.exe", "applicationframehost.exe", "useroobebroker.exe", "mobsync.exe",
    };
}
