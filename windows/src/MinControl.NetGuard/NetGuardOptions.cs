namespace MinControl.NetGuard;

/// <summary>Runtime knobs of the network guard. Defaults are the production values.</summary>
public sealed class NetGuardOptions
{
    /// <summary>Loopback port of the filtering proxy (also written into the managed user's proxy settings).</summary>
    public int ProxyPort { get; set; } = 3129;

    public string CategoriesDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinControl", "categories");

    /// <summary>Base URL of the UT1 per-category archives (<c>&lt;base&gt;&lt;list&gt;.tar.gz</c>).</summary>
    public string CategorySourceBaseUrl { get; set; } = Categories.Ut1Catalog.DefaultBaseUrl;

    /// <summary>First category download after service start (lets the machine settle after boot).</summary>
    public TimeSpan CategoryUpdateInitialDelay { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Category lists are re-checked (conditional GET) this often.</summary>
    public TimeSpan CategoryUpdateInterval { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Retry delay after a failed category download.</summary>
    public TimeSpan CategoryRetryInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Timeout of one archive download (the UT1 server can be slow; adult is tens of MB).</summary>
    public TimeSpan CategoryDownloadTimeout { get; set; } = TimeSpan.FromMinutes(45);

    /// <summary>Set false to disable downloading (lists in <see cref="CategoriesDirectory"/> are still used).</summary>
    public bool CategoryDownloadEnabled { get; set; } = true;

    /// <summary>How often WFP filters + proxy are verified and repaired.</summary>
    public TimeSpan WatchdogInterval { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>net.domain aggregation window.</summary>
    public TimeSpan DomainWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Best-effort bypass scan (listeners on proxy-like ports, VPN adapters, direct connections).</summary>
    public TimeSpan BypassScanInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Same (sid, host) web.blocked is emitted at most once per this period (browsers retry a lot).</summary>
    public TimeSpan BlockedEventDedup { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>In blocklist mode, refuse CONNECT/HTTP to raw IP addresses (no host name to judge). Allowlist mode always refuses.</summary>
    public bool BlockIpLiteralsInBlocklistMode { get; set; }

    /// <summary>
    /// Destination ports a managed user may CONNECT/GET through the proxy (anti-tunnelling: arbitrary-port CONNECT
    /// would let a VPN/SSH client ride the proxy). Empty = any port.
    /// </summary>
    public HashSet<int> AllowedPorts { get; set; } = [80, 443, 8080, 8443, 5222, 5223, 5228];

    /// <summary>Max size of an HTTP request head the proxy accepts.</summary>
    public int MaxRequestHeadBytes { get; set; } = 64 * 1024;

    /// <summary>Upstream connect timeout.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Time a client has to send its request head.</summary>
    public TimeSpan RequestHeadTimeout { get; set; } = TimeSpan.FromSeconds(30);
}
