namespace MinControl.Browser;

/// <summary>Configuration of the browser stream. Store ids are deployment config, never committed.</summary>
public sealed class BrowserOptions
{
    /// <summary>Chrome Web Store id of the unlisted MinControl extension (32 chars a-p). Empty = no forcelist entry.</summary>
    public string ChromeExtensionId { get; set; } = "";

    /// <summary>Edge Add-ons id of the hidden MinControl extension. Empty = no forcelist entry.</summary>
    public string EdgeExtensionId { get; set; } = "";

    public string ChromeUpdateUrl { get; set; } = "https://clients2.google.com/service/update2/crx";
    public string EdgeUpdateUrl { get; set; } = "https://edge.microsoft.com/extensionwebstorebase/v1/crx";

    /// <summary>Native messaging host name; must match HOST_NAME in extension/src/background.ts.</summary>
    public string NativeHostName { get; set; } = "com.mincontrol.nativehost";

    /// <summary>Absolute path of MinControl.NativeHost.exe (install dir, admin-only writable).</summary>
    public string NativeHostExePath { get; set; } =
        Path.Combine(AppContext.BaseDirectory, "MinControl.NativeHost.exe");

    /// <summary>Where the generated native host manifest is written (next to the exe by default).</summary>
    public string? NativeHostManifestPath { get; set; }

    /// <summary>Pipe name without the \\.\pipe\ prefix.</summary>
    public string PipeName { get; set; } = "MinControl.Browser";

    /// <summary>Reject pipe clients whose image is not <see cref="NativeHostExePath"/>.</summary>
    public bool RequireNativeHostImage { get; set; } = true;

    public int MaxPipeInstances { get; set; } = 16;

    /// <summary>A managed user's browser running this long without a heartbeat raises tamper.extension_missing.</summary>
    public TimeSpan HeartbeatTimeout { get; set; } = TimeSpan.FromMinutes(3);

    public TimeSpan HeartbeatCheckInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Max messages a single pipe client may send per 10 s before it is disconnected.</summary>
    public int MaxMessagesPer10s { get; set; } = 200;

    /// <summary>How often the browsers' History databases are checked for changes.</summary>
    public TimeSpan HistoryPollInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>The first time a browser profile is seen, only visits this recent are imported.</summary>
    public TimeSpan HistoryFirstImportWindow { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Max visits read from one profile per poll (the rest follows on the next poll).</summary>
    public int HistoryMaxVisitsPerPoll { get; set; } = 500;

    /// <summary>Restricted data root (cursor file + tmp\ copies). Null = the Core DataPaths root
    /// (%ProgramData%\MinControl).</summary>
    public string? HistoryDataDirectory { get; set; }

    /// <summary>True when an extension id is configured for <paramref name="browser"/> (msedge | chrome): only then is
    /// the extension expected and its heartbeat monitored.</summary>
    public bool ExtensionConfigured(string browser) => browser switch
    {
        "msedge" => Policy.BrowserPolicyMapper.IsExtensionId(EdgeExtensionId),
        "chrome" => Policy.BrowserPolicyMapper.IsExtensionId(ChromeExtensionId),
        _ => false,
    };

    internal string ResolvedManifestPath =>
        NativeHostManifestPath ?? Path.Combine(Path.GetDirectoryName(NativeHostExePath) ?? AppContext.BaseDirectory,
            NativeHostName + ".json");
}
