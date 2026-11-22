using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Core.Policy;
using Microsoft.Win32;

namespace MinControl.Browser.Policy;

/// <summary>One registry value relative to a hive root (HKU\&lt;SID&gt; or HKLM).</summary>
public sealed record RegistryWrite(string Key, string Name, RegistryValueKind Kind, object Value);

/// <summary>Our entry in a browser's ExtensionInstallForcelist list key.</summary>
public sealed record ForcelistEntry(string Key, string ExtensionId, string Value);

/// <summary>
/// Pure mapping from policy to registry values (SPEC §8.4, §8.5). No registry access here — the writer applies it.
/// </summary>
public sealed class BrowserPolicyMapper
{
    public const string EdgePolicyKey = @"Software\Policies\Microsoft\Edge";
    public const string ChromePolicyKey = @"Software\Policies\Google\Chrome";
    public const string ForcelistSubKey = "ExtensionInstallForcelist";
    public const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    public const string ConnectionsKey = InternetSettingsKey + @"\Connections";
    public const string IeControlPanelPolicyKey = @"Software\Policies\Microsoft\Internet Explorer\Control Panel";
    public const string MachineInternetSettingsPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    public const string ChromeNativeHostsKey = @"SOFTWARE\Google\Chrome\NativeMessagingHosts";
    public const string EdgeNativeHostsKey = @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts";

    /// <summary>Proxy bypass: "&lt;-loopback&gt;" removes the implicit loopback bypass so nothing skips the proxy.</summary>
    public const string ProxyBypass = "<-loopback>";

    private readonly BrowserOptions _options;

    public BrowserPolicyMapper(BrowserOptions options) => _options = options;

    public static int YouTubeRestrictValue(string? youtube) => youtube switch
    {
        "strict" => 2,
        "moderate" => 1,
        _ => 0,
    };

    public static string ProxyServer(int port)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        return "127.0.0.1:" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>All scalar values written into HKU\&lt;SID&gt; for one managed user.</summary>
    public IReadOnlyList<RegistryWrite> MapUserValues(WebPolicy web, int proxyPort)
    {
        ArgumentNullException.ThrowIfNull(web);
        string proxy = ProxyServer(proxyPort);
        var list = new List<RegistryWrite>();

        foreach (var (key, privateMode) in new[] { (EdgePolicyKey, "InPrivateModeAvailability"), (ChromePolicyKey, "IncognitoModeAvailability") })
        {
            list.Add(Dword(key, privateMode, 1));                       // 1 = private/incognito disabled
            list.Add(Dword(key, "DeveloperToolsAvailability", 2));      // 2 = never
            list.Add(Dword(key, "BrowserGuestModeEnabled", 0));
            list.Add(Dword(key, "BrowserAddPersonEnabled", 0));
            list.Add(Str(key, "DnsOverHttpsMode", "off"));
            list.Add(Dword(key, "ForceGoogleSafeSearch", web.SafeSearch ? 1 : 0));
            list.Add(Dword(key, "ForceYouTubeRestrict", YouTubeRestrictValue(web.Youtube)));
            list.Add(Str(key, "ProxyMode", "fixed_servers"));
            list.Add(Str(key, "ProxyServer", proxy));
            list.Add(Str(key, "ProxyBypassList", ProxyBypass));
        }

        // WinINET proxy for apps using the system proxy (per-user).
        list.Add(Dword(InternetSettingsKey, "ProxyEnable", 1));
        list.Add(Str(InternetSettingsKey, "ProxyServer", proxy));
        list.Add(Str(InternetSettingsKey, "ProxyOverride", ProxyBypass));
        list.Add(new RegistryWrite(ConnectionsKey, "DefaultConnectionSettings", RegistryValueKind.Binary,
            BuildWinInetConnectionSettings(proxy, ProxyBypass, counter: 1)));

        // Lock: the user cannot change proxy / auto-config in the Settings UI or inetcpl.
        list.Add(Dword(IeControlPanelPolicyKey, "Proxy", 1));
        list.Add(Dword(IeControlPanelPolicyKey, "AutoConfig", 1));
        list.Add(Dword(IeControlPanelPolicyKey, "ConnectionSettings", 1));
        return list;
    }

    /// <summary>(key, name) pairs the writer deletes on removal; same set as <see cref="MapUserValues"/>.
    /// The Connections blob is reset rather than deleted (see <see cref="MapUserResetValues"/>).</summary>
    public IReadOnlyList<(string Key, string Name)> UserValueNames() =>
        MapUserValues(new WebPolicy("blocklist", [], [], [], false, "off", [], []), 1)
            .Where(w => w.Key != ConnectionsKey)
            .Select(w => (w.Key, w.Name))
            .ToList();

    /// <summary>Values written on removal: WinINET back to "direct".</summary>
    public static IReadOnlyList<RegistryWrite> MapUserResetValues() =>
    [
        Dword(InternetSettingsKey, "ProxyEnable", 0),
        new(ConnectionsKey, "DefaultConnectionSettings", RegistryValueKind.Binary, BuildWinInetConnectionSettings("", "", counter: 1, proxyEnabled: false)),
    ];

    /// <summary>Forcelist entries for the configured store ids (none when ids are empty).</summary>
    public IReadOnlyList<ForcelistEntry> MapForcelists()
    {
        var list = new List<ForcelistEntry>();
        if (IsExtensionId(_options.EdgeExtensionId))
            list.Add(new(EdgePolicyKey + "\\" + ForcelistSubKey, _options.EdgeExtensionId, _options.EdgeExtensionId + ";" + _options.EdgeUpdateUrl));
        if (IsExtensionId(_options.ChromeExtensionId))
            list.Add(new(ChromePolicyKey + "\\" + ForcelistSubKey, _options.ChromeExtensionId, _options.ChromeExtensionId + ";" + _options.ChromeUpdateUrl));
        return list;
    }

    public static bool IsExtensionId(string? id) => id is { Length: 32 } && id.All(c => c is >= 'a' and <= 'p');

    /// <summary>
    /// Chrome/Edge read list policies as values "1","2",... until the first gap. Keeps entries of other
    /// extensions (in their numeric order), drops any existing entry for <paramref name="extensionId"/>, appends
    /// <paramref name="entry"/> when non-null and renumbers contiguously from "1".
    /// </summary>
    public static IReadOnlyDictionary<string, string> MergeForcelist(IReadOnlyDictionary<string, object> existing,
        string extensionId, string? entry)
    {
        var kept = existing
            .Where(kv => kv.Value is string)
            .Select(kv => (Order: int.TryParse(kv.Key, out var n) ? n : int.MaxValue, kv.Key, Value: (string)kv.Value))
            .Where(x => !x.Value.Split(';', 2)[0].Trim().Equals(extensionId, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Order).ThenBy(x => x.Key, StringComparer.Ordinal)
            .Select(x => x.Value)
            .ToList();
        if (entry is not null) kept.Add(entry);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i < kept.Count; i++) result[(i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture)] = kept[i];
        return result;
    }

    /// <summary>HKLM values: native-messaging host registration for both browsers + per-user proxy scope.</summary>
    public IReadOnlyList<RegistryWrite> MapMachineValues()
    {
        string manifest = _options.ResolvedManifestPath;
        return
        [
            Str(ChromeNativeHostsKey + "\\" + _options.NativeHostName, "", manifest),
            Str(EdgeNativeHostsKey + "\\" + _options.NativeHostName, "", manifest),
            // 1 = proxy settings are per user (the default). Pinned so nobody can switch to machine-wide,
            // which would push the managed user's proxy onto the admin (I1/I2).
            Dword(MachineInternetSettingsPolicyKey, "ProxySettingsPerUser", 1),
        ];
    }

    /// <summary>Native messaging host manifest (JSON) for Chrome and Edge.</summary>
    public string BuildNativeHostManifest()
    {
        var origins = new JsonArray();
        foreach (var id in new[] { _options.ChromeExtensionId, _options.EdgeExtensionId }.Where(IsExtensionId).Distinct())
            origins.Add($"chrome-extension://{id}/");
        var doc = new JsonObject
        {
            ["name"] = _options.NativeHostName,
            ["description"] = "MinControl browser bridge",
            ["path"] = _options.NativeHostExePath,
            ["type"] = "stdio",
            ["allowed_origins"] = origins,
        };
        return doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// WinINET "DefaultConnectionSettings" blob: version 0x46, change counter, flags (1 = direct, 2 = proxy),
    /// proxy string, bypass string, auto-config URL (empty), 32 reserved zero bytes. All lengths are uint32 LE.
    /// </summary>
    public static byte[] BuildWinInetConnectionSettings(string proxy, string bypass, int counter, bool proxyEnabled = true)
    {
        byte[] p = Encoding.ASCII.GetBytes(proxy);
        byte[] b = Encoding.ASCII.GetBytes(bypass);
        var buf = new byte[4 * 6 + p.Length + b.Length + 32];
        int o = 0;
        void U32(uint v) { BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(o), v); o += 4; }
        U32(0x46);
        U32((uint)counter);
        U32(proxyEnabled ? 0x03u : 0x01u);
        U32((uint)p.Length); p.CopyTo(buf, o); o += p.Length;
        U32((uint)b.Length); b.CopyTo(buf, o); o += b.Length;
        U32(0);                       // auto-config URL length
        return buf;                   // trailing 32 bytes stay zero
    }

    private static RegistryWrite Dword(string key, string name, int v) => new(key, name, RegistryValueKind.DWord, v);
    private static RegistryWrite Str(string key, string name, string v) => new(key, name, RegistryValueKind.String, v);
}
