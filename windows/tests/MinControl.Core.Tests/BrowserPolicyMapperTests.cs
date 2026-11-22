using System.Buffers.Binary;
using System.Text;
using System.Text.Json.Nodes;
using MinControl.Browser;
using MinControl.Browser.Events;
using MinControl.Browser.Policy;
using MinControl.Core.Policy;
using Microsoft.Win32;
using Xunit;

namespace MinControl.Core.Tests;

// Needs: <ProjectReference Include="..\..\src\MinControl.Browser\MinControl.Browser.csproj" /> and
// TargetFramework net10.0-windows in MinControl.Core.Tests.csproj (see docs/contract-requests/browser.md).
public class BrowserPolicyMapperTests
{
    private const string EdgeId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string ChromeId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static WebPolicy Web(bool safeSearch = true, string youtube = "strict") =>
        new("blocklist", [], ["tiktok.com"], [], safeSearch, youtube, ["msedge.exe", "chrome.exe"], []);

    private static BrowserPolicyMapper Mapper(string edge = EdgeId, string chrome = ChromeId) => new(new BrowserOptions
    {
        EdgeExtensionId = edge,
        ChromeExtensionId = chrome,
        NativeHostExePath = @"C:\Program Files\MinControl\MinControl.NativeHost.exe",
    });

    private static object Value(IReadOnlyList<RegistryWrite> writes, string key, string name) =>
        writes.Single(w => w.Key == key && w.Name == name).Value;

    [Theory]
    [InlineData(BrowserPolicyMapper.EdgePolicyKey, "InPrivateModeAvailability")]
    [InlineData(BrowserPolicyMapper.ChromePolicyKey, "IncognitoModeAvailability")]
    public void Private_mode_is_disabled(string key, string name)
    {
        var w = Mapper().MapUserValues(Web(), 8877);
        Assert.Equal(1, Value(w, key, name));
    }

    [Theory]
    [InlineData(BrowserPolicyMapper.EdgePolicyKey)]
    [InlineData(BrowserPolicyMapper.ChromePolicyKey)]
    public void Hardening_values_for_both_browsers(string key)
    {
        var w = Mapper().MapUserValues(Web(), 8877);
        Assert.Equal(2, Value(w, key, "DeveloperToolsAvailability"));
        Assert.Equal(0, Value(w, key, "BrowserGuestModeEnabled"));
        Assert.Equal(0, Value(w, key, "BrowserAddPersonEnabled"));
        Assert.Equal("off", Value(w, key, "DnsOverHttpsMode"));
        Assert.Equal("fixed_servers", Value(w, key, "ProxyMode"));
        Assert.Equal("127.0.0.1:8877", Value(w, key, "ProxyServer"));
        Assert.Equal("<-loopback>", Value(w, key, "ProxyBypassList"));
        Assert.Equal(RegistryValueKind.String, w.Single(x => x.Key == key && x.Name == "ProxyMode").Kind);
        Assert.Equal(RegistryValueKind.DWord, w.Single(x => x.Key == key && x.Name == "DeveloperToolsAvailability").Kind);
    }

    [Theory]
    [InlineData(BrowserPolicyMapper.EdgePolicyKey)]
    [InlineData(BrowserPolicyMapper.ChromePolicyKey)]
    public void History_is_kept_and_cannot_be_deleted(string key)
    {
        var w = Mapper("", "").MapUserValues(Web(), 8877);
        Assert.Equal(0, Value(w, key, "AllowDeletingBrowserHistory"));
        Assert.Equal(0, Value(w, key, "SavingBrowserHistoryDisabled"));
        Assert.Equal(0, Value(w, key, "ForceEphemeralProfiles"));
        Assert.Equal(0, Value(w, key, "BrowserAddPersonEnabled"));
        Assert.Equal(0, Value(w, key, "BrowserGuestModeEnabled"));
        Assert.DoesNotContain(w, x => x.Name == "SyncDisabled");
        Assert.Contains(key + @"\ClearBrowsingDataOnExitList", BrowserPolicyMapper.ClearedListKeys());
    }

    [Fact]
    public void Edge_does_not_clear_browsing_data_on_exit()
    {
        var w = Mapper().MapUserValues(Web(), 8877);
        Assert.Equal(0, Value(w, BrowserPolicyMapper.EdgePolicyKey, "ClearBrowsingDataOnExit"));
        Assert.DoesNotContain(w, x => x.Key == BrowserPolicyMapper.ChromePolicyKey && x.Name == "ClearBrowsingDataOnExit");
    }

    [Theory]
    [InlineData(true, "strict", 1, 2)]
    [InlineData(true, "moderate", 1, 1)]
    [InlineData(false, "off", 0, 0)]
    public void SafeSearch_and_YouTube_follow_policy(bool safe, string youtube, int expectSafe, int expectYt)
    {
        var w = Mapper().MapUserValues(Web(safe, youtube), 8877);
        foreach (var key in new[] { BrowserPolicyMapper.EdgePolicyKey, BrowserPolicyMapper.ChromePolicyKey })
        {
            Assert.Equal(expectSafe, Value(w, key, "ForceGoogleSafeSearch"));
            Assert.Equal(expectYt, Value(w, key, "ForceYouTubeRestrict"));
        }
    }

    [Fact]
    public void WinInet_proxy_and_lock()
    {
        var w = Mapper().MapUserValues(Web(), 8877);
        Assert.Equal(1, Value(w, BrowserPolicyMapper.InternetSettingsKey, "ProxyEnable"));
        Assert.Equal("127.0.0.1:8877", Value(w, BrowserPolicyMapper.InternetSettingsKey, "ProxyServer"));
        Assert.Equal(1, Value(w, BrowserPolicyMapper.IeControlPanelPolicyKey, "Proxy"));
        var blob = (byte[])Value(w, BrowserPolicyMapper.ConnectionsKey, "DefaultConnectionSettings");
        Assert.Equal(0x46u, BinaryPrimitives.ReadUInt32LittleEndian(blob));
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(8)));
        int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(12));
        Assert.Equal("127.0.0.1:8877", Encoding.ASCII.GetString(blob, 16, len));
    }

    [Fact]
    public void All_user_writes_stay_under_known_keys()
    {
        var allowed = new[]
        {
            BrowserPolicyMapper.EdgePolicyKey, BrowserPolicyMapper.ChromePolicyKey, BrowserPolicyMapper.InternetSettingsKey,
            BrowserPolicyMapper.ConnectionsKey, BrowserPolicyMapper.IeControlPanelPolicyKey,
        };
        Assert.All(Mapper().MapUserValues(Web(), 8877), w => Assert.Contains(w.Key, allowed));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(70000)]
    public void Invalid_port_is_rejected(int port) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Mapper().MapUserValues(Web(), port));

    [Fact]
    public void Removal_names_cover_every_policy_value()
    {
        var names = Mapper().UserValueNames();
        foreach (var w in Mapper().MapUserValues(Web(), 8877).Where(w => w.Key != BrowserPolicyMapper.ConnectionsKey))
            Assert.Contains((w.Key, w.Name), names);
    }

    [Fact]
    public void Forcelist_uses_store_update_urls()
    {
        var f = Mapper().MapForcelists();
        Assert.Equal(2, f.Count);
        Assert.Contains(f, e => e.Key == BrowserPolicyMapper.EdgePolicyKey + @"\ExtensionInstallForcelist"
            && e.Value == EdgeId + ";https://edge.microsoft.com/extensionwebstorebase/v1/crx");
        Assert.Contains(f, e => e.Key == BrowserPolicyMapper.ChromePolicyKey + @"\ExtensionInstallForcelist"
            && e.Value == ChromeId + ";https://clients2.google.com/service/update2/crx");
    }

    [Fact]
    public void Forcelist_skipped_without_valid_ids()
    {
        Assert.Empty(Mapper(edge: "", chrome: "not-an-id").MapForcelists());
    }

    [Fact]
    public void Merge_keeps_foreign_entries_and_renumbers()
    {
        var existing = new Dictionary<string, object>
        {
            ["1"] = "cccccccccccccccccccccccccccccccc;https://x",
            ["3"] = EdgeId + ";https://old",
            ["5"] = "dddddddddddddddddddddddddddddddd;https://y",
        };
        var merged = BrowserPolicyMapper.MergeForcelist(existing, EdgeId, EdgeId + ";https://new");
        Assert.Equal(["1", "2", "3"], merged.Keys.OrderBy(k => k));
        Assert.StartsWith("cccc", merged["1"]);
        Assert.StartsWith("dddd", merged["2"]);
        Assert.Equal(EdgeId + ";https://new", merged["3"]);
    }

    [Fact]
    public void Merge_with_null_entry_removes_ours()
    {
        var existing = new Dictionary<string, object> { ["1"] = EdgeId + ";https://u", ["2"] = "cccccccccccccccccccccccccccccccc;https://x" };
        var merged = BrowserPolicyMapper.MergeForcelist(existing, EdgeId, null);
        Assert.Single(merged);
        Assert.StartsWith("cccc", merged["1"]);
    }

    [Fact]
    public void Machine_values_register_native_host_for_both_browsers()
    {
        var w = Mapper().MapMachineValues();
        const string manifest = @"C:\Program Files\MinControl\com.mincontrol.nativehost.json";
        Assert.Equal(manifest, Value(w, BrowserPolicyMapper.ChromeNativeHostsKey + @"\com.mincontrol.nativehost", ""));
        Assert.Equal(manifest, Value(w, BrowserPolicyMapper.EdgeNativeHostsKey + @"\com.mincontrol.nativehost", ""));
        Assert.Equal(1, Value(w, BrowserPolicyMapper.MachineInternetSettingsPolicyKey, "ProxySettingsPerUser"));
    }

    [Fact]
    public void Native_host_manifest_lists_both_origins()
    {
        var doc = JsonNode.Parse(Mapper().BuildNativeHostManifest())!.AsObject();
        Assert.Equal("com.mincontrol.nativehost", (string?)doc["name"]);
        Assert.Equal("stdio", (string?)doc["type"]);
        var origins = doc["allowed_origins"]!.AsArray().Select(n => (string?)n).ToList();
        Assert.Equal([$"chrome-extension://{ChromeId}/", $"chrome-extension://{EdgeId}/"], origins);
    }

    [Theory]
    [InlineData("*.TikTok.com", "tiktok.com")]
    [InlineData("café.vn", "xn--caf-dma.vn")]
    [InlineData("bad host", null)]
    [InlineData("", null)]
    public void Extension_rule_domains_are_normalized(string raw, string? expected) =>
        Assert.Equal(expected, ExtensionRuleBuilder.NormalizeDomain(raw));

    [Fact]
    public void Event_validator_rejects_unknown_fields_and_proxy_source()
    {
        Assert.NotNull(BrowserEventValidator.Sanitize("web.search", new JsonObject { ["engine"] = "google", ["query"] = "x" }));
        Assert.Null(BrowserEventValidator.Sanitize("web.search", new JsonObject { ["engine"] = "google", ["query"] = "x", ["extra"] = 1 }));
        Assert.Null(BrowserEventValidator.Sanitize("web.blocked", new JsonObject { ["host"] = "a.com", ["source"] = "proxy", ["reason"] = "blocklist" }));
        Assert.Null(BrowserEventValidator.Sanitize("web.visit", new JsonObject { ["url"] = "https://a", ["browser"] = "firefox" }));
        Assert.Null(BrowserEventValidator.Sanitize("download.completed", new JsonObject { ["fileName"] = "a.exe", ["sizeBytes"] = -1 }));
    }
}
