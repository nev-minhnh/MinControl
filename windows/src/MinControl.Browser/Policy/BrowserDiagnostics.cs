using System.Text.Json.Nodes;
using MinControl.Browser.History;
using MinControl.Browser.Registry;
using MinControl.Core.Abstractions;
using MinControl.Core.Diagnostics;

namespace MinControl.Browser.Policy;

/// <summary>
/// <c>browser</c> section: per managed SID, the policy values MinControl writes (ProxyMode/ProxyServer, InPrivate /
/// Incognito, DnsOverHttpsMode, AllowDeletingBrowserHistory, WinINET proxy…) read back from HKU\&lt;SID&gt; and compared
/// with what the current policy expects, plus history reader cursors. Only hives that are already loaded (user logged on)
/// are read: diagnostics never load NTUSER.DAT.
/// </summary>
public sealed class BrowserDiagnostics(IRegistryHive hive, IUserDirectory users, IPolicyProvider policy, BrowserPolicyMapper mapper,
    Func<int?> proxyPort, Func<string, bool> isHiveLoaded, Func<BrowserHistoryReader?> history) : IDiagnosticsSection
{
    public string Name => "browser";

    public JsonObject Collect()
    {
        var o = new JsonObject();
        var port = proxyPort();
        var perSid = new JsonObject();
        foreach (var sid in users.ManagedSids.OrderBy(s => s, StringComparer.Ordinal))
        {
            var entry = new JsonObject();
            perSid[sid] = entry;
            if (!isHiveLoaded(sid)) { entry["hiveLoaded"] = false; continue; }
            entry["hiveLoaded"] = true;

            Dictionary<(string, string), object>? expected = null;
            if (policy.Current?.Users.TryGetValue(sid, out var up) == true && port is { } p)
                expected = mapper.MapUserValues(up.Web, p).ToDictionary(w => (w.Key, w.Name), w => w.Value);

            using var scope = hive.OpenUserHive(sid, users.ProfilePath(sid));
            var values = new JsonObject();
            var mismatches = new JsonArray();
            foreach (var group in mapper.UserValueNames().GroupBy(v => v.Key))
            {
                var actual = scope.GetValues(group.Key);
                foreach (var (key, name) in group)
                {
                    actual.TryGetValue(name, out var value);
                    var label = $"{ShortKey(key)}\\{name}";
                    values[label] = Render(value);
                    if (expected is not null && expected.TryGetValue((key, name), out var want) && !SameValue(want, value))
                        mismatches.Add(label);
                }
            }
            entry["values"] = values;
            entry["mismatches"] = mismatches;
        }
        o["proxyPort"] = port;
        o["users"] = perSid;

        var reader = history();
        if (reader is not null)
        {
            var cursors = new JsonObject();
            foreach (var (key, c) in reader.Cursors.All().OrderBy(kv => kv.Key, StringComparer.Ordinal).Take(100))
                cursors[key] = new JsonObject { ["lastVisitId"] = c.LastVisitId, ["lastVisitTime"] = c.LastVisitTime, ["size"] = c.Size };
            o["historyCursors"] = cursors;
        }
        return o;
    }

    private static string ShortKey(string key) => key
        .Replace(@"Software\Policies\Microsoft\Edge", "Edge", StringComparison.OrdinalIgnoreCase)
        .Replace(@"Software\Policies\Google\Chrome", "Chrome", StringComparison.OrdinalIgnoreCase)
        .Replace(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "WinINET", StringComparison.OrdinalIgnoreCase)
        .Replace(@"Software\Policies\Microsoft\Internet Explorer\Control Panel", "IEPolicy", StringComparison.OrdinalIgnoreCase);

    private static JsonNode? Render(object? v) => v switch
    {
        null => null,
        int i => i,
        long l => l,
        string s => s,
        string[] a => DiagJson.Strings(a),
        byte[] b => $"binary[{b.Length}]",
        _ => v.ToString(),
    };

    private static bool SameValue(object want, object? have) => want switch
    {
        int i => have is int h && h == i,
        string s => have is string h && string.Equals(h, s, StringComparison.Ordinal),
        _ => true,   // binary/multi-string: not compared
    };
}
