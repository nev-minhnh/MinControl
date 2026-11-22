using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Monitoring.Native;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace MinControl.Monitoring.Installs;

/// <summary>
/// Detects new installs by diffing registry keys (read-only):
/// <list type="bullet">
/// <item>HKLM\...\Uninstall (64- and 32-bit views) → scope machine;</item>
/// <item>HKU\&lt;SID&gt;\...\Uninstall of each logged-on managed user → scope user;</item>
/// <item>HKU\&lt;SID&gt;\...\AppModel\Repository\Packages → scope appx (per-user AppX/MSIX registrations).</item>
/// </list>
/// A dedicated thread arms RegNotifyChangeKeyValue on every key, rescans on change (debounced) and at least
/// every <see cref="MonitoringOptions.InstallRescanInterval"/>. The first scan of a key is a silent baseline.
/// </summary>
internal sealed class InstallWatcher : IMonitorComponent
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string AppxRepoPath =
        @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    private static readonly string[] FrameworkPrefixes =
    [
        "Microsoft.VCLibs", "Microsoft.NET.", "Microsoft.UI.Xaml", "Microsoft.WindowsAppRuntime",
        "Microsoft.Services.Store.Engagement", "Microsoft.Advertising", "Microsoft.DirectX",
    ];

    private sealed record Entry(string Product, string? Version, string? Publisher);

    private sealed record WatchedKey(string Id, RegistryKey Key, string Scope, string? Sid, bool Appx);

    private readonly IUserDirectory _users;
    private readonly IEventSink _sink;
    private readonly MonitoringOptions _options;
    private readonly ILogger _log;
    private readonly Dictionary<string, Dictionary<string, Entry>> _snapshots = new(StringComparer.OrdinalIgnoreCase);
    private readonly ManualResetEvent _stop = new(false);
    private Thread? _thread;

    public InstallWatcher(IUserDirectory users, IEventSink sink, MonitoringOptions options, ILogger log)
    {
        _users = users;
        _sink = sink;
        _options = options;
        _log = log;
    }

    public void Start()
    {
        _stop.Reset();
        _thread = new Thread(Loop) { IsBackground = true, Name = "MinControl install watcher" };
        _thread.Start();
    }

    public void Stop()
    {
        _stop.Set();
        _thread?.Join(TimeSpan.FromSeconds(5));
    }

    private void Loop()
    {
        while (!_stop.WaitOne(0))
        {
            var keys = new List<WatchedKey>();
            var events = new List<AutoResetEvent>();
            try
            {
                keys = OpenKeys();
                // Arm notifications BEFORE scanning so nothing between scan and wait is lost.
                foreach (var k in keys)
                {
                    var ev = new AutoResetEvent(false);
                    int rc = NativeMethods.RegNotifyChangeKeyValue(k.Key.Handle, true,
                        NativeMethods.REG_NOTIFY_CHANGE_NAME | NativeMethods.REG_NOTIFY_CHANGE_LAST_SET,
                        ev.SafeWaitHandle, true);
                    if (rc == 0) events.Add(ev); else ev.Dispose();
                }

                bool anyManaged = _users.ManagedSids.Count > 0;
                foreach (var k in keys) ScanAndDiff(k, emit: anyManaged);

                var handles = new List<WaitHandle> { _stop };
                handles.AddRange(events.Take(62));
                int idx = WaitHandle.WaitAny([.. handles], _options.InstallRescanInterval);
                if (idx == 0) return;
                if (idx != WaitHandle.WaitTimeout && _stop.WaitOne(TimeSpan.FromSeconds(3))) return; // debounce installers
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Install watcher iteration failed");
                if (_stop.WaitOne(TimeSpan.FromSeconds(30))) return;
            }
            finally
            {
                foreach (var e in events) e.Dispose();
                foreach (var k in keys) k.Key.Dispose();
            }
        }
    }

    private List<WatchedKey> OpenKeys()
    {
        var list = new List<WatchedKey>();
        void TryAdd(string id, Func<RegistryKey?> open, string scope, string? sid, bool appx)
        {
            try
            {
                if (open() is { } key) list.Add(new WatchedKey(id, key, scope, sid, appx));
            }
            catch (Exception ex) { _log.LogDebug(ex, "Cannot open {Id}", id); }
        }

        TryAdd("hklm64", () => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(UninstallPath),
            "machine", null, false);
        TryAdd("hklm32", () => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32).OpenSubKey(UninstallPath),
            "machine", null, false);

        foreach (var sid in _users.ManagedSids)
        {
            // Only hives that are loaded (user logged on); we never load hives here.
            TryAdd("hku:" + sid, () => Registry.Users.OpenSubKey(sid + "\\" + UninstallPath), "user", sid, false);
            TryAdd("appx:" + sid, () => Registry.Users.OpenSubKey(sid + "\\" + AppxRepoPath), "appx", sid, true);
        }
        return list;
    }

    private void ScanAndDiff(WatchedKey k, bool emit)
    {
        var current = k.Appx ? ScanAppx(k.Key) : ScanUninstall(k.Key);
        if (!_snapshots.TryGetValue(k.Id, out var previous))
        {
            _snapshots[k.Id] = current;   // baseline
            return;
        }
        _snapshots[k.Id] = current;
        if (!emit) return;

        foreach (var (name, entry) in current)
        {
            if (previous.ContainsKey(name)) continue;   // only new products; version bumps (auto-updates) are noise
            try
            {
                _sink.Emit(EventTypes.InstallDetected, k.Sid,
                    EventData.Install(entry.Product, entry.Version, entry.Publisher, k.Scope));
            }
            catch (Exception ex) { _log.LogWarning(ex, "Emit install.detected"); }
        }
    }

    private static Dictionary<string, Entry> ScanUninstall(RegistryKey root)
    {
        var result = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in root.GetSubKeyNames())
        {
            try
            {
                using var sub = root.OpenSubKey(name);
                if (sub is null) continue;
                if (sub.GetValue("DisplayName") is not string display || string.IsNullOrWhiteSpace(display)) continue;
                if (sub.GetValue("SystemComponent") is int sc && sc == 1) continue;
                if (sub.GetValue("ParentKeyName") is string) continue;          // patches / sub-components
                if (sub.GetValue("ReleaseType") is string rt
                    && (rt.Contains("Update", StringComparison.OrdinalIgnoreCase) || rt.Contains("Hotfix", StringComparison.OrdinalIgnoreCase)))
                    continue;
                result[name] = new Entry(display.Trim(), sub.GetValue("DisplayVersion") as string,
                    sub.GetValue("Publisher") as string);
            }
            catch { /* key vanished mid-scan */ }
        }
        return result;
    }

    private static Dictionary<string, Entry> ScanAppx(RegistryKey root)
    {
        var result = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        foreach (var fullName in root.GetSubKeyNames())
        {
            // Name_Version_Arch_ResourceId_PublisherId (ResourceId empty for main packages)
            var parts = fullName.Split('_');
            if (parts.Length != 5 || parts[3].Length != 0) continue;
            if (FrameworkPrefixes.Any(p => parts[0].StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;

            string product = parts[0];
            try
            {
                using var sub = root.OpenSubKey(fullName);
                if (sub?.GetValue("DisplayName") is string dn && dn.Length > 0
                    && !dn.StartsWith("@{", StringComparison.Ordinal) && !dn.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase))
                    product = dn;
            }
            catch { /* use package name */ }

            // key by family-ish identity so an update shows as a version change, not a new product
            result[parts[0] + "_" + parts[2]] = new Entry(product, parts[1], null);
        }
        return result;
    }
}
