using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Win32Registry = Microsoft.Win32.Registry;

namespace MinControl.Browser.Registry;

/// <summary>Real registry. Must run as SYSTEM (service). NEVER exercised on the dev machine.</summary>
public sealed partial class WindowsRegistryHive : IRegistryHive
{
    private static readonly Lock LoadLock = new();

    public IRegistryScope OpenUserHive(string sid, string? profilePath)
    {
        if (!SidLooksValid(sid)) throw new ArgumentException("invalid SID", nameof(sid));
        lock (LoadLock)
        {
            using (var existing = Win32Registry.Users.OpenSubKey(sid))
                if (existing is not null) return new Scope(Win32Registry.Users, sid, unloadOnDispose: false);

            if (string.IsNullOrEmpty(profilePath)) throw new InvalidOperationException($"no profile path for {sid}");
            string hiveFile = Path.Combine(profilePath, "NTUSER.DAT");
            if (!File.Exists(hiveFile)) throw new FileNotFoundException("user hive not found", hiveFile);

            Privileges.Enable("SeBackupPrivilege", "SeRestorePrivilege");
            int rc = RegLoadKey(HKEY_USERS, sid, hiveFile);
            if (rc != 0) throw new Win32Exception(rc, $"RegLoadKey {sid}");
            return new Scope(Win32Registry.Users, sid, unloadOnDispose: true);
        }
    }

    public IRegistryScope OpenLocalMachine() =>
        new Scope(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), "", unloadOnDispose: false);

    private static bool SidLooksValid(string sid) =>
        sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && sid.All(c => char.IsAsciiDigit(c) || c is '-' or 'S');

    private sealed class Scope(RegistryKey root, string prefix, bool unloadOnDispose) : IRegistryScope
    {
        private bool _disposed;

        private string Full(string key) => prefix.Length == 0 ? key : prefix + "\\" + key;

        public void SetValue(string key, string name, RegistryValueKind kind, object value)
        {
            using var k = root.CreateSubKey(Full(key), writable: true)
                ?? throw new InvalidOperationException($"cannot create {key}");
            k.SetValue(name, value, kind);
        }

        public void DeleteValue(string key, string name)
        {
            using var k = root.OpenSubKey(Full(key), writable: true);
            k?.DeleteValue(name, throwOnMissingValue: false);
        }

        public IReadOnlyDictionary<string, object> GetValues(string key)
        {
            var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            using var k = root.OpenSubKey(Full(key));
            if (k is null) return result;
            foreach (var name in k.GetValueNames())
                if (k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is { } v) result[name] = v;
            return result;
        }

        public void DeleteKeyIfEmpty(string key, string stopAt)
        {
            string current = key.TrimEnd('\\');
            while (current.Length > 0 && !string.Equals(current, stopAt.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            {
                using (var k = root.OpenSubKey(Full(current)))
                {
                    if (k is null || k.ValueCount > 0 || k.SubKeyCount > 0) return;
                }
                root.DeleteSubKey(Full(current), throwOnMissingSubKey: false);
                int cut = current.LastIndexOf('\\');
                current = cut < 0 ? "" : current[..cut];
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (unloadOnDispose)
            {
                lock (LoadLock)
                {
                    // All RegistryKey handles above are closed per call, so the hive can be unloaded now.
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    int rc = RegUnLoadKey(HKEY_USERS, prefix);
                    if (rc != 0) throw new Win32Exception(rc, $"RegUnLoadKey {prefix}");
                }
            }
            else if (prefix.Length == 0)
            {
                root.Dispose();
            }
        }
    }

    private static readonly nint HKEY_USERS = unchecked((nint)(int)0x80000003);

    [LibraryImport("advapi32.dll", EntryPoint = "RegLoadKeyW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegLoadKey(nint hKey, string subKey, string file);

    [LibraryImport("advapi32.dll", EntryPoint = "RegUnLoadKeyW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegUnLoadKey(nint hKey, string subKey);
}
