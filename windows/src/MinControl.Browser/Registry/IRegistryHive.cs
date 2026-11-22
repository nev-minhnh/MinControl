using Microsoft.Win32;

namespace MinControl.Browser.Registry;

/// <summary>Registry access used by <see cref="Policy.BrowserPolicyWriter"/>; faked in tests.</summary>
public interface IRegistryHive
{
    /// <summary>Opens HKU\&lt;sid&gt;. If the user is not logged on, loads &lt;profile&gt;\NTUSER.DAT under HKU\&lt;sid&gt;
    /// (RegLoadKey, needs SeBackup/SeRestore) and unloads it when the scope is disposed.</summary>
    IRegistryScope OpenUserHive(string sid, string? profilePath);

    /// <summary>HKLM, 64-bit view.</summary>
    IRegistryScope OpenLocalMachine();
}

/// <summary>Key paths are relative to the scope root (e.g. "Software\Policies\Google\Chrome").</summary>
public interface IRegistryScope : IDisposable
{
    void SetValue(string key, string name, RegistryValueKind kind, object value);
    void DeleteValue(string key, string name);
    /// <summary>All values of a key (empty when the key does not exist).</summary>
    IReadOnlyDictionary<string, object> GetValues(string key);
    /// <summary>Deletes the key when it has no values and no subkeys; walks up while parents become empty,
    /// stopping at <paramref name="stopAt"/> (exclusive).</summary>
    void DeleteKeyIfEmpty(string key, string stopAt);
}
