using System.Text;
using MinControl.Browser.Registry;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MinControl.Browser.Policy;

/// <summary>
/// Applies <see cref="BrowserPolicyMapper"/> output to HKU\&lt;SID&gt; (loading NTUSER.DAT when needed) and registers
/// the native messaging host under HKLM. Touches only SIDs that <see cref="IUserDirectory.IsManaged"/> accepts (I1/I2).
/// </summary>
public sealed class BrowserPolicyWriter : IBrowserPolicyWriter
{
    private readonly IRegistryHive _hive;
    private readonly IUserDirectory _users;
    private readonly BrowserPolicyMapper _mapper;
    private readonly BrowserOptions _options;
    private readonly ILogger<BrowserPolicyWriter> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public BrowserPolicyWriter(IRegistryHive hive, IUserDirectory users, BrowserPolicyMapper mapper,
        IOptions<BrowserOptions> options, ILogger<BrowserPolicyWriter> log)
    {
        _hive = hive; _users = users; _mapper = mapper; _options = options.Value; _log = log;
    }

    public async Task ApplyAsync(string sid, WebPolicy web, int proxyPort, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(web);
        if (!_users.IsManaged(sid) || _users.IsAdministrator(sid))
        {
            _log.LogWarning("refusing to write browser policy for unmanaged/admin SID {Sid}", sid);
            return;
        }
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await Task.Run(() =>
            {
                ApplyMachine();
                using var user = _hive.OpenUserHive(sid, _users.ProfilePath(sid));
                foreach (var w in _mapper.MapUserValues(web, proxyPort)) user.SetValue(w.Key, w.Name, w.Kind, w.Value);
                foreach (var f in _mapper.MapForcelists()) WriteForcelist(user, f.Key, f.ExtensionId, f.Value);
                foreach (var key in BrowserPolicyMapper.ClearedListKeys())
                {
                    foreach (var name in user.GetValues(key).Keys) user.DeleteValue(key, name);
                    user.DeleteKeyIfEmpty(key, @"Software\Policies");
                }
            }, ct).ConfigureAwait(false);
            _log.LogInformation("browser policy applied for {Sid} (proxy port {Port})", sid, proxyPort);
        }
        finally { _gate.Release(); }
    }

    public async Task RemoveAsync(string sid, CancellationToken ct)
    {
        // Removal is allowed for any SID we may have written before (e.g. a user who became admin or left the
        // policy): it only deletes values this class owns.
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await Task.Run(() =>
            {
                using var user = _hive.OpenUserHive(sid, _users.ProfilePath(sid));
                foreach (var (key, name) in _mapper.UserValueNames()) user.DeleteValue(key, name);
                foreach (var w in BrowserPolicyMapper.MapUserResetValues()) user.SetValue(w.Key, w.Name, w.Kind, w.Value);
                foreach (var id in new[] { _options.EdgeExtensionId, _options.ChromeExtensionId }.Where(BrowserPolicyMapper.IsExtensionId))
                {
                    WriteForcelist(user, BrowserPolicyMapper.EdgePolicyKey + "\\" + BrowserPolicyMapper.ForcelistSubKey, id, null);
                    WriteForcelist(user, BrowserPolicyMapper.ChromePolicyKey + "\\" + BrowserPolicyMapper.ForcelistSubKey, id, null);
                }
                foreach (var key in new[]
                {
                    BrowserPolicyMapper.EdgePolicyKey + "\\" + BrowserPolicyMapper.ForcelistSubKey,
                    BrowserPolicyMapper.ChromePolicyKey + "\\" + BrowserPolicyMapper.ForcelistSubKey,
                    BrowserPolicyMapper.IeControlPanelPolicyKey,
                })
                {
                    user.DeleteKeyIfEmpty(key, @"Software\Policies");
                }
            }, ct).ConfigureAwait(false);
            _log.LogInformation("browser policy removed for {Sid}", sid);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Uninstall only: removes the HKLM native host registration and the manifest file.</summary>
    public async Task UnregisterNativeHostAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await Task.Run(() =>
            {
                using var hklm = _hive.OpenLocalMachine();
                foreach (var w in _mapper.MapMachineValues().Where(w => w.Key.Contains("NativeMessagingHosts", StringComparison.Ordinal)))
                {
                    hklm.DeleteValue(w.Key, w.Name);
                    hklm.DeleteKeyIfEmpty(w.Key, w.Key[..w.Key.LastIndexOf('\\')]);
                }
                if (File.Exists(_options.ResolvedManifestPath)) File.Delete(_options.ResolvedManifestPath);
            }, ct).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private void ApplyMachine()
    {
        string manifestPath = _options.ResolvedManifestPath;
        string manifest = _mapper.BuildNativeHostManifest();
        if (!File.Exists(manifestPath) || File.ReadAllText(manifestPath, Encoding.UTF8) != manifest)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(manifestPath)!);
            File.WriteAllText(manifestPath, manifest, new UTF8Encoding(false));
        }
        using var hklm = _hive.OpenLocalMachine();
        foreach (var w in _mapper.MapMachineValues()) hklm.SetValue(w.Key, w.Name, w.Kind, w.Value);
    }

    private static void WriteForcelist(IRegistryScope scope, string key, string extensionId, string? entry)
    {
        var existing = scope.GetValues(key);
        var merged = BrowserPolicyMapper.MergeForcelist(existing, extensionId, entry);
        foreach (var name in existing.Keys) if (!merged.ContainsKey(name)) scope.DeleteValue(key, name);
        foreach (var (name, value) in merged)
            if (!existing.TryGetValue(name, out var old) || !Equals(old, value))
                scope.SetValue(key, name, Microsoft.Win32.RegistryValueKind.String, value);
    }
}
