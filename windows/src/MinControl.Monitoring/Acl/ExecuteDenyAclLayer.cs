using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
using MinControl.Monitoring.Rules;
using Microsoft.Extensions.Logging;

namespace MinControl.Monitoring.Acl;

/// <summary>
/// Optional kernel-enforced layer (SPEC §8.3, gated by <see cref="MonitoringOptions.EnableAclLayer"/>, default off):
/// adds a deny <c>ExecuteFile</c> ACE for the managed SID on executables targeted by <c>block</c> rules.
/// Eligible rules: <c>match</c> has a <c>path</c> (optionally <c>exe</c>) and nothing else, no <c>except</c> list,
/// wildcards only in the file-name segment. Eligible files: strictly under %ProgramFiles% or
/// %ProgramFiles(x86)% (never %windir%; never user-writable locations whose DACL the user could change).
/// Applied ACEs are recorded in a SYSTEM-only state file and removed when the rule disappears.
/// </summary>
public sealed class ExecuteDenyAclLayer : IMonitorComponent
{
    private readonly IPolicyProvider _policy;
    private readonly IUserDirectory _users;
    private readonly MonitoringOptions _options;
    private readonly ILogger<ExecuteDenyAclLayer> _log;
    private readonly object _gate = new();
    private Timer? _timer;

    public ExecuteDenyAclLayer(IPolicyProvider policy, IUserDirectory users, MonitoringOptions options, ILogger<ExecuteDenyAclLayer> log)
    {
        _policy = policy;
        _users = users;
        _options = options;
        _log = log;
    }

    private string StateFile => Path.Combine(_options.StateDirectory, "acl-deny-execute.json");

    void IMonitorComponent.Start()
    {
        if (!_options.EnableAclLayer) return;
        _policy.PolicyChanged += OnPolicyChanged;
        // also re-applies after app updates replace the exe (new file = no ACE)
        _timer = new Timer(_ => Reconcile(), null, TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(10));
    }

    void IMonitorComponent.Stop()
    {
        _policy.PolicyChanged -= OnPolicyChanged;
        _timer?.Dispose();
    }

    private void OnPolicyChanged(object? sender, DevicePolicy e) => ThreadPool.QueueUserWorkItem(_ => Reconcile());

    /// <summary>Computes the wanted (sid, file) set from the policy and converges the file system to it.</summary>
    public void Reconcile()
    {
        if (!_options.EnableAclLayer) return;
        lock (_gate)
        {
            try
            {
                var wanted = Wanted(_policy.Current);
                var applied = LoadState();

                foreach (var item in applied.Except(wanted))
                    TryChange(item, add: false);
                var nowApplied = new HashSet<AclItem>();
                foreach (var item in wanted)
                    if (TryChange(item, add: true)) nowApplied.Add(item);
                // keep entries whose removal failed so we retry next time
                foreach (var item in applied.Except(wanted))
                    if (File.Exists(item.File) && HasDenyAce(item)) nowApplied.Add(item);
                SaveState(nowApplied);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "ACL layer reconcile failed");
            }
        }
    }

    public readonly record struct AclItem(string Sid, string File);

    internal HashSet<AclItem> Wanted(DevicePolicy? policy)
    {
        var set = new HashSet<AclItem>();
        if (policy is null) return set;
        var roots = MachineInstallRoots();
        foreach (var (sid, up) in policy.Users)
        {
            if (!_users.IsManaged(sid) || _users.IsAdministrator(sid)) continue;   // I1 / I2
            foreach (var rule in up.AppRules)
            {
                if (!string.Equals(rule.Action, "block", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var file in EligibleFiles(rule, roots))
                    set.Add(new AclItem(sid, file));
            }
        }
        return set;
    }

    internal static IEnumerable<string> EligibleFiles(AppRule rule, IReadOnlyList<string> roots)
    {
        var m = rule.Match;
        if (rule.Except is { Count: > 0 } || m.Path is null || m.Publisher is not null || m.Sha256 is not null
            || m.PathUnderUserWritable == true)
            yield break;

        var expanded = PathExpander.Expand(m.Path, profilePath: null);
        if (expanded.Contains('%')) yield break;                               // per-user or unknown variable
        var dir = Path.GetDirectoryName(expanded);
        var namePattern = Path.GetFileName(expanded);
        if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(namePattern) || Glob.HasWildcards(dir)) yield break;
        if (!roots.Any(r => AppRuleEvaluator.IsUnder(expanded, r))) yield break;
        if (!Directory.Exists(dir)) yield break;

        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly).ToList(); }
        catch { yield break; }
        foreach (var f in files)
        {
            if (!Glob.IsMatch(namePattern, Path.GetFileName(f))) continue;
            if (m.Exe is not null && !Glob.IsMatch(m.Exe, Path.GetFileName(f))) continue;
            yield return f;
        }
    }

    private static List<string> MachineInstallRoots()
    {
        var roots = new List<string>();
        foreach (var f in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
        {
            var p = Environment.GetFolderPath(f);
            if (!string.IsNullOrEmpty(p) && !roots.Contains(p, StringComparer.OrdinalIgnoreCase)) roots.Add(p);
        }
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        // never let a root sit inside %windir%
        roots.RemoveAll(r => !string.IsNullOrEmpty(win) && (AppRuleEvaluator.IsUnder(r, win)
                                                         || string.Equals(r, win, StringComparison.OrdinalIgnoreCase)));
        return roots;
    }

    private static FileSystemAccessRule Rule(string sid)
        => new(new SecurityIdentifier(sid), FileSystemRights.ExecuteFile, AccessControlType.Deny);

    private bool TryChange(AclItem item, bool add)
    {
        try
        {
            var fi = new FileInfo(item.File);
            if (!fi.Exists) return false;
            var sec = fi.GetAccessControl(AccessControlSections.Access);
            if (add)
            {
                if (HasDenyAce(sec, item.Sid)) return true;
                sec.AddAccessRule(Rule(item.Sid));
            }
            else
            {
                if (!HasDenyAce(sec, item.Sid)) return true;
                sec.RemoveAccessRuleSpecific(Rule(item.Sid));
            }
            fi.SetAccessControl(sec);
            _log.LogInformation("{Op} deny-execute ACE for {Sid} on {File}", add ? "Added" : "Removed", item.Sid, item.File);
            return true;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Cannot {Op} ACE on {File}", add ? "add" : "remove", item.File);
            return false;
        }
    }

    private static bool HasDenyAce(AclItem item)
    {
        try { return HasDenyAce(new FileInfo(item.File).GetAccessControl(AccessControlSections.Access), item.Sid); }
        catch { return false; }
    }

    private static bool HasDenyAce(FileSecurity sec, string sid)
    {
        foreach (FileSystemAccessRule r in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)))
        {
            if (r.AccessControlType == AccessControlType.Deny && !r.IsInherited
                && r.IdentityReference.Value.Equals(sid, StringComparison.OrdinalIgnoreCase)
                && (r.FileSystemRights & FileSystemRights.ExecuteFile) != 0)
                return true;
        }
        return false;
    }

    private HashSet<AclItem> LoadState()
    {
        try
        {
            if (!File.Exists(StateFile)) return [];
            return JsonSerializer.Deserialize<HashSet<AclItem>>(File.ReadAllText(StateFile)) ?? [];
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "ACL state unreadable");
            return [];
        }
    }

    private void SaveState(HashSet<AclItem> items)
    {
        Directory.CreateDirectory(_options.StateDirectory);   // parent ProgramData\MinControl ACL is set by Setup (I7)
        var tmp = StateFile + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(items));
        File.Move(tmp, StateFile, overwrite: true);
    }
}
