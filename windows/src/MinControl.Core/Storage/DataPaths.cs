using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace MinControl.Core.Storage;

/// <summary>Locations under %ProgramData%\MinControl (I7) and the ACL helper.</summary>
public sealed class DataPaths
{
    public DataPaths(string? root = null)
    {
        Root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinControl");
    }

    public string Root { get; }
    public string StateDb => Path.Combine(Root, "state.db");
    public string DeviceKey => Path.Combine(Root, "device.key");
    public string Screens => Path.Combine(Root, "screens");
    public string Logs => Path.Combine(Root, "logs");

    public void EnsureExists() => Directory.CreateDirectory(Root);

    /// <summary>
    /// Sets the directory ACL to SYSTEM:F + Administrators:F, inheritance to children, no inherited ACEs
    /// (so Users/Authenticated Users get nothing). Windows only; call from Setup/Service running elevated.
    /// Existing children get the inherited ACEs re-applied by the OS because they inherit from this folder.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public void ApplyRestrictedAcl()
    {
        EnsureExists();
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.SetOwner(admins);
        new DirectoryInfo(Root).SetAccessControl(sec);
    }

    /// <summary>True when the directory ACL grants nothing to principals other than SYSTEM/Administrators.</summary>
    [SupportedOSPlatform("windows")]
    public bool IsAclRestricted()
    {
        if (!Directory.Exists(Root)) return false;
        var sec = new DirectoryInfo(Root).GetAccessControl();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        foreach (FileSystemAccessRule r in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (r.AccessControlType != AccessControlType.Allow) continue;
            var sid = (SecurityIdentifier)r.IdentityReference;
            if (!sid.Equals(system) && !sid.Equals(admins)) return false;
        }
        return true;
    }
}
