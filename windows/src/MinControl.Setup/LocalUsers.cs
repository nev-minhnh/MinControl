using System.Runtime.InteropServices;
using System.Security.Principal;

namespace MinControl.Setup;

public sealed record LocalUser(string Sid, string Name, bool IsAdmin);

/// <summary>Enumerates enabled local accounts (incl. Microsoft-account-linked ones) and their admin flag. Read-only.</summary>
internal static class LocalUsers
{
    private const int FilterNormalAccount = 0x0002, MaxPreferredLength = -1, UfAccountDisable = 0x0002, UserPrivAdmin = 2, NerrSuccess = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1
    {
        public string usri1_name; public string usri1_password; public int usri1_password_age; public int usri1_priv;
        public string usri1_home_dir; public string usri1_comment; public int usri1_flags; public string usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo0 { public IntPtr lgrmi0_sid; }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserEnum(string? servername, int level, int filter, out IntPtr bufptr, int prefmaxlen,
        out int entriesread, out int totalentries, ref int resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? servername, string localgroupname, int level, out IntPtr bufptr,
        int prefmaxlen, out int entriesread, out int totalentries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    public static IReadOnlyList<LocalUser> Enumerate()
    {
        var admins = AdministratorSids();
        var result = new List<LocalUser>();
        int resume = 0;
        var rc = NetUserEnum(null, 1, FilterNormalAccount, out var buf, MaxPreferredLength, out var read, out _, ref resume);
        if (rc != NerrSuccess) throw new InvalidOperationException($"NetUserEnum failed ({rc})");
        try
        {
            var size = Marshal.SizeOf<UserInfo1>();
            for (int i = 0; i < read; i++)
            {
                var u = Marshal.PtrToStructure<UserInfo1>(buf + i * size);
                if ((u.usri1_flags & UfAccountDisable) != 0) continue;
                string sid;
                try { sid = ((SecurityIdentifier)new NTAccount(Environment.MachineName, u.usri1_name).Translate(typeof(SecurityIdentifier))).Value; }
                catch (IdentityNotMappedException) { continue; }
                if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) continue;
                result.Add(new LocalUser(sid, u.usri1_name, u.usri1_priv == UserPrivAdmin || admins.Contains(sid)));
            }
        }
        finally { NetApiBufferFree(buf); }
        return result;
    }

    private static HashSet<string> AdministratorSids()
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        var groupName = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Translate(typeof(NTAccount)).Value;
        groupName = groupName[(groupName.IndexOf('\\') + 1)..];
        var resume = IntPtr.Zero;
        var rc = NetLocalGroupGetMembers(null, groupName, 0, out var buf, MaxPreferredLength, out var read, out _, ref resume);
        if (rc != NerrSuccess) throw new InvalidOperationException($"NetLocalGroupGetMembers failed ({rc})");
        try
        {
            var size = Marshal.SizeOf<LocalGroupMembersInfo0>();
            for (int i = 0; i < read; i++)
                set.Add(new SecurityIdentifier(Marshal.PtrToStructure<LocalGroupMembersInfo0>(buf + i * size).lgrmi0_sid).Value);
        }
        finally { NetApiBufferFree(buf); }
        return set;
    }
}
