using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using MinControl.Monitoring.Native;
using MinControl.Monitoring.Rules;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

namespace MinControl.Monitoring.Acl;

/// <summary>
/// Production wiring of <see cref="UserWritableAcl"/>: reads owner + DACL from the file system and evaluates them for
/// the managed user's real token groups (taken from one of the user's own, unrestricted processes) or, when no
/// such token is available, the user SID + well-known interactive groups. Token groups are cached per SID for
/// 10 minutes; directory verdicts are cached by <see cref="UserWritableAcl"/>.
/// </summary>
internal sealed class UserWritableProbe
{
    private static readonly TimeSpan PrincipalTtl = TimeSpan.FromMinutes(10);

    private readonly UserWritableAcl _acl = new(ReadSecurity);
    private readonly ConcurrentDictionary<string, (PrincipalSet Set, bool FromToken, long At)> _principals =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ILogger _log;

    public UserWritableProbe(ILogger log) => _log = log;

    /// <summary>Policy change / periodic: forget cached verdicts and token groups.</summary>
    public void Invalidate()
    {
        _acl.Invalidate();
        _principals.Clear();
    }

    /// <param name="pidHint">A live process of <paramref name="sid"/> whose token groups can be used, or 0.</param>
    public bool IsUserWritable(string sid, string exePath, int pidHint)
    {
        try
        {
            return _acl.IsUserWritable(exePath, PrincipalsFor(sid, pidHint));
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "ACL check failed for {Path}; treating as user-writable", exePath);
            return true; // fail closed
        }
    }

    private PrincipalSet PrincipalsFor(string sid, int pidHint)
    {
        long now = Environment.TickCount64;
        if (_principals.TryGetValue(sid, out var c) && now - c.At < (long)PrincipalTtl.TotalMilliseconds
            && (c.FromToken || pidHint <= 0))
            return c.Set;

        PrincipalSet set;
        bool fromToken = false;
        if (pidHint > 0 && TokenPrincipals(sid, pidHint) is { } fromProcess)
        {
            set = fromProcess;
            fromToken = true;
        }
        else
        {
            set = PrincipalSet.Fallback(sid);
        }
        _principals[sid] = (set, fromToken, now);
        return set;
    }

    /// <summary>Token groups of an unrestricted process owned by <paramref name="sid"/>, unioned with the well-known
    /// interactive groups (adding groups can only make the check stricter). Null when unusable.</summary>
    private static PrincipalSet? TokenPrincipals(string sid, int pid)
    {
        using var process = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process.IsInvalid) return null;
        if (!NativeMethods.OpenProcessToken(process, NativeMethods.TOKEN_QUERY, out var token)) return null;
        using (token)
        {
            // Sandboxed children (browser renderers...) carry restricted tokens whose groups are mostly deny-only.
            if (NativeMethods.IsTokenRestricted(token)) return null;
            if (!string.Equals(TokenUserSid(token), sid, StringComparison.OrdinalIgnoreCase)) return null;

            var enabled = new List<string>(PrincipalSet.WellKnownInteractiveGroups);
            var denyOnly = new List<string>();
            var buffer = TokenInfo(token, NativeMethods.TokenGroups);
            if (buffer == IntPtr.Zero) return null;
            try
            {
                // TOKEN_GROUPS { DWORD GroupCount; SID_AND_ATTRIBUTES Groups[]; } - array is pointer-aligned
                int count = Marshal.ReadInt32(buffer);
                int stride = IntPtr.Size * 2;
                for (int i = 0; i < count; i++)
                {
                    IntPtr entry = buffer + IntPtr.Size + i * stride;
                    IntPtr psid = Marshal.ReadIntPtr(entry);
                    uint attrs = (uint)Marshal.ReadInt32(entry, IntPtr.Size);
                    string group = new SecurityIdentifier(psid).Value;
                    if ((attrs & NativeMethods.SE_GROUP_USE_FOR_DENY_ONLY) != 0) denyOnly.Add(group);
                    else if ((attrs & NativeMethods.SE_GROUP_ENABLED) != 0) enabled.Add(group);
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return new PrincipalSet(sid, enabled, denyOnly);
        }
    }

    private static string? TokenUserSid(SafeAccessTokenHandle token)
    {
        var buffer = TokenInfo(token, NativeMethods.TokenUser);
        if (buffer == IntPtr.Zero) return null;
        try { return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value; } // TOKEN_USER { SID_AND_ATTRIBUTES }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static IntPtr TokenInfo(SafeAccessTokenHandle token, int infoClass)
    {
        NativeMethods.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out int needed);
        if (needed <= 0) return IntPtr.Zero;
        IntPtr buffer = Marshal.AllocHGlobal(needed);
        if (NativeMethods.GetTokenInformation(token, infoClass, buffer, needed, out _)) return buffer;
        Marshal.FreeHGlobal(buffer);
        return IntPtr.Zero;
    }

    /// <summary>Owner + DACL of a path, null when missing or unreadable (callers treat null as writable).</summary>
    private static RawSecurityDescriptor? ReadSecurity(string path, bool isDirectory)
    {
        try
        {
            const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
            FileSystemSecurity sec;
            if (isDirectory)
            {
                var di = new DirectoryInfo(path.Length == 2 ? path + "\\" : path);
                if (!di.Exists) return null;
                sec = di.GetAccessControl(sections);
            }
            else
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return null;
                sec = fi.GetAccessControl(sections);
            }
            return new RawSecurityDescriptor(sec.GetSecurityDescriptorBinaryForm(), 0);
        }
        catch (Exception)
        {
            return null;
        }
    }
}
