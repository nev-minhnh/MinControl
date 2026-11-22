using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Service.Logic;
using MinControl.Service.Native;
using MinControl.Service.Sessions;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace MinControl.Service.Users;

internal sealed record LocalAccount(string Sid, string Name, bool IsAdministrator);

/// <summary>Local accounts, Administrators membership and the managed set (I1/I2).
/// Managed = listed in the current policy AND not an administrator.</summary>
internal sealed class UserDirectory : IUserDirectory
{
    public const string AdministratorsSid = "S-1-5-32-544";
    private const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    private readonly IPolicyProvider _policy;
    private readonly IEventSink _events;
    private readonly IClock _clock;
    private readonly ILogger<UserDirectory> _log;
    private readonly object _gate = new();
    private readonly DailyLatch _adminAlert = new();
    private HashSet<string> _admins = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _managed = new(StringComparer.OrdinalIgnoreCase);
    private long _lastRefreshMono = long.MinValue;

    public UserDirectory(IPolicyProvider policy, IEventSink events, IClock clock, ILogger<UserDirectory> log)
    {
        _policy = policy;
        _events = events;
        _clock = clock;
        _log = log;
        _policy.PolicyChanged += (_, _) => Refresh();
    }

    public bool IsManaged(string sid)
    {
        RefreshIfStale();
        lock (_gate) return _managed.Contains(sid);
    }

    public bool IsAdministrator(string sid)
    {
        RefreshIfStale();
        lock (_gate) return _admins.Contains(sid);
    }

    /// <summary>Raised (on the refreshing thread) when the managed set changed: a SID joined/left the policy or
    /// became / stopped being an administrator. Policy, NetGuard and browser policies are re-applied on it.</summary>
    public event EventHandler? ManagedSetChanged;

    public IReadOnlyCollection<string> ManagedSids
    {
        get
        {
            RefreshIfStale();
            lock (_gate) return _managed.ToArray();
        }
    }

    public string? SidOfProcess(int pid)
    {
        if (pid <= 4) return null; // Idle / System
        using var process = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        return process.IsInvalid ? null : SidOfProcess(process);
    }

    public static string? SidOfProcess(Microsoft.Win32.SafeHandles.SafeProcessHandle process)
    {
        if (!Win32.OpenProcessToken(process, Win32.TOKEN_QUERY, out var token)) return null;
        using (token) return Win32.TokenUserSid(token);
    }

    public string? ProfilePath(string sid)
    {
        if (!sid.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase) || sid.Contains('\\')) return null;
        using var key = Registry.LocalMachine.OpenSubKey($@"{ProfileListKey}\{sid}");
        return key?.GetValue("ProfileImagePath") is string p ? Environment.ExpandEnvironmentVariables(p) : null;
    }

    /// <summary>Enabled local user accounts (for Setup / diagnostics).</summary>
    public IReadOnlyList<LocalAccount> LocalAccounts()
    {
        var result = new List<LocalAccount>();
        var resume = 0;
        int status;
        do
        {
            status = Win32.NetUserEnum(null, 0, Win32.FILTER_NORMAL_ACCOUNT, out var buffer, Win32.MAX_PREFERRED_LENGTH,
                out var read, out _, ref resume);
            if (status != Win32.NERR_Success && status != Win32.ERROR_MORE_DATA) break;
            try
            {
                for (var i = 0; i < read; i++)
                {
                    var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size));
                    if (string.IsNullOrEmpty(name)) continue;
                    var sid = TryTranslate(name);
                    if (sid is not null) result.Add(new LocalAccount(sid, name, IsAdministrator(sid)));
                }
            }
            finally { if (buffer != IntPtr.Zero) Win32.NetApiBufferFree(buffer); }
        } while (status == Win32.ERROR_MORE_DATA);
        return result;
    }

    private void RefreshIfStale()
    {
        if (_clock.MonotonicMs - Interlocked.Read(ref _lastRefreshMono) > 60_000) Refresh();
    }

    /// <summary>Recomputes admins + managed. Called on policy change, logon and every 60 s.</summary>
    public void Refresh()
    {
        Interlocked.Exchange(ref _lastRefreshMono, _clock.MonotonicMs);
        var admins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var sid in DirectAdministratorMembers()) admins.Add(sid);
            // Nested / domain-group membership is only visible in a logged-on token.
            foreach (var s in Wts.Enumerate())
            {
                var userSid = Wts.UserSid(s.SessionId);
                var groups = userSid is null ? null : Wts.UserGroupSids(s.SessionId);
                if (groups is not null && groups.Contains(AdministratorsSid, StringComparer.OrdinalIgnoreCase))
                    admins.Add(userSid!);
            }
        }
        catch (Exception e)
        {
            _log.LogError(e, "admin enumeration failed; keeping previous admin set");
            lock (_gate) admins.UnionWith(_admins);
        }

        var policy = _policy.Current;
        var policySids = policy?.Users.Keys.ToArray() ?? Array.Empty<string>();
        var managed = new HashSet<string>(policySids.Where(s => !admins.Contains(s)), StringComparer.OrdinalIgnoreCase);
        bool changed;
        lock (_gate)
        {
            changed = !_managed.SetEquals(managed);
            _admins = admins;
            _managed = managed;
        }
        if (changed)
        {
            try { ManagedSetChanged?.Invoke(this, EventArgs.Empty); }
            catch (Exception e) { _log.LogError(e, "ManagedSetChanged handler failed"); }
        }

        foreach (var sid in policySids.Where(admins.Contains))
        {
            var day = PolicyToday(policy!.Timezone);
            bool fire;
            lock (_gate) fire = _adminAlert.TryFire(sid, day);
            if (!fire) continue;
            _log.LogWarning("policy-managed SID {Sid} is an administrator; not enforcing (I2)", sid);
            _events.Emit(EventTypes.TamperManagedUserIsAdmin, sid,
                new JsonObject { ["detail"] = "managed user is a member of Administrators; enforcement suspended" });
        }
    }

    private DateOnly PolicyToday(string timezone)
    {
        var now = _clock.UtcNow;
        try { return DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(now, TimeZoneInfo.FindSystemTimeZoneById(timezone)).DateTime); }
        catch (Exception) { return DateOnly.FromDateTime(now.UtcDateTime); }
    }

    private static IEnumerable<string> DirectAdministratorMembers()
    {
        // Group name is localized; resolve it from the well-known SID.
        var account = new SecurityIdentifier(AdministratorsSid).Translate(typeof(NTAccount)).Value;
        var groupName = account[(account.IndexOf('\\') + 1)..];
        var list = new List<string>();
        var resume = IntPtr.Zero;
        int status;
        do
        {
            status = Win32.NetLocalGroupGetMembers(null, groupName, 0, out var buffer, Win32.MAX_PREFERRED_LENGTH,
                out var read, out _, ref resume);
            if (status != Win32.NERR_Success && status != Win32.ERROR_MORE_DATA)
                throw new InvalidOperationException($"NetLocalGroupGetMembers failed: {status}");
            try
            {
                for (var i = 0; i < read; i++) // LOCALGROUP_MEMBERS_INFO_0 { PSID }
                    list.Add(new SecurityIdentifier(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)).Value);
            }
            finally { if (buffer != IntPtr.Zero) Win32.NetApiBufferFree(buffer); }
        } while (status == Win32.ERROR_MORE_DATA);
        return list;
    }

    private static string? TryTranslate(string name)
    {
        try { return ((SecurityIdentifier)new NTAccount(Environment.MachineName, name).Translate(typeof(SecurityIdentifier))).Value; }
        catch (IdentityNotMappedException) { return null; }
    }
}
