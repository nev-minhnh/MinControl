using System.Runtime.InteropServices;
using MinControl.Service.Native;

namespace MinControl.Service.Sessions;

/// <summary>Thin wrapper over the Terminal Services API (requires LocalSystem for WTSQueryUserToken).</summary>
internal static class Wts
{
    public readonly record struct SessionEntry(int SessionId, Win32.WTS_CONNECTSTATE_CLASS State);

    public static IReadOnlyList<SessionEntry> Enumerate()
    {
        if (!Win32.WTSEnumerateSessionsW(Win32.WTS_CURRENT_SERVER_HANDLE, 0, 1, out var buffer, out var count))
            return Array.Empty<SessionEntry>();
        try
        {
            var size = Marshal.SizeOf<Win32.WTS_SESSION_INFO>();
            var list = new List<SessionEntry>(count);
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<Win32.WTS_SESSION_INFO>(buffer + i * size);
                if (info.SessionId != 0) list.Add(new SessionEntry(info.SessionId, info.State)); // 0 = services
            }
            return list;
        }
        finally { Win32.WTSFreeMemory(buffer); }
    }

    /// <summary>SID of the user logged on to the session, null if nobody (or the token is not available yet).</summary>
    public static string? UserSid(int sessionId)
    {
        if (!Win32.WTSQueryUserToken(sessionId, out var token)) return null;
        using (token) return Win32.TokenUserSid(token);
    }

    /// <summary>Group SIDs of the logged-on user's token (covers nested/domain membership of Administrators).</summary>
    public static IReadOnlyList<string>? UserGroupSids(int sessionId)
    {
        if (!Win32.WTSQueryUserToken(sessionId, out var token)) return null;
        using (token) return Win32.TokenGroupSids(token);
    }

    /// <summary>Lock state from WTSINFOEX level 1 (SessionFlags at offset 12). Null if unknown.</summary>
    public static bool? IsLocked(int sessionId)
    {
        if (!Win32.WTSQuerySessionInformationW(Win32.WTS_CURRENT_SERVER_HANDLE, sessionId, Win32.WTSSessionInfoEx,
                out var buffer, out var bytes))
            return null;
        try
        {
            if (bytes < 16 || Marshal.ReadInt32(buffer) != 1) return null;
            var flags = Marshal.ReadInt32(buffer, 12);
            return flags switch
            {
                Win32.WTS_SESSIONSTATE_LOCK => true,
                Win32.WTS_SESSIONSTATE_UNLOCK => false,
                _ => null,
            };
        }
        finally { Win32.WTSFreeMemory(buffer); }
    }

    public static int ActiveConsoleSessionId() => Win32.WTSGetActiveConsoleSessionId(); // -1 (0xFFFFFFFF) if none

    /// <summary>Enforcement action. Callers MUST have checked that the session belongs to a managed SID (I1/I2).</summary>
    public static bool Logoff(int sessionId) => Win32.WTSLogoffSession(Win32.WTS_CURRENT_SERVER_HANDLE, sessionId, false);
}
