using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace MinControl.Service.Native;

// Hand-written P/Invoke (blittable signatures only). Kept internal to the Service.
internal static class Win32
{
    public const uint ERROR_INSUFFICIENT_BUFFER = 122;

    // ---- token access / classes
    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001, TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008,
        TOKEN_ADJUST_DEFAULT = 0x0080, TOKEN_ADJUST_SESSIONID = 0x0100, MAXIMUM_ALLOWED = 0x02000000;
    public const int TokenUser = 1, TokenGroups = 2, TokenSessionId = 12;
    public const int SecurityImpersonation = 2, TokenPrimary = 1;

    // ---- process access / creation
    public const uint PROCESS_TERMINATE = 0x0001, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, SYNCHRONIZE = 0x00100000;
    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400, CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000;
    public const uint WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 0x102;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    private const int SM_SHUTTINGDOWN = 0x2000;

    /// <summary>True while Windows is shutting down / restarting (the stop may arrive before SERVICE_CONTROL_SHUTDOWN).</summary>
    public static bool IsSystemShuttingDown()
    {
        try { return GetSystemMetrics(SM_SHUTTINGDOWN) != 0; }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException) { return false; }
    }

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(SafeProcessHandle handle, uint ms);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    public static extern bool QueryFullProcessImageName(SafeProcessHandle process, int flags, char[] buffer, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    public static extern int WTSGetActiveConsoleSessionId();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out int clientPid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ProcessIdToSessionId(int pid, out int sessionId);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenProcessToken")]
    public static extern bool OpenProcessTokenRaw(IntPtr process, uint access, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(SafeAccessTokenHandle token, int cls, IntPtr info, int length, out int returned);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetTokenInformation(SafeAccessTokenHandle token, int cls, ref int info, int length);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing, uint access, IntPtr attributes,
        int impersonationLevel, int tokenType, out SafeAccessTokenHandle newToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessAsUserW")]
    public static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string? applicationName,
        char[] commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        uint creationFlags, IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    // ---- WTS
    public static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
    public const int WTSSessionInfoEx = 25;
    public const int WTS_SESSIONSTATE_LOCK = 0, WTS_SESSIONSTATE_UNLOCK = 1;

    public enum WTS_CONNECTSTATE_CLASS
    {
        Active, Connected, ConnectQuery, Shadow, Disconnected, Idle, Listen, Reset, Down, Init,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQueryUserToken(int sessionId, out SafeAccessTokenHandle token);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSLogoffSession(IntPtr server, int sessionId, bool wait);

    // ---- netapi32 (local accounts / groups)
    public const int NERR_Success = 0, ERROR_MORE_DATA = 234, FILTER_NORMAL_ACCOUNT = 2, MAX_PREFERRED_LENGTH = -1;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserEnum(string? server, int level, int filter, out IntPtr buffer, int prefMaxLen,
        out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupGetMembers(string? server, string groupName, int level, out IntPtr buffer,
        int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);

    // ---- helpers

    /// <summary>Reads a variable-length token information class into unmanaged memory and hands it to <paramref name="read"/>.</summary>
    public static T? WithTokenInfo<T>(SafeAccessTokenHandle token, int cls, Func<IntPtr, T> read)
    {
        GetTokenInformation(token, cls, IntPtr.Zero, 0, out var needed);
        if (needed <= 0) return default;
        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            return GetTokenInformation(token, cls, buffer, needed, out _) ? read(buffer) : default;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    /// <summary>SID string of the token user (TOKEN_USER.User.Sid).</summary>
    public static string? TokenUserSid(SafeAccessTokenHandle token) =>
        WithTokenInfo(token, TokenUser, p => new System.Security.Principal.SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);

    /// <summary>All group SIDs in the token (regardless of attributes, so UAC deny-only Administrators is included).</summary>
    public static IReadOnlyList<string> TokenGroupSids(SafeAccessTokenHandle token) =>
        WithTokenInfo<IReadOnlyList<string>>(token, TokenGroups, p =>
        {
            var count = Marshal.ReadInt32(p);
            var size = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
            var list = new List<string>(count);
            for (var i = 0; i < count; i++)
            {
                var entry = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(p + IntPtr.Size + i * size);
                list.Add(new System.Security.Principal.SecurityIdentifier(entry.Sid).Value);
            }
            return list;
        }) ?? Array.Empty<string>();

    public static string? ImagePath(SafeProcessHandle process)
    {
        var buffer = new char[1024];
        var size = buffer.Length;
        return QueryFullProcessImageName(process, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
    }
}
