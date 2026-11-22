using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace MinControl.NetGuard.Native;

/// <summary>
/// One row of the TCP owner table (ports in host byte order). <paramref name="Created"/> is the kernel's creation
/// timestamp of the connection (TCP_TABLE_OWNER_MODULE_* tables only; null when unavailable).
/// </summary>
public readonly record struct TcpRow(IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort, int State, int Pid,
    DateTimeOffset? Created = null)
{
    public const int StateListen = 2, StateEstablished = 5;
}

/// <summary>
/// Thin wrapper over iphlpapi!GetExtendedTcpTable (TCP_TABLE_OWNER_PID_* / TCP_TABLE_OWNER_MODULE_ALL). Read-only,
/// except <see cref="TryDeleteTcb"/> which resets one IPv4 connection (SetTcpEntry, needs admin/SYSTEM).
/// </summary>
public static partial class TcpTable
{
    private const int AF_INET = 2, AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_LISTENER = 3, TCP_TABLE_OWNER_PID_CONNECTIONS = 4, TCP_TABLE_OWNER_PID_ALL = 5;
    private const int TCP_TABLE_OWNER_MODULE_ALL = 8;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint MIB_TCP_STATE_DELETE_TCB = 12;

    [LibraryImport("iphlpapi.dll", SetLastError = false)]
    private static partial uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf, int tableClass, int reserved);

    [LibraryImport("iphlpapi.dll", SetLastError = false)]
    private static unsafe partial uint SetTcpEntry(uint* pTcpRow);

    public static List<TcpRow> Connections(AddressFamily family) => Read(family, TCP_TABLE_OWNER_PID_CONNECTIONS);
    public static List<TcpRow> Listeners(AddressFamily family) => Read(family, TCP_TABLE_OWNER_PID_LISTENER);
    public static List<TcpRow> All(AddressFamily family) => Read(family, TCP_TABLE_OWNER_PID_ALL);

    /// <summary>All rows with creation timestamps (owner-module table); falls back to the owner-PID table (Created = null).</summary>
    public static List<TcpRow> AllWithCreateTime(AddressFamily family) =>
        ReadModule(family) ?? Read(family, TCP_TABLE_OWNER_PID_ALL);

    /// <summary>
    /// Resets one established IPv4 connection (SetTcpEntry with MIB_TCP_STATE_DELETE_TCB). IPv6 has no equivalent API.
    /// Returns false on failure or for a non-IPv4 row.
    /// </summary>
    public static unsafe bool TryDeleteTcb(TcpRow row)
    {
        if (row.LocalAddress.AddressFamily != AddressFamily.InterNetwork || row.RemoteAddress.AddressFamily != AddressFamily.InterNetwork)
            return false;
        // MIB_TCPROW: state, localAddr, localPort, remoteAddr, remotePort (5 x DWORD; addresses/ports in network order)
        var r = stackalloc uint[5];
        r[0] = MIB_TCP_STATE_DELETE_TCB;
        r[1] = Addr(row.LocalAddress);
        r[2] = BinaryPrimitives.ReverseEndianness((ushort)row.LocalPort);
        r[3] = Addr(row.RemoteAddress);
        r[4] = BinaryPrimitives.ReverseEndianness((ushort)row.RemotePort);
        return SetTcpEntry(r) == 0;
    }

    private static uint Addr(IPAddress a)
    {
        Span<byte> b = stackalloc byte[4];
        a.TryWriteBytes(b, out _);
        return MemoryMarshal.Read<uint>(b);   // same in-memory layout as dwLocalAddr / new IPAddress(uint)
    }

    /// <summary>PID owning the client end of a loopback connection to <paramref name="serverPort"/> from <paramref name="clientPort"/>.</summary>
    public static int? OwnerOfLoopbackClient(IPEndPoint client, int serverPort)
    {
        var family = client.AddressFamily == AddressFamily.InterNetworkV6 && !client.Address.IsIPv4MappedToIPv6
            ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        foreach (var r in Connections(family))
            if (r.LocalPort == client.Port && r.RemotePort == serverPort && IPAddress.IsLoopback(r.LocalAddress))
                return r.Pid;
        return null;
    }

    private static unsafe List<TcpRow> Read(AddressFamily family, int tableClass)
    {
        var af = family == AddressFamily.InterNetworkV6 ? AF_INET6 : AF_INET;
        var rows = new List<TcpRow>();
        int size = 0;
        IntPtr buf = IntPtr.Zero;
        try
        {
            for (var attempt = 0; attempt < 5; attempt++)
            {
                var rc = GetExtendedTcpTable(buf, ref size, false, af, tableClass, 0);
                if (rc == 0) break;
                if (rc != ERROR_INSUFFICIENT_BUFFER) return rows;
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                size += 4096;
                buf = Marshal.AllocHGlobal(size);
            }
            if (buf == IntPtr.Zero) return rows;

            var p = (byte*)buf;
            var count = *(uint*)p;
            p += 4;
            if (af == AF_INET)
            {
                // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 x DWORD)
                for (var i = 0; i < count; i++, p += 24)
                {
                    var d = (uint*)p;
                    rows.Add(new TcpRow(new IPAddress(d[1]), Port(d[2]), new IPAddress(d[3]), Port(d[4]), (int)d[0], (int)d[5]));
                }
            }
            else
            {
                // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid = 56 bytes
                for (var i = 0; i < count; i++, p += 56)
                {
                    var local = new IPAddress(new ReadOnlySpan<byte>(p, 16), *(uint*)(p + 16));
                    var lport = Port(*(uint*)(p + 20));
                    var remote = new IPAddress(new ReadOnlySpan<byte>(p + 24, 16), *(uint*)(p + 40));
                    var rport = Port(*(uint*)(p + 44));
                    rows.Add(new TcpRow(local, lport, remote, rport, (int)*(uint*)(p + 48), (int)*(uint*)(p + 52)));
                }
            }
            return rows;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    private static unsafe List<TcpRow>? ReadModule(AddressFamily family)
    {
        var af = family == AddressFamily.InterNetworkV6 ? AF_INET6 : AF_INET;
        int size = 0;
        IntPtr buf = IntPtr.Zero;
        try
        {
            var ok = false;
            for (var attempt = 0; attempt < 5; attempt++)
            {
                var rc = GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_MODULE_ALL, 0);
                if (rc == 0) { ok = buf != IntPtr.Zero; break; }
                if (rc != ERROR_INSUFFICIENT_BUFFER) return null;
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                size += 8192;
                buf = Marshal.AllocHGlobal(size);
            }
            if (!ok) return null;

            var rows = new List<TcpRow>();
            var count = *(uint*)buf;
            // Rows contain a LARGE_INTEGER, so they are 8-byte aligned: the first row starts at offset 8.
            var p = (byte*)buf + 8;
            if (af == AF_INET)
            {
                // MIB_TCPROW_OWNER_MODULE: 6 x DWORD, liCreateTimestamp (8), OwningModuleInfo[16] (128) = 160 bytes
                for (var i = 0; i < count; i++, p += 160)
                {
                    var d = (uint*)p;
                    rows.Add(new TcpRow(new IPAddress(d[1]), Port(d[2]), new IPAddress(d[3]), Port(d[4]), (int)d[0], (int)d[5],
                        FileTime(*(long*)(p + 24))));
                }
            }
            else
            {
                // MIB_TCP6ROW_OWNER_MODULE: 56 bytes as MIB_TCP6ROW_OWNER_PID, liCreateTimestamp (8), OwningModuleInfo (128) = 192
                for (var i = 0; i < count; i++, p += 192)
                {
                    var local = new IPAddress(new ReadOnlySpan<byte>(p, 16), *(uint*)(p + 16));
                    var lport = Port(*(uint*)(p + 20));
                    var remote = new IPAddress(new ReadOnlySpan<byte>(p + 24, 16), *(uint*)(p + 40));
                    var rport = Port(*(uint*)(p + 44));
                    rows.Add(new TcpRow(local, lport, remote, rport, (int)*(uint*)(p + 48), (int)*(uint*)(p + 52), FileTime(*(long*)(p + 56))));
                }
            }
            return rows;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    // liCreateTimestamp is a FILETIME (UTC); 0 (or garbage) = unknown.
    private static DateTimeOffset? FileTime(long ft)
    {
        if (ft <= 0) return null;
        try { return DateTimeOffset.FromFileTime(ft).ToUniversalTime(); }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    // dwLocalPort holds the port in network byte order in the low 16 bits.
    private static int Port(uint raw) => BinaryPrimitives.ReverseEndianness((ushort)(raw & 0xFFFF));
}

/// <summary>Process image path lookup (PROCESS_QUERY_LIMITED_INFORMATION; works for other users' processes as SYSTEM).</summary>
public static partial class ProcessInfo
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr h);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(IntPtr h, uint flags, char* buffer, ref int size);

    public static unsafe string? ImagePath(int pid)
    {
        if (pid <= 4) return null;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var buf = stackalloc char[1024];
            var size = 1024;
            return QueryFullProcessImageName(h, 0, buf, ref size) ? new string(buf, 0, size) : null;
        }
        finally { CloseHandle(h); }
    }
}
