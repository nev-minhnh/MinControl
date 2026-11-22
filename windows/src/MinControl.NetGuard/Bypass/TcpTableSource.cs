using System.Net.Sockets;
using MinControl.NetGuard.Native;

namespace MinControl.NetGuard.Bypass;

/// <summary>Seam over the OS TCP table so <see cref="BypassDetector"/> can be tested with synthetic rows.</summary>
public interface ITcpTableSource
{
    /// <summary>All TCP rows of one family, with <see cref="TcpRow.Created"/> when the OS provides it.</summary>
    IReadOnlyList<TcpRow> Read(AddressFamily family);

    /// <summary>Resets one IPv4 connection. False on failure (IPv6 cannot be reset).</summary>
    bool TryReset(TcpRow row);

    /// <summary>Full image path of a process, null if gone/inaccessible.</summary>
    string? ImagePath(int pid);
}

/// <summary>Production source: iphlpapi (GetExtendedTcpTable / SetTcpEntry) and QueryFullProcessImageName.</summary>
public sealed class SystemTcpTableSource : ITcpTableSource
{
    public IReadOnlyList<TcpRow> Read(AddressFamily family) => TcpTable.AllWithCreateTime(family);
    public bool TryReset(TcpRow row) => TcpTable.TryDeleteTcb(row);
    public string? ImagePath(int pid) => ProcessInfo.ImagePath(pid);
}
