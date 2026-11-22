using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.NetGuard.Native;
using MinControl.NetGuard.Telemetry;

namespace MinControl.NetGuard.Bypass;

/// <summary>
/// Best-effort detection of attempts to get around the proxy. Connections refused by WFP never reach user mode,
/// so instead we periodically look at the TCP tables and adapters:
/// <list type="number">
/// <item>a managed-user process LISTENING on a proxy-like port (local SOCKS/HTTP proxy, Tor, Clash, v2ray…);</item>
/// <item>a managed-user process with an ESTABLISHED TCP connection to a non-loopback address that is not an exempt
///   app — should be impossible while WFP filters are in place, so it means the lock is broken or bypassed;</item>
/// <item>a network adapter whose description looks like a VPN/tunnel driver appearing after the baseline
///   (not attributable to a user → userSid null).</item>
/// </list>
/// Each finding emits <c>tamper.proxy_bypass_attempt</c>, de-duplicated for 10 minutes. UDP is not inspected.
/// </summary>
public sealed class BypassDetector
{
    public static readonly IReadOnlySet<int> ProxyLikePorts = new HashSet<int>
    {
        1080, 1081, 3128, 8080, 8118, 8888, 9050, 9051, 9150, 7890, 7891, 7897, 10808, 10809, 1087, 2080, 20170, 20171,
    };

    private static readonly string[] VpnAdapterMarkers =
    [
        "tap-windows", "tap-win32", "wintun", "wireguard", "openvpn", "nordlynx", "protonvpn", "tunnelbear", "hotspot shield",
        "psiphon", "windscribe", "expressvpn", "surfshark", "cyberghost", "softether", "zerotier", "tailscale", "hamachi",
        "outline", "cloudflare warp", "fortinet", "cisco anyconnect", "private internet access", "urban vpn", "hola",
    ];

    private readonly IUserDirectory _users;
    private readonly IEventSink _events;
    private readonly EventThrottle _throttle;
    private readonly ILogger _log;
    private readonly HashSet<string> _baselineAdapters = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselineTaken;

    public BypassDetector(IUserDirectory users, IEventSink events, IClock clock, ILogger<BypassDetector>? log = null)
    {
        _users = users;
        _events = events;
        _throttle = new EventThrottle(clock, TimeSpan.FromMinutes(10));
        _log = (ILogger?)log ?? NullLogger.Instance;
    }

    /// <param name="proxyPort">Our own port (never reported).</param>
    /// <param name="exemptPaths">Resolved netExemptApps per SID (direct connections expected).</param>
    public void Scan(int proxyPort, IReadOnlyDictionary<string, IReadOnlyList<string>> exemptPaths)
    {
        try { ScanTcp(proxyPort, exemptPaths); }
        catch (Exception ex) { _log.LogDebug(ex, "TCP bypass scan failed"); }
        try { ScanAdapters(); }
        catch (Exception ex) { _log.LogDebug(ex, "Adapter bypass scan failed"); }
    }

    private void ScanTcp(int proxyPort, IReadOnlyDictionary<string, IReadOnlyList<string>> exemptPaths)
    {
        if (_users.ManagedSids.Count == 0) return;
        var sidCache = new Dictionary<int, string?>();
        string? SidOf(int pid)
        {
            if (!sidCache.TryGetValue(pid, out var s)) sidCache[pid] = s = pid > 4 ? _users.SidOfProcess(pid) : null;
            return s;
        }

        foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
        {
            foreach (var row in TcpTable.All(family))
            {
                if (row.State == TcpRow.StateListen)
                {
                    if (row.LocalPort == proxyPort || !ProxyLikePorts.Contains(row.LocalPort)) continue;
                    var sid = SidOf(row.Pid);
                    if (sid is null || !_users.IsManaged(sid)) continue;
                    Report(sid, row.Pid, $"listener on proxy-like port {row.LocalPort}", $"listen|{row.LocalPort}");
                }
                else if (row.State == TcpRow.StateEstablished)
                {
                    if (IPAddress.IsLoopback(row.RemoteAddress) || row.RemoteAddress.Equals(IPAddress.Any) || row.RemoteAddress.Equals(IPAddress.IPv6Any)) continue;
                    var sid = SidOf(row.Pid);
                    if (sid is null || !_users.IsManaged(sid)) continue;
                    var path = ProcessInfo.ImagePath(row.Pid);
                    if (path is not null && exemptPaths.TryGetValue(sid, out var ex) &&
                        ex.Any(e => string.Equals(e, path, StringComparison.OrdinalIgnoreCase))) continue;
                    Report(sid, row.Pid, $"direct connection to {row.RemoteAddress}:{row.RemotePort} (WFP lock bypassed?)", $"direct|{path}");
                }
            }
        }
    }

    private void ScanAdapters()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var desc = $"{nic.Description} {nic.Name}";
            if (!_baselineTaken) { _baselineAdapters.Add(nic.Id); continue; }
            if (_baselineAdapters.Contains(nic.Id)) continue;
            _baselineAdapters.Add(nic.Id);
            var looksVpn = nic.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp
                || VpnAdapterMarkers.Any(m => desc.Contains(m, StringComparison.OrdinalIgnoreCase));
            if (!looksVpn) continue;
            if (!_throttle.ShouldEmit("nic|" + nic.Id)) continue;
            Emit(null, new JsonObject { ["detail"] = Clip($"new VPN/tunnel adapter: {nic.Description} ({nic.Name})") });
        }
        _baselineTaken = true;
    }

    private void Report(string sid, int pid, string detail, string dedupKey)
    {
        if (!_throttle.ShouldEmit(sid + "|" + dedupKey)) return;
        var path = ProcessInfo.ImagePath(pid);
        var data = new JsonObject { ["detail"] = Clip($"{detail}; pid {pid}") };
        if (path is not null) data["exe"] = DomainAggregator.Truncate(Path.GetFileName(path), 260);
        Emit(sid, data);
    }

    private void Emit(string? sid, JsonObject data)
    {
        try { _events.Emit(EventTypes.TamperProxyBypassAttempt, sid, data); }
        catch (Exception ex) { _log.LogWarning(ex, "Emit tamper.proxy_bypass_attempt failed"); }
    }

    private static string Clip(string s) => DomainAggregator.Truncate(s, 1024);
}
