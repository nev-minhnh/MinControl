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
using MinControl.NetGuard.Wfp;

namespace MinControl.NetGuard.Bypass;

/// <summary>Outcome of <see cref="BypassDetector.OnFiltersApplied"/>.</summary>
public readonly record struct EnforcementResult(int Reset, int ResetFailed, int Ipv6Left);

/// <summary>
/// Best-effort detection of attempts to get around the proxy. Connections refused by WFP never reach user mode,
/// so instead we periodically look at the TCP tables and adapters:
/// <list type="number">
/// <item>a managed-user process LISTENING on a proxy-like port (local SOCKS/HTTP proxy, Tor, Clash, v2ray…);</item>
/// <item>a managed-user process with an ESTABLISHED TCP connection to a non-loopback address that is not an exempt
///   app and was created after that user's filters were (re)applied (+ grace) — WFP ALE filters only stop NEW
///   connections, so older ones are pre-existing, not a bypass. Reported only while our filters for the SID are
///   verified present (missing filters are tamper.wfp_filter_missing, the watchdog's job);</item>
/// <item>a network adapter whose description looks like a VPN/tunnel driver appearing after the baseline
///   (not attributable to a user → userSid null).</item>
/// </list>
/// Nothing is reported during the first minute after service start. Direct connections are aggregated per
/// (sid, exe) into one <c>tamper.proxy_bypass_attempt</c> per 10 minutes; other findings are de-duplicated for
/// 10 minutes. UDP is not inspected.
/// <para><see cref="OnFiltersApplied"/> resets (IPv4) the pre-existing connections the new filters would block.</para>
/// </summary>
public sealed class BypassDetector
{
    public static readonly IReadOnlySet<int> ProxyLikePorts = new HashSet<int>
    {
        1080, 1081, 3128, 8080, 8118, 8888, 9050, 9051, 9150, 7890, 7891, 7897, 10808, 10809, 1087, 2080, 20170, 20171,
    };

    /// <summary>No findings at all this long after service start (install/restart churn).</summary>
    public static readonly TimeSpan StartupQuiet = TimeSpan.FromSeconds(60);
    /// <summary>Connections created before (filters applied + this) count as pre-existing.</summary>
    public static readonly TimeSpan ApplyGrace = TimeSpan.FromSeconds(10);
    /// <summary>Aggregation / de-duplication window.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    private static readonly string[] VpnAdapterMarkers =
    [
        "tap-windows", "tap-win32", "wintun", "wireguard", "openvpn", "nordlynx", "protonvpn", "tunnelbear", "hotspot shield",
        "psiphon", "windscribe", "expressvpn", "surfshark", "cyberghost", "softether", "zerotier", "tailscale", "hamachi",
        "outline", "cloudflare warp", "fortinet", "cisco anyconnect", "private internet access", "urban vpn", "hola",
    ];

    private readonly IUserDirectory _users;
    private readonly IEventSink _events;
    private readonly IClock _clock;
    private readonly ITcpTableSource _tcp;
    private readonly EventThrottle _throttle;
    private readonly ILogger _log;
    private readonly long _startMs;
    private readonly object _gate = new();
    private readonly HashSet<string> _baselineAdapters = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselineTaken;

    // sid -> wall-clock time its filters were last (re)applied. A SID without an entry has no filters of ours.
    private readonly Dictionary<string, DateTimeOffset> _appliedAt = new(StringComparer.OrdinalIgnoreCase);
    // Fallback when the OS gives no creation time: when we first saw a connection.
    private readonly Dictionary<string, DateTimeOffset> _firstSeen = new(StringComparer.Ordinal);
    // (sid|exe) -> aggregation state of direct connections.
    private readonly Dictionary<string, DirectAggregate> _direct = new(StringComparer.OrdinalIgnoreCase);

    private sealed class DirectAggregate
    {
        public long LastEmitMs = long.MinValue / 2;
        public bool Emitted;
        public int Pending;                                          // new connections seen while throttled
        public HashSet<string> Seen = new(StringComparer.Ordinal);   // connections already counted (still open)
    }

    private readonly record struct Conn(string Key, string Endpoint, int Pid);

    public BypassDetector(IUserDirectory users, IEventSink events, IClock clock, ILogger<BypassDetector>? log = null,
        ITcpTableSource? tcp = null)
    {
        _users = users;
        _events = events;
        _clock = clock;
        _tcp = tcp ?? new SystemTcpTableSource();
        _throttle = new EventThrottle(clock, Window);
        _log = (ILogger?)log ?? NullLogger.Instance;
        _startMs = clock.MonotonicMs;
    }

    // ------------------------------------------------------------------ enforcement

    /// <summary>
    /// Call after filters were successfully added/changed for <paramref name="rules"/> (only those SIDs). Records the
    /// apply time and resets the SIDs' established IPv4 connections the filters would now block (not loopback, not an
    /// exempt app). IPv6 ones cannot be reset; they are left and treated as pre-existing. Other SIDs are never touched.
    /// </summary>
    public EnforcementResult OnFiltersApplied(IReadOnlyCollection<WfpUserRule> rules)
    {
        if (rules.Count == 0) return default;
        lock (_gate)
        {
            var now = _clock.UtcNow;
            var bySid = new Dictionary<string, WfpUserRule>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in rules)
            {
                bySid[r.Sid] = r;
                _appliedAt[r.Sid] = now;
            }

            int reset = 0, failed = 0, v6 = 0;
            var sidCache = new Dictionary<int, string?>();
            var pathCache = new Dictionary<int, string?>();
            foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
            {
                IReadOnlyList<TcpRow> rows;
                try { rows = _tcp.Read(family); }
                catch (Exception ex) { _log.LogWarning(ex, "TCP table read failed ({Family})", family); continue; }
                foreach (var row in rows)
                {
                    if (row.State != TcpRow.StateEstablished || IsLocal(row) || row.Pid <= 4) continue;
                    var sid = Cached(sidCache, row.Pid, _users.SidOfProcess);
                    if (sid is null || !bySid.TryGetValue(sid, out var rule)) continue;   // I1/I2: only the SIDs just locked
                    var path = Cached(pathCache, row.Pid, _tcp.ImagePath);
                    if (IsExempt(path, rule.ExemptAppPaths)) continue;
                    _firstSeen.TryAdd(ConnKey(row), now);   // pre-existing for the fallback logic
                    if (row.RemoteAddress.AddressFamily == AddressFamily.InterNetwork && !row.RemoteAddress.IsIPv4MappedToIPv6
                        && family == AddressFamily.InterNetwork)
                    {
                        bool ok;
                        try { ok = _tcp.TryReset(row); } catch (Exception ex) { _log.LogDebug(ex, "TCP reset failed"); ok = false; }
                        if (ok) reset++; else failed++;
                    }
                    else v6++;
                }
            }
            _log.LogInformation(
                "Filters applied for {Users} user(s): reset {Reset} pre-existing IPv4 connection(s), {Failed} reset failure(s), {V6} IPv6 left open",
                rules.Count, reset, failed, v6);
            return new EnforcementResult(reset, failed, v6);
        }
    }

    /// <summary>Forget SIDs whose filters were removed.</summary>
    public void OnFiltersRemoved()
    {
        lock (_gate) _appliedAt.Clear();
    }

    // ------------------------------------------------------------------ scanning

    /// <param name="proxyPort">Our own port (never reported).</param>
    /// <param name="exemptPaths">Resolved netExemptApps per SID (direct connections expected).</param>
    /// <param name="filtersPresent">True when our WFP filters for the SID are verified present (cached verify).
    /// Null = assume present.</param>
    public void Scan(int proxyPort, IReadOnlyDictionary<string, IReadOnlyList<string>> exemptPaths,
        Func<string, bool>? filtersPresent = null)
    {
        lock (_gate)
        {
            var quiet = _clock.MonotonicMs - _startMs < (long)StartupQuiet.TotalMilliseconds;
            if (!quiet)
            {
                try { ScanTcp(proxyPort, exemptPaths, filtersPresent); }
                catch (Exception ex) { _log.LogDebug(ex, "TCP bypass scan failed"); }
            }
            try { ScanAdapters(report: !quiet); }
            catch (Exception ex) { _log.LogDebug(ex, "Adapter bypass scan failed"); }
        }
    }

    private void ScanTcp(int proxyPort, IReadOnlyDictionary<string, IReadOnlyList<string>> exemptPaths, Func<string, bool>? filtersPresent)
    {
        if (_users.ManagedSids.Count == 0) return;
        var now = _clock.UtcNow;
        var sidCache = new Dictionary<int, string?>();
        var pathCache = new Dictionary<int, string?>();
        string? SidOf(int pid) => pid > 4 ? Cached(sidCache, pid, _users.SidOfProcess) : null;

        var present = new HashSet<string>(StringComparer.Ordinal);
        var groups = new Dictionary<(string Sid, string Exe), List<Conn>>();

        foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
        {
            foreach (var row in _tcp.Read(family))
            {
                if (row.State == TcpRow.StateListen)
                {
                    if (row.LocalPort == proxyPort || !ProxyLikePorts.Contains(row.LocalPort)) continue;
                    var sid = SidOf(row.Pid);
                    if (sid is null || !_users.IsManaged(sid)) continue;
                    if (!_throttle.ShouldEmit($"{sid}|listen|{row.LocalPort}")) continue;
                    var path = Cached(pathCache, row.Pid, _tcp.ImagePath);
                    Emit(sid, Data(FormatListener(ExeLabel(path, row.Pid), row.LocalPort), path));
                }
                else if (row.State == TcpRow.StateEstablished)
                {
                    if (IsLocal(row)) continue;
                    var sid = SidOf(row.Pid);
                    if (sid is null || !_users.IsManaged(sid)) continue;
                    if (!_appliedAt.TryGetValue(sid, out var appliedAt)) continue;   // no filters of ours for this SID
                    var path = Cached(pathCache, row.Pid, _tcp.ImagePath);
                    if (exemptPaths.TryGetValue(sid, out var ex) && IsExempt(path, ex)) continue;

                    var key = ConnKey(row);
                    present.Add(key);
                    var created = row.Created;
                    if (created is null)
                    {
                        if (!_firstSeen.TryGetValue(key, out var fs)) _firstSeen[key] = fs = now;
                        created = fs;
                    }
                    if (created.Value < appliedAt + ApplyGrace) continue;   // pre-existing: the lock never had a chance

                    var g = (sid, ExeLabel(path, row.Pid));
                    if (!groups.TryGetValue(g, out var list)) groups[g] = list = [];
                    list.Add(new Conn(key, Endpoint(row.RemoteAddress, row.RemotePort), row.Pid));
                }
            }
        }

        // Fallback bookkeeping must not grow forever.
        foreach (var k in _firstSeen.Keys.Where(k => !present.Contains(k)).ToList()) _firstSeen.Remove(k);

        var verified = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var ((sid, exe), conns) in groups)
        {
            if (!verified.TryGetValue(sid, out var ok))
            {
                try { ok = filtersPresent?.Invoke(sid) ?? true; }
                catch (Exception e) { _log.LogDebug(e, "Filter verify failed"); ok = false; }
                verified[sid] = ok;
            }
            if (!ok) continue;   // filters missing: tamper.wfp_filter_missing (watchdog), not a bypass
            ReportDirect(sid, exe, conns);
        }
        PruneAggregates(present);
    }

    private void ReportDirect(string sid, string exe, List<Conn> conns)
    {
        var nowMs = _clock.MonotonicMs;
        var aggKey = sid + "|" + exe;
        if (!_direct.TryGetValue(aggKey, out var agg)) _direct[aggKey] = agg = new DirectAggregate();
        var fresh = conns.Where(c => agg.Seen.Add(c.Key)).ToList();
        var canEmit = !agg.Emitted || nowMs - agg.LastEmitMs >= (long)Window.TotalMilliseconds;
        if (!canEmit) { agg.Pending += fresh.Count; return; }
        var total = fresh.Count + agg.Pending;
        if (total == 0) return;   // only connections already reported are still open
        var first = fresh.Count > 0 ? fresh[0] : conns[0];
        agg.Emitted = true;
        agg.LastEmitMs = nowMs;
        agg.Pending = 0;
        var path = _tcp.ImagePath(first.Pid);
        Emit(sid, Data(FormatDirect(exe, first.Endpoint, total - 1), path));
    }

    private void PruneAggregates(HashSet<string> present)
    {
        var nowMs = _clock.MonotonicMs;
        foreach (var (k, agg) in _direct.ToList())
        {
            agg.Seen.RemoveWhere(c => !present.Contains(c));
            if (agg.Seen.Count == 0 && agg.Pending == 0 && nowMs - agg.LastEmitMs >= (long)Window.TotalMilliseconds) _direct.Remove(k);
        }
    }

    private void ScanAdapters(bool report)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var desc = $"{nic.Description} {nic.Name}";
            if (!_baselineTaken || !report) { _baselineAdapters.Add(nic.Id); continue; }
            if (_baselineAdapters.Contains(nic.Id)) continue;
            _baselineAdapters.Add(nic.Id);
            var looksVpn = nic.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp
                || VpnAdapterMarkers.Any(m => desc.Contains(m, StringComparison.OrdinalIgnoreCase));
            if (!looksVpn) continue;
            if (!_throttle.ShouldEmit("nic|" + nic.Id)) continue;
            Emit(null, new JsonObject { ["detail"] = Clip(FormatAdapter(nic.Description, nic.Name)) });
        }
        _baselineTaken = true;
    }

    // ------------------------------------------------------------------ formatting (public for tests)

    public static string FormatDirect(string exe, string endpoint, int others) =>
        $"Kết nối thẳng ra Internet không qua bộ lọc: {exe} → {endpoint}" + (others > 0 ? $" (+{others} kết nối khác)" : "");

    public static string FormatListener(string exe, int port) =>
        $"Phát hiện proxy/VPN cục bộ: {exe} đang mở cổng {port} (cổng thường dùng để vượt bộ lọc)";

    public static string FormatAdapter(string description, string name) =>
        $"Xuất hiện card mạng VPN/đường hầm mới: {description} ({name})";

    public static string Endpoint(IPAddress address, int port)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]:{port}" : $"{address}:{port}";
    }

    // ------------------------------------------------------------------ helpers

    private static string ExeLabel(string? path, int pid) => path is null ? $"tiến trình pid {pid}" : Path.GetFileName(path);

    private static JsonObject Data(string detail, string? path)
    {
        var data = new JsonObject { ["detail"] = Clip(detail) };
        if (path is not null) data["exe"] = DomainAggregator.Truncate(Path.GetFileName(path), 260);
        return data;
    }

    /// <summary>Loopback in the WFP sense (FWP_CONDITION_FLAG_IS_LOOPBACK also covers the host's own addresses).</summary>
    private static bool IsLocal(TcpRow row)
    {
        var remote = row.RemoteAddress.IsIPv4MappedToIPv6 ? row.RemoteAddress.MapToIPv4() : row.RemoteAddress;
        var local = row.LocalAddress.IsIPv4MappedToIPv6 ? row.LocalAddress.MapToIPv4() : row.LocalAddress;
        return IPAddress.IsLoopback(remote) || remote.Equals(IPAddress.Any) || remote.Equals(IPAddress.IPv6Any)
               || remote.Equals(local);
    }

    private static bool IsExempt(string? path, IReadOnlyList<string> exempt) =>
        path is not null && exempt.Any(e => string.Equals(e, path, StringComparison.OrdinalIgnoreCase));

    private static string ConnKey(TcpRow r) => $"{r.LocalAddress}|{r.LocalPort}|{r.RemoteAddress}|{r.RemotePort}|{r.Pid}";

    private static string? Cached(Dictionary<int, string?> cache, int pid, Func<int, string?> get)
    {
        if (!cache.TryGetValue(pid, out var v)) cache[pid] = v = get(pid);
        return v;
    }

    private void Emit(string? sid, JsonObject data)
    {
        try { _events.Emit(EventTypes.TamperProxyBypassAttempt, sid, data); }
        catch (Exception ex) { _log.LogWarning(ex, "Emit tamper.proxy_bypass_attempt failed"); }
    }

    private static string Clip(string s) => DomainAggregator.Truncate(s, 1024);
}
