using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policy;
using MinControl.NetGuard.Telemetry;
using MinControl.NetGuard.Web;

namespace MinControl.NetGuard.Proxy;

/// <summary>
/// HTTP/1.1 forward proxy + CONNECT tunnelling on 127.0.0.1:&lt;port&gt;. No TLS interception.
/// Managed callers (I1) are filtered by <see cref="WebDecisionEngine"/>; callers of other SIDs are passed through
/// untouched and unlogged; callers whose SID cannot be determined are refused (fail closed, I4).
/// Plain HTTP is handled one request per client connection (Connection: close) to keep host decisions exact.
/// </summary>
public sealed class FilteringProxy : IAsyncDisposable
{
    private const int PumpBufferSize = 32 * 1024;

    private readonly NetGuardOptions _options;
    private readonly IUserDirectory _users;
    private readonly IPolicyProvider _policy;
    private readonly IEventSink _events;
    private readonly IClock _clock;
    private readonly WebDecisionEngine _engine;
    private readonly CallerIdentifier _callers;
    private readonly DomainAggregator _aggregator;
    private readonly EventThrottle _blockedThrottle;
    private readonly ILogger _log;
    private readonly object _gate = new();
    private Socket? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private int _active;

    public FilteringProxy(NetGuardOptions options, IUserDirectory users, IPolicyProvider policy, IEventSink events, IClock clock,
        WebDecisionEngine engine, CallerIdentifier callers, DomainAggregator aggregator, ILogger<FilteringProxy>? log = null)
    {
        _options = options;
        _users = users;
        _policy = policy;
        _events = events;
        _clock = clock;
        _engine = engine;
        _callers = callers;
        _aggregator = aggregator;
        _blockedThrottle = new EventThrottle(clock, options.BlockedEventDedup);
        _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public int Port => _options.ProxyPort;
    public int ActiveConnections => Volatile.Read(ref _active);

    public bool IsListening
    {
        get
        {
            lock (_gate) return _listener is not null && _acceptLoop is { IsCompleted: false };
        }
    }

    /// <summary>Idempotent: starts listening if not already.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_listener is not null && _acceptLoop is { IsCompleted: false }) return;
            StopCore();
            var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                s.ExclusiveAddressUse = true;   // nobody else may bind our port
                s.Bind(new IPEndPoint(IPAddress.Loopback, _options.ProxyPort));
                s.Listen(1024);
            }
            catch
            {
                s.Dispose();
                throw;
            }
            _listener = s;
            _cts = new CancellationTokenSource();
            _acceptLoop = Task.Run(() => AcceptLoopAsync(s, _cts.Token));
            _log.LogInformation("Filtering proxy listening on 127.0.0.1:{Port}", _options.ProxyPort);
        }
    }

    public Task StopAsync()
    {
        Task? loop;
        lock (_gate)
        {
            loop = _acceptLoop;
            StopCore();
        }
        return loop ?? Task.CompletedTask;
    }

    private void StopCore()
    {
        try { _cts?.Cancel(); } catch (ObjectDisposedException) { }
        _listener?.Dispose();
        _listener = null;
        _cts?.Dispose();
        _cts = null;
        _acceptLoop = null;
    }

    public async ValueTask DisposeAsync()
    {
        try { await StopAsync().ConfigureAwait(false); } catch { /* shutting down */ }
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException ex)
            {
                _log.LogWarning(ex, "Proxy accept failed");
                continue;
            }
            client.NoDelay = true;
            _ = Task.Run(() => HandleClientAsync(client, ct), CancellationToken.None);
        }
    }

    private async Task HandleClientAsync(Socket client, CancellationToken serverCt)
    {
        Interlocked.Increment(ref _active);
        var buffer = ArrayPool<byte>.Shared.Rent(_options.MaxRequestHeadBytes);
        Socket? upstream = null;
        try
        {
            // ---- read request head
            int filled = 0, headEnd = -1;
            using (var headCts = CancellationTokenSource.CreateLinkedTokenSource(serverCt))
            {
                headCts.CancelAfter(_options.RequestHeadTimeout);
                while (headEnd < 0)
                {
                    if (filled >= _options.MaxRequestHeadBytes) { await SendQuiet(client, Responses.Simple(431, "Request Header Fields Too Large")); return; }
                    var n = await client.ReceiveAsync(buffer.AsMemory(filled, _options.MaxRequestHeadBytes - filled), SocketFlags.None, headCts.Token).ConfigureAwait(false);
                    if (n == 0) return;
                    var scanFrom = Math.Max(0, filled - 3);
                    filled += n;
                    var e = HttpHead.FindHeadEnd(buffer.AsSpan(scanFrom, filled - scanFrom));
                    if (e >= 0) headEnd = scanFrom + e;
                }
            }

            if (!HttpHead.TryParse(buffer.AsSpan(0, headEnd), out var head, out _) || head is null)
            {
                await SendQuiet(client, Responses.Simple(400, "Bad Request"));
                return;
            }

            // ---- who is calling
            var caller = client.RemoteEndPoint is IPEndPoint ep ? _callers.Identify(ep, _options.ProxyPort) : new Caller(-1, null, null);
            if (caller.Sid is null)
            {
                // Cannot attribute the connection to a user → refuse (fail closed). Non-managed users don't use the proxy.
                await SendQuiet(client, Responses.Simple(407, "Caller Unknown"));
                return;
            }
            var managed = _users.IsManaged(caller.Sid);
            var host = DomainPattern.NormalizeHost(head.Host);

            if (IsSelfLoop(host, head.Port))
            {
                await SendQuiet(client, Responses.Simple(508, "Loop Detected"));
                return;
            }

            var connectHost = host;
            var logDomains = false;
            if (managed)
            {
                var policy = _policy.Current;
                UserPolicy? user = null;
                policy?.Users.TryGetValue(caller.Sid, out user);
                logDomains = user?.Monitoring.DomainLog ?? false;
                WebDecision decision;
                if (policy is null || user is null)
                    decision = new WebDecision(false, BlockReasons.Blocklist, null, host);   // fail closed
                else if (_options.AllowedPorts.Count > 0 && !_options.AllowedPorts.Contains(head.Port))
                    decision = new WebDecision(false, BlockReasons.Port, null, host);
                else
                    decision = _engine.Decide(user.Web, host, _clock.UtcNow, policy.Timezone);

                if (!decision.Allowed)
                {
                    OnBlocked(caller, head, host, decision, logDomains);
                    await SendQuiet(client, head.IsConnect ? Responses.ConnectBlocked : Responses.BlockPage(host, decision.Reason, decision.Category));
                    return;
                }
                connectHost = decision.ConnectHost;
            }

            // ---- connect upstream (proxy runs as SYSTEM → not subject to the per-user WFP block)
            upstream = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                using var cto = CancellationTokenSource.CreateLinkedTokenSource(serverCt);
                cto.CancelAfter(_options.ConnectTimeout);
                await upstream.ConnectAsync(connectHost, head.Port, cto.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                if (managed && logDomains) _aggregator.RecordConnection(caller.Sid, caller.ExeName, host, true);
                await SendQuiet(client, Responses.Simple(serverCt.IsCancellationRequested ? 503 : 502, "Bad Gateway"));
                return;
            }

            if (managed && logDomains) _aggregator.RecordConnection(caller.Sid, caller.ExeName, host, true);

            long preOut = filled - headEnd;   // bytes the client already sent past the head (TLS ClientHello or body)
            if (head.IsConnect)
            {
                await client.SendAsync(Responses.ConnectEstablished, SocketFlags.None, serverCt).ConfigureAwait(false);
            }
            else
            {
                var up = head.BuildUpstreamHead();
                await upstream.SendAsync(up, SocketFlags.None, serverCt).ConfigureAwait(false);
            }
            if (preOut > 0)
                await upstream.SendAsync(buffer.AsMemory(headEnd, (int)preOut), SocketFlags.None, serverCt).ConfigureAwait(false);

            ArrayPool<byte>.Shared.Return(buffer);
            buffer = null!;

            var toUp = PumpAsync(client, upstream, serverCt);
            var toDown = PumpAsync(upstream, client, serverCt);
            await Task.WhenAll(toUp, toDown).ConfigureAwait(false);

            if (managed && logDomains)
                _aggregator.RecordBytes(caller.Sid, caller.ExeName, host, true, toUp.Result + preOut, toDown.Result);
        }
        catch (OperationCanceledException) { }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Proxy connection failed");
        }
        finally
        {
            if (buffer is not null) ArrayPool<byte>.Shared.Return(buffer);
            upstream?.Dispose();
            client.Dispose();
            Interlocked.Decrement(ref _active);
        }
    }

    private bool IsSelfLoop(string host, int port)
    {
        if (port != _options.ProxyPort) return false;
        return host is "localhost" || (IPAddress.TryParse(host, out var ip) && (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any)));
    }

    private void OnBlocked(Caller caller, HttpHead head, string host, WebDecision d, bool logDomains)
    {
        var sid = caller.Sid!;
        if (logDomains) _aggregator.RecordConnection(sid, caller.ExeName, host, false);
        if (!_blockedThrottle.ShouldEmit(sid + "|" + host)) return;
        var data = new JsonObject
        {
            ["host"] = DomainAggregator.Truncate(host, 253),
            ["source"] = "proxy",
            ["reason"] = d.Reason ?? BlockReasons.Blocklist,
            ["exe"] = DomainAggregator.Truncate(caller.ExeName, 260),
        };
        if (d.Category is not null) data["category"] = DomainAggregator.Truncate(d.Category, 32);
        if (!head.IsConnect) data["url"] = DomainAggregator.Truncate(head.Target, 2048);
        try { _events.Emit(EventTypes.WebBlocked, sid, data); }
        catch (Exception ex) { _log.LogWarning(ex, "Emit web.blocked failed"); }
    }

    /// <summary>Copies until EOF, then half-closes the destination. Returns bytes copied.</summary>
    private static async Task<long> PumpAsync(Socket from, Socket to, CancellationToken ct)
    {
        var buf = ArrayPool<byte>.Shared.Rent(PumpBufferSize);
        long total = 0;
        try
        {
            while (true)
            {
                var n = await from.ReceiveAsync(buf.AsMemory(), SocketFlags.None, ct).ConfigureAwait(false);
                if (n == 0) break;
                var sent = 0;
                while (sent < n)
                    sent += await to.SendAsync(buf.AsMemory(sent, n - sent), SocketFlags.None, ct).ConfigureAwait(false);
                total += n;
            }
            try { to.Shutdown(SocketShutdown.Send); } catch { /* peer gone */ }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // Abort both directions: closing makes the other pump finish too.
            try { from.Close(); } catch { }
            try { to.Close(); } catch { }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
        return total;
    }

    private static async Task SendQuiet(Socket s, byte[] data)
    {
        try
        {
            await s.SendAsync(data, SocketFlags.None).ConfigureAwait(false);
            s.Shutdown(SocketShutdown.Both);
        }
        catch { /* client gone */ }
    }
}
