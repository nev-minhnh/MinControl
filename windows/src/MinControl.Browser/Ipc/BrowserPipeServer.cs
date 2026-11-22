using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Browser.Policy;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MinControl.Browser.Ipc;

/// <summary>
/// Service side of \\.\pipe\MinControl.Browser. Each client is MinControl.NativeHost.exe started by a browser in
/// a user session. Authentication: the client PID's token SID (via IUserDirectory) must be a managed SID, and the
/// client image must be the installed native host. Only hello / heartbeat / web.* / download.* messages are
/// accepted; rules for the client's SID are pushed on connect and on every policy change.
/// </summary>
public sealed class BrowserPipeServer : BackgroundService
{
    private readonly IUserDirectory _users;
    private readonly IBrowserEventIngress _ingress;
    private readonly IPolicyProvider? _policy;
    private readonly BrowserOptions _options;
    private readonly ILogger<BrowserPipeServer> _log;
    private readonly ConcurrentDictionary<Connection, byte> _connections = new();

    public BrowserPipeServer(IUserDirectory users, IBrowserEventIngress ingress, IOptions<BrowserOptions> options,
        ILogger<BrowserPipeServer> log, IPolicyProvider? policy = null)
    {
        _users = users; _ingress = ingress; _options = options.Value; _log = log; _policy = policy;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (_policy is not null) _policy.PolicyChanged += OnPolicyChanged;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                NamedPipeServerStream? server = null;
                try
                {
                    server = CreateServer();
                    await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                    var accepted = server;
                    server = null;
                    _ = Task.Run(() => HandleClientAsync(accepted, ct), ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "browser pipe accept failed");
                    await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
                }
                finally { server?.Dispose(); }
            }
        }
        finally
        {
            if (_policy is not null) _policy.PolicyChanged -= OnPolicyChanged;
        }
    }

    private NamedPipeServerStream CreateServer()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        // Users may connect (read/write) but not create instances; who they are is checked per connection.
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));

        return NamedPipeServerStreamAcl.Create(_options.PipeName, PipeDirection.InOut, _options.MaxPipeInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 64 * 1024, 64 * 1024, security);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using var pipeScope = pipe.ConfigureAwait(false);
        string? sid = Authenticate(pipe);
        if (sid is null) return;

        var conn = new Connection(pipe, sid);
        _connections[conn] = 0;
        try
        {
            await SendRulesAsync(conn, ct).ConfigureAwait(false);
            await ReadLoopAsync(conn, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or EndOfStreamException or InvalidDataException or JsonException or OperationCanceledException)
        {
            _log.LogDebug("browser pipe client of {Sid} closed: {Message}", sid, ex.Message);
        }
        finally
        {
            _connections.TryRemove(conn, out _);
        }
    }

    private string? Authenticate(NamedPipeServerStream pipe)
    {
        try
        {
            int pid = PipeNative.ClientProcessId(pipe.SafePipeHandle);
            string? sid = _users.SidOfProcess(pid);
            if (sid is null || !_users.IsManaged(sid))
            {
                _log.LogInformation("browser pipe: rejecting pid {Pid} (sid {Sid} not managed)", pid, sid ?? "?");
                return null;
            }
            if (_options.RequireNativeHostImage)
            {
                string? image = PipeNative.ImagePath(pid);
                if (image is null || !string.Equals(Path.GetFullPath(image), Path.GetFullPath(_options.NativeHostExePath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    _log.LogWarning("browser pipe: rejecting pid {Pid} of {Sid}, image {Image}", pid, sid, image ?? "?");
                    return null;
                }
            }
            return sid;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "browser pipe: cannot authenticate client");
            return null;
        }
    }

    private async Task ReadLoopAsync(Connection conn, CancellationToken ct)
    {
        var windowStart = Environment.TickCount64;
        int inWindow = 0;
        while (!ct.IsCancellationRequested)
        {
            byte[]? frame = await MessageFraming.ReadAsync(conn.Pipe, MessageFraming.MaxFrameBytes, ct).ConfigureAwait(false);
            if (frame is null) return;

            long now = Environment.TickCount64;
            if (now - windowStart > 10_000) { windowStart = now; inWindow = 0; }
            if (++inWindow > _options.MaxMessagesPer10s)
            {
                _log.LogWarning("browser pipe: {Sid} exceeded the message rate, disconnecting", conn.Sid);
                return;
            }

            if (JsonNode.Parse(frame) is not JsonObject msg) continue;
            string? t = Str(msg, "t");
            switch (t)
            {
                case "hello":
                case "heartbeat":
                    if (Str(msg, "browser") is "msedge" or "chrome")
                    {
                        conn.Browser = Str(msg, "browser");
                        _ingress.OnHeartbeat(conn.Sid, conn.Browser!);
                    }
                    break;
                case "event":
                    if (Str(msg, "type") is { } type && msg["data"] is JsonObject data)
                    {
                        msg.Remove("data");   // detach before handing over
                        _ingress.OnBrowserEvent(conn.Sid, type, data);
                    }
                    break;
                default:
                    break;  // anything else is ignored: the pipe carries only the browser message set
            }
        }
    }

    private static string? Str(JsonObject o, string name) =>
        o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private void OnPolicyChanged(object? sender, DevicePolicy policy)
    {
        foreach (var conn in _connections.Keys)
        {
            _ = Task.Run(async () =>
            {
                try { await SendRulesAsync(conn, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { _log.LogDebug(ex, "rule push to {Sid} failed", conn.Sid); }
            });
        }
    }

    private async Task SendRulesAsync(Connection conn, CancellationToken ct)
    {
        UserPolicy? user = _policy?.Current?.Users.TryGetValue(conn.Sid, out var u) == true ? u : null;
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(ExtensionRuleBuilder.Build(user));
        await conn.WriteLock.WaitAsync(ct).ConfigureAwait(false);
        try { await MessageFraming.WriteAsync(conn.Pipe, body, ct).ConfigureAwait(false); }
        finally { conn.WriteLock.Release(); }
    }

    private sealed class Connection(NamedPipeServerStream pipe, string sid)
    {
        public NamedPipeServerStream Pipe { get; } = pipe;
        public string Sid { get; } = sid;
        public string? Browser { get; set; }
        public SemaphoreSlim WriteLock { get; } = new(1, 1);
    }
}
