using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Service.Logic;
using MinControl.Service.Native;
using Microsoft.Extensions.Logging;

namespace MinControl.Service.Ipc;

/// <param name="StartedUtc">When this app (same exe + pid) got the focus; title updates keep it.</param>
/// <param name="Hwnd">Foreground top-level window (0 when the helper is older than the keyword feature).</param>
internal sealed record ForegroundInfo(string ExePath, string? Title, int Pid, long Mono, DateTimeOffset StartedUtc, long Hwnd = 0);

internal sealed record CaptureFrame(byte[] Jpeg, int Width, int Height);

/// <summary>Server end of \\.\pipe\MinControl.Session.&lt;sessionId&gt;. DACL = SYSTEM only, created with
/// FIRST_PIPE_INSTANCE (no squatting), and the connecting client must be the helper PID we launched.</summary>
internal sealed class SessionChannel : IAsyncDisposable
{
    private const int MaxExe = 1024, MaxTitle = 512;

    private readonly Func<int?> _expectedClientPid;
    private readonly IClock _clock;
    private readonly ILogger _log;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<long, TaskCompletionSource<CaptureFrame?>> _captures = new();
    private readonly ConcurrentDictionary<long, TaskCompletionSource<bool>> _closes = new();
    private Task _loop = Task.CompletedTask;
    private volatile NamedPipeServerStream? _pipe;
    private long _requestId;
    private long _lastSeenMono = long.MinValue / 2;
    private long _idleMs;

    public SessionChannel(int sessionId, Func<int?> expectedClientPid, IClock clock, ILogger log)
    {
        SessionId = sessionId;
        _expectedClientPid = expectedClientPid;
        _clock = clock;
        _log = log;
    }

    public int SessionId { get; }
    public bool Connected => _pipe is { IsConnected: true };
    public long LastSeenMono => Interlocked.Read(ref _lastSeenMono);
    public long IdleMs => Interlocked.Read(ref _idleMs);
    public ForegroundInfo? Foreground { get; private set; }

    /// <summary>Raised (on the pipe reader thread) for every foreground report (the helper sends one per change of
    /// window, exe or title). Handlers must not block.</summary>
    public event Action<SessionChannel, ForegroundInfo>? ForegroundChanged;

    public void Start() => _loop = Task.Run(() => RunAsync(_cts.Token));

    private static NamedPipeServerStream CreatePipe(int sessionId)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(IpcFraming.PipeName(sessionId), PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 64 * 1024, 64 * 1024,
            security);
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePipe(SessionId);
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
                if (!Win32.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid)
                    || clientPid != _expectedClientPid())
                {
                    _log.LogWarning("session {Session}: rejected pipe client pid {Pid}", SessionId, clientPid);
                    continue;
                }
                _pipe = pipe;
                Touch();
                while (await IpcFraming.ReadAsync(pipe, ct).ConfigureAwait(false) is { } message)
                    Handle(message);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e)
            {
                // IOException here includes "pipe already exists" (squatting attempt): the helper then never
                // connects and the supervisor's 30 s absence rule logs the user off (fail closed, I4).
                _log.LogWarning(e, "session {Session}: pipe loop error", SessionId);
                try { await Task.Delay(500, ct).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
            }
            finally
            {
                _pipe = null;
                if (pipe is not null) await pipe.DisposeAsync().ConfigureAwait(false);
                foreach (var (id, tcs) in _captures) if (_captures.TryRemove(id, out _)) tcs.TrySetResult(null);
                foreach (var (id, tcs) in _closes) if (_closes.TryRemove(id, out _)) tcs.TrySetResult(false);
            }
        }
    }

    private void Touch() => Interlocked.Exchange(ref _lastSeenMono, _clock.MonotonicMs);

    private void Handle(IpcMessage m)
    {
        Touch();
        switch (m.Type)
        {
            case IpcTypes.Foreground:
                var exe = m.Str("exe");
                if (string.IsNullOrEmpty(exe) || exe.Length > MaxExe) return;
                var title = m.Str("title");
                if (title is { Length: > MaxTitle }) title = title[..MaxTitle];
                var pid = (int)(m.Long("pid") ?? 0);
                var previous = Foreground;
                var started = previous is not null && previous.Pid == pid
                    && string.Equals(previous.ExePath, exe, StringComparison.OrdinalIgnoreCase)
                    ? previous.StartedUtc : _clock.UtcNow;
                var info = new ForegroundInfo(exe, title, pid, _clock.MonotonicMs, started, m.Long("hwnd") ?? 0);
                Foreground = info;
                try { ForegroundChanged?.Invoke(this, info); }
                catch (Exception e) { _log.LogWarning(e, "session {Session}: foreground handler failed", SessionId); }
                break;
            case IpcTypes.CloseResult:
                if (_closes.TryRemove(m.Long("requestId") ?? -1, out var closeTcs))
                    closeTcs.TrySetResult(m.Data["ok"] is JsonValue ok && ok.TryGetValue<bool>(out var b) && b);
                break;
            case IpcTypes.Idle:
                Interlocked.Exchange(ref _idleMs, Math.Max(0, m.Long("idleMs") ?? 0));
                break;
            case IpcTypes.CaptureResult:
                var requestId = m.Long("requestId") ?? -1;
                if (!_captures.TryRemove(requestId, out var tcs)) return;
                var b64 = m.Str("jpeg");
                CaptureFrame? frame = null;
                if (!string.IsNullOrEmpty(b64))
                {
                    try { frame = new CaptureFrame(Convert.FromBase64String(b64), (int)(m.Long("width") ?? 0), (int)(m.Long("height") ?? 0)); }
                    catch (FormatException) { frame = null; }
                }
                tcs.TrySetResult(frame);
                break;
            case IpcTypes.Heartbeat or IpcTypes.Hello:
                break;
            default:
                _log.LogDebug("session {Session}: unknown message {Type}", SessionId, m.Type);
                break;
        }
    }

    public async Task<bool> SendAsync(IpcMessage message, CancellationToken ct)
    {
        var pipe = _pipe;
        if (pipe is null || !pipe.IsConnected) return false;
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await IpcFraming.WriteAsync(pipe, message, ct).ConfigureAwait(false);
            return true;
        }
        catch (IOException e)
        {
            _log.LogDebug(e, "session {Session}: send failed", SessionId);
            return false;
        }
        catch (ObjectDisposedException) { return false; }
        finally { _writeLock.Release(); }
    }

    public async Task<CaptureFrame?> CaptureAsync(int maxWidth, int jpegQuality, TimeSpan timeout, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _requestId);
        var tcs = new TaskCompletionSource<CaptureFrame?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _captures[id] = tcs;
        try
        {
            var request = IpcMessage.Of(IpcTypes.Capture, new JsonObject
            {
                ["requestId"] = id, ["maxWidth"] = Math.Clamp(maxWidth, 160, 7680), ["jpegQuality"] = Math.Clamp(jpegQuality, 10, 95),
            });
            if (!await SendAsync(request, ct).ConfigureAwait(false)) return null;
            return await tcs.Task.WaitAsync(timeout, ct).ConfigureAwait(false);
        }
        catch (TimeoutException) { return null; }
        finally { _captures.TryRemove(id, out _); }
    }

    /// <summary>Asks the helper to close the browser tab (Ctrl+W, only while <paramref name="hwnd"/> is the foreground
    /// window of <paramref name="pid"/>) or the window (WM_CLOSE) and show the toast. True when the helper did it.</summary>
    public async Task<bool> CloseWindowAsync(long hwnd, int pid, bool tab, string toastTitle, string toastReason, TimeSpan timeout, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _requestId);
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _closes[id] = tcs;
        try
        {
            var request = IpcMessage.Of(IpcTypes.CloseWindow, new JsonObject
            {
                ["requestId"] = id, ["hwnd"] = hwnd, ["pid"] = pid, ["mode"] = tab ? "tab" : "window",
                ["title"] = toastTitle.Length > 200 ? toastTitle[..200] : toastTitle,
                ["reason"] = toastReason.Length > 300 ? toastReason[..300] : toastReason,
            });
            if (!await SendAsync(request, ct).ConfigureAwait(false)) return false;
            return await tcs.Task.WaitAsync(timeout, ct).ConfigureAwait(false);
        }
        catch (TimeoutException) { return false; }
        finally { _closes.TryRemove(id, out _); }
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        try { await _loop.ConfigureAwait(false); } catch (Exception) { /* already logged */ }
        _cts.Dispose();
        _writeLock.Dispose();
    }
}

/// <summary>All live session channels, keyed by session id.</summary>
internal sealed class SessionChannelRegistry(IClock clock, ILoggerFactory loggers)
{
    private readonly ConcurrentDictionary<int, SessionChannel> _channels = new();

    /// <summary>Foreground reports of every session helper (session id, report).</summary>
    public event Action<int, ForegroundInfo>? ForegroundChanged;
    private readonly ILogger _log = loggers.CreateLogger<SessionChannel>();

    private readonly object _gate = new();

    public SessionChannel GetOrStart(int sessionId, Func<int?> expectedClientPid)
    {
        lock (_gate) // a channel owns a FIRST_PIPE_INSTANCE pipe: never start two for one session
        {
            if (_channels.TryGetValue(sessionId, out var existing)) return existing;
            var c = new SessionChannel(sessionId, expectedClientPid, clock, _log);
            c.ForegroundChanged += (ch, info) => ForegroundChanged?.Invoke(ch.SessionId, info);
            _channels[sessionId] = c;
            c.Start();
            return c;
        }
    }

    public SessionChannel? TryGet(int sessionId) => _channels.GetValueOrDefault(sessionId);

    public IReadOnlyCollection<int> SessionIds => _channels.Keys.ToArray();

    public async Task StopAsync(int sessionId)
    {
        if (_channels.TryRemove(sessionId, out var c)) await c.DisposeAsync().ConfigureAwait(false);
    }
}
