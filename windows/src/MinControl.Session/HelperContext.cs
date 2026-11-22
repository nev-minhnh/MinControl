using System.Text.Json.Nodes;
using MinControl.Service.Logic;
using Timer = System.Windows.Forms.Timer;

namespace MinControl.Session;

/// <summary>Headless message loop of the session helper: pipe to the service, foreground tracking
/// (SetWinEventHook + 5 s title poll), idle reporting, heartbeat, and the overlay / toast / message UI.</summary>
internal sealed class HelperContext : ApplicationContext
{
    private readonly SynchronizationContext _ui;
    private readonly CancellationTokenSource _cts = new();
    private readonly PipeClient _pipe;
    private readonly Native.WinEventProc _hookProc; // must stay referenced while the hook is installed
    private readonly IntPtr _hook;
    private readonly Timer _titlePoll = new() { Interval = 5_000 };
    private readonly Timer _idle = new() { Interval = 1_000 };
    private readonly Timer _heartbeat = new() { Interval = 2_000 };
    private readonly OverlayManager _overlay = new();
    private readonly object _fgGate = new();
    private (string Exe, string Title, int Pid)? _lastForeground;
    private ToastForm? _toast;

    public HelperContext(int sessionId, int servicePid)
    {
        _ui = SynchronizationContext.Current ?? throw new InvalidOperationException("UI context required");
        _pipe = new PipeClient(sessionId, servicePid, OnMessageAsync, OnConnectedAsync);

        _hookProc = (_, _, _, _, _, _, _) => ReportForeground(force: false);
        _hook = Native.SetWinEventHook(Native.EVENT_SYSTEM_FOREGROUND, Native.EVENT_SYSTEM_FOREGROUND, IntPtr.Zero,
            _hookProc, 0, 0, Native.WINEVENT_OUTOFCONTEXT | Native.WINEVENT_SKIPOWNPROCESS);

        _titlePoll.Tick += (_, _) => ReportForeground(force: false);
        _idle.Tick += (_, _) => Send(IpcTypes.Idle, new JsonObject { ["idleMs"] = Native.IdleMs() });
        _heartbeat.Tick += (_, _) => Send(IpcTypes.Heartbeat, new JsonObject());
        _titlePoll.Start();
        _idle.Start();
        _heartbeat.Start();

        _ = Task.Run(() => _pipe.RunAsync(_cts.Token));
    }

    private void Send(string type, JsonObject data) => _ = _pipe.SendAsync(IpcMessage.Of(type, data));

    private async Task OnConnectedAsync()
    {
        await _pipe.SendAsync(IpcMessage.Of(IpcTypes.Hello, new JsonObject { ["pid"] = Environment.ProcessId })).ConfigureAwait(false);
        ReportForeground(force: true);
    }

    private void ReportForeground(bool force)
    {
        try
        {
            var hwnd = Native.GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return;
            Native.GetWindowThreadProcessId(hwnd, out var pid);
            if (pid == 0 || pid == Environment.ProcessId) return; // our own overlay is not "usage" of an app
            var exe = Native.ImagePath(pid);
            if (exe is null) return;
            var title = Native.WindowTitle(hwnd);
            lock (_fgGate)
            {
                var current = (exe, title, pid);
                if (!force && _lastForeground == current) return;
                _lastForeground = current;
            }
            Send(IpcTypes.Foreground, new JsonObject { ["exe"] = exe, ["title"] = title, ["pid"] = pid });
        }
        catch (Exception) { /* best effort */ }
    }

    private Task OnMessageAsync(IpcMessage m)
    {
        switch (m.Type)
        {
            case IpcTypes.Warning:
                var minutes = (int)(m.Long("remainingMin") ?? 0);
                _ui.Post(_ => ShowToast(minutes), null);
                break;
            case IpcTypes.LockOverlay:
                var reason = m.Str("reason") ?? "";
                var seconds = (int)(m.Long("graceSec") ?? 0);
                _ui.Post(_ => _overlay.Show(reason, seconds), null);
                break;
            case IpcTypes.ClearOverlay:
                _ui.Post(_ => _overlay.Hide(), null);
                break;
            case IpcTypes.Message:
                var text = m.Str("text") ?? "";
                _ui.Post(_ => new MessageForm(text).Show(), null);
                break;
            case IpcTypes.Capture:
                var requestId = m.Long("requestId") ?? 0;
                var maxWidth = (int)(m.Long("maxWidth") ?? 1280);
                var quality = (int)(m.Long("jpegQuality") ?? 60);
                _ = Task.Run(async () =>
                {
                    var result = new JsonObject { ["requestId"] = requestId };
                    try
                    {
                        var (jpeg, w, h) = ScreenCapture.CaptureJpeg(maxWidth, quality);
                        result["jpeg"] = Convert.ToBase64String(jpeg);
                        result["width"] = w;
                        result["height"] = h;
                    }
                    catch (Exception e) { result["error"] = e.GetType().Name; }
                    await _pipe.SendAsync(IpcMessage.Of(IpcTypes.CaptureResult, result)).ConfigureAwait(false);
                });
                break;
        }
        return Task.CompletedTask;
    }

    private void ShowToast(int minutes)
    {
        _toast?.Close();
        _toast = new ToastForm(minutes);
        _toast.FormClosed += (s, _) => { if (ReferenceEquals(_toast, s)) _toast = null; };
        _toast.Show();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _cts.Cancel();
            if (_hook != IntPtr.Zero) Native.UnhookWinEvent(_hook);
            _titlePoll.Dispose();
            _idle.Dispose();
            _heartbeat.Dispose();
            _overlay.Hide();
            _cts.Dispose();
        }
        base.Dispose(disposing);
    }
}
