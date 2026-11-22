using System.IO.Pipes;
using MinControl.Service.Logic;

namespace MinControl.Session;

/// <summary>Client end of \\.\pipe\MinControl.Session.&lt;sessionId&gt;. Only talks to a server whose process
/// id is the service PID passed on our command line (defeats a squatted pipe). Reconnects forever.</summary>
internal sealed class PipeClient(int sessionId, int servicePid, Func<IpcMessage, Task> onMessage, Func<Task> onConnected)
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private volatile NamedPipeClientStream? _pipe;

    public bool Connected => _pipe is { IsConnected: true };

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var pipe = new NamedPipeClientStream(".", IpcFraming.PipeName(sessionId), PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                await pipe.ConnectAsync(2000, ct).ConfigureAwait(false);
                if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var serverPid) || serverPid != servicePid)
                    throw new IOException($"pipe server pid {serverPid} is not the service ({servicePid})");
                _pipe = pipe;
                await onConnected().ConfigureAwait(false);
                while (await IpcFraming.ReadAsync(pipe, ct).ConfigureAwait(false) is { } message)
                    await onMessage(message).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception) { /* timeout, broken pipe, bad frame: reconnect */ }
            finally
            {
                _pipe = null;
                await pipe.DisposeAsync().ConfigureAwait(false);
            }
            try { await Task.Delay(500, ct).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
        }
    }

    public async Task<bool> SendAsync(IpcMessage message)
    {
        var pipe = _pipe;
        if (pipe is null || !pipe.IsConnected) return false;
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await IpcFraming.WriteAsync(pipe, message, CancellationToken.None).ConfigureAwait(false);
            return true;
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or InvalidOperationException) { return false; }
        finally { _writeLock.Release(); }
    }
}
