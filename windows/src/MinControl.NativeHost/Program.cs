using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Browser.Ipc;

namespace MinControl.NativeHost;

/// <summary>
/// Chrome/Edge native messaging host. Started by the browser in the user's session with the caller origin as
/// argument; relays native-messaging frames between the extension (stdin/stdout) and the MinControl service
/// (\\.\pipe\MinControl.Browser). The service authenticates us by our token SID and image path; we check that the
/// pipe server runs in session 0 (a service), so a user process cannot squat the pipe name.
/// Exits when either side closes; the extension reconnects.
/// stdout carries only protocol frames — diagnostics go to stderr (shown in the browser's log).
/// </summary>
internal static class Program
{
    private const string PipeName = "MinControl.Browser";
    private const int MaxToExtensionBytes = 1024 * 1024;

    private static readonly HashSet<string> FromExtension = new(StringComparer.Ordinal) { "hello", "heartbeat", "event" };
    private static readonly HashSet<string> FromService = new(StringComparer.Ordinal) { "rules", "ping" };

    private static async Task<int> Main()
    {
        using var cts = new CancellationTokenSource();
        Stream stdin = Console.OpenStandardInput();
        Stream stdout = Console.OpenStandardOutput();

        await using NamedPipeClientStream? pipe = await ConnectAsync(cts.Token).ConfigureAwait(false);
        if (pipe is null)
        {
            Log("service pipe unavailable");
            return 2;
        }

        Task up = PumpAsync(stdin, pipe, MessageFraming.MaxFrameBytes, FromExtension, cts.Token);
        Task down = PumpAsync(pipe, stdout, MaxToExtensionBytes, FromService, cts.Token);
        Task first = await Task.WhenAny(up, down).ConfigureAwait(false);
        await cts.CancelAsync().ConfigureAwait(false);
        if (first.Exception is { } ex) Log(ex.GetBaseException().Message);
        return 0;
    }

    private static async Task<NamedPipeClientStream?> ConnectAsync(CancellationToken ct)
    {
        for (int attempt = 0; attempt < 8; attempt++)
        {
            var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                await pipe.ConnectAsync(2000, ct).ConfigureAwait(false);
                int serverPid = PipeNative.ServerProcessId(pipe.SafePipeHandle);
                if (PipeNative.SessionOf(serverPid) != 0)
                {
                    Log($"pipe server pid {serverPid} is not a service; refusing");
                    await pipe.DisposeAsync().ConfigureAwait(false);
                    return null;
                }
                return pipe;
            }
            catch (Exception ex) when (ex is TimeoutException or IOException or System.ComponentModel.Win32Exception)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(1 << attempt, 8)), ct).ConfigureAwait(false);
            }
        }
        return null;
    }

    /// <summary>Copies frames whose "t" is in <paramref name="allowed"/>; drops anything else.</summary>
    private static async Task PumpAsync(Stream from, Stream to, int maxBytes, HashSet<string> allowed, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            byte[]? frame = await MessageFraming.ReadAsync(from, maxBytes, ct).ConfigureAwait(false);
            if (frame is null) return;
            string? t;
            try
            {
                t = JsonNode.Parse(frame) is JsonObject o && o["t"] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
            }
            catch (JsonException)
            {
                continue;
            }
            if (t is null || !allowed.Contains(t)) continue;
            await MessageFraming.WriteAsync(to, frame, ct).ConfigureAwait(false);
        }
    }

    private static void Log(string message)
    {
        try { Console.Error.WriteLine("MinControl.NativeHost: " + message); } catch (IOException) { }
    }
}
