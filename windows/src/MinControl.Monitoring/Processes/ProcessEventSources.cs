using System.Diagnostics;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace MinControl.Monitoring.Processes;

public readonly record struct ProcessStarted(int Pid, int ParentPid, string? ImagePath);

/// <summary>Raw process start/stop notifications for all users (filtering happens in the monitor).</summary>
public interface IProcessEventSource : IDisposable
{
    event Action<ProcessStarted>? Started;
    event Action<int>? Stopped;
    /// <summary>Starts delivering events on a background thread. Throws if the source cannot start.</summary>
    void Start();
}

/// <summary>
/// Real-time ETW session on <c>Microsoft-Windows-Kernel-Process</c> (keyword WINEVENT_KEYWORD_PROCESS).
/// Requires LocalSystem / admin. A timer force-flushes buffers so delivery latency stays ~ the flush interval.
/// </summary>
internal sealed class EtwProcessEventSource : IProcessEventSource
{
    private static readonly Guid KernelProcessProvider = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");
    private const ulong KeywordProcess = 0x10;

    private readonly MonitoringOptions _options;
    private readonly ILogger _log;
    private TraceEventSession? _session;
    private Thread? _thread;
    private Timer? _flush;

    public event Action<ProcessStarted>? Started;
    public event Action<int>? Stopped;

    public EtwProcessEventSource(MonitoringOptions options, ILogger log)
    {
        _options = options;
        _log = log;
    }

    public void Start()
    {
        var session = new TraceEventSession(_options.EtwSessionName) { StopOnDispose = true, BufferSizeMB = 4 };
        try
        {
            var parser = new RegisteredTraceEventParser(session.Source);
            parser.All += OnEvent;
            session.EnableProvider(KernelProcessProvider, TraceEventLevel.Informational, KeywordProcess);
        }
        catch
        {
            session.Dispose();
            throw;
        }
        _session = session;

        _thread = new Thread(() =>
        {
            try { session.Source.Process(); }
            catch (Exception ex) { _log.LogError(ex, "ETW process session stopped unexpectedly"); }
        })
        { IsBackground = true, Name = "MinControl ETW process" };
        _thread.Start();

        _flush = new Timer(_ =>
        {
            try { _session?.Flush(); } catch { /* session going away */ }
        }, null, _options.EtwFlushIntervalMs, _options.EtwFlushIntervalMs);
    }

    private void OnEvent(TraceEvent e)
    {
        try
        {
            switch ((int)e.ID)
            {
                case 1: // ProcessStart
                    int pid = Convert.ToInt32(e.PayloadByName("ProcessID"));
                    int ppid = Convert.ToInt32(e.PayloadByName("ParentProcessID"));
                    var image = e.PayloadByName("ImageName") as string;
                    Started?.Invoke(new ProcessStarted(pid, ppid,
                        string.IsNullOrEmpty(image) ? null : DevicePathMap.ToDosPath(image)));
                    break;
                case 2: // ProcessStop
                    Stopped?.Invoke(Convert.ToInt32(e.PayloadByName("ProcessID")));
                    break;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Bad Kernel-Process event");
        }
    }

    public void Dispose()
    {
        _flush?.Dispose();
        try { _session?.Dispose(); } catch { /* ignore */ }
        _session = null;
    }
}

/// <summary>Fallback when ETW is unavailable: diff of the process list every few hundred ms.</summary>
internal sealed class PollingProcessEventSource : IProcessEventSource
{
    private readonly int _intervalMs;
    private Timer? _timer;
    private HashSet<int> _known = [];
    private int _busy;

    public event Action<ProcessStarted>? Started;
    public event Action<int>? Stopped;

    public PollingProcessEventSource(MonitoringOptions options) => _intervalMs = Math.Max(100, options.PollIntervalMs);

    public void Start()
    {
        _known = Snapshot();
        _timer = new Timer(_ => Tick(), null, _intervalMs, _intervalMs);
    }

    private static HashSet<int> Snapshot()
    {
        var set = new HashSet<int>();
        foreach (var p in Process.GetProcesses())
        {
            set.Add(p.Id);
            p.Dispose();
        }
        return set;
    }

    private void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var now = Snapshot();
            foreach (var pid in now)
                if (!_known.Contains(pid)) Started?.Invoke(new ProcessStarted(pid, 0, null));
            foreach (var pid in _known)
                if (!now.Contains(pid)) Stopped?.Invoke(pid);
            _known = now;
        }
        catch { /* transient */ }
        finally { Volatile.Write(ref _busy, 0); }
    }

    public void Dispose() => _timer?.Dispose();
}
