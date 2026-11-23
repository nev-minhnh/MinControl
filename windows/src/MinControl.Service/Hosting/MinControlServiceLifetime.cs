using System.ServiceProcess;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Storage;
using MinControl.Service.Logic;
using MinControl.Service.Sessions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MinControl.Service.Hosting;

/// <summary>WindowsServiceLifetime (a ServiceBase) that also accepts SERVICE_CONTROL_SESSIONCHANGE and
/// forwards it to the <see cref="SessionTracker"/>; reports unexpected stops as tamper.service_stopped
/// (not on OS shutdown, not when Setup/the MSI announced the stop with a fresh <see cref="ExpectedStopMarker"/>).</summary>
internal sealed class MinControlServiceLifetime : WindowsServiceLifetime
{
    private readonly SessionTracker _sessions;
    private readonly IEventSink _events;
    private readonly DataPaths _paths;
    private readonly IClock _clock;
    private readonly ILogger _log;
    private volatile bool _systemShutdown;

    public MinControlServiceLifetime(
        IHostEnvironment environment,
        IHostApplicationLifetime applicationLifetime,
        ILoggerFactory loggerFactory,
        IOptions<HostOptions> optionsAccessor,
        IOptions<WindowsServiceLifetimeOptions> windowsServiceOptionsAccessor,
        SessionTracker sessions,
        IEventSink events,
        DataPaths paths,
        IClock clock)
        : base(environment, applicationLifetime, loggerFactory, optionsAccessor, windowsServiceOptionsAccessor)
    {
        _sessions = sessions;
        _events = events;
        _paths = paths;
        _clock = clock;
        _log = loggerFactory.CreateLogger<MinControlServiceLifetime>();
        CanHandleSessionChangeEvent = true; // must be set before ServiceBase.Run registers the control handler
        CanShutdown = true;
    }

    protected override void OnSessionChange(SessionChangeDescription change)
    {
        SessionChangeKind? kind = change.Reason switch
        {
            SessionChangeReason.SessionLogon => SessionChangeKind.Logon,
            SessionChangeReason.SessionLogoff => SessionChangeKind.Logoff,
            SessionChangeReason.SessionLock => SessionChangeKind.Lock,
            SessionChangeReason.SessionUnlock => SessionChangeKind.Unlock,
            SessionChangeReason.ConsoleConnect => SessionChangeKind.ConsoleConnect,
            SessionChangeReason.ConsoleDisconnect => SessionChangeKind.ConsoleDisconnect,
            SessionChangeReason.RemoteConnect => SessionChangeKind.RemoteConnect,
            SessionChangeReason.RemoteDisconnect => SessionChangeKind.RemoteDisconnect,
            _ => null,
        };
        if (kind is { } k) _sessions.OnSessionChange(k, change.SessionId);
        base.OnSessionChange(change);
    }

    protected override void OnShutdown()
    {
        _systemShutdown = true;
        base.OnShutdown();
    }

    protected override void OnStart(string[] args)
    {
        // A marker left by the maintenance that stopped us is used up: a later stop must be judged on its own.
        ExpectedStopMarker.Delete(_paths.ExpectedStop);
        base.OnStart(args);
    }

    protected override void OnStop()
    {
        // Non-admins cannot stop the service (default service DACL); a stop that is neither a system shutdown nor
        // announced by Setup/the MSI (upgrade, repair, re-enrolment, uninstall) is an admin action or an attack.
        // Best effort: the outbox is durable, upload happens later.
        var expected = ExpectedStopMarker.IsFresh(_paths.ExpectedStop, _clock.UtcNow);
        var osShutdown = _systemShutdown || Native.Win32.IsSystemShuttingDown();
        if (StopClassifier.ShouldReport(osShutdown, expected))
        {
            try
            {
                _events.Emit(EventTypes.TamperServiceStopped, null, new JsonObject { ["detail"] = TamperText.ServiceStopped });
            }
            catch (Exception e) { _log.LogError(e, "cannot record service stop"); }
        }
        else _log.LogInformation("Service stop (expected: {Expected}, OS shutdown: {Shutdown}): not reported", expected, osShutdown);
        base.OnStop();
    }
}
