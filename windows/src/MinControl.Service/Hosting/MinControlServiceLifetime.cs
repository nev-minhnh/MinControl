using System.ServiceProcess;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Service.Sessions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MinControl.Service.Hosting;

/// <summary>WindowsServiceLifetime (a ServiceBase) that also accepts SERVICE_CONTROL_SESSIONCHANGE and
/// forwards it to the <see cref="SessionTracker"/>; reports unexpected stops as tamper.service_stopped.</summary>
internal sealed class MinControlServiceLifetime : WindowsServiceLifetime
{
    private readonly SessionTracker _sessions;
    private readonly IEventSink _events;
    private readonly ILogger _log;
    private volatile bool _systemShutdown;

    public MinControlServiceLifetime(
        IHostEnvironment environment,
        IHostApplicationLifetime applicationLifetime,
        ILoggerFactory loggerFactory,
        IOptions<HostOptions> optionsAccessor,
        IOptions<WindowsServiceLifetimeOptions> windowsServiceOptionsAccessor,
        SessionTracker sessions,
        IEventSink events)
        : base(environment, applicationLifetime, loggerFactory, optionsAccessor, windowsServiceOptionsAccessor)
    {
        _sessions = sessions;
        _events = events;
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

    protected override void OnStop()
    {
        // Non-admins cannot stop the service (default service DACL); any stop that is not a system shutdown is
        // an admin action or an attack, so report it. Best effort: the outbox is durable, upload happens later.
        if (!_systemShutdown)
        {
            try
            {
                _events.Emit(EventTypes.TamperServiceStopped, null, new JsonObject { ["detail"] = "service stop requested" });
            }
            catch (Exception e) { _log.LogError(e, "cannot record service stop"); }
        }
        base.OnStop();
    }
}
