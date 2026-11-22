using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using Microsoft.Extensions.Logging;

namespace MinControl.Browser.Events;

/// <summary>Validated entry point for extension events. The SID comes from the pipe client's token, never from
/// the message. Events of unmanaged SIDs are dropped (I1/I2); data is checked against event.schema.json.</summary>
public sealed class BrowserEventIngress : IBrowserEventIngress
{
    private readonly IEventSink _sink;
    private readonly IUserDirectory _users;
    private readonly IPolicyProvider? _policy;
    private readonly ExtensionHeartbeatTracker _heartbeats;
    private readonly ILogger<BrowserEventIngress> _log;

    public BrowserEventIngress(IEventSink sink, IUserDirectory users, ExtensionHeartbeatTracker heartbeats,
        ILogger<BrowserEventIngress> log, IPolicyProvider? policy = null)
    {
        _sink = sink; _users = users; _heartbeats = heartbeats; _log = log; _policy = policy;
    }

    public void OnBrowserEvent(string sid, string type, JsonObject data)
    {
        if (!_users.IsManaged(sid)) return;
        if (!BrowserEventValidator.AcceptedTypes.Contains(type))
        {
            _log.LogDebug("dropping browser event of type {Type}", type);
            return;
        }
        var clean = BrowserEventValidator.Sanitize(type, data);
        if (clean is null)
        {
            _log.LogDebug("dropping malformed {Type} from {Sid}", type, sid);
            return;
        }
        var monitoring = _policy?.Current?.Users.TryGetValue(sid, out var u) == true ? u.Monitoring : null;
        if (monitoring is not null)
        {
            bool history = type is EventTypes.WebVisit or EventTypes.WebSearch;
            if (history && !monitoring.BrowserHistory) return;
            if (type == EventTypes.DownloadCompleted && !monitoring.Downloads) return;
        }
        _sink.Emit(type, sid, clean);
    }

    public void OnHeartbeat(string sid, string browser)
    {
        if (!_users.IsManaged(sid)) return;
        if (browser is not ("msedge" or "chrome")) return;
        _heartbeats.Record(sid, browser);
    }
}
