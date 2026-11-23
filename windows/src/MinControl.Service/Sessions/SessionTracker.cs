using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Service.Users;
using Microsoft.Extensions.Logging;

namespace MinControl.Service.Sessions;

internal enum SessionChangeKind { Logon, Logoff, Lock, Unlock, ConsoleConnect, ConsoleDisconnect, RemoteConnect, RemoteDisconnect }

internal sealed record SessionSnapshot(int SessionId, string? Sid, bool Locked, long LogonMono);

/// <summary>Tracks interactive sessions from SERVICE_CONTROL_SESSIONCHANGE (forwarded by the service lifetime)
/// plus an initial WTS enumeration. Emits session.* events for managed SIDs only (I1).</summary>
internal sealed class SessionTracker(UserDirectory users, IEventSink events, IClock clock, ILogger<SessionTracker> log,
    IStateChangeNotifier? stateNotifier = null)
{
    private readonly object _gate = new();
    private readonly Dictionary<int, SessionSnapshot> _sessions = new();
    private bool _initialized;

    /// <summary>Raised (outside the lock) after any change; consumers re-read <see cref="Sessions"/>.</summary>
    public event Action? Changed;

    public void EnsureInitialized()
    {
        lock (_gate)
        {
            if (_initialized) return;
            _initialized = true;
            foreach (var s in Wts.Enumerate())
            {
                var sid = Wts.UserSid(s.SessionId);
                if (sid is null) continue;
                _sessions[s.SessionId] = new SessionSnapshot(s.SessionId, sid, Wts.IsLocked(s.SessionId) ?? false, clock.MonotonicMs);
            }
        }
        users.Refresh();
        Changed?.Invoke();
    }

    public IReadOnlyList<SessionSnapshot> Sessions
    {
        get { lock (_gate) return _sessions.Values.ToList(); }
    }

    public SessionSnapshot? Get(int sessionId)
    {
        lock (_gate) return _sessions.GetValueOrDefault(sessionId);
    }

    public IReadOnlyList<int> SessionsOf(string sid)
    {
        lock (_gate)
            return _sessions.Values.Where(s => string.Equals(s.Sid, sid, StringComparison.OrdinalIgnoreCase))
                .Select(s => s.SessionId).ToList();
    }

    public int ActiveConsoleSessionId => Wts.ActiveConsoleSessionId();

    /// <summary>Called on the SCM dispatcher thread: must stay quick and never throw.</summary>
    public void OnSessionChange(SessionChangeKind kind, int sessionId)
    {
        try { Handle(kind, sessionId); }
        catch (Exception e) { log.LogError(e, "session change {Kind} {Session} failed", kind, sessionId); }
        try { Changed?.Invoke(); }
        catch (Exception e) { log.LogError(e, "session change subscriber failed"); }
        if (kind is SessionChangeKind.Logon or SessionChangeKind.Logoff or SessionChangeKind.Lock or SessionChangeKind.Unlock)
            stateNotifier?.Notify(); // state goes to the cloud at once (API.md section 15)
    }

    private void Handle(SessionChangeKind kind, int sessionId)
    {
        if (sessionId == 0) return;
        string? sid;
        string? eventType = null;
        lock (_gate)
        {
            _sessions.TryGetValue(sessionId, out var cur);
            switch (kind)
            {
                case SessionChangeKind.Logon:
                    sid = Wts.UserSid(sessionId);
                    if (sid is null) return;
                    _sessions[sessionId] = new SessionSnapshot(sessionId, sid, false, clock.MonotonicMs);
                    eventType = EventTypes.SessionLogon;
                    break;
                case SessionChangeKind.Logoff:
                    sid = cur?.Sid;
                    _sessions.Remove(sessionId);
                    eventType = EventTypes.SessionLogoff;
                    break;
                case SessionChangeKind.Lock or SessionChangeKind.Unlock:
                    var locked = kind == SessionChangeKind.Lock;
                    sid = cur?.Sid ?? Wts.UserSid(sessionId);
                    if (sid is null) return;
                    _sessions[sessionId] = (cur ?? new SessionSnapshot(sessionId, sid, locked, clock.MonotonicMs)) with { Locked = locked };
                    eventType = locked ? EventTypes.SessionLock : EventTypes.SessionUnlock;
                    break;
                default:
                    // Connect/disconnect: the active console session changed; we read it live. Pick up sessions
                    // we missed (e.g. service started during a fast-user-switch).
                    if (cur is null && (sid = Wts.UserSid(sessionId)) is not null)
                        _sessions[sessionId] = new SessionSnapshot(sessionId, sid, Wts.IsLocked(sessionId) ?? false, clock.MonotonicMs);
                    return;
            }
        }

        if (kind == SessionChangeKind.Logon) users.Refresh(); // admin membership of the new token
        if (sid is null || eventType is null || !users.IsManaged(sid)) return; // I1: nothing about other SIDs
        events.Emit(eventType, sid, new JsonObject { ["sessionId"] = sessionId });
    }
}
