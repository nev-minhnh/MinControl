using MinControl.Core.Abstractions;
using MinControl.Service.Ipc;
using MinControl.Service.Logic;
using MinControl.Service.Sessions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MinControl.Service.Keywords;

/// <summary>
/// Hosts <see cref="KeywordEnforcer"/> (API.md §17 banned words): feeds it every foreground report of the session helpers
/// (one per change of window/exe/title; the helper polls the title every second), re-checks the current foreground of
/// each session every 2 s (a close that failed because the window was not in front at that instant is retried), and
/// receives fresh history visits (<see cref="IKeywordGuard"/>). Closing is done by the helper of the session.
/// </summary>
internal sealed class KeywordGuard : IHostedService, IKeywordGuard
{
    private static readonly TimeSpan CloseTimeout = TimeSpan.FromSeconds(5);
    private readonly SessionChannelRegistry _channels;
    private readonly KeywordEnforcer _enforcer;
    private Timer? _recheck;

    public KeywordGuard(IPolicyProvider policy, IUserDirectory users, SessionTracker sessions, SessionChannelRegistry channels,
        IEventSink events, IClock clock, ILogger<KeywordGuard> log)
    {
        _channels = channels;
        _enforcer = new KeywordEnforcer(policy, users.IsManaged, id => sessions.Get(id)?.Sid,
            sid => sessions.SessionsOf(sid)
                .Select(id => (Id: id, Fg: channels.TryGet(id)?.Foreground))
                .Where(x => x.Fg is not null)
                .Select(x => (x.Id, Window(x.Fg!))),
            (id, hwnd, pid, tab, title, reason) => channels.TryGet(id) is { } ch
                ? ch.CloseWindowAsync(hwnd, pid, tab, title, reason, CloseTimeout, CancellationToken.None)
                : Task.FromResult(false),
            events, clock, log);
    }

    private static ForegroundWindow Window(ForegroundInfo f) => new(f.ExePath, f.Title, f.Pid, f.Hwnd);

    public Task StartAsync(CancellationToken ct)
    {
        _channels.ForegroundChanged += OnForeground;
        _recheck = new Timer(_ =>
        {
            foreach (var id in _channels.SessionIds)
                if (_channels.TryGet(id)?.Foreground is { } fg) OnForeground(id, fg);
        }, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken ct)
    {
        _channels.ForegroundChanged -= OnForeground;
        _recheck?.Dispose();
        return Task.CompletedTask;
    }

    private void OnForeground(int sessionId, ForegroundInfo fg) => _ = _enforcer.CheckForegroundAsync(sessionId, Window(fg));

    public void OnHistoryVisit(string sid, string browser, string url, string? title, DateTimeOffset visitedAt) =>
        _ = _enforcer.CheckHistoryAsync(sid, url, title, visitedAt);
}
