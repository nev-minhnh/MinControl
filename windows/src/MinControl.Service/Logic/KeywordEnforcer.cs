using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Keywords;
using MinControl.Core.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MinControl.Service.Logic;

// Pure keyword enforcement (no Win32, no DI). Linked into the test project; KeywordGuard wires it to the helpers.

/// <summary>Foreground top-level window of a session as reported by the helper.</summary>
public sealed record ForegroundWindow(string ExePath, string? Title, int Pid, long Hwnd);

/// <summary>
/// Banned words (API.md §17 <c>userPolicy.keywords</c>). A hit closes the offending browser tab (Ctrl+W, sent by the helper
/// only while that window is still in front) or the other app's window (WM_CLOSE), shows "Đã đóng trang vì có từ bị cấm: …"
/// and emits one <c>web.blocked</c> (reason keyword, action closed_tab / closed_window) per closed tab/window — nothing
/// when nothing was closed. One close attempt per window per <see cref="PerWindowInterval"/>. Fresh history visits
/// (≤ <see cref="HistoryFreshness"/>) whose URL query holds a banned word close the tab when it is still the foreground
/// page. Managed SIDs only (I1).
/// </summary>
public sealed class KeywordEnforcer
{
    /// <summary>(sessionId, hwnd, pid, closeTab, toastTitle, toastReason) → the helper did it.</summary>
    public delegate Task<bool> CloseFn(int sessionId, long hwnd, int pid, bool tab, string title, string reason);

    public static readonly TimeSpan PerWindowInterval = TimeSpan.FromMilliseconds(1500);
    public static readonly TimeSpan HistoryFreshness = TimeSpan.FromMinutes(2);

    private readonly IPolicyProvider _policy;
    private readonly Func<string, bool> _isManaged;
    private readonly Func<int, string?> _sidOfSession;
    private readonly Func<string, IEnumerable<(int SessionId, ForegroundWindow Window)>> _foregroundOf;
    private readonly CloseFn _close;
    private readonly IEventSink _events;
    private readonly IClock _clock;
    private readonly ILogger _log;
    private readonly ConcurrentDictionary<(int, long), long> _lastAttempt = new();
    private readonly ConcurrentDictionary<string, (IReadOnlyList<string>? Words, KeywordMatcher? Matcher)> _matchers = new(StringComparer.OrdinalIgnoreCase);

    public KeywordEnforcer(IPolicyProvider policy, Func<string, bool> isManaged, Func<int, string?> sidOfSession,
        Func<string, IEnumerable<(int, ForegroundWindow)>> foregroundOf, CloseFn close, IEventSink events, IClock clock, ILogger? log = null)
    {
        _policy = policy;
        _isManaged = isManaged;
        _sidOfSession = sidOfSession;
        _foregroundOf = foregroundOf;
        _close = close;
        _events = events;
        _clock = clock;
        _log = log ?? NullLogger.Instance;
    }

    /// <summary>Evaluates one foreground report; returns the hit that was acted upon (closed), else null.</summary>
    public async Task<KeywordHit?> CheckForegroundAsync(int sessionId, ForegroundWindow fg)
    {
        try
        {
            if (fg.Hwnd == 0 || string.IsNullOrWhiteSpace(fg.Title)) return null;
            var sid = _sidOfSession(sessionId);
            if (sid is null || !_isManaged(sid)) return null;
            if (Keywords(sid) is not { } kw) return null;
            var hit = KeywordRules.Evaluate(kw.Policy, kw.Matcher, fg.ExePath, fg.Title);
            if (hit is null) return null;
            return await CloseAsync(sessionId, sid, fg, hit).ConfigureAwait(false) ? hit : null;
        }
        catch (Exception e)
        {
            _log.LogWarning(e, "keyword check failed");
            return null;
        }
    }

    /// <summary>A fresh visit whose URL query holds a banned word: close the tab if it is still the foreground page.</summary>
    public async Task<KeywordHit?> CheckHistoryAsync(string sid, string url, string? title, DateTimeOffset visitedAt)
    {
        try
        {
            if (_clock.UtcNow - visitedAt > HistoryFreshness || !_isManaged(sid)) return null;
            if (Keywords(sid) is not { } kw) return null;
            var hit = KeywordRules.EvaluateUrl(kw.Policy, kw.Matcher, url, title);
            if (hit is null) return null;
            foreach (var (sessionId, fg) in _foregroundOf(sid))
            {
                if (fg.Hwnd == 0 || !KeywordRules.IsBrowser(fg.ExePath) || string.IsNullOrWhiteSpace(fg.Title)) continue;
                var page = KeywordMatcher.PageTitle(fg.Title);
                var samePage = string.IsNullOrWhiteSpace(title)
                    ? page.Contains(hit.Query!, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(page, title.Trim(), StringComparison.Ordinal);
                if (!samePage) continue;
                var h = hit with { Title = page };
                if (await CloseAsync(sessionId, sid, fg, h).ConfigureAwait(false)) return h;
            }
            return null;
        }
        catch (Exception e)
        {
            _log.LogWarning(e, "keyword history check failed");
            return null;
        }
    }

    private async Task<bool> CloseAsync(int sessionId, string sid, ForegroundWindow fg, KeywordHit hit)
    {
        if (!TryAcquire(sessionId, fg.Hwnd)) return false;
        var ok = await _close(sessionId, fg.Hwnd, fg.Pid, hit.Browser, KeywordRules.ToastText(hit), Short(hit.Query ?? hit.Title, 120))
            .ConfigureAwait(false);
        _log.LogInformation("keyword '{Keyword}' in {Exe} (session {Session}): {Action} {Ok}", hit.Keyword, Path.GetFileName(fg.ExePath),
            sessionId, hit.Browser ? "close tab" : "close window", ok);
        if (!ok) return false;
        try { _events.Emit(EventTypes.WebBlocked, sid, BlockedData(hit, fg.ExePath)); }
        catch (Exception e) { _log.LogWarning(e, "emit web.blocked (keyword) failed"); }
        return true;
    }

    /// <summary>At most one close attempt per window per <see cref="PerWindowInterval"/>.</summary>
    public bool TryAcquire(int sessionId, long hwnd)
    {
        var now = _clock.MonotonicMs;
        var key = (sessionId, hwnd);
        while (true)
        {
            if (_lastAttempt.TryGetValue(key, out var last))
            {
                if (now - last < (long)PerWindowInterval.TotalMilliseconds) return false;
                if (_lastAttempt.TryUpdate(key, now, last)) break;
            }
            else if (_lastAttempt.TryAdd(key, now)) break;
        }
        if (_lastAttempt.Count > 1000)
            foreach (var kv in _lastAttempt)
                if (now - kv.Value > 60_000) _lastAttempt.TryRemove(kv.Key, out _);
        return true;
    }

    /// <summary><c>web.blocked</c> of a closed tab/window (event.schema.json $defs/webBlocked).</summary>
    public static JsonObject BlockedData(KeywordHit hit, string exePath)
    {
        var data = new JsonObject
        {
            ["host"] = hit.Host,
            ["source"] = "proxy",   // the agent (schema enum proxy|extension): the helper acted, not the extension
            ["reason"] = "keyword",
            ["keyword"] = Short(hit.Keyword, 64),
            ["action"] = hit.Browser ? "closed_tab" : "closed_window",
            ["rule"] = Short(KeywordRules.Rule(hit), 128),
            ["exe"] = Short(Path.GetFileName(exePath), 260),
            ["count"] = 1,
        };
        if (!string.IsNullOrWhiteSpace(hit.Title)) data["title"] = Short(hit.Title, 512);
        if (hit.Query is not null)
        {
            data["query"] = Short(hit.Query, 512);
            data["engine"] = hit.Engine ?? "other";
        }
        return data;
    }

    private (KeywordPolicy Policy, KeywordMatcher Matcher)? Keywords(string sid)
    {
        if (_policy.Current?.Users.GetValueOrDefault(sid)?.Keywords is not { Words.Count: > 0 } kp) return null;
        if (!kp.MatchSearches && !kp.MatchTitles) return null;
        var cached = _matchers.GetValueOrDefault(sid);
        if (cached.Matcher is null || !ReferenceEquals(cached.Words, kp.Words))
        {
            cached = (kp.Words, new KeywordMatcher(kp.Words));
            _matchers[sid] = cached;
        }
        return (kp, cached.Matcher!);
    }

    private static string Short(string s, int max) => s.Length <= max ? s : s[..max];
}

/// <summary>Whether a service stop is reported as tamper.service_stopped: never on OS shutdown, never when Setup/the
/// MSI announced it with a fresh expected-stop marker.</summary>
public static class StopClassifier
{
    public static bool ShouldReport(bool osShuttingDown, bool expectedStopMarkerFresh) => !osShuttingDown && !expectedStopMarkerFresh;
}
