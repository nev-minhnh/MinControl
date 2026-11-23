using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policy;
using MinControl.NetGuard.Bypass;
using MinControl.NetGuard.Proxy;
using MinControl.NetGuard.Telemetry;
using MinControl.NetGuard.Web;
using MinControl.NetGuard.Wfp;

namespace MinControl.NetGuard;

/// <summary>
/// <see cref="INetGuard"/> implementation: persistent per-user WFP lock + loopback filtering proxy + background
/// watchdog (filters/proxy repair every 60 s), net.domain flushing, bypass scanning and category refresh.
/// The proxy reads <see cref="IPolicyProvider.Current"/> on every request, so web rules follow policy changes
/// immediately; <see cref="ApplyAsync"/> is only needed when the managed-user set or netExemptApps change.
/// </summary>
public sealed class NetGuardService : INetGuard, IAsyncDisposable
{
    private static readonly TimeSpan Tick = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan CategoryRefreshInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan VerifyCacheTtl = TimeSpan.FromSeconds(60);

    private readonly NetGuardOptions _options;
    private readonly IWfpManager _wfp;
    private readonly FilteringProxy _proxy;
    private readonly DomainAggregator _aggregator;
    private readonly BypassDetector _bypass;
    private readonly ExemptAppResolver _exempt;
    private readonly CategoryStore _categories;
    private readonly IUserDirectory _users;
    private readonly IEventSink _events;
    private readonly IClock _clock;
    private readonly ILogger _log;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private IReadOnlyList<WfpUserRule>? _desired;   // null until the first successful ApplyAsync
    private CancellationTokenSource? _loopCts;
    private Task? _loop;
    private VerifyCache? _verifyCache;   // last WFP verify result, reused by the bypass scan for ≤ 60 s

    private sealed record VerifyCache(long AtMs, IReadOnlyList<WfpUserRule> Desired, WfpVerifyResult Result);

    /// <summary>Outcome of the last WFP apply (start, policy change or watchdog repair), for diagnostics.</summary>
    public sealed record ApplyOutcome(DateTimeOffset At, string Trigger, bool Ok, IReadOnlyList<string> Sids, string? Error);

    public ApplyOutcome? LastApply { get; private set; }
    public IReadOnlyList<WfpUserRule>? Desired => _desired;
    public FilteringProxy Proxy => _proxy;
    public BypassDetector Bypass => _bypass;

    private void ApplyWfp(IReadOnlyList<WfpUserRule> rules, string trigger)
    {
        var sids = rules.Select(r => r.Sid).ToList();
        try
        {
            _wfp.Apply(rules);
            LastApply = new ApplyOutcome(_clock.UtcNow, trigger, true, sids, null);
        }
        catch (Exception ex)
        {
            LastApply = new ApplyOutcome(_clock.UtcNow, trigger, false, sids, ex.Message);
            _log.LogError(ex, "WFP apply ({Trigger}) failed for {Users} user(s)", trigger, rules.Count);
            throw;
        }
    }

    public NetGuardService(NetGuardOptions options, IWfpManager wfp, FilteringProxy proxy, DomainAggregator aggregator,
        BypassDetector bypass, ExemptAppResolver exempt, CategoryStore categories, IUserDirectory users, IEventSink events,
        IClock clock, ILogger<NetGuardService>? log = null)
    {
        _options = options;
        _wfp = wfp;
        _proxy = proxy;
        _aggregator = aggregator;
        _bypass = bypass;
        _exempt = exempt;
        _categories = categories;
        _users = users;
        _events = events;
        _clock = clock;
        _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public int ProxyPort => _options.ProxyPort;

    public async Task ApplyAsync(DevicePolicy policy, IReadOnlyCollection<string> managedSids, CancellationToken ct)
    {
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var rules = BuildRules(policy, managedSids);
            // Proxy first: once filters are in place the managed user can only reach the network through it.
            StartProxySafe();
            await Task.Run(() => ApplyWfp(rules, "policy"), ct).ConfigureAwait(false);   // transactional: on failure old filters stay (I4)
            var changed = ChangedRules(_desired, rules);
            _desired = rules;
            _verifyCache = null;
            EnforceNow(changed);
            EnsureLoop();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<bool> VerifyAsync(CancellationToken ct)
    {
        var desired = _desired;
        if (!_proxy.IsListening) return false;
        if (desired is null) return false;
        try
        {
            var r = await Task.Run(() => _wfp.Verify(desired), ct).ConfigureAwait(false);
            return r.Ok;
        }
        catch (WfpException ex)
        {
            _log.LogWarning(ex, "WFP verify failed");
            return false;
        }
    }

    public async Task RemoveAllAsync(CancellationToken ct)
    {
        await StopLoopAsync().ConfigureAwait(false);   // outside the lock: the watchdog takes it too
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await Task.Run(() => _wfp.RemoveAll(), ct).ConfigureAwait(false);
            _desired = null;
            _verifyCache = null;
            _bypass.OnFiltersRemoved();
            await _proxy.StopAsync().ConfigureAwait(false);
            _aggregator.FlushAll();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        // Service shutdown: filters stay installed on purpose (persistent, fail closed).
        await StopLoopAsync().ConfigureAwait(false);
        await _proxy.DisposeAsync().ConfigureAwait(false);
        try { _aggregator.FlushAll(); } catch { /* sink may be gone */ }
    }

    // ------------------------------------------------------------------ internals

    private List<WfpUserRule> BuildRules(DevicePolicy policy, IReadOnlyCollection<string> managedSids)
    {
        var rules = new List<WfpUserRule>();
        foreach (var sid in managedSids.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            // I2: an administrator never gets filters, even if listed.
            if (_users.IsAdministrator(sid)) { _log.LogWarning("SID {Sid} is an administrator; no network lock applied (I2)", sid); continue; }
            policy.Users.TryGetValue(sid, out var user);
            var exempt = user is null ? [] : _exempt.Resolve(user.Web.NetExemptApps);
            rules.Add(new WfpUserRule(sid, exempt));
        }
        return rules;
    }

    /// <summary>Rules that are new or whose exempt apps changed compared with <paramref name="previous"/>.</summary>
    internal static List<WfpUserRule> ChangedRules(IReadOnlyList<WfpUserRule>? previous, IReadOnlyList<WfpUserRule> next)
    {
        var old = (previous ?? []).ToDictionary(r => r.Sid, StringComparer.OrdinalIgnoreCase);
        return next.Where(r => !old.TryGetValue(r.Sid, out var o) ||
                               !o.ExemptAppPaths.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(r.ExemptAppPaths)).ToList();
    }

    /// <summary>Resets the pre-existing connections the just-applied filters would block (only those SIDs).</summary>
    private void EnforceNow(IReadOnlyList<WfpUserRule> rules)
    {
        if (rules.Count == 0) return;
        try { _bypass.OnFiltersApplied(rules); }
        catch (Exception ex) { _log.LogWarning(ex, "Resetting pre-existing connections failed"); }
    }

    /// <summary>
    /// Bypass-scan check: are our filters for <paramref name="sid"/> installed? Uses a WFP verify result at most
    /// 60 s old. Unknown (no rule / verify error) = false, so nothing is reported without proof the lock is in place.
    /// </summary>
    internal bool FiltersPresentFor(string sid)
    {
        var desired = _desired;
        var rule = desired?.FirstOrDefault(r => string.Equals(r.Sid, sid, StringComparison.OrdinalIgnoreCase));
        if (desired is null || rule is null) return false;
        var cache = _verifyCache;
        if (cache is null || !ReferenceEquals(cache.Desired, desired) ||
            _clock.MonotonicMs - cache.AtMs > (long)VerifyCacheTtl.TotalMilliseconds)
        {
            try { cache = new VerifyCache(_clock.MonotonicMs, desired, _wfp.Verify(desired)); }
            catch (WfpException ex) { _log.LogWarning(ex, "WFP verify failed"); return false; }
            _verifyCache = cache;
        }
        var r = cache.Result;
        if (!r.ProviderPresent || !r.SublayerPresent) return false;
        var missing = r.MissingFilterKeys.ToHashSet();
        return !WfpManager.ExpectedKeys(rule).Any(missing.Contains);
    }

    private void StartProxySafe()
    {
        try { _proxy.Start(); }
        catch (Exception ex) { _log.LogError(ex, "Proxy failed to start on port {Port}", _options.ProxyPort); }
    }

    private void EnsureLoop()
    {
        if (_loop is { IsCompleted: false }) return;
        _loopCts = new CancellationTokenSource();
        _loop = Task.Run(() => LoopAsync(_loopCts.Token));
    }

    private async Task StopLoopAsync()
    {
        var cts = _loopCts;
        var loop = _loop;
        _loopCts = null;
        _loop = null;
        if (cts is null) return;
        cts.Cancel();
        try { if (loop is not null) await loop.ConfigureAwait(false); } catch (OperationCanceledException) { }
        cts.Dispose();
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        var lastWatchdog = _clock.MonotonicMs;
        var lastBypass = long.MinValue / 2;
        var lastCategories = _clock.MonotonicMs;
        using var timer = new PeriodicTimer(Tick);
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            var now = _clock.MonotonicMs;
            try { _aggregator.Flush(); } catch (Exception ex) { _log.LogWarning(ex, "net.domain flush failed"); }

            if (now - lastWatchdog >= (long)_options.WatchdogInterval.TotalMilliseconds)
            {
                lastWatchdog = now;
                try { await WatchdogAsync(ct).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "NetGuard watchdog failed"); }
            }
            if (now - lastBypass >= (long)_options.BypassScanInterval.TotalMilliseconds)
            {
                lastBypass = now;
                var desired = _desired;
                var exempt = desired?.ToDictionary(r => r.Sid, r => r.ExemptAppPaths, StringComparer.OrdinalIgnoreCase)
                             ?? new Dictionary<string, IReadOnlyList<string>>();
                _bypass.Scan(_options.ProxyPort, exempt, FiltersPresentFor);
            }
            if (now - lastCategories >= (long)CategoryRefreshInterval.TotalMilliseconds)
            {
                lastCategories = now;
                try { await _categories.RefreshAsync(ct).ConfigureAwait(false); } catch (Exception ex) when (ex is not OperationCanceledException) { }
            }
        }
    }

    /// <summary>Re-adds missing filters (emitting tamper.wfp_filter_missing) and restarts the proxy if it died.</summary>
    internal async Task WatchdogAsync(CancellationToken ct)
    {
        if (!_proxy.IsListening)
        {
            _log.LogWarning("Proxy not listening; restarting");
            StartProxySafe();
        }

        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var desired = _desired;
            if (desired is null) return;
            WfpVerifyResult r;
            try { r = _wfp.Verify(desired); }
            catch (WfpException ex) { _log.LogWarning(ex, "WFP verify failed"); return; }
            _verifyCache = new VerifyCache(_clock.MonotonicMs, desired, r);
            if (r.Ok) return;

            var missing = r.MissingFilterKeys.ToHashSet();
            var affected = desired.Where(rule => !r.ProviderPresent || !r.SublayerPresent ||
                                                 WfpManager.ExpectedKeys(rule).Any(missing.Contains)).ToList();
            foreach (var rule in affected)
            {
                var detail = !r.ProviderPresent || !r.SublayerPresent
                    ? "WFP provider/sublayer removed; re-added"
                    : $"{WfpManager.ExpectedKeys(rule).Count(missing.Contains)} WFP filter(s) missing; re-added";
                try { _events.Emit(EventTypes.TamperWfpFilterMissing, rule.Sid, new JsonObject { ["detail"] = detail }); }
                catch (Exception ex) { _log.LogWarning(ex, "Emit tamper.wfp_filter_missing failed"); }
            }
            try
            {
                ApplyWfp(desired, "watchdog");
                _verifyCache = null;
                EnforceNow(affected);   // connections opened while the filters were missing are pre-existing now
            }
            catch (WfpException ex) { _log.LogError(ex, "WFP re-apply failed"); }
        }
        finally
        {
            _lock.Release();
        }
    }
}
