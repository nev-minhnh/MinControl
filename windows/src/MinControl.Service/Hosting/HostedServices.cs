using System.Text.Json;
using System.Threading.Channels;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
using MinControl.Core.Storage;
using MinControl.Service.Users;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MinControl.Service.Hosting;

/// <summary>Runs the cloud link (connect/auth/receive/reconnect forever; win-core implements the loop).</summary>
internal sealed class CloudLinkHost(ICloudLink link, ILogger<CloudLinkHost> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await link.RunAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) { log.LogError(e, "cloud link crashed; restarting in 10 s"); }
            try { await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }
}

/// <summary>Starts / stops process monitoring (MinControl.Monitoring); the monitor re-evaluates running processes on
/// every PolicyChanged itself.</summary>
internal sealed class AppMonitorHost(IAppMonitor monitor) : IHostedService
{
    public Task StartAsync(CancellationToken ct) => monitor.StartAsync(ct);
    public Task StopAsync(CancellationToken ct) => monitor.StopAsync();
}

/// <summary>
/// Applies NetGuard (WFP + proxy) and the Edge/Chrome policies, serialized, at start, on every PolicyChanged, when the
/// managed set changes (SID added/removed, user became/stopped being admin) and every <see cref="RecheckPeriod"/>
/// (which also refreshes the managed set). SIDs that leave the managed set get <see cref="IBrowserPolicyWriter.RemoveAsync"/>;
/// the set of SIDs with written browser policies is persisted in state.db so this also happens after a restart.
/// </summary>
internal sealed class PolicyApplier(
    IPolicyProvider policy,
    UserDirectory users,
    INetGuard netGuard,
    IBrowserPolicyWriter browser,
    StateStore store,
    ILogger<PolicyApplier> log) : BackgroundService
{
    internal const string AppliedSidsMetaKey = "browser_policy_sids";
    private static readonly TimeSpan RecheckPeriod = TimeSpan.FromMinutes(1);

    private readonly Channel<bool> _queue = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropOldest });

    private void Trigger() => _queue.Writer.TryWrite(true);
    private void OnPolicyChanged(object? sender, DevicePolicy p) => Trigger();
    private void OnManagedSetChanged(object? sender, EventArgs e) => Trigger();

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        policy.PolicyChanged += OnPolicyChanged;
        users.ManagedSetChanged += OnManagedSetChanged;
        try
        {
            Trigger(); // initial apply (also removes leftovers when there is no policy at all)
            // Reading ManagedSids refreshes a stale (> 60 s) managed set, which raises ManagedSetChanged on a change.
            using var recheck = new Timer(_ => RefreshManagedSet(), null, RecheckPeriod, RecheckPeriod);
            await foreach (var _ in _queue.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                try { await ApplyAsync(ct).ConfigureAwait(false); }
                catch (Exception e) when (e is not OperationCanceledException) { log.LogError(e, "policy apply failed"); }
            }
        }
        finally
        {
            policy.PolicyChanged -= OnPolicyChanged;
            users.ManagedSetChanged -= OnManagedSetChanged;
        }
    }

    private void RefreshManagedSet()
    {
        try { _ = users.ManagedSids; }
        catch (Exception e) { log.LogDebug(e, "managed-set refresh failed"); }
    }

    private async Task ApplyAsync(CancellationToken ct)
    {
        users.Refresh(); // the directory's own PolicyChanged handler may not have run yet
        var p = policy.Current;
        var managed = users.ManagedSids; // in policy AND not an administrator (I2)

        if (p is not null)
            await netGuard.ApplyAsync(p, managed, ct).ConfigureAwait(false);

        var previous = LoadAppliedSids();
        var applied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (p is not null)
        {
            foreach (var sid in managed)
            {
                if (!p.Users.TryGetValue(sid, out var user)) continue;
                applied.Add(sid); // recorded before writing: a partial write must still be removed if the SID leaves
                try { await browser.ApplyAsync(sid, user.Web, netGuard.ProxyPort, ct).ConfigureAwait(false); }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    log.LogError(e, "browser policy apply failed for {Sid}", sid);
                }
            }
        }

        foreach (var sid in previous.Where(s => !applied.Contains(s)))
        {
            try
            {
                await browser.RemoveAsync(sid, ct).ConfigureAwait(false);
                log.LogInformation("browser policy removed for {Sid} (left the managed set)", sid);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                log.LogError(e, "browser policy removal failed for {Sid}; retrying on the next apply", sid);
                applied.Add(sid);
            }
        }
        SaveAppliedSids(applied);
        log.LogInformation("policy v{Version} applied for {Count} managed users", p?.Version, managed.Count);
    }

    private HashSet<string> LoadAppliedSids()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (store.GetMeta(AppliedSidsMetaKey) is { Length: > 0 } json
                && JsonSerializer.Deserialize<string[]>(json) is { } sids)
                set.UnionWith(sids.Where(s => s.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase)));
        }
        catch (JsonException e) { log.LogWarning(e, "applied-SID list unreadable; ignoring"); }
        return set;
    }

    private void SaveAppliedSids(HashSet<string> sids) =>
        store.SetMeta(AppliedSidsMetaKey, JsonSerializer.Serialize(sids.Order(StringComparer.OrdinalIgnoreCase).ToArray()));
}
