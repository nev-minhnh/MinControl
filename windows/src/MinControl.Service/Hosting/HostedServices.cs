using System.Threading.Channels;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
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

/// <summary>Starts process monitoring (MinControl.Monitoring). Registered only in MERGED builds.</summary>
internal sealed class AppMonitorHost(IAppMonitor monitor) : IHostedService
{
    public Task StartAsync(CancellationToken ct) => monitor.StartAsync(ct);
    public Task StopAsync(CancellationToken ct) => monitor.StopAsync();
}

/// <summary>Applies NetGuard + browser policies at start and on every PolicyChanged, serialized.
/// Registered only in MERGED builds.</summary>
internal sealed class PolicyApplier(
    IPolicyProvider policy,
    IUserDirectory users,
    INetGuard netGuard,
    IBrowserPolicyWriter browser,
    ILogger<PolicyApplier> log) : BackgroundService
{
    private readonly Channel<DevicePolicy> _queue = Channel.CreateBounded<DevicePolicy>(
        new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropOldest });

    private void OnChanged(object? sender, DevicePolicy p) => _queue.Writer.TryWrite(p);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        policy.PolicyChanged += OnChanged;
        try
        {
            if (policy.Current is { } initial) _queue.Writer.TryWrite(initial);
            await foreach (var p in _queue.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                try { await ApplyAsync(p, ct).ConfigureAwait(false); }
                catch (Exception e) when (e is not OperationCanceledException) { log.LogError(e, "policy apply v{Version} failed", p.Version); }
            }
        }
        finally { policy.PolicyChanged -= OnChanged; }
    }

    private async Task ApplyAsync(DevicePolicy p, CancellationToken ct)
    {
        var managed = users.ManagedSids; // admins excluded (I2)
        await netGuard.ApplyAsync(p, managed, ct).ConfigureAwait(false);
        foreach (var sid in managed)
        {
            if (p.Users.TryGetValue(sid, out var user))
                await browser.ApplyAsync(sid, user.Web, netGuard.ProxyPort, ct).ConfigureAwait(false);
        }
        log.LogInformation("policy v{Version} applied for {Count} managed users", p.Version, managed.Count);
    }
}
