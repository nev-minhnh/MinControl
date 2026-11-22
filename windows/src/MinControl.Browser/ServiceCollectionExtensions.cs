using MinControl.Browser.Events;
using MinControl.Browser.Ipc;
using MinControl.Browser.Policy;
using MinControl.Browser.Registry;
using MinControl.Core.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace MinControl.Browser;

public static class ServiceCollectionExtensions
{
    /// <summary>Registers the browser stream: policy writer, event ingress, pipe server for the native host and
    /// the extension heartbeat monitor. Requires IUserDirectory, IEventSink, IClock (and optionally IPolicyProvider).</summary>
    public static IServiceCollection AddMinControlBrowser(this IServiceCollection services, Action<BrowserOptions>? configure = null)
    {
        var builder = services.AddOptions<BrowserOptions>();
        if (configure is not null) builder.Configure(configure);

        services.TryAddSingleton<IRegistryHive, WindowsRegistryHive>();
        services.TryAddSingleton(sp => new BrowserPolicyMapper(sp.GetRequiredService<IOptions<BrowserOptions>>().Value));
        services.TryAddSingleton<BrowserPolicyWriter>();
        services.TryAddSingleton<IBrowserPolicyWriter>(sp => sp.GetRequiredService<BrowserPolicyWriter>());

        services.TryAddSingleton<ExtensionHeartbeatTracker>();
        services.TryAddSingleton<BrowserEventIngress>();
        services.TryAddSingleton<IBrowserEventIngress>(sp => sp.GetRequiredService<BrowserEventIngress>());

        services.TryAddSingleton<ExtensionHeartbeatMonitor>();
        services.TryAddSingleton<IExtensionHealth>(sp => sp.GetRequiredService<ExtensionHeartbeatMonitor>());
        services.AddHostedService(sp => sp.GetRequiredService<ExtensionHeartbeatMonitor>());
        services.AddHostedService<BrowserPipeServer>();
        return services;
    }
}
