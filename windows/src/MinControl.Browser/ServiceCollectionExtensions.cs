using MinControl.Browser.Events;
using MinControl.Browser.Ipc;
using MinControl.Browser.Policy;
using MinControl.Browser.Registry;
using MinControl.Browser.History;
using MinControl.Core.Abstractions;
using MinControl.Core.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace MinControl.Browser;

public static class ServiceCollectionExtensions
{
    /// <summary>Registers the browser stream: policy writer, event ingress, pipe server for the native host and
    /// the extension heartbeat monitor and the History-database reader. Requires IUserDirectory, IEventSink, IClock (and optionally IPolicyProvider).</summary>
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

        services.TryAddSingleton<IHistoryFileLocator, HistoryFileLocator>();
        services.TryAddSingleton<IHistoryEventSink>(sp => new HistoryEventSink(sp.GetRequiredService<IEventSink>()));
        services.TryAddSingleton(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<BrowserOptions>>().Value;
            string root = HistoryRoot(sp, opts);
            var log = sp.GetRequiredService<ILoggerFactory>().CreateLogger<BrowserHistoryReader>();
            return new BrowserHistoryReader(sp.GetRequiredService<IUserDirectory>(), sp.GetService<IPolicyProvider>(),
                sp.GetRequiredService<IHistoryEventSink>(), sp.GetRequiredService<IClock>(), sp.GetRequiredService<IHistoryFileLocator>(),
                new HistoryCursorStore(Path.Combine(root, "browser-history.json"), log), Path.Combine(root, "tmp"), opts, log);
        });
        services.AddHostedService(sp => sp.GetRequiredService<BrowserHistoryReader>());
        return services;
    }

    private static string HistoryRoot(IServiceProvider sp, BrowserOptions opts) =>
        opts.HistoryDataDirectory
        ?? sp.GetService<DataPaths>()?.Root
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinControl");
}
