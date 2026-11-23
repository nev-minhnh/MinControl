using MinControl.Core.Abstractions;
using Microsoft.Extensions.Logging;
using MinControl.Core.Cloud;
using MinControl.Core.Diagnostics;
using MinControl.Core.Storage;
using MinControl.Monitoring.Acl;
using MinControl.Monitoring.Inventory;
using MinControl.Monitoring.Processes;
using MinControl.Monitoring.Rules;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MinControl.Monitoring;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IAppMonitor"/> (process control + install/USB/download monitors).
    /// Requires IUserDirectory, IPolicyProvider, IEventSink, IApprovalStore, IClock and logging from the host.
    /// IScreenTimeEngine and ISessionActions are resolved lazily from the container (they depend on
    /// IAppMonitor.GroupOf themselves, so constructor injection would be a cycle). The host calls
    /// IAppMonitor.StartAsync/StopAsync.
    /// </summary>
    public static IServiceCollection AddMinControlMonitoring(this IServiceCollection services,
        Action<MonitoringOptions>? configure = null)
    {
        var options = new MonitoringOptions();
        configure?.Invoke(options);
        services.TryAddSingleton(options);
        services.TryAddSingleton<IFileFacts, FileFactsCache>();
        services.TryAddSingleton<IProcessControl, ProcessControl>();
        services.TryAddSingleton<ExecuteDenyAclLayer>();
        services.TryAddSingleton<UsageLedger>();
        services.TryAddSingleton<IInventorySources>(sp => new WindowsInventorySources(sp.GetRequiredService<IUserDirectory>(),
            sp.GetRequiredService<ILoggerFactory>().CreateLogger<WindowsInventorySources>()));
        services.TryAddSingleton(sp => new InventoryUploader(sp.GetRequiredService<HttpClient>(), sp.GetRequiredService<StateStore>(),
            sp.GetRequiredService<UploadTokenHolder>(), sp.GetRequiredService<IClock>(),
            () => sp.GetRequiredService<MinControl.Core.CoreOptions>().ServerUrl ?? sp.GetRequiredService<StateStore>().GetMeta(StateStore.MetaKeys.ServerUrl),
            sp.GetService<ILogger<InventoryUploader>>()));
        services.TryAddSingleton(sp => new InventoryService(sp.GetRequiredService<IUserDirectory>(), sp.GetRequiredService<IClock>(),
            sp.GetRequiredService<UsageLedger>(), sp.GetRequiredService<IFileFacts>(), sp.GetRequiredService<IInventorySources>(),
            () => sp.GetService<InventoryUploader>(), () => sp.GetService<IForegroundTracker>(),
            sp.GetRequiredService<ILoggerFactory>().CreateLogger<InventoryService>()));
        services.TryAddSingleton<AppMonitor>();
        services.TryAddSingleton<IAppMonitor>(sp => sp.GetRequiredService<AppMonitor>());
        services.AddSingleton<IDiagnosticsSection>(sp => new MonitorDiagnostics(sp.GetRequiredService<AppMonitor>(),
            sp.GetRequiredService<IPolicyProvider>(), sp.GetRequiredService<IUserDirectory>(), sp.GetRequiredService<MonitoringOptions>()));
        return services;
    }
}
