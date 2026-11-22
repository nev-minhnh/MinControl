using MinControl.Core.Abstractions;
using MinControl.Monitoring.Acl;
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
        services.TryAddSingleton<AppMonitor>();
        services.TryAddSingleton<IAppMonitor>(sp => sp.GetRequiredService<AppMonitor>());
        return services;
    }
}
