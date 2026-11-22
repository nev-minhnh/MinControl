using Microsoft.Extensions.DependencyInjection;
using MinControl.Core.Abstractions;
using MinControl.NetGuard.Bypass;
using MinControl.NetGuard.Proxy;
using MinControl.NetGuard.Telemetry;
using MinControl.NetGuard.Web;
using MinControl.NetGuard.Wfp;

namespace MinControl.NetGuard;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the network guard (<see cref="INetGuard"/>). Requires <see cref="IUserDirectory"/>,
    /// <see cref="IPolicyProvider"/>, <see cref="IEventSink"/> and <see cref="IClock"/> from the other streams.
    /// Nothing is started here: the Service calls <see cref="INetGuard.ApplyAsync"/> on start and on policy change.
    /// </summary>
    public static IServiceCollection AddMinControlNetGuard(this IServiceCollection services, Action<NetGuardOptions>? configure = null)
    {
        var options = new NetGuardOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        services.AddSingleton<CategoryStore>();
        services.AddSingleton<ICategoryStore>(sp => sp.GetRequiredService<CategoryStore>());
        services.AddSingleton(sp => new WebDecisionEngine(sp.GetRequiredService<ICategoryStore>(), sp.GetRequiredService<NetGuardOptions>()));
        services.AddSingleton<CallerIdentifier>();
        services.AddSingleton<DomainAggregator>();
        services.AddSingleton<FilteringProxy>();
        services.AddSingleton<ExemptAppResolver>();
        services.AddSingleton<IWfpManager, WfpManager>();
        services.AddSingleton<ITcpTableSource, SystemTcpTableSource>();
        services.AddSingleton<BypassDetector>();
        services.AddSingleton<NetGuardService>();
        services.AddSingleton<INetGuard>(sp => sp.GetRequiredService<NetGuardService>());
        return services;
    }
}
