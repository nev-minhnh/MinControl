using Microsoft.Extensions.DependencyInjection;
using MinControl.Core.Abstractions;
using MinControl.Core.Diagnostics;
using MinControl.NetGuard.Bypass;
using MinControl.NetGuard.Categories;
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
    /// Also registers <see cref="CategoryUpdater"/> as a hosted service (UT1 list downloads).
    /// Nothing else is started here: the Service calls <see cref="INetGuard.ApplyAsync"/> on start and on policy change.
    /// </summary>
    public static IServiceCollection AddMinControlNetGuard(this IServiceCollection services, Action<NetGuardOptions>? configure = null)
    {
        var options = new NetGuardOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        services.AddSingleton<CategoryStore>();
        services.AddSingleton<ICategoryStore>(sp => sp.GetRequiredService<CategoryStore>());
        services.AddSingleton<CategoryUpdater>();
        services.AddHostedService(sp => sp.GetRequiredService<CategoryUpdater>());
        services.AddSingleton<IBlockNotifier, SessionBlockNotifier>();
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
        // diag.report sections (API.md §14)
        services.AddSingleton<IDiagnosticsSection>(sp => new WfpDiagnostics(sp.GetRequiredService<IWfpManager>(), sp.GetRequiredService<NetGuardService>()));
        services.AddSingleton<IDiagnosticsSection>(sp => new ProxyDiagnostics(sp.GetRequiredService<FilteringProxy>(), sp.GetRequiredService<NetGuardService>(),
            sp.GetRequiredService<IClock>()));
        services.AddSingleton<IDiagnosticsSection>(sp => new CategoryDiagnostics(sp.GetRequiredService<CategoryStore>(), sp.GetRequiredService<CategoryUpdater>(),
            sp.GetRequiredService<NetGuardOptions>()));
        return services;
    }
}
