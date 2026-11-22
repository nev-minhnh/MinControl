using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using MinControl.Core.Abstractions;
using MinControl.Core.Cloud;
using MinControl.Core.Commands;
using MinControl.Core.Crypto;
using MinControl.Core.Diagnostics;
using MinControl.Core.Policies;
using MinControl.Core.ScreenTime;
using MinControl.Core.Storage;
using MinControl.Core.Telemetry;
using MinControl.Core.Util;

namespace MinControl.Core;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Core services as singletons: IClock, StateStore, DeviceIdentity, EnvelopeVerifier,
    /// IPolicyProvider (PolicyProvider), IScreenTimeEngine (ScreenTimeEngine), IEventSink (EventSink),
    /// IApprovalStore, CommandDispatcher, EnvelopeHandler, IScreenshotUploader (ScreenshotUploader),
    /// ICloudLink (CloudLink). The host runs ICloudLink.RunAsync itself (win-session CloudLinkHost); the engine
    /// flushes its ledger when the container disposes it.
    /// Optional seams resolved lazily if registered by the host: ISessionActions, IForegroundTracker,
    /// IUserDirectory, IAppMonitor, IUserSessionStatus.
    /// </summary>
    public static IServiceCollection AddMinControlCore(this IServiceCollection services, Action<CoreOptions>? configure = null)
    {
        var options = new CoreOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);

        services.TryAddSingleton<IClock, SystemClock>();
        services.AddSingleton(new DataPaths(options.DataDirectory));
        services.AddSingleton(sp =>
        {
            var paths = sp.GetRequiredService<DataPaths>();
            paths.EnsureExists();
            return new StateStore(paths.StateDb) { OutboxCapBytes = options.OutboxCapBytes };
        });
        services.AddSingleton<IKeyProtector>(_ => options.KeyProtector ?? new DpapiMachineKeyProtector());
        services.AddSingleton(sp => new DeviceIdentity(sp.GetRequiredService<DataPaths>(), sp.GetRequiredService<IKeyProtector>()));
        services.AddSingleton(_ => SchemaValidator.Shared);
        services.AddSingleton(sp => new EnvelopeVerifier(sp.GetRequiredService<StateStore>(), sp.GetRequiredService<IClock>(), sp.GetRequiredService<SchemaValidator>()));
        services.AddSingleton(sp => new PolicyProvider(sp.GetRequiredService<StateStore>(), sp.GetRequiredService<EnvelopeVerifier>(),
            sp.GetRequiredService<IClock>(), sp.GetService<ILogger<PolicyProvider>>()));
        services.AddSingleton<IPolicyProvider>(sp => sp.GetRequiredService<PolicyProvider>());

        services.AddSingleton(sp => new EventSink(sp.GetRequiredService<StateStore>(), sp.GetRequiredService<IClock>(), null, sp.GetService<ILogger<EventSink>>()));
        services.AddSingleton<IEventSink>(sp => sp.GetRequiredService<EventSink>());
        services.AddSingleton<IApprovalStore>(sp => new ApprovalStore(sp.GetRequiredService<StateStore>(), sp.GetRequiredService<IClock>()));

        services.AddSingleton(sp => new ScreenTimeEngine(sp.GetRequiredService<StateStore>(), sp.GetRequiredService<PolicyProvider>(),
            sp.GetRequiredService<IClock>(), () => sp.GetService<IAppMonitor>()));
        services.AddSingleton<IScreenTimeEngine>(sp => sp.GetRequiredService<ScreenTimeEngine>());

        services.AddSingleton(sp => new ScreenshotStorage(sp.GetRequiredService<DataPaths>().Screens));
        services.AddSingleton(sp => new ScreenshotUploader(sp.GetRequiredService<StateStore>(), sp.GetRequiredService<EventSink>(), sp.GetRequiredService<IClock>(),
            sp.GetRequiredService<ScreenshotStorage>()));
        services.AddSingleton<IScreenshotUploader>(sp => sp.GetRequiredService<ScreenshotUploader>());

        services.AddSingleton(sp => new CommandDispatcher(sp.GetRequiredService<StateStore>(), sp.GetRequiredService<PolicyProvider>(),
            sp.GetRequiredService<IClock>(), sp.GetRequiredService<IApprovalStore>(),
            () => sp.GetService<ISessionActions>(), () => sp.GetService<IScreenshotUploader>(),
            () => sp.GetService<IUserDirectory>(), () => sp.GetService<IForegroundTracker>(), sp.GetService<ILogger<CommandDispatcher>>(),
            () => sp.GetService<DiagnosticsCollector>()));

        // diag.report (API.md §14): ring-buffer logger + collector over every registered IDiagnosticsSection.
        services.TryAddSingleton<LogRing>();
        services.AddSingleton<ILoggerProvider>(sp => new RingBufferLoggerProvider(sp.GetRequiredService<LogRing>()));
        services.AddSingleton<IDiagnosticsSection>(sp => new PolicyDiagnostics(sp.GetRequiredService<PolicyProvider>(), sp.GetRequiredService<StateStore>()));
        services.AddSingleton(sp => new DiagnosticsCollector(() => sp.GetServices<IDiagnosticsSection>(), sp.GetRequiredService<LogRing>(),
            sp.GetRequiredService<IEventSink>(), sp.GetRequiredService<IClock>(), sp.GetService<ILogger<DiagnosticsCollector>>()));
        services.AddSingleton(sp => new EnvelopeHandler(sp.GetRequiredService<EnvelopeVerifier>(), sp.GetRequiredService<PolicyProvider>(),
            sp.GetRequiredService<CommandDispatcher>(), sp.GetRequiredService<StateStore>(), sp.GetService<ILogger<EnvelopeHandler>>()));

        services.AddSingleton<UploadTokenHolder>();
        services.AddSingleton(sp => new DeviceStateBuilder(sp.GetRequiredService<PolicyProvider>(), sp.GetRequiredService<IScreenTimeEngine>(),
            sp.GetRequiredService<IClock>(), options.AgentVersion, () => sp.GetService<IForegroundTracker>(), () => sp.GetService<IUserSessionStatus>()));
        services.AddSingleton(_ => new HttpClient { Timeout = TimeSpan.FromSeconds(60) });
        services.AddSingleton(sp =>
        {
            var store = sp.GetRequiredService<StateStore>();
            return new CloudUploader(sp.GetRequiredService<HttpClient>(), store, sp.GetRequiredService<UploadTokenHolder>(),
                sp.GetRequiredService<IClock>(), () => options.ServerUrl ?? store.GetMeta(StateStore.MetaKeys.ServerUrl),
                sp.GetService<ILogger<CloudUploader>>());
        });
        services.AddSingleton(sp => new CloudLink(sp.GetRequiredService<StateStore>(), sp.GetRequiredService<DeviceIdentity>(),
            sp.GetRequiredService<EnvelopeHandler>(), sp.GetRequiredService<DeviceStateBuilder>(), sp.GetRequiredService<CloudUploader>(),
            sp.GetRequiredService<UploadTokenHolder>(), sp.GetRequiredService<IEventSink>(), sp.GetRequiredService<IClock>(), options,
            sp.GetRequiredService<PolicyProvider>(), sp.GetRequiredService<CommandDispatcher>(), sp.GetRequiredService<EventSink>(),
            sp.GetRequiredService<ScreenshotStorage>(), sp.GetService<ILogger<CloudLink>>()));
        services.AddSingleton<ICloudLink>(sp => sp.GetRequiredService<CloudLink>());

        return services;
    }
}
