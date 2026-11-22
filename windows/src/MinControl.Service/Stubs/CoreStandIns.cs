#if !MERGED
// TEMPORARY stand-ins for win-core types that do not exist on the s-session branch yet.
// DELETE THIS FILE when merging s-wincore (or build with -p:MERGED=true). If it is left in after the merge,
// the duplicate MinControl.Core types trigger CS0436 (warning-as-error) - the build fails loudly, never silently.
// Nothing here enforces anything; it only lets the Service compile and resolve its DI graph.
using System.Diagnostics;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MinControl.Core;

/// <summary>Stand-in for win-core's options type (real members unknown here).</summary>
public sealed class CoreOptions
{
}

public static class ServiceCollectionExtensions
{
    /// <summary>Stand-in for win-core's AddMinControlCore.</summary>
    public static IServiceCollection AddMinControlCore(this IServiceCollection services, Action<CoreOptions> configure)
    {
        configure(new CoreOptions());
        services.AddSingleton<IClock, StandInClock>();
        services.AddSingleton<IEventSink, StandInEventSink>();
        services.AddSingleton<IPolicyProvider, StandInPolicyProvider>();
        services.AddSingleton<IScreenTimeEngine, StandInEngine>();
        services.AddSingleton<ICloudLink, StandInCloudLink>();
        return services;
    }

    private sealed class StandInClock : IClock
    {
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
        public long MonotonicMs => Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency;
    }

    private sealed class StandInEventSink(ILogger<StandInEventSink> log) : IEventSink
    {
        public void Emit(string type, string? userSid, System.Text.Json.Nodes.JsonObject data) =>
            log.LogInformation("event {Type} {Sid} {Data}", type, userSid, data.ToJsonString());
    }

    private sealed class StandInPolicyProvider : IPolicyProvider
    {
        public DevicePolicy? Current => null; // no policy => nobody is managed
        public event EventHandler<DevicePolicy>? PolicyChanged { add { } remove { } }
    }

    private sealed class StandInEngine : IScreenTimeEngine
    {
        public ScreenTimeState Evaluate(string sid, DateTimeOffset utcNow) =>
            new(true, "ok", 0, null, null, null, new Dictionary<string, GroupState>());
        public void RecordUsage(string sid, string? foregroundExePath, long activeMsDelta) { }
        public IReadOnlyCollection<string> ExhaustedGroups(string sid, DateTimeOffset utcNow) => Array.Empty<string>();
    }

    private sealed class StandInCloudLink : ICloudLink
    {
        public bool Connected => false;
        public Task RunAsync(CancellationToken ct) => Task.Delay(Timeout.Infinite, ct);
    }
}
#endif
