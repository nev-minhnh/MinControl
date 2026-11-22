using System.Security.Principal;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MinControl.Browser;
using MinControl.Browser.Policy;
using MinControl.Browser.Registry;
using MinControl.Core.Abstractions;
using MinControl.Core.Policy;
using MinControl.Core.Util;
using MinControl.NetGuard;
using MinControl.NetGuard.Bypass;
using MinControl.NetGuard.Proxy;
using MinControl.NetGuard.Telemetry;
using MinControl.NetGuard.Web;
using MinControl.NetGuard.Wfp;

namespace MinControl.Setup;

/// <summary>
/// Uninstall-time cleanup using the real NetGuard / Browser implementations, composed by hand (Setup has no DI
/// container). Only removal paths are used: nothing here starts the proxy, adds filters or writes policies.
/// </summary>
internal static class Cleanup
{
    /// <summary>Deletes every persistent WFP filter/sublayer/provider owned by MinControl (I4 lock for managed users).</summary>
    public static async Task RemoveNetGuardAsync(CancellationToken ct)
    {
        var options = new NetGuardOptions();
        var users = new SetupUserDirectory();
        var sink = new DiscardingEventSink();
        var clock = new SystemClock();
        var categories = new CategoryStore(options);
        var aggregator = new DomainAggregator(sink, clock, options);
        var proxy = new FilteringProxy(options, users, new NoPolicy(), sink, clock,
            new WebDecisionEngine(categories, options), new CallerIdentifier(users, clock), aggregator);
        await using var netGuard = new NetGuardService(options, new WfpManager(), proxy, aggregator,
            new BypassDetector(users, sink, clock), new ExemptAppResolver(), categories, users, sink, clock);
        await netGuard.RemoveAllAsync(ct);
    }

    /// <summary>
    /// Removes MinControl's browser policies from every user profile (loads NTUSER.DAT for users that are not
    /// logged on) and the HKLM native-messaging host registration + manifest. Returns per-SID failures.
    /// NOTE: calls the concrete <see cref="BrowserPolicyWriter.UnregisterNativeHostAsync"/>; switch to the
    /// IBrowserPolicyWriter member once r2-windows adds it to the seam.
    /// </summary>
    public static async Task<IReadOnlyList<string>> RemoveBrowserPoliciesAsync(AgentConfig config, string installDir, CancellationToken ct)
    {
        var options = BrowserOptionsFor(config, installDir);
        var users = new SetupUserDirectory();
        var writer = new BrowserPolicyWriter(new WindowsRegistryHive(), users, new BrowserPolicyMapper(options),
            Options.Create(options), NullLogger<BrowserPolicyWriter>.Instance);
        var failures = new List<string>();
        foreach (var sid in SystemTools.UserProfiles().Keys)
        {
            try { await writer.RemoveAsync(sid, ct); }
            catch (Exception e) when (e is not OperationCanceledException) { failures.Add($"{sid}: {e.Message}"); }
        }
        await writer.UnregisterNativeHostAsync(ct);
        return failures;
    }

    /// <summary>Same options the Service uses, so manifest path / value names match exactly.</summary>
    public static BrowserOptions BrowserOptionsFor(AgentConfig config, string installDir) => new()
    {
        ChromeExtensionId = config.ChromeExtensionId ?? "",
        EdgeExtensionId = config.EdgeExtensionId ?? "",
        NativeHostExePath = Path.Combine(installDir, "MinControl.NativeHost.exe"),
    };

    // ------------------------------------------------------------------ minimal seam implementations

    /// <summary>Profile lookup only; Setup never treats anyone as managed.</summary>
    private sealed class SetupUserDirectory : IUserDirectory
    {
        private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        private readonly IReadOnlyDictionary<string, string> _profiles = SystemTools.UserProfiles();
        private HashSet<string>? _admins;

        public bool IsManaged(string sid) => false;
        public bool IsAdministrator(string sid)
        {
            _admins ??= LocalUsers.Enumerate().Where(u => u.IsAdmin).Select(u => u.Sid).ToHashSet(StringComparer.OrdinalIgnoreCase);
            return _admins.Contains(sid) || sid == Admins.Value;
        }
        public IReadOnlyCollection<string> ManagedSids => [];
        public string? SidOfProcess(int pid) => null;
        public string? ProfilePath(string sid) => _profiles.TryGetValue(sid, out var p) ? p : null;
    }

    private sealed class DiscardingEventSink : IEventSink
    {
        public void Emit(string type, string? userSid, JsonObject data) { }
    }

    private sealed class NoPolicy : IPolicyProvider
    {
        public DevicePolicy? Current => null;
        public event EventHandler<DevicePolicy>? PolicyChanged { add { } remove { } }
    }
}
