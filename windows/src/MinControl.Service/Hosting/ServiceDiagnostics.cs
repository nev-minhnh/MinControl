using System.Diagnostics;
using System.Reflection;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MinControl.Core;
using MinControl.Core.Abstractions;
using MinControl.Core.Diagnostics;
using MinControl.Service.Sessions;
using MinControl.Service.Users;

namespace MinControl.Service.Hosting;

/// <summary><c>service</c> section: version, uptime, hosted services, cloud link state.</summary>
internal sealed class ServiceDiagnostics(IServiceProvider services, CoreOptions core, IClock clock) : IDiagnosticsSection
{
    public string Name => "service";

    public JsonObject Collect()
    {
        var asm = Assembly.GetEntryAssembly() ?? typeof(ServiceDiagnostics).Assembly;
        var version = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                      ?? asm.GetName().Version?.ToString();
        using var self = Process.GetCurrentProcess();
        var lifetime = services.GetService<IHostApplicationLifetime>();
        return new JsonObject
        {
            ["version"] = version,
            ["agentVersion"] = core.AgentVersion,
            ["now"] = DiagJson.Utc(clock.UtcNow),
            ["startedAt"] = DiagJson.Utc(new DateTimeOffset(self.StartTime.ToUniversalTime(), TimeSpan.Zero)),
            ["uptimeSec"] = (long)(DateTime.Now - self.StartTime).TotalSeconds,
            ["os"] = Environment.OSVersion.VersionString,
            ["is64Bit"] = Environment.Is64BitProcess,
            ["workingSetMb"] = self.WorkingSet64 / (1024 * 1024),
            ["threads"] = self.Threads.Count,
            ["stopping"] = lifetime?.ApplicationStopping.IsCancellationRequested,
            ["hostedServices"] = DiagJson.Strings(services.GetServices<IHostedService>().Select(h => h.GetType().Name)),
            ["cloudConnected"] = services.GetService<ICloudLink>()?.Connected,
            ["netGuardVerified"] = NetGuardVerified(),
        };
    }

    private bool? NetGuardVerified()
    {
        var ng = services.GetService<INetGuard>();
        if (ng is null) return null;
        try { return ng.VerifyAsync(CancellationToken.None).GetAwaiter().GetResult(); }
        catch { return false; }
    }
}

/// <summary><c>users</c> section: managed SIDs, admin flags, interactive sessions.</summary>
internal sealed class UsersDiagnostics(UserDirectory users, SessionTracker sessions, IPolicyProvider policy) : IDiagnosticsSection
{
    public string Name => "users";

    public JsonObject Collect()
    {
        var policySids = policy.Current?.Users.Keys.ToList() ?? [];
        var list = new JsonArray();
        foreach (var sid in policySids.Concat(users.ManagedSids).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.Ordinal))
        {
            list.Add(new JsonObject
            {
                ["sid"] = sid,
                ["inPolicy"] = policySids.Contains(sid, StringComparer.OrdinalIgnoreCase),
                ["managed"] = users.IsManaged(sid),
                ["administrator"] = users.IsAdministrator(sid),
                ["profile"] = users.ProfilePath(sid) is { } p ? Path.GetFileName(p) : null,
            });
        }
        return new JsonObject
        {
            ["users"] = list,
            ["activeConsoleSession"] = sessions.ActiveConsoleSessionId,
            ["sessions"] = DiagJson.Array(sessions.Sessions, s => new JsonObject
            {
                ["id"] = s.SessionId, ["sid"] = s.Sid, ["locked"] = s.Locked,
                ["managed"] = s.Sid is not null && users.IsManaged(s.Sid),
            }),
        };
    }
}
