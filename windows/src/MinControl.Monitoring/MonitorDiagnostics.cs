using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Diagnostics;

namespace MinControl.Monitoring;

/// <summary><c>monitor</c> section: process source (ETW / polling), rules per managed user, tracked processes, last blocks.</summary>
internal sealed class MonitorDiagnostics(AppMonitor monitor, IPolicyProvider policy, IUserDirectory users, MonitoringOptions options)
    : IDiagnosticsSection
{
    public string Name => "monitor";

    public JsonObject Collect()
    {
        var rules = new JsonObject();
        if (policy.Current is { } p)
        {
            foreach (var (sid, u) in p.Users)
            {
                rules[sid] = new JsonObject
                {
                    ["managed"] = users.IsManaged(sid),
                    ["appRules"] = u.AppRules.Count,
                    ["blockRules"] = u.AppRules.Count(r => string.Equals(r.Action, "block", StringComparison.OrdinalIgnoreCase)),
                    ["appGroups"] = u.AppGroups.Count,
                    ["groupsWithQuota"] = u.AppGroups.Count(g => g.Value.DailyQuotaMin is not null),
                    ["newExecutable"] = u.NewExecutable,
                    ["allowedBrowsers"] = DiagJson.Strings(u.Web.AllowedBrowsers),
                };
            }
        }
        var tracked = new JsonObject();
        foreach (var (sid, n) in monitor.TrackedPerSid()) tracked[sid] = n;
        return new JsonObject
        {
            ["source"] = monitor.SourceMode,
            ["etwRunning"] = monitor.SourceMode == "etw+poll",
            ["sourceError"] = monitor.SourceError,
            ["pollIntervalMs"] = monitor.PollIntervalMs,
            ["etwFlushIntervalMs"] = options.EtwFlushIntervalMs,
            ["aclLayerEnabled"] = options.EnableAclLayer,
            ["rules"] = rules,
            ["trackedProcesses"] = tracked,
            ["blocksSinceStart"] = monitor.BlockCount,
            ["lastBlocks"] = DiagJson.Array(monitor.RecentBlocks(), b => new JsonObject
            {
                ["at"] = DiagJson.Utc(b.At), ["sid"] = b.Sid, ["exe"] = b.Exe, ["pid"] = b.Pid, ["rule"] = b.Rule, ["killed"] = b.Killed,
            }),
        };
    }
}
