using System.Text.Json.Nodes;
using MinControl.Core.Policies;
using MinControl.Core.Storage;

namespace MinControl.Core.Diagnostics;

/// <summary><c>policy</c> section: version, seq, stored ok, and a per-user summary of what is being enforced.</summary>
public sealed class PolicyDiagnostics(PolicyProvider policy, StateStore store) : IDiagnosticsSection
{
    public string Name => "policy";

    public JsonObject Collect()
    {
        var current = policy.Current;
        var stored = store.GetPolicy();
        var o = new JsonObject
        {
            ["present"] = current is not null,
            ["version"] = current?.Version,
            ["seq"] = policy.CurrentSeq,
            ["storedVersion"] = stored?.Version,
            ["storedSeq"] = stored?.Seq,
            ["storedAt"] = stored?.StoredAt,
            ["storedOk"] = !policy.StoredPolicyRejected,
            ["timezone"] = current?.Timezone,
        };
        if (current is null) return o;
        var users = new JsonObject();
        foreach (var (sid, u) in current.Users)
        {
            users[sid] = new JsonObject
            {
                ["appRules"] = DiagJson.Array(u.AppRules, r => new JsonObject
                {
                    ["action"] = r.Action,
                    ["match"] = DiagJson.FromObject(r.Match),
                    ["except"] = r.Except is { Count: > 0 } ex ? ex.Count : null,
                }),
                ["appGroups"] = DiagJson.Strings(u.AppGroups.Keys),
                ["newExecutable"] = u.NewExecutable,
                ["web"] = new JsonObject
                {
                    ["mode"] = u.Web.Mode,
                    ["blockedCategories"] = DiagJson.Strings(u.Web.BlockedCategories),
                    ["blockDomains"] = DiagJson.Strings(u.Web.BlockDomains.Take(100)),
                    ["blockDomainsCount"] = u.Web.BlockDomains.Count,
                    ["allowDomainsCount"] = u.Web.AllowDomains.Count,
                    ["safeSearch"] = u.Web.SafeSearch,
                    ["youtube"] = u.Web.Youtube,
                    ["allowedBrowsers"] = DiagJson.Strings(u.Web.AllowedBrowsers),
                    ["netExemptApps"] = u.Web.NetExemptApps.Count,
                    ["categorySchedules"] = u.Web.CategorySchedules?.Count ?? 0,
                },
                ["domainLog"] = u.Monitoring.DomainLog,
            };
        }
        o["users"] = users;
        return o;
    }
}
