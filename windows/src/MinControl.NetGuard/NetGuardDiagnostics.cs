using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Diagnostics;
using MinControl.NetGuard.Categories;
using MinControl.NetGuard.Proxy;
using MinControl.NetGuard.Web;
using MinControl.NetGuard.Wfp;

namespace MinControl.NetGuard;

/// <summary><c>wfp</c> section: provider/sublayer, every sublayer by weight, our filters per SID (layer, action, weight,
/// flags, decoded conditions), the expected-vs-installed diff and the last apply outcome.</summary>
public sealed class WfpDiagnostics(IWfpManager wfp, NetGuardService netGuard) : IDiagnosticsSection
{
    public string Name => "wfp";

    public JsonObject Collect()
    {
        var o = new JsonObject
        {
            ["plan"] = WfpFilterPlan.Revision,
            ["sublayerWeightOurs"] = WfpManager.SublayerWeight,
        };
        if (netGuard.LastApply is { } a)
            o["lastApply"] = new JsonObject
            {
                ["at"] = DiagJson.Utc(a.At), ["trigger"] = a.Trigger, ["ok"] = a.Ok,
                ["sids"] = DiagJson.Strings(a.Sids), ["error"] = a.Error,
            };
        var desired = netGuard.Desired;
        o["desiredSids"] = desired is null ? null : DiagJson.Strings(desired.Select(r => r.Sid));

        var snap = wfp.Describe();
        o["providerPresent"] = snap.ProviderPresent;
        o["sublayerPresent"] = snap.SublayerPresent;
        o["sublayers"] = DiagJson.Array(snap.Sublayers.Take(40), s => new JsonObject
        {
            ["name"] = s.Name, ["weight"] = s.Weight, ["ours"] = s.Ours, ["id"] = s.Key.ToString(),
        });
        var higher = snap.Sublayers.Where(s => !s.Ours && s.Weight >= WfpManager.SublayerWeight).Select(s => s.Name ?? s.Key.ToString()).ToList();
        o["sublayersAtOrAboveOurs"] = DiagJson.Strings(higher);

        var bySid = new JsonObject();
        foreach (var g in snap.Filters.GroupBy(f => f.Sid ?? "unknown").OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            bySid[g.Key] = DiagJson.Array(g.OrderBy(f => f.Layer, StringComparer.Ordinal).ThenByDescending(f => f.Weight, StringComparer.Ordinal), f => new JsonObject
            {
                ["id"] = f.Id,
                ["filter"] = f.Key.ToString(),
                ["name"] = f.Name,
                ["layer"] = f.Layer,
                ["action"] = f.Action,
                ["weight"] = f.Weight,
                ["effectiveWeight"] = f.EffectiveWeight,
                ["flags"] = $"0x{f.Flags:X}",
                ["conditions"] = DiagJson.Strings(f.Conditions),
            });
        }
        o["filters"] = bySid;
        o["filterCount"] = snap.Filters.Count;

        if (desired is not null)
        {
            var installed = snap.Filters.Select(f => f.Key).ToHashSet();
            var expected = desired.SelectMany(WfpManager.ExpectedKeys).ToHashSet();
            o["missingFilters"] = expected.Count(k => !installed.Contains(k));
            o["unexpectedFilters"] = installed.Count(k => !expected.Contains(k));
        }
        return o;
    }
}

/// <summary><c>proxy</c> section: listening state, live connections per SID/host, recent decisions, counters,
/// live re-evaluation and bypass resets.</summary>
public sealed class ProxyDiagnostics(FilteringProxy proxy, NetGuardService netGuard, IClock clock) : IDiagnosticsSection
{
    public string Name => "proxy";

    public JsonObject Collect()
    {
        var now = clock.UtcNow;
        var (allowed, blocked, closedLive) = proxy.Totals;
        var (reAt, reResult) = proxy.LastReevaluation;
        var tunnels = proxy.Tunnels.Snapshot();
        var perSid = new JsonObject();
        foreach (var g in tunnels.GroupBy(t => t.Sid).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            perSid[g.Key] = new JsonObject
            {
                ["count"] = g.Count(),
                ["hosts"] = DiagJson.Array(g.GroupBy(t => t.Host).OrderByDescending(h => h.Count()).Take(100), h => new JsonObject
                {
                    ["host"] = h.Key,
                    ["count"] = h.Count(),
                    ["exe"] = DiagJson.Strings(h.Select(t => t.ExeName).Distinct(StringComparer.OrdinalIgnoreCase)),
                    ["oldestSec"] = (long)(now - h.Min(t => t.StartedUtc)).TotalSeconds,
                    ["connectHost"] = h.First().ConnectHost == h.Key ? null : h.First().ConnectHost,
                }),
            };
        }
        return new JsonObject
        {
            ["listening"] = proxy.IsListening,
            ["port"] = proxy.Port,
            ["activeConnections"] = proxy.ActiveConnections,
            ["liveTunnels"] = perSid,
            ["totals"] = new JsonObject { ["allowed"] = allowed, ["blocked"] = blocked, ["closedLive"] = closedLive },
            ["lastReevaluation"] = new JsonObject { ["at"] = DiagJson.Utc(reAt), ["result"] = reResult },
            ["bypassResets"] = netGuard.Bypass.BypassResets,
            ["recentDecisions"] = DiagJson.Array(proxy.RecentDecisions(), d => new JsonObject
            {
                ["at"] = DiagJson.Utc(d.At), ["sid"] = d.Sid, ["exe"] = d.Exe, ["host"] = d.Host, ["allowed"] = d.Allowed,
                ["reason"] = d.Reason, ["category"] = d.Category, ["trigger"] = d.Trigger,
            }),
        };
    }
}

/// <summary><c>categories</c> section: per list file bytes / entries / lastModified / lastError, loaded totals.</summary>
public sealed class CategoryDiagnostics(CategoryStore store, CategoryUpdater updater, NetGuardOptions options) : IDiagnosticsSection
{
    public string Name => "categories";

    public JsonObject Collect()
    {
        var snap = store.Current;
        var states = updater.SourceStates();
        var files = new JsonArray();
        if (Directory.Exists(store.Directory))
        {
            foreach (var f in Directory.EnumerateFiles(store.Directory).Select(p => new FileInfo(p))
                         .Where(f => f.Extension is ".bin" or ".txt").OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase))
            {
                states.TryGetValue(f.Name, out var st);
                files.Add(new JsonObject
                {
                    ["file"] = f.Name,
                    ["category"] = CategoryStore.CategoryOfFile(f.Name),
                    ["bytes"] = f.Length,
                    ["entries"] = st?.Domains,
                    ["lastModified"] = DiagJson.Utc(new DateTimeOffset(f.LastWriteTimeUtc, TimeSpan.Zero)),
                    ["sourceLastModified"] = DiagJson.Utc(st?.LastModified),
                    ["updated"] = DiagJson.Utc(st?.UpdatedUtc),
                });
            }
        }
        var errors = new JsonObject();
        foreach (var (k, v) in updater.LastErrors) errors[k] = v;
        return new JsonObject
        {
            ["directory"] = store.Directory,
            ["directoryExists"] = Directory.Exists(store.Directory),
            ["downloadEnabled"] = options.CategoryDownloadEnabled,
            ["loadedHashedDomains"] = snap.HashedDomainCount,
            ["loadedTextDomains"] = snap.TextDomainCount,
            ["lastPass"] = DiagJson.Utc(updater.LastPassUtc),
            ["files"] = files,
            ["lastErrors"] = errors,
        };
    }
}
