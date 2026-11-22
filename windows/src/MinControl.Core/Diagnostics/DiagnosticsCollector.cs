using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Util;

namespace MinControl.Core.Diagnostics;

/// <summary>One section of <c>diag.report</c> (API.md §14). Implemented by each component from its real state.
/// Must never return keys or tokens (the collector scrubs again anyway).</summary>
public interface IDiagnosticsSection
{
    /// <summary>Section name: service | users | policy | wfp | proxy | browser | categories | monitor (logs is built in).</summary>
    string Name { get; }
    JsonObject Collect();
}

/// <summary>
/// Builds and emits the <c>diag.report</c> event for a <c>diagnose</c> command: every registered
/// <see cref="IDiagnosticsSection"/> (each isolated: a throwing or slow section becomes <c>{"error": …}</c>) plus the
/// <c>logs</c> section from <see cref="LogRing"/>; scrubbed by <see cref="SecretScrubber"/> and capped at
/// <see cref="MaxBytes"/> by halving the largest arrays.
/// </summary>
public sealed class DiagnosticsCollector
{
    public const int MaxBytes = 256 * 1024;
    /// <summary>Head-room for the event envelope (id, deviceId, ts, type…) around <c>data</c>.</summary>
    private const int EnvelopeReserve = 2 * 1024;
    private const int MaxSections = 40;
    private static readonly TimeSpan SectionTimeout = TimeSpan.FromSeconds(15);

    private readonly Func<IEnumerable<IDiagnosticsSection>> _sections;
    private readonly LogRing _logs;
    private readonly IEventSink _sink;
    private readonly IClock _clock;
    private readonly ILogger _log;

    public DiagnosticsCollector(Func<IEnumerable<IDiagnosticsSection>> sections, LogRing logs, IEventSink sink, IClock clock,
        ILogger<DiagnosticsCollector>? log = null)
    {
        _sections = sections;
        _logs = logs;
        _sink = sink;
        _clock = clock;
        _log = (ILogger?)log ?? NullLogger.Instance;
    }

    /// <summary>Collects and emits <c>diag.report</c>. Returns the emitted data.</summary>
    public async Task<JsonObject> ReportAsync(string commandId, CancellationToken ct)
    {
        var data = await BuildAsync(commandId, ct).ConfigureAwait(false);
        _sink.Emit(EventTypes.DiagReport, null, data);
        _log.LogInformation("diag.report {CommandId} emitted: {Bytes} bytes, {Sections} sections",
            commandId, Size(data), ((JsonObject)data["sections"]!).Count);
        return data;
    }

    public async Task<JsonObject> BuildAsync(string commandId, CancellationToken ct)
    {
        var sections = new JsonObject();
        foreach (var s in _sections().Take(MaxSections - 1))
        {
            if (sections.ContainsKey(s.Name)) continue;
            sections[s.Name] = await CollectOneAsync(s, ct).ConfigureAwait(false);
        }
        sections["logs"] = LogsSection();
        var scrubbed = (JsonObject)SecretScrubber.Scrub(sections)!;
        var data = new JsonObject { ["commandId"] = commandId, ["sections"] = scrubbed };
        Cap(data, MaxBytes - EnvelopeReserve);
        return data;
    }

    private async Task<JsonNode> CollectOneAsync(IDiagnosticsSection s, CancellationToken ct)
    {
        try
        {
            var task = Task.Run(s.Collect, ct);
            var done = await Task.WhenAny(task, Task.Delay(SectionTimeout, ct)).ConfigureAwait(false);
            if (done != task) return new JsonObject { ["error"] = "timeout" };
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "diagnostics section {Section} failed", s.Name);
            return new JsonObject { ["error"] = $"{ex.GetType().Name}: {ex.Message}" };
        }
    }

    private JsonObject LogsSection()
    {
        static JsonArray Lines(IEnumerable<LogLine> lines) => new(lines.Select(l => (JsonNode)new JsonObject
        {
            ["at"] = Time.Utc(l.At),
            ["level"] = l.Level.ToString(),
            ["category"] = l.Category,
            ["message"] = l.Message,
        }).ToArray());
        return new JsonObject
        {
            ["generatedAt"] = Time.Utc(_clock.UtcNow),
            ["problems"] = Lines(_logs.Problems()),
            ["decisions"] = Lines(_logs.Decisions()),
        };
    }

    public static int Size(JsonNode node) => Encoding.UTF8.GetByteCount(node.ToJsonString());

    /// <summary>Shrinks <paramref name="data"/> in place until it serialises to ≤ <paramref name="max"/> bytes:
    /// repeatedly halves the largest array (keeping its first half: sections list the most relevant items first),
    /// then replaces whole sections when no array is left to shrink.</summary>
    public static void Cap(JsonObject data, int max)
    {
        var sections = (JsonObject)data["sections"]!;
        for (var guard = 0; guard < 10_000 && Size(data) > max; guard++)
        {
            // A section that cannot fit on its own is dropped first, before other sections lose their arrays.
            var (bigName, bigSize) = sections.Select(kv => (kv.Key, Size: kv.Value is null ? 0 : Size(kv.Value)))
                .OrderByDescending(x => x.Size).First();
            if (bigSize > max / 2 && !Arrays(sections[bigName]).Any(a => a.Count > 1))
            {
                sections[bigName] = new JsonObject { ["truncated"] = true, ["error"] = "section too large" };
                continue;
            }
            var (array, section) = LargestArray(sections);
            if (array is not null && array.Count > 1)
            {
                var keep = array.Count / 2;
                while (array.Count > keep) array.RemoveAt(array.Count - 1);
                if (sections[section!] is JsonObject so) so["truncated"] = true;
                continue;
            }
            // No shrinkable array: drop the biggest section's content.
            var biggest = sections.OrderByDescending(kv => kv.Value is null ? 0 : Size(kv.Value)).First().Key;
            sections[biggest] = new JsonObject { ["truncated"] = true, ["error"] = "section too large" };
        }
    }

    private static (JsonArray? Array, string? Section) LargestArray(JsonObject sections)
    {
        JsonArray? best = null;
        string? bestSection = null;
        var bestSize = -1;
        foreach (var (name, node) in sections)
        {
            foreach (var a in Arrays(node))
            {
                if (a.Count <= 1) continue;
                var size = Size(a);
                if (size > bestSize) { best = a; bestSection = name; bestSize = size; }
            }
        }
        return (best, bestSection);
    }

    private static IEnumerable<JsonArray> Arrays(JsonNode? node)
    {
        switch (node)
        {
            case JsonArray a:
                yield return a;
                foreach (var c in a) foreach (var x in Arrays(c)) yield return x;
                break;
            case JsonObject o:
                foreach (var (_, c) in o) foreach (var x in Arrays(c)) yield return x;
                break;
        }
    }
}

/// <summary>Small helpers for section builders.</summary>
public static class DiagJson
{
    public static string? Utc(DateTimeOffset? t) => t is null ? null : Time.Utc(t.Value);

    public static JsonArray Array<T>(IEnumerable<T> items, Func<T, JsonNode?> map) => new(items.Select(map).ToArray());

    public static JsonArray Strings(IEnumerable<string> items) => new(items.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());

    public static string Invariant(FormattableString s) => s.ToString(CultureInfo.InvariantCulture);

    public static JsonNode? FromObject<T>(T value) => JsonSerializer.SerializeToNode(value, Protocol.ProtocolJson.Options);
}
