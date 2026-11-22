using System.Text.Json;
using Json.Schema;

namespace MinControl.Core.Policies;

/// <summary>Validates JSON against the protocol schemas (embedded copies of protocol/*.schema.json).</summary>
public sealed class SchemaValidator
{
    private readonly SchemaRegistry _registry = new();
    private readonly object _gate = new();

    public static SchemaValidator Shared => SharedLazy.Value;
    private static readonly Lazy<SchemaValidator> SharedLazy = new(() => new SchemaValidator());

    public SchemaValidator()
    {
        var asm = typeof(SchemaValidator).Assembly;
        var build = new BuildOptions { SchemaRegistry = _registry };
        // common first so $refs resolve regardless of registration order
        var names = asm.GetManifestResourceNames().Where(n => n.StartsWith("MinControl.Schemas.", StringComparison.Ordinal))
            .OrderBy(n => n.Contains("common", StringComparison.Ordinal) ? 0 : 1).ThenBy(n => n, StringComparer.Ordinal).ToList();
        if (names.Count == 0) throw new InvalidOperationException("protocol schemas are not embedded in MinControl.Core");
        foreach (var n in names)
        {
            using var s = asm.GetManifestResourceStream(n)!;
            using var r = new StreamReader(s);
            JsonSchema.FromText(r.ReadToEnd(), build);
        }
    }

    /// <param name="stem">schema file stem, e.g. <c>policy</c>, <c>command</c>, <c>signed-body</c>.</param>
    public bool IsValid(string stem, JsonElement doc)
    {
        lock (_gate)
        {
            var schema = (JsonSchema?)_registry.Get(new Uri($"https://mincontrol.local/protocol/{stem}.schema.json"))
                ?? throw new ArgumentException($"unknown schema '{stem}'");
            return schema.Evaluate(doc).IsValid;
        }
    }
}
