using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;
using MinControl.Core.Protocol;
using Xunit;

namespace MinControl.Core.Tests;

public class ProtocolContractTests
{
    private static readonly string ProtocolDir = FindProtocolDir();
    private static readonly SchemaRegistry Registry = BuildRegistry();

    private static string FindProtocolDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var p = Path.Combine(dir.FullName, "protocol");
            if (Directory.Exists(p) && Directory.GetFiles(p, "*.schema.json").Length > 0) return p;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("protocol/ folder not found above " + AppContext.BaseDirectory);
    }

    private static SchemaRegistry BuildRegistry()
    {
        var reg = new SchemaRegistry();
        var build = new BuildOptions { SchemaRegistry = reg };
        foreach (var f in Directory.GetFiles(ProtocolDir, "*.schema.json"))
            JsonSchema.FromText(File.ReadAllText(f), build);   // registers by $id
        return reg;
    }

    private static JsonSchema Load(string stem) =>
        (JsonSchema)Registry.Get(new Uri($"https://mincontrol.local/protocol/{stem}.schema.json"))!;

    private static bool IsValid(string stem, JsonNode? doc) =>
        Load(stem).Evaluate(JsonSerializer.SerializeToElement(doc)).IsValid;

    public static IEnumerable<object[]> Fixtures(string kind)
    {
        var root = Path.Combine(FindProtocolDir(), "fixtures");
        foreach (var stemDir in Directory.GetDirectories(root).OrderBy(x => x, StringComparer.Ordinal))
        {
            var d = Path.Combine(stemDir, kind);
            if (!Directory.Exists(d)) continue;
            foreach (var f in Directory.GetFiles(d, "*.json").OrderBy(x => x, StringComparer.Ordinal))
                yield return new object[] { Path.GetFileName(stemDir), Path.GetFileName(f) };
        }
    }

    public static IEnumerable<object[]> Valid() => Fixtures("valid");
    public static IEnumerable<object[]> Invalid() => Fixtures("invalid");
    public static IEnumerable<object[]> SemanticInvalid() => Fixtures("semantic-invalid");
    public static IEnumerable<object[]> CommandFixtures() =>
        Fixtures("valid").Where(x => (string)x[0] == "command");

    private static string ReadText(string stem, string kind, string file) =>
        File.ReadAllText(Path.Combine(ProtocolDir, "fixtures", stem, kind, file));

    [Theory, MemberData(nameof(Valid))]
    public void Valid_fixture_passes(string stem, string file) =>
        Assert.True(IsValid(stem, JsonNode.Parse(ReadText(stem, "valid", file))), $"{stem}/valid/{file} should be valid");

    [Theory, MemberData(nameof(Invalid))]
    public void Invalid_fixture_fails(string stem, string file) =>
        Assert.False(IsValid(stem, JsonNode.Parse(ReadText(stem, "invalid", file))), $"{stem}/invalid/{file} should be invalid");

    [Theory, MemberData(nameof(SemanticInvalid))]
    public void Semantic_invalid_fixture_is_schema_valid(string stem, string file) =>
        Assert.True(IsValid(stem, JsonNode.Parse(ReadText(stem, "semantic-invalid", file))), $"{stem}/semantic-invalid/{file} should pass the schema");

    [Fact(Skip = "M2: semantic policy validator")]
    public void Semantic_invalid_fixtures_rejected_by_policy_validator() { }

    [Theory, MemberData(nameof(CommandFixtures))]
    public void Command_roundtrips(string stem, string file)
    {
        var cmd = JsonSerializer.Deserialize<Command>(ReadText(stem, "valid", file), ProtocolJson.Options);
        Assert.NotNull(cmd);
        var json = JsonSerializer.Serialize(cmd, ProtocolJson.Options);
        Assert.True(IsValid("command", JsonNode.Parse(json)), $"re-serialised {file} invalid: {json}");
    }
}
