using System.Text.Json.Nodes;
using MinControl.Core.Policies;
using Xunit;

namespace MinControl.Core.Tests;

public class PolicyValidationTests
{
    public static IEnumerable<object[]> Files(string kind) =>
        Directory.GetFiles(Path.Combine(TestData.ProtocolDir, "fixtures", "policy", kind), "*.json")
            .OrderBy(f => f, StringComparer.Ordinal).Select(f => new object[] { Path.GetFileName(f) });

    public static IEnumerable<object[]> SemanticInvalid() => Files("semantic-invalid");
    public static IEnumerable<object[]> SchemaInvalid() => Files("invalid");
    public static IEnumerable<object[]> Valid() => Files("valid");

    [Theory, MemberData(nameof(SemanticInvalid))]
    public void Semantic_invalid_fixture_is_rejected(string file)
    {
        var r = PolicyParser.Parse(TestData.Fixture("policy", "semantic-invalid", file));
        Assert.False(r.Ok, $"{file} must be rejected");
        Assert.Equal("invalid_body", r.Error);
    }

    [Theory, MemberData(nameof(SchemaInvalid))]
    public void Schema_invalid_fixture_is_rejected(string file) =>
        Assert.False(PolicyParser.Parse(TestData.Fixture("policy", "invalid", file)).Ok, $"{file} must be rejected");

    [Theory, MemberData(nameof(Valid))]
    public void Valid_fixture_is_accepted(string file)
    {
        var r = PolicyParser.Parse(TestData.Fixture("policy", "valid", file));
        Assert.True(r.Ok, $"{file}: {r.Detail}");
    }

    [Fact]
    public void Basic_fixture_maps_to_typed_policy()
    {
        var p = PolicyParser.Parse(TestData.Fixture("policy", "valid", "basic.json")).Policy!;
        var u = p.Users[TestData.Sid];
        Assert.Equal("Asia/Ho_Chi_Minh", p.Timezone);
        Assert.Equal(120, u.ScreenTime.DailyQuotaMin.Mon);
        Assert.Equal(["15:00-21:00"], u.ScreenTime.AllowedWindows.Fri);
        Assert.Equal(60, u.AppGroups["games"].DailyQuotaMin!.Mon);
        Assert.NotNull(u.Web.CategorySchedules);
    }

    private static PolicyParseResult ParseMutated(Action<JsonObject> mutate)
    {
        var p = TestData.BasicPolicy();
        mutate(TestData.User(p));
        return PolicyParser.Parse(p.ToJsonString());
    }

    [Fact]
    public void Warning_at_or_above_quota_is_rejected() =>
        Assert.False(ParseMutated(u => u["screenTime"]!["dailyQuotaMin"]!["mon"] = 5).Ok);

    [Fact]
    public void Day_without_quota_ignores_warnings() =>
        Assert.True(ParseMutated(u => u["screenTime"]!["dailyQuotaMin"]!["mon"] = 0).Ok);

    [Fact]
    public void Adjacent_windows_are_allowed() =>
        Assert.True(ParseMutated(u => u["screenTime"]!["allowedWindows"]!["mon"] = new JsonArray("15:00-17:00", "17:00-18:00")).Ok);

    [Fact]
    public void Window_ending_at_24_is_allowed() =>
        Assert.True(ParseMutated(u => u["screenTime"]!["allowedWindows"]!["mon"] = new JsonArray("20:00-24:00")).Ok);

    [Fact]
    public void Overlapping_category_schedule_is_rejected() =>
        Assert.False(ParseMutated(u => u["web"]!["categorySchedules"]!["games"]!["mon"] = new JsonArray("15:00-17:00", "16:00-18:00")).Ok);

    [Fact]
    public void Domain_both_blocked_and_allowed_is_rejected() =>
        Assert.False(ParseMutated(u => u["web"]!["allowDomains"] = new JsonArray("*.example-bad.com")).Ok);

    [Fact]
    public void Unknown_property_is_rejected() =>
        Assert.False(ParseMutated(u => u["screenTime"]!["bonus"] = 5).Ok);
}
