using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;
using MinControl.Core.Util;
using MinControl.Monitoring.Inventory;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>
/// Cross-stream contract: the inventory document the Windows agent builds must validate against
/// protocol/inventory.schema.json (the cloud rejects anything else). Added at integration because the
/// Windows and cloud streams were built in parallel.
/// </summary>
public class InventorySchemaContractTests
{
    private static JsonSchema Schema()
    {
        var reg = new SchemaRegistry();
        var build = new BuildOptions { SchemaRegistry = reg };
        foreach (var f in Directory.GetFiles(TestData.ProtocolDir, "*.schema.json"))
            JsonSchema.FromText(File.ReadAllText(f), build);
        return (JsonSchema)reg.Get(new Uri("https://mincontrol.local/protocol/inventory.schema.json"))!;
    }

    private static string Id(string s) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    [Fact]
    public void AgentInventoryDocumentMatchesProtocolSchema()
    {
        var apps = new[]
        {
            new AppEntry(Id("win32|steam"), "Steam", "win32", "Valve Corporation", "2.10", @"C:\Program Files (x86)\Steam",
                "steam.exe", @"C:\Program Files (x86)\Steam\steam.exe", DateTimeOffset.Parse("2026-11-22T10:00:00Z"), 95, "game"),
            new AppEntry(Id("appx|zalo"), "Zalo", "appx", null, null, @"C:\Program Files\WindowsApps\Zalo", null, null, null, null, "social"),
            new AppEntry(Id("seen|c:\\games\\x.exe"), "x.exe", "seen", null, null, null, "x.exe", @"C:\Games\x.exe",
                DateTimeOffset.Parse("2026-11-22T09:00:00Z"), 12, "other"),
        };
        var doc = new JsonObject
        {
            ["deviceId"] = "01JDQ3Z8K4M2N6P8R0S2T4V6W8",
            ["generatedAt"] = Time.Utc(DateTimeOffset.Parse("2026-11-22T10:05:00Z")),
            ["users"] = new JsonObject
            {
                ["S-1-5-21-1111111111-2222222222-3333333333-1001"] = new JsonObject
                {
                    ["apps"] = new JsonArray(apps.Select(InventoryService.ToJson).ToArray<JsonNode?>()),
                },
            },
        };
        var result = Schema().Evaluate(JsonSerializer.SerializeToElement(doc), new EvaluationOptions { OutputFormat = OutputFormat.List });
        Assert.True(result.IsValid, string.Join("; ", (result.Details ?? []).Where(d => d.Errors is not null)
            .SelectMany(d => d.Errors!.Select(e => $"{d.InstanceLocation}: {e.Value}"))));
    }
}
