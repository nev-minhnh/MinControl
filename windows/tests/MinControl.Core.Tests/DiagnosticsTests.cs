using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using MinControl.Core.Commands;
using MinControl.Core.Diagnostics;
using MinControl.Core.Events;
using MinControl.Core.Policies;
using MinControl.Core.Telemetry;
using MinControl.Core.Util;
using Xunit;

namespace MinControl.Core.Tests;

public class DiagnosticsTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 5, 0, 0, TimeSpan.Zero);
    private const string FakeJwt = "eyJhbGciOiJFZERTQSJ9.eyJkZXZpY2VJZCI6IjAxSkRRM1o4SzRNMk42UDhSMFMyVDRWNlc4In0.Q2xhdWRlU2lnbmF0dXJlVmFsdWVYeXo";
    private const string FakeKeyB64 = "MC4CAQAwBQYDK2VwBCIEIHq7cP9xKZ2mVb3hT0sLrWqY8eNfGd1aUjXo5ScRkMpQ";

    private sealed class Section(string name, Func<JsonObject> collect) : IDiagnosticsSection
    {
        public string Name => name;
        public JsonObject Collect() => collect();
    }

    private sealed class Sink : MinControl.Core.Abstractions.IEventSink
    {
        public List<(string Type, string? Sid, JsonObject Data)> Events { get; } = [];
        public void Emit(string type, string? userSid, JsonObject data) => Events.Add((type, userSid, data));
    }

    private static void AssertEventSchemaValid(string type, JsonObject data)
    {
        var ev = new JsonObject
        {
            ["id"] = "01JDQ3Z8K4M2N6P8R0S2T4V6W8",
            ["deviceId"] = TestData.DeviceId,
            ["ts"] = Time.Utc(T0),
            ["monoMs"] = 1,
            ["type"] = type,
            ["data"] = data.DeepClone(),
        };
        Assert.True(SchemaValidator.Shared.IsValid("event", JsonSerializer.SerializeToElement(ev)), ev.ToJsonString()[..Math.Min(2000, ev.ToJsonString().Length)]);
    }

    [Fact]
    public async Task Report_contains_sections_and_logs_without_secrets_and_is_schema_valid()
    {
        var ring = new LogRing();
        var provider = new RingBufferLoggerProvider(ring, () => T0);
        var proxyLog = provider.CreateLogger("MinControl.NetGuard.Proxy.FilteringProxy");
        proxyLog.LogInformation("Proxy last minute: {Allowed} allowed, {Blocked} blocked", 10, 3);
        proxyLog.LogWarning(new InvalidOperationException($"upload failed with Bearer {FakeJwt}"), "upload token={Token}", FakeJwt);
        provider.CreateLogger("Microsoft.Hosting.Lifetime").LogInformation("Application started");   // not ours: not kept
        provider.CreateLogger("System.Net.Http").LogError("key: {K}", FakeKeyB64);

        var sink = new Sink();
        var collector = new DiagnosticsCollector(() =>
        [
            new Section("wfp", () => new JsonObject
            {
                ["providerPresent"] = true,
                ["filters"] = new JsonArray(new JsonObject { ["layer"] = "connect-v4", ["action"] = "block", ["filter"] = Guid.NewGuid().ToString() }),
                ["sha256"] = new string('a', 64),
            }),
            new Section("service", () => new JsonObject
            {
                ["version"] = "0.1.9",
                ["uploadToken"] = FakeJwt,                // dropped by name
                ["privateKey"] = FakeKeyB64,              // dropped by name
                ["note"] = $"authorization: Bearer {FakeJwt}",
                ["blob"] = FakeKeyB64,                    // masked by value
            }),
            new Section("broken", () => throw new IOException("disk on fire")),
        ], ring, sink, new FakeClock(T0));

        var data = await collector.ReportAsync("01JDQ3Z8K4M2N6P8R0S2T4V6W9", CancellationToken.None);

        var e = Assert.Single(sink.Events);
        Assert.Equal(EventTypes.DiagReport, e.Type);
        Assert.Null(e.Sid);
        Assert.Equal("01JDQ3Z8K4M2N6P8R0S2T4V6W9", (string?)e.Data["commandId"]);
        AssertEventSchemaValid(e.Type, e.Data);

        var json = data.ToJsonString();
        Assert.DoesNotContain(FakeJwt, json);
        Assert.DoesNotContain(FakeKeyB64, json);
        Assert.DoesNotContain("eyJ", json);
        Assert.DoesNotContain("uploadToken", json);
        Assert.DoesNotContain("privateKey", json);
        Assert.Contains(new string('a', 64), json);                 // hex digests survive
        Assert.Equal("0.1.9", (string?)data["sections"]!["service"]!["version"]);
        Assert.Contains("disk on fire", (string?)data["sections"]!["broken"]!["error"]);

        var logs = data["sections"]!["logs"]!;
        var decisions = logs["decisions"]!.AsArray();
        Assert.Single(decisions);
        Assert.Equal("NetGuard.Proxy.FilteringProxy", (string?)decisions[0]!["category"]);
        Assert.Contains("10 allowed", (string?)decisions[0]!["message"]);
        var problems = logs["problems"]!.AsArray();
        Assert.Equal(2, problems.Count);
        Assert.Contains(problems, p => ((string?)p!["message"])!.Contains("InvalidOperationException"));
    }

    [Fact]
    public async Task Report_is_capped_at_256_kb()
    {
        var big = new JsonArray(Enumerable.Range(0, 20_000).Select(i => (JsonNode?)new JsonObject
        {
            ["host"] = $"host-{i}.example-domain-for-size.com", ["exe"] = "msedge.exe", ["allowed"] = i % 2 == 0,
        }).ToArray());
        var ring = new LogRing();
        for (var i = 0; i < 500; i++)
            ring.Add(new LogLine(T0, LogLevel.Error, "X", new string('x', 900) + i));
        var collector = new DiagnosticsCollector(() =>
        [
            new Section("proxy", () => new JsonObject { ["recentDecisions"] = big.DeepClone(), ["listening"] = true }),
            new Section("monster", () => new JsonObject { ["blob"] = new string('y', 400_000).Replace("yy", "y ") }),
        ], ring, new Sink(), new FakeClock(T0));

        var data = await collector.BuildAsync("01JDQ3Z8K4M2N6P8R0S2T4V6W9", CancellationToken.None);
        var size = Encoding.UTF8.GetByteCount(data.ToJsonString());
        Assert.True(size <= DiagnosticsCollector.MaxBytes, $"size {size}");
        Assert.True((bool)data["sections"]!["proxy"]!["listening"]!);
        Assert.True((bool)data["sections"]!["proxy"]!["truncated"]!);
        Assert.True(data["sections"]!["proxy"]!["recentDecisions"]!.AsArray().Count > 0);
        Assert.True((bool)data["sections"]!["monster"]!["truncated"]!);
        Assert.Equal(LogRing.Capacity, ring.Problems().Count);
        AssertEventSchemaValid(EventTypes.DiagReport, data);
    }

    [Theory]
    [InlineData("Authorization: Bearer abc.def.ghi", "abc.def.ghi")]
    [InlineData("token=s3cr3t-value&x=1", "s3cr3t-value")]
    [InlineData("\"secret\": \"hunter2\"", "hunter2")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nMIIEv\n-----END PRIVATE KEY-----", "MIIEv")]
    public void Scrubber_masks_inline_secrets(string text, string secret)
    {
        var s = SecretScrubber.Scrub(text);
        Assert.DoesNotContain(secret, s);
        Assert.Contains(SecretScrubber.Redacted, s);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Microsoft\EdgeWebView\Application\131.0.2903.70\msedgewebview2.exe")]
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-1001")]
    [InlineData("O:SYG:SYD:(A;;CC;;;S-1-5-21-1-2-3-1001)(A;;CC;;;AC)")]
    [InlineData("ALE_USER_ID == O:SY")]
    [InlineData("rr3---sn-8qj-nbo6.googlevideo.com")]
    public void Scrubber_keeps_diagnostic_text(string text) => Assert.Equal(text, SecretScrubber.Scrub(text));

    [Fact]
    public async Task Diagnose_command_emits_report_and_acks_applied()
    {
        using var h = new CoreHarness(T0);
        h.ApplyPolicy(TestData.BasicPolicy());
        var ring = new LogRing();
        var collector = new DiagnosticsCollector(() => [new PolicyDiagnostics(h.Policy, h.Store)], ring, h.Events, h.Clock);
        // without a collector the command fails cleanly
        var ack0 = await h.CommandAsync(new JsonObject { ["type"] = "diagnose" });
        Assert.Equal("failed", ack0.Status);

        var refreshed = 0;
        var dispatcher = new CommandDispatcher(h.Store, h.Policy, h.Clock, new ApprovalStore(h.Store, h.Clock), diagnostics: () => collector);
        dispatcher.RefreshRequested += () => refreshed++;

        var body = new JsonObject { ["type"] = "diagnose", ["commandId"] = UlidGenerator.Shared.New(h.Clock.UtcNow) };
        var env = TestData.Parse(TestData.Envelope(h.Master, "command", 1000, body, h.Clock.UtcNow));
        var v = h.Verifier.Verify(env);
        Assert.True(v.Ok, v.Error);
        var ack = await dispatcher.DispatchAsync(v.Envelope!, CancellationToken.None);

        Assert.Equal("applied", ack.Status);
        Assert.Equal(1, refreshed);
        var item = Assert.Single(h.Store.PeekOutbox(100), o => o.Type == EventTypes.DiagReport);
        var ev = JsonNode.Parse(item.Json)!.AsObject();
        Assert.True(SchemaValidator.Shared.IsValid("event", JsonSerializer.SerializeToElement(ev)), item.Json);
        Assert.Equal((string?)body["commandId"], (string?)ev["data"]!["commandId"]);
        var policy = ev["data"]!["sections"]!["policy"]!;
        Assert.True((bool)policy["present"]!);
        Assert.True((bool)policy["storedOk"]!);
        Assert.NotNull(policy["users"]![TestData.Sid]);
    }
}
