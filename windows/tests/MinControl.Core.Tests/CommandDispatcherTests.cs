using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Core.Cloud;
using MinControl.Core.Crypto;
using MinControl.Core.Policies;
using MinControl.Core.Protocol;
using MinControl.Core.Util;
using Xunit;

namespace MinControl.Core.Tests;

public class CommandDispatcherTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 23, 9, 0, 0, TimeSpan.Zero);
    private readonly CoreHarness _h = new(Now);

    public CommandDispatcherTests()
    {
        var p = TestData.BasicPolicy();
        // an administrator listed in the policy must still never be managed (I2)
        p["users"]![TestData.AdminSid] = TestData.User(p).DeepClone();
        _h.Users.Admins.Add(TestData.AdminSid);
        _h.ApplyPolicy(p);
    }

    public void Dispose() => _h.Dispose();

    private static JsonObject Body(string type, string? sid = TestData.Sid)
    {
        var b = new JsonObject { ["type"] = type };
        if (sid is not null) b["userSid"] = sid;
        return b;
    }

    private static void AssertSchemaValid(CommandAck ack) =>
        Assert.True(SchemaValidator.Shared.IsValid("command-ack", JsonSerializer.SerializeToElement(ack, ProtocolJson.Options)),
            JsonSerializer.Serialize(ack, ProtocolJson.Options));

    [Fact]
    public async Task Unknown_sid_is_rejected_unmanaged_user()
    {
        var ack = await _h.CommandAsync(Body("logoff", "S-1-5-21-9-9-9-1001"));
        Assert.Equal("rejected", ack.Status);
        Assert.Equal(VerifyErrors.UnmanagedUser, ack.Error);
        Assert.Empty(_h.Session.Calls);
        AssertSchemaValid(ack);
    }

    [Fact]
    public async Task Admin_sid_is_rejected_unmanaged_user()
    {
        var ack = await _h.CommandAsync(Body("lock_now", TestData.AdminSid));
        Assert.Equal(VerifyErrors.UnmanagedUser, ack.Error);
        Assert.Empty(_h.Store.GetOverrides(TestData.AdminSid));
    }

    [Fact]
    public async Task Add_time_for_unknown_group_is_not_found()
    {
        var b = Body("add_time"); b["minutes"] = 10; b["group"] = "social";
        var ack = await _h.CommandAsync(b);
        Assert.Equal("rejected", ack.Status);
        Assert.Equal(VerifyErrors.NotFound, ack.Error);
        AssertSchemaValid(ack);
    }

    [Fact]
    public async Task Lock_until_in_the_past_is_invalid_body()
    {
        var b = Body("lock_now"); b["until"] = Time.Utc(Now.AddMinutes(-1));
        Assert.Equal(VerifyErrors.InvalidBody, (await _h.CommandAsync(b)).Error);
    }

    [Fact]
    public async Task Approve_exe_records_decision()
    {
        var sha = new string('b', 64);
        var b = Body("approve_exe"); b["sha256"] = sha; b["decision"] = "allow";
        var ack = await _h.CommandAsync(b);
        Assert.Equal("applied", ack.Status);
        AssertSchemaValid(ack);
        Assert.Equal("allow", new MinControl.Core.Telemetry.ApprovalStore(_h.Store, _h.Clock).DecisionFor(TestData.Sid, sha));
    }

    [Fact]
    public async Task Message_and_logoff_reach_session_actions()
    {
        var m = Body("message"); m["text"] = "Đi ngủ thôi";
        Assert.Equal("applied", (await _h.CommandAsync(m)).Status);
        Assert.Equal("applied", (await _h.CommandAsync(Body("logoff"))).Status);
        Assert.Equal([$"message {TestData.Sid} Đi ngủ thôi", $"logoff {TestData.Sid}"], _h.Session.Calls);
    }

    [Fact]
    public async Task Kill_of_missing_process_fails_not_found()
    {
        _h.Session.KillResult = false;
        var b = Body("kill_process"); b["pid"] = 4242;
        var ack = await _h.CommandAsync(b);
        Assert.Equal("failed", ack.Status);
        Assert.Equal(VerifyErrors.NotFound, ack.Error);
        AssertSchemaValid(ack);
    }

    [Fact]
    public async Task Screenshot_without_pipeline_fails()
    {
        var ack = await _h.CommandAsync(Body("screenshot"));
        Assert.Equal("failed", ack.Status);
        AssertSchemaValid(ack);
    }

    [Fact]
    public async Task Refresh_raises_event()
    {
        var raised = false;
        _h.Commands.RefreshRequested += () => raised = true;
        Assert.Equal("applied", (await _h.CommandAsync(Body("refresh", null))).Status);
        Assert.True(raised);
    }

    [Fact]
    public async Task Redelivered_applied_command_is_acked_applied_again()
    {
        var handler = new EnvelopeHandler(_h.Verifier, _h.Policy, _h.Commands, _h.Store);
        var body = Body("unlock"); body["commandId"] = UlidGenerator.Shared.New(Now);
        var env = TestData.Parse(TestData.Envelope(_h.Master, "command", 100, body, Now));
        var first = await handler.HandleAsync(env, CancellationToken.None);
        Assert.Equal("applied", (string?)first!["ack"]!["status"]);
        var again = await handler.HandleAsync(env, CancellationToken.None);
        Assert.Equal("applied", (string?)again!["ack"]!["status"]);

        var other = Body("unlock"); other["commandId"] = UlidGenerator.Shared.New(Now);
        var old = await handler.HandleAsync(TestData.Parse(TestData.Envelope(_h.Master, "command", 50, other, Now)), CancellationToken.None);
        Assert.Equal("rejected", (string?)old!["ack"]!["status"]);
        Assert.Equal(VerifyErrors.Replayed, (string?)old["ack"]!["error"]);
    }

    [Fact]
    public async Task Policy_envelope_yields_policy_applied_or_rejected()
    {
        var handler = new EnvelopeHandler(_h.Verifier, _h.Policy, _h.Commands, _h.Store);
        var p = TestData.BasicPolicy(); p["version"] = 8;
        var ok = await handler.HandleAsync(TestData.Parse(TestData.Envelope(_h.Master, "policy", 50, p, Now)), CancellationToken.None);
        Assert.Equal("policy_applied", (string?)ok!["t"]);
        Assert.Equal(8, (int)ok["version"]!);

        var bad = JsonNode.Parse(TestData.Fixture("policy", "semantic-invalid", "overlapping-windows.json"))!;
        var rej = await handler.HandleAsync(TestData.Parse(TestData.Envelope(_h.Master, "policy", 51, bad, Now)), CancellationToken.None);
        Assert.Equal("policy_rejected", (string?)rej!["t"]);
        Assert.Equal(8, _h.Policy.Current!.Version);
    }
}
