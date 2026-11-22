using System.Text.Json.Nodes;
using MinControl.Core.Cloud;
using MinControl.Core.Crypto;
using MinControl.Core.Storage;
using MinControl.Core.Util;
using Xunit;

namespace MinControl.Core.Tests;

public class MasterKeysRotationTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 23, 8, 0, 0, TimeSpan.Zero);
    private readonly CoreHarness _h = new(Now);
    private readonly EnvelopeHandler _handler;
    private readonly MasterKey _new = MasterKey.Ed25519();

    public MasterKeysRotationTests() { _handler = new EnvelopeHandler(_h.Verifier, _h.Policy, _h.Commands, _h.Store); }
    public void Dispose() { _h.Dispose(); _new.Dispose(); }

    private static string SealKey(byte fill) => Base64Url.Encode(Enumerable.Repeat(fill, 32).ToArray());

    private static JsonObject Body(MasterKey k, byte seal = 7) => new()
    {
        ["keys"] = new JsonArray(new JsonObject
        {
            ["keyId"] = k.KeyId, ["alg"] = k.Alg, ["publicKey"] = Base64Url.Encode(k.PublicKey), ["role"] = "sign",
        }),
        ["sealPubKey"] = SealKey(seal),
    };

    private Task<JsonObject?> Send(MasterKey signer, long seq, JsonObject body, string kind = "master_keys") =>
        _handler.HandleAsync(TestData.Parse(TestData.Envelope(signer, kind, seq, body, Now)), CancellationToken.None);

    private string[] Pinned() => _h.Store.GetMasterKeys().Select(k => k.KeyId).ToArray();

    [Fact]
    public async Task Happy_path_replaces_keys_and_seal()
    {
        var r = await Send(_h.Master, 1, Body(_new, 9));
        Assert.Equal("master_keys_applied", (string?)r!["t"]);
        Assert.Equal(1, (long)r["seq"]!);
        Assert.Equal([_new.KeyId], Pinned());
        Assert.Equal(SealKey(9), _h.Store.GetMeta(StateStore.MetaKeys.MasterSealPubKey));
    }

    [Fact]
    public async Task Wrong_signer_is_rejected_and_nothing_changes()
    {
        using var rogue = MasterKey.Ed25519();
        var r = await Send(rogue, 1, Body(rogue));
        Assert.Equal("master_keys_rejected", (string?)r!["t"]);
        Assert.Equal(VerifyErrors.UnknownKey, (string?)r["error"]);
        Assert.Equal([_h.Master.KeyId], Pinned());
        Assert.Null(_h.Store.GetMeta(StateStore.MetaKeys.MasterSealPubKey));
    }

    [Fact]
    public async Task Replay_is_rejected()
    {
        Assert.Equal("master_keys_applied", (string?)(await Send(_h.Master, 5, Body(_new)))!["t"]);
        var r = await Send(_new, 5, Body(_h.Master));
        Assert.Equal("master_keys_rejected", (string?)r!["t"]);
        Assert.Equal(VerifyErrors.Replayed, (string?)r["error"]);
        Assert.Equal([_new.KeyId], Pinned());
    }

    [Fact]
    public async Task Old_key_is_rejected_after_rotation()
    {
        await Send(_h.Master, 1, Body(_new));
        var p = TestData.BasicPolicy();
        var old = await Send(_h.Master, 1, p, "policy");
        Assert.Equal("policy_rejected", (string?)old!["t"]);
        Assert.Equal(VerifyErrors.UnknownKey, (string?)old["error"]);
        var ok = await Send(_new, 1, p, "policy");
        Assert.Equal("policy_applied", (string?)ok!["t"]);
    }

    [Fact]
    public async Task Invalid_body_is_rejected()
    {
        var bad = Body(_new); bad["sealPubKey"] = "short";
        var r = await Send(_h.Master, 1, bad);
        Assert.Equal("master_keys_rejected", (string?)r!["t"]);
        Assert.Equal(VerifyErrors.InvalidBody, (string?)r["error"]);
        Assert.Equal([_h.Master.KeyId], Pinned());
    }

    [Fact]
    public async Task Rotate_then_restart_keeps_enforcing_stored_old_key_policy()
    {
        Assert.Equal("policy_applied", (string?)(await Send(_h.Master, 1, TestData.BasicPolicy(), "policy"))!["t"]);
        await Send(_h.Master, 1, Body(_new));
        var restarted = new MinControl.Core.Policies.PolicyProvider(_h.Store, new EnvelopeVerifier(_h.Store, _h.Clock), _h.Clock);
        Assert.NotNull(restarted.Current);
        Assert.False(restarted.StoredPolicyRejected);
        Assert.Single(_h.Store.GetRetiredKeys());
    }

    [Fact]
    public async Task New_envelope_signed_by_retired_key_is_rejected_unknown_key()
    {
        await Send(_h.Master, 1, TestData.BasicPolicy(), "policy");
        await Send(_h.Master, 1, Body(_new));
        var r = await Send(_h.Master, 2, TestData.BasicPolicy(), "policy");
        Assert.Equal(VerifyErrors.UnknownKey, (string?)r!["error"]);
        var c = await Send(_h.Master, 1, new JsonObject { ["commandId"] = "01JDQ40000000000000000V0CK", ["type"] = "refresh" }, "command");
        Assert.Equal(VerifyErrors.UnknownKey, (string?)c!["ack"]!["error"]);
        var k = await Send(_h.Master, 2, Body(_h.Master), "master_keys");
        Assert.Equal(VerifyErrors.UnknownKey, (string?)k!["error"]);
    }

    [Fact]
    public async Task Retired_keys_are_dropped_once_a_new_policy_is_stored()
    {
        await Send(_h.Master, 1, TestData.BasicPolicy(), "policy");
        await Send(_h.Master, 1, Body(_new));
        Assert.Single(_h.Store.GetRetiredKeys());
        Assert.Equal("policy_applied", (string?)(await Send(_new, 2, TestData.BasicPolicy(), "policy"))!["t"]);
        Assert.Empty(_h.Store.GetRetiredKeys());
        var restarted = new MinControl.Core.Policies.PolicyProvider(_h.Store, new EnvelopeVerifier(_h.Store, _h.Clock), _h.Clock);
        Assert.NotNull(restarted.Current);
    }
}
