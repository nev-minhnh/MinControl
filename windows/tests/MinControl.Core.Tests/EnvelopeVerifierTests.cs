using System.Text.Json.Nodes;
using MinControl.Core.Crypto;
using MinControl.Core.Storage;
using MinControl.Core.Util;
using Xunit;

namespace MinControl.Core.Tests;

public class EnvelopeVerifierTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 8, 50, 0, TimeSpan.Zero);
    private readonly FakeClock _clock = new(Now);
    private readonly StateStore _store = new(":memory:");
    private readonly MasterKey _ed = MasterKey.Ed25519();
    private readonly MasterKey _ec = MasterKey.Es256();
    private readonly EnvelopeVerifier _verifier;

    public EnvelopeVerifierTests()
    {
        _store.SetMeta(StateStore.MetaKeys.DeviceId, TestData.DeviceId);
        _store.ReplaceMasterKeys([_ed.Pinned, _ec.Pinned]);
        _verifier = new EnvelopeVerifier(_store, _clock);
    }

    public void Dispose() { _store.Dispose(); _ed.Dispose(); _ec.Dispose(); }

    private static JsonObject Refresh() => new() { ["commandId"] = "01JDQ40000000000000000V0CK", ["type"] = "refresh" };

    private VerifyResult Verify(string envJson) => _verifier.Verify(TestData.Parse(envJson));

    [Fact]
    public void Good_ed25519_signature_is_accepted()
    {
        var r = Verify(TestData.Envelope(_ed, "command", 1, Refresh(), Now));
        Assert.True(r.Ok, r.Error);
        Assert.Equal("command", r.Envelope!.Body.Kind);
        Assert.Equal(1, _store.GetSeq("command"));
    }

    [Fact]
    public void Good_es256_signature_is_accepted() =>
        Assert.True(Verify(TestData.Envelope(_ec, "command", 1, Refresh(), Now)).Ok);

    [Fact]
    public void Policy_envelope_is_accepted() =>
        Assert.True(Verify(TestData.Envelope(_ed, "policy", 1, TestData.BasicPolicy(), Now)).Ok);

    [Fact]
    public void Unpinned_key_is_unknown_key()
    {
        using var rogue = MasterKey.Ed25519();
        var r = Verify(TestData.Envelope(rogue, "command", 1, Refresh(), Now));
        Assert.Equal(VerifyErrors.UnknownKey, r.Error);
        Assert.Equal("01JDQ40000000000000000V0CK", r.CommandIdHint);
        Assert.Equal(0, _store.GetSeq("command"));
    }

    [Fact]
    public void Wrong_key_under_pinned_keyId_is_bad_signature()
    {
        using var rogue = MasterKey.Ed25519();
        var r = Verify(TestData.Envelope(_ed, "command", 1, Refresh(), Now, signWith: rogue));
        Assert.Equal(VerifyErrors.BadSignature, r.Error);
        Assert.Equal(0, _store.GetSeq("command"));
    }

    [Fact]
    public void Alg_mismatch_with_pinned_key_is_unknown_key()
    {
        // ES256 key id presented as ed25519
        var json = TestData.Envelope(_ec, "command", 1, Refresh(), Now).Replace("\"es256\"", "\"ed25519\"");
        Assert.Equal(VerifyErrors.UnknownKey, Verify(json).Error);
    }

    [Fact]
    public void Tampered_payload_is_bad_signature()
    {
        var env = TestData.Parse(TestData.Envelope(_ed, "command", 1, Refresh(), Now));
        var payload = Base64Url.Decode(env.Payload);
        payload[^3] ^= 0x01;
        var r = _verifier.Verify(env with { Payload = Base64Url.Encode(payload) });
        Assert.Equal(VerifyErrors.BadSignature, r.Error);
    }

    [Fact]
    public void Replay_of_same_seq_is_rejected()
    {
        var json = TestData.Envelope(_ed, "command", 5, Refresh(), Now);
        Assert.True(Verify(json).Ok);
        Assert.Equal(VerifyErrors.Replayed, Verify(json).Error);
        Assert.Equal(VerifyErrors.Replayed, Verify(TestData.Envelope(_ed, "command", 4, Refresh(), Now)).Error);
        Assert.True(Verify(TestData.Envelope(_ed, "command", 6, Refresh(), Now)).Ok);
    }

    [Fact]
    public void Seq_is_tracked_per_kind()
    {
        Assert.True(Verify(TestData.Envelope(_ed, "command", 7, Refresh(), Now)).Ok);
        Assert.True(Verify(TestData.Envelope(_ed, "policy", 1, TestData.BasicPolicy(), Now)).Ok);
    }

    [Fact]
    public void Expired_envelope_is_rejected()
    {
        var r = Verify(TestData.Envelope(_ed, "command", 1, Refresh(), Now.AddHours(-2), Now.AddHours(-1)));
        Assert.Equal(VerifyErrors.Expired, r.Error);
        Assert.Equal(0, _store.GetSeq("command"));
    }

    [Fact]
    public void ExpiresAt_equal_to_now_is_expired() =>
        Assert.Equal(VerifyErrors.Expired, Verify(TestData.Envelope(_ed, "command", 1, Refresh(), Now.AddMinutes(-10), Now)).Error);

    [Fact]
    public void IssuedAt_within_5_min_skew_is_accepted() =>
        Assert.True(Verify(TestData.Envelope(_ed, "command", 1, Refresh(), Now.AddMinutes(5))).Ok);

    [Fact]
    public void IssuedAt_beyond_skew_is_rejected() =>
        Assert.Equal(VerifyErrors.Expired, Verify(TestData.Envelope(_ed, "command", 1, Refresh(), Now.AddMinutes(6))).Error);

    [Fact]
    public void Envelope_for_other_device_is_wrong_device()
    {
        var r = Verify(TestData.Envelope(_ed, "command", 1, Refresh(), Now, deviceId: TestData.OtherDeviceId));
        Assert.Equal(VerifyErrors.WrongDevice, r.Error);
        Assert.Equal(0, _store.GetSeq("command"));
    }

    [Fact]
    public void Wrong_device_is_checked_before_replay_and_expiry()
    {
        var r = Verify(TestData.Envelope(_ed, "command", 0, Refresh(), Now.AddDays(-2), Now.AddDays(-1), deviceId: TestData.OtherDeviceId));
        Assert.Equal(VerifyErrors.WrongDevice, r.Error);
    }

    [Fact]
    public void Schema_invalid_body_is_rejected_and_consumes_seq()
    {
        var bad = new JsonObject { ["commandId"] = "01JDQ40000000000000000V0CK", ["type"] = "add_time", ["userSid"] = TestData.Sid, ["minutes"] = 0 };
        var r = Verify(TestData.Envelope(_ed, "command", 3, bad, Now));
        Assert.Equal(VerifyErrors.InvalidBody, r.Error);
        Assert.Equal(3, _store.GetSeq("command"));
    }

    [Fact]
    public void Stored_envelope_reverifies_without_freshness()
    {
        var json = TestData.Envelope(_ed, "policy", 1, TestData.BasicPolicy(), Now);
        Assert.True(Verify(json).Ok);
        _clock.UtcNow = Now.AddDays(30);
        Assert.True(_verifier.VerifyStored(TestData.Parse(json)).Ok);
    }

    [Fact]
    public void KeyId_is_sha256_prefix()
    {
        Assert.Equal(16, _ed.KeyId.Length);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(_ec.PublicKey))[..16], _ec.KeyId);
        Assert.Equal(65, _ec.PublicKey.Length);
    }
}
