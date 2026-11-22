using System.Text.Json;
using MinControl.Core.Abstractions;
using MinControl.Core.Policies;
using MinControl.Core.Protocol;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.Crypto;

/// <summary>Error codes shared by command acks and policy_rejected (command-ack.schema.json).</summary>
public static class VerifyErrors
{
    public const string BadSignature = "bad_signature", UnknownKey = "unknown_key", WrongDevice = "wrong_device",
        Replayed = "replayed", Expired = "expired", InvalidBody = "invalid_body", UnmanagedUser = "unmanaged_user",
        NotFound = "not_found", Internal = "internal";
}

public sealed record VerifiedEnvelope(SignedEnvelope Envelope, SignedBody Body, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);

/// <param name="Kind">from the (possibly unverified) payload, for error reporting only.</param>
/// <param name="Seq">from the (possibly unverified) payload, for error reporting only.</param>
/// <param name="CommandIdHint">body.commandId when it looks like a ULID (needed to ack a rejected command).</param>
public sealed record VerifyResult(VerifiedEnvelope? Envelope, string? Error, string? Detail, string? Kind, long Seq, string? CommandIdHint)
{
    public bool Ok => Envelope is not null;
}

/// <summary>
/// Implements protocol/README.md step 6, in order: keyId pinned → signature valid → deviceId is ours →
/// seq &gt; last accepted seq for that kind → issuedAt − 5 min ≤ now &lt; expiresAt. Only then the signed body
/// is validated against signed-body.schema.json (which includes policy/command by kind). The seq is
/// persisted as soon as steps 1–5 pass, so a replay of a valid-signature envelope with a broken body is
/// also rejected.
/// </summary>
public sealed class EnvelopeVerifier
{
    public static readonly TimeSpan IssuedAtSkew = TimeSpan.FromMinutes(5);

    private readonly StateStore _store;
    private readonly IClock _clock;
    private readonly SchemaValidator _schemas;
    private readonly object _gate = new();

    public EnvelopeVerifier(StateStore store, IClock clock, SchemaValidator? schemas = null)
    {
        _store = store; _clock = clock; _schemas = schemas ?? SchemaValidator.Shared;
    }

    public VerifyResult Verify(SignedEnvelope env)
    {
        lock (_gate) return VerifyCore(env, checkFreshness: true);
    }

    /// <summary>Re-verifies a stored envelope (key pinned, signature, device) without seq/expiry checks.
    /// Used at startup so a tampered state.db cannot inject a policy.</summary>
    public VerifyResult VerifyStored(SignedEnvelope env)
    {
        lock (_gate) return VerifyCore(env, checkFreshness: false);
    }

    private VerifyResult VerifyCore(SignedEnvelope env, bool checkFreshness)
    {
        var payloadOk = Base64Url.TryDecode(env.Payload, out var payload);
        var hint = payloadOk ? Peek(payload) : default;
        VerifyResult Fail(string error, string? detail = null) => new(null, error, detail, hint.Kind, hint.Seq, hint.CommandId);

        if (env.V != 1 || env.Alg is not (Signatures.Ed25519 or Signatures.Es256) || !payloadOk)
            return Fail(VerifyErrors.InvalidBody, "malformed envelope");

        // 1. keyId pinned (and its algorithm matches)
        var key = _store.GetMasterKeys().FirstOrDefault(k => k.KeyId == env.KeyId);
        if (key is null || key.Alg != env.Alg) return Fail(VerifyErrors.UnknownKey);

        // 2. signature over the raw payload bytes
        if (!Base64Url.TryDecode(env.Sig, out var sig) || sig.Length != 64 || !Signatures.Verify(key.Alg, key.PublicKey, payload, sig))
            return Fail(VerifyErrors.BadSignature);

        // payload is authentic from here on
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(payload);
            root = doc.RootElement.Clone();
        }
        catch (JsonException) { return Fail(VerifyErrors.InvalidBody, "payload is not JSON"); }
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("deviceId", out var devEl) || devEl.ValueKind != JsonValueKind.String
            || !root.TryGetProperty("kind", out var kindEl) || kindEl.ValueKind != JsonValueKind.String
            || !root.TryGetProperty("seq", out var seqEl) || seqEl.ValueKind != JsonValueKind.Number || !seqEl.TryGetInt64(out var seq)
            || !root.TryGetProperty("issuedAt", out var iaEl) || !Time.TryParseUtc(iaEl.ValueKind == JsonValueKind.String ? iaEl.GetString() : null, out var issuedAt)
            || !root.TryGetProperty("expiresAt", out var exEl) || !Time.TryParseUtc(exEl.ValueKind == JsonValueKind.String ? exEl.GetString() : null, out var expiresAt))
            return Fail(VerifyErrors.InvalidBody, "signed body misses deviceId/kind/seq/issuedAt/expiresAt");
        var kind = kindEl.GetString()!;
        if (kind is not ("policy" or "command")) return Fail(VerifyErrors.InvalidBody, "unknown kind");

        // 3. our device
        var myId = _store.GetMeta(StateStore.MetaKeys.DeviceId);
        if (myId is null || !string.Equals(devEl.GetString(), myId, StringComparison.Ordinal)) return Fail(VerifyErrors.WrongDevice);

        if (checkFreshness)
        {
            // 4. replay
            if (seq <= _store.GetSeq(kind)) return Fail(VerifyErrors.Replayed, $"seq {seq} <= {_store.GetSeq(kind)}");
            // 5. validity window
            var now = _clock.UtcNow;
            if (now < issuedAt - IssuedAtSkew || now >= expiresAt) return Fail(VerifyErrors.Expired);
            if (!_store.TryAdvanceSeq(kind, seq)) return Fail(VerifyErrors.Replayed);
        }

        // 6. schema of the signed body (validates body per kind)
        if (!_schemas.IsValid("signed-body", root)) return Fail(VerifyErrors.InvalidBody, $"{kind} body does not match its schema");
        var body = new SignedBody(devEl.GetString()!, kind, seq, iaEl.GetString()!, exEl.GetString()!, root.GetProperty("body").Clone());
        return new VerifyResult(new VerifiedEnvelope(env, body, issuedAt, expiresAt), null, null, kind, seq, hint.CommandId);
    }

    private static (string? Kind, long Seq, string? CommandId) Peek(byte[] payload)
    {
        try
        {
            using var doc = JsonDocument.Parse(payload);
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object) return default;
            string? kind = r.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() : null;
            long seq = r.TryGetProperty("seq", out var s) && s.ValueKind == JsonValueKind.Number && s.TryGetInt64(out var sv) ? sv : 0;
            string? cid = null;
            if (r.TryGetProperty("body", out var b) && b.ValueKind == JsonValueKind.Object
                && b.TryGetProperty("commandId", out var c) && c.ValueKind == JsonValueKind.String && UlidGenerator.IsValid(c.GetString()))
                cid = c.GetString();
            return (kind, seq, cid);
        }
        catch (JsonException) { return default; }
    }
}
