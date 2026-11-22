using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Commands;
using MinControl.Core.Crypto;
using MinControl.Core.Policies;
using MinControl.Core.Protocol;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.Cloud;

/// <summary>
/// Verifies one incoming envelope and executes it. Returns the WS reply: <c>ack</c> for commands,
/// <c>policy_applied</c>/<c>policy_rejected</c> for policies, or null when nothing can be answered
/// (e.g. an unverifiable command without a recognisable commandId).
/// </summary>
public sealed class EnvelopeHandler
{
    private readonly EnvelopeVerifier _verifier;
    private readonly PolicyProvider _policy;
    private readonly CommandDispatcher _commands;
    private readonly StateStore _store;
    private readonly ILogger _log;

    public EnvelopeHandler(EnvelopeVerifier verifier, PolicyProvider policy, CommandDispatcher commands, StateStore store, ILogger<EnvelopeHandler>? log = null)
    {
        _verifier = verifier; _policy = policy; _commands = commands; _store = store;
        _log = log ?? (ILogger)NullLogger.Instance;
    }

    public async Task<JsonObject?> HandleAsync(SignedEnvelope env, CancellationToken ct)
    {
        var v = _verifier.Verify(env);
        // The cloud re-sends delivered-but-unacked commands after a reconnect. Replayed implies the signature and
        // device already checked out; if we applied that commandId before, ack it as applied again.
        if (!v.Ok && v.Error == VerifyErrors.Replayed && v.Kind == "command" && v.CommandIdHint is { } cid && _store.IsCommandApplied(cid))
            return Ack(_commands.Applied(cid));
        if (!v.Ok)
        {
            _log.LogWarning("envelope rejected: {Error} {Detail} (kind {Kind}, seq {Seq})", v.Error, v.Detail, v.Kind, v.Seq);
            if (v.Kind == "policy") return PolicyRejected(v.Seq, v.Error!);
            if (v.Kind == "master_keys") return KeysRejected(v.Seq, v.Error!);
            if (v.CommandIdHint is not null) return Ack(_commands.Reject(v.CommandIdHint, "rejected", v.Error!, v.Detail));
            return null;
        }
        var e = v.Envelope!;
        if (e.Body.Kind == "policy")
        {
            var (error, detail) = _policy.Apply(e);
            if (error is not null)
            {
                _log.LogWarning("policy seq {Seq} rejected: {Detail}", e.Body.Seq, detail);
                return PolicyRejected(e.Body.Seq, error);
            }
            return new JsonObject { ["t"] = "policy_applied", ["version"] = _policy.Current!.Version, ["seq"] = e.Body.Seq };
        }
        if (e.Body.Kind == "master_keys")
        {
            var error = ApplyMasterKeys(e.Body.Body);
            if (error is not null) return KeysRejected(e.Body.Seq, error);
            _log.LogInformation("master keys replaced by envelope seq {Seq}", e.Body.Seq);
            return new JsonObject { ["t"] = "master_keys_applied", ["seq"] = e.Body.Seq };
        }
        var ack = await _commands.DispatchAsync(e, ct).ConfigureAwait(false);
        if (ack.Status == "applied") _store.MarkCommandApplied(ack.CommandId, ack.At);
        return Ack(ack);
    }

    /// <summary>Replaces pinned keys + seal key atomically. Returns an error code or null.</summary>
    private string? ApplyMasterKeys(JsonElement body)
    {
        try
        {
            var keys = new List<PinnedKey>();
            foreach (var k in body.GetProperty("keys").EnumerateArray())
            {
                var alg = k.GetProperty("alg").GetString()!;
                if (!Base64Url.TryDecode(k.GetProperty("publicKey").GetString(), out var pk)) return VerifyErrors.InvalidBody;
                keys.Add(new PinnedKey(k.GetProperty("keyId").GetString()!, alg, pk));
            }
            var seal = body.GetProperty("sealPubKey").GetString()!;
            if (!Base64Url.TryDecode(seal, out var sb) || sb.Length != 32) return VerifyErrors.InvalidBody;
            _store.ReplaceMasterKeysAndSeal(keys, seal);
            return null;
        }
        catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return VerifyErrors.InvalidBody;
        }
    }

    private static JsonObject KeysRejected(long seq, string error) =>
        new() { ["t"] = "master_keys_rejected", ["seq"] = seq, ["error"] = error };

    private static JsonObject PolicyRejected(long seq, string error) =>
        new() { ["t"] = "policy_rejected", ["seq"] = seq, ["error"] = error };

    private static JsonObject Ack(CommandAck ack) =>
        new() { ["t"] = "ack", ["ack"] = JsonSerializer.SerializeToNode(ack, ProtocolJson.Options) };
}
