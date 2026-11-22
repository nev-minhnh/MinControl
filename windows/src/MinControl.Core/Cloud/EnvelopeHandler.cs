using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Commands;
using MinControl.Core.Crypto;
using MinControl.Core.Policies;
using MinControl.Core.Protocol;
using MinControl.Core.Storage;

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
        var ack = await _commands.DispatchAsync(e, ct).ConfigureAwait(false);
        if (ack.Status == "applied") _store.MarkCommandApplied(ack.CommandId, ack.At);
        return Ack(ack);
    }

    private static JsonObject PolicyRejected(long seq, string error) =>
        new() { ["t"] = "policy_rejected", ["seq"] = seq, ["error"] = error };

    private static JsonObject Ack(CommandAck ack) =>
        new() { ["t"] = "ack", ["ack"] = JsonSerializer.SerializeToNode(ack, ProtocolJson.Options) };
}
