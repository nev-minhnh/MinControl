using System.Text.Json;

namespace MinControl.Core.Protocol;

// TODO(M2): Policy model. TODO(M3): Event / EventBatch models.

/// <summary>Wrapper for everything the master signs. Payload is base64url(UTF-8 JSON of SignedBody).</summary>
public sealed record SignedEnvelope(int V, string Alg, string KeyId, string Payload, string Sig);

/// <summary>Decoded envelope payload. Body is kept raw; parse it according to Kind (policy/command).</summary>
public sealed record SignedBody(
    string DeviceId, string Kind, long Seq, string IssuedAt, string ExpiresAt, JsonElement Body);

public sealed record CommandAck(string CommandId, string Status, string At, string? Error = null, string? Detail = null);
