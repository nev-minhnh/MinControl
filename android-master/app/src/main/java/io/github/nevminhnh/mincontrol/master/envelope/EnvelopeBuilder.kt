package io.github.nevminhnh.mincontrol.master.envelope

import io.github.nevminhnh.mincontrol.master.data.protocol.BodyKind
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyJson
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolJson
import io.github.nevminhnh.mincontrol.master.data.protocol.SigAlg
import io.github.nevminhnh.mincontrol.master.data.protocol.SignedBody
import io.github.nevminhnh.mincontrol.master.data.protocol.SignedEnvelope
import io.github.nevminhnh.mincontrol.master.util.B64Url
import io.github.nevminhnh.mincontrol.master.util.toRfc3339
import kotlinx.serialization.json.jsonObject
import java.time.Duration
import java.time.Instant

/**
 * Builds signed envelopes per protocol/README.md: the [SignedBody] is serialised to UTF-8 JSON exactly once,
 * those bytes are signed and base64url-encoded into `payload`. Nothing is ever re-serialised.
 */
object EnvelopeBuilder {
    val COMMAND_TTL: Duration = Duration.ofHours(24)
    /** Long: the cloud never delivers expired policy envelopes. */
    val POLICY_TTL: Duration = Duration.ofDays(365)

    /** Commands expire after 24 h; `lock_now` with `until` stays valid until `until` + 1 h if that is later. */
    fun commandTtl(command: Command, now: Instant): Duration {
        val until = (command as? Command.LockNow)?.until?.let { runCatching { Instant.parse(it) }.getOrNull() }
        val lockTtl = until?.let { Duration.between(now, it.plus(Duration.ofHours(1))) }
        return if (lockTtl != null && lockTtl > COMMAND_TTL) lockTtl else COMMAND_TTL
    }

    fun commandBody(deviceId: String, seq: Long, command: Command, now: Instant = Instant.now(), ttl: Duration = commandTtl(command, now)) =
        SignedBody(
            deviceId = deviceId,
            kind = BodyKind.COMMAND,
            seq = seq,
            issuedAt = now.toRfc3339(),
            expiresAt = now.plus(ttl).toRfc3339(),
            body = ProtocolJson.encodeToJsonElement(Command.serializer(), command).jsonObject,
        )

    fun policyBody(deviceId: String, seq: Long, policy: Policy, now: Instant = Instant.now(), ttl: Duration = POLICY_TTL) =
        SignedBody(
            deviceId = deviceId,
            kind = BodyKind.POLICY,
            seq = seq,
            issuedAt = now.toRfc3339(),
            expiresAt = now.plus(ttl).toRfc3339(),
            body = PolicyJson.encodeToJsonElement(Policy.serializer(), policy).jsonObject,
        )

    /** The exact bytes that get signed. Call once per envelope. */
    fun payloadBytes(body: SignedBody): ByteArray =
        ProtocolJson.encodeToString(SignedBody.serializer(), body).toByteArray(Charsets.UTF_8)

    fun envelope(alg: SigAlg, keyId: String, payload: ByteArray, signature: ByteArray): SignedEnvelope {
        require(signature.size == 64) { "signature must be 64 bytes" }
        require(Regex("^[0-9a-f]{16}$").matches(keyId)) { "bad keyId" }
        return SignedEnvelope(v = 1, alg = alg, keyId = keyId, payload = B64Url.encode(payload), sig = B64Url.encode(signature))
    }

    /** Signs [body] with [sign] (which receives the payload bytes and returns alg, keyId, 64-byte signature). */
    suspend fun build(body: SignedBody, sign: suspend (ByteArray) -> Triple<SigAlg, String, ByteArray>): SignedEnvelope {
        val payload = payloadBytes(body)
        val (alg, keyId, sig) = sign(payload)
        return envelope(alg, keyId, payload, sig)
    }

    fun decodePayload(envelope: SignedEnvelope): SignedBody =
        ProtocolJson.decodeFromString(SignedBody.serializer(), B64Url.decode(envelope.payload).toString(Charsets.UTF_8))

    fun decodePolicy(envelope: SignedEnvelope): Policy =
        PolicyJson.decodeFromJsonElement(Policy.serializer(), decodePayload(envelope).body)
}
