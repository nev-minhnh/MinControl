package io.github.nevminhnh.mincontrol.master.transfer

import io.github.nevminhnh.mincontrol.master.data.protocol.BodyKind
import io.github.nevminhnh.mincontrol.master.data.protocol.MasterKeyEntry
import io.github.nevminhnh.mincontrol.master.data.protocol.MasterKeysBody
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolJson
import io.github.nevminhnh.mincontrol.master.envelope.EnvelopeBuilder
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterKey
import io.github.nevminhnh.mincontrol.master.data.protocol.SignedBody
import io.github.nevminhnh.mincontrol.master.security.SealedBox
import io.github.nevminhnh.mincontrol.master.ui.pairing.Fingerprint
import io.github.nevminhnh.mincontrol.master.util.B64Url
import io.github.nevminhnh.mincontrol.master.util.sha256
import io.github.nevminhnh.mincontrol.master.util.toHex
import io.github.nevminhnh.mincontrol.master.util.toRfc3339
import kotlinx.serialization.json.jsonObject
import java.time.Duration
import java.time.Instant

/** Pure (unit-testable) pieces of the phone transfer (API.md 13). */
object TransferProtocol {
    /** `master_keys` envelopes expire after 30 days. */
    val MASTER_KEYS_TTL: Duration = Duration.ofDays(30)
    private val KEY_ID = Regex("^[0-9a-f]{16}$")
    private val B64URL = Regex("^[A-Za-z0-9_-]+$")

    /** Bytes signed by the new phone's sign key for `POST /v1/master/transfers/claim`. */
    fun claimSignText(token: String): ByteArray = ("transfer|$token").toByteArray(Charsets.UTF_8)

    /** Fingerprint of a raw public key: first 12 hex chars of sha256, upper-case (compare with [Fingerprint.format]). */
    fun fingerprint(rawPublicKey: ByteArray): String = sha256(rawPublicKey).toHex().take(12).uppercase()

    /** `XXXX-XXXX-XXXX` for display. */
    fun displayFingerprint(rawPublicKey: ByteArray): String = Fingerprint.format(fingerprint(rawPublicKey))!!

    /** The new phone's sign key from a claimed transfer; null when missing or malformed. */
    fun newSignKey(newKeys: List<RegisterKey>): RegisterKey? =
        newKeys.firstOrNull { it.role == "sign" && KEY_ID.matches(it.keyId) && B64URL.matches(it.publicKey) }

    /**
     * The fingerprint the old phone shows, computed locally from the new sign public key (never trusting the server's
     * `fp` alone). Throws if the server's `fp` (when present) disagrees.
     */
    fun claimedFingerprint(newKeys: List<RegisterKey>, serverFp: String?): String {
        val sign = newSignKey(newKeys) ?: throw IllegalArgumentException("transfer has no sign key")
        val fp = fingerprint(B64Url.decode(sign.publicKey))
        if (serverFp != null && Fingerprint.normalize(serverFp) != null) {
            require(Fingerprint.matches(serverFp, fp)) { "server fingerprint does not match the new key" }
        }
        return Fingerprint.format(fp)!!
    }

    /** `master_keys` body: only the `sign` keys of the new phone (schema: role const "sign", 1..4 keys) + its seal key. */
    fun masterKeysBody(newKeys: List<RegisterKey>, sealPubKey: String): MasterKeysBody {
        val sign = newKeys.filter { it.role == "sign" }
        require(sign.isNotEmpty() && sign.size <= 4) { "need 1..4 sign keys" }
        sign.forEach { require(KEY_ID.matches(it.keyId) && B64URL.matches(it.publicKey)) { "bad key ${it.keyId}" } }
        require(B64Url.decode(sealPubKey).size == 32) { "bad seal public key" }
        return MasterKeysBody(sign.map { MasterKeyEntry(it.keyId, it.alg, it.publicKey) }, sealPubKey)
    }

    fun signedBody(deviceId: String, seq: Long, body: MasterKeysBody, now: Instant = Instant.now(), ttl: Duration = MASTER_KEYS_TTL) =
        SignedBody(
            deviceId = deviceId,
            kind = BodyKind.MASTER_KEYS,
            seq = seq,
            issuedAt = now.toRfc3339(),
            expiresAt = now.plus(ttl).toRfc3339(),
            body = ProtocolJson.encodeToJsonElement(MasterKeysBody.serializer(), body).jsonObject,
        )

    /** Seals the old seal PRIVATE key to the new phone's X25519 transport key (crypto_box_seal), base64url. */
    fun sealSealKey(oldSealSk: ByteArray, transportPubKeyB64: String): String {
        require(oldSealSk.size == SealedBox.KEY_BYTES)
        val pk = B64Url.decode(transportPubKeyB64)
        require(pk.size == SealedBox.KEY_BYTES) { "bad transport public key" }
        return B64Url.encode(SealedBox.seal(oldSealSk, pk))
    }

    /** New phone: opens `sealedSealKey` with its transport key pair; returns the old 32-byte seal private key. */
    fun openSealedSealKey(sealedB64: String, transportSk: ByteArray): ByteArray {
        val sk = SealedBox.open(B64Url.decode(sealedB64), transportSk, SealedBox.publicKey(transportSk))
        if (sk.size != SealedBox.KEY_BYTES) throw SealedBox.OpenException("bad sealed seal key length")
        return sk
    }

    /** Current policy re-signed by the new phone: same content, version = max(server, body) + 1. */
    fun republishedPolicy(current: PolicyResponse): Policy {
        val p = EnvelopeBuilder.decodePolicy(current.envelope)
        return p.copy(version = maxOf(current.version, p.version) + 1)
    }

    /** Seconds left until [expiresAt] (RFC 3339), clamped at 0; null when unparsable. */
    fun secondsLeft(expiresAt: String?, now: Instant = Instant.now()): Long? =
        expiresAt?.let { runCatching { Instant.parse(it) }.getOrNull() }?.let { maxOf(0L, Duration.between(now, it).seconds) }

    /** `9:05` style countdown. */
    fun countdown(seconds: Long): String = "%d:%02d".format(seconds / 60, seconds % 60)
}
