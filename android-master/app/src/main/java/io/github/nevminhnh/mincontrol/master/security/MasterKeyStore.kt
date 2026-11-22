package io.github.nevminhnh.mincontrol.master.security

import io.github.nevminhnh.mincontrol.master.data.protocol.SigAlg
import java.security.Signature

enum class KeyRole(val wire: String) { SIGN("sign"), READ("read") }

class MasterPublicKey(
    val role: KeyRole,
    val alg: SigAlg,
    val keyId: String,
    /** Raw public key: Ed25519 32 B, P-256 uncompressed SEC1 65 B. */
    val raw: ByteArray,
)

/**
 * An initialised (not yet authenticated) [Signature] for the biometric-gated `sign` key.
 * Wrap [signature] in a `BiometricPrompt.CryptoObject`; after authentication call [finish].
 */
class SignSession(val signature: Signature, val alg: SigAlg, val keyId: String) {
    /** Signs [data] and returns the 64-byte wire signature (Ed25519 raw or ES256 P1363). */
    fun finish(data: ByteArray): ByteArray {
        signature.update(data)
        return normalise(alg, signature.sign())
    }
}

fun normalise(alg: SigAlg, sig: ByteArray): ByteArray = when (alg) {
    SigAlg.ED25519 -> sig.also { require(it.size == 64) { "unexpected Ed25519 signature size" } }
    SigAlg.ES256 -> SigFormat.derToP1363(sig, 32)
}

/**
 * Holds the two master keys (API.md §4): role `sign` (user authentication on every use; signs policy and
 * command envelopes) and role `read` (no authentication; signs `X-MC-Auth` request headers).
 */
interface MasterKeyStore {
    fun hasKeys(): Boolean
    /** Generates missing keys. Throws [KeySetupException] if the device has no secure lock screen. */
    fun ensureKeys()
    fun publicKey(role: KeyRole): MasterPublicKey
    /** Signs with the `read` key (no prompt). Returns the 64-byte wire signature. */
    fun signRead(data: ByteArray): ByteArray
    /** Starts a signature with the `sign` key; must be completed through BiometricPrompt. */
    fun startSign(): SignSession
    fun deleteAll()
}

class KeySetupException(message: String, cause: Throwable? = null) : Exception(message, cause)
