package io.github.nevminhnh.mincontrol.master.security

import io.github.nevminhnh.mincontrol.master.util.B64Url
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Passphrase-protected backup of the X25519 seal private key, so a lost phone does not lose old
 * screenshots (SPEC §4). Argon2id (BouncyCastle) derives an AES-256-GCM key; the file is JSON.
 */
object SealKeyBackup {
    private const val AAD = "mincontrol-seal-backup-v1"
    private val json = Json { ignoreUnknownKeys = false }

    @Serializable
    data class File(
        val v: Int = 1,
        val kdf: String = "argon2id",
        val m: Int,
        val t: Int,
        val p: Int,
        val salt: String,
        val nonce: String,
        val ct: String,
    )

    class BadPassphrase : Exception("wrong passphrase or corrupted backup")

    data class Params(val memoryKiB: Int = 32 * 1024, val iterations: Int = 3, val parallelism: Int = 1)

    fun export(secretKey: ByteArray, passphrase: CharArray, params: Params = Params(), random: SecureRandom = SecureRandom()): String {
        require(secretKey.size == 32)
        val salt = ByteArray(16).also(random::nextBytes)
        val nonce = ByteArray(12).also(random::nextBytes)
        val key = derive(passphrase, salt, params.memoryKiB, params.iterations, params.parallelism)
        val ct = gcm(Cipher.ENCRYPT_MODE, key, nonce).doFinal(secretKey)
        return json.encodeToString(
            File.serializer(),
            File(m = params.memoryKiB, t = params.iterations, p = params.parallelism,
                salt = B64Url.encode(salt), nonce = B64Url.encode(nonce), ct = B64Url.encode(ct)),
        )
    }

    /** Returns the 32-byte X25519 secret key. */
    fun import(text: String, passphrase: CharArray): ByteArray {
        val f = json.decodeFromString(File.serializer(), text.trim())
        require(f.v == 1 && f.kdf == "argon2id") { "unsupported backup format" }
        require(f.m in 8..1024 * 1024 && f.t in 1..20 && f.p in 1..8) { "bad KDF parameters" }
        val key = derive(passphrase, B64Url.decode(f.salt), f.m, f.t, f.p)
        return try {
            gcm(Cipher.DECRYPT_MODE, key, B64Url.decode(f.nonce)).doFinal(B64Url.decode(f.ct))
        } catch (e: AEADBadTagException) {
            throw BadPassphrase()
        }.also { require(it.size == 32) { "bad key length" } }
    }

    private fun gcm(mode: Int, key: ByteArray, nonce: ByteArray): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(AAD.toByteArray())
        }

    private fun derive(passphrase: CharArray, salt: ByteArray, m: Int, t: Int, p: Int): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt).withMemoryAsKB(m).withIterations(t).withParallelism(p)
            .build()
        val gen = Argon2BytesGenerator().apply { init(params) }
        return ByteArray(32).also { gen.generateBytes(passphrase, it) }
    }
}
