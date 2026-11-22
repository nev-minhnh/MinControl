package io.github.nevminhnh.mincontrol.master.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.nevminhnh.mincontrol.master.util.B64Url
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** AES-256-GCM with a non-exportable Android Keystore key (no user auth). Output = iv(12) || ct+tag. */
class KeystoreAead(private val alias: String = "mc_aead_v1") {
    private val ks = KeyStore.getInstance(AndroidMasterKeyStore.ANDROID_KEYSTORE).apply { load(null) }

    private fun key(): SecretKey {
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidMasterKeyStore.ANDROID_KEYSTORE)
            .apply { init(spec) }.generateKey()
    }

    fun encrypt(plain: ByteArray, aad: ByteArray? = null): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        aad?.let(c::updateAAD)
        return c.iv + c.doFinal(plain)
    }

    fun decrypt(blob: ByteArray, aad: ByteArray? = null): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, 12)) }
        aad?.let(c::updateAAD)
        return c.doFinal(blob, 12, blob.size - 12)
    }
}

/** SharedPreferences whose values are sealed with [KeystoreAead] (replacement for EncryptedSharedPreferences). */
class SecurePrefs(context: Context, private val aead: KeystoreAead = KeystoreAead()) {
    private val prefs = context.getSharedPreferences("mc_secure", Context.MODE_PRIVATE)

    fun getString(key: String): String? = getBytes(key)?.toString(Charsets.UTF_8)
    fun putString(key: String, value: String?) = putBytes(key, value?.toByteArray(Charsets.UTF_8))

    fun getBytes(key: String): ByteArray? = prefs.getString(key, null)?.let {
        runCatching { aead.decrypt(B64Url.decode(it), key.toByteArray()) }.getOrNull()
    }

    fun putBytes(key: String, value: ByteArray?) {
        prefs.edit().apply {
            if (value == null) remove(key) else putString(key, B64Url.encode(aead.encrypt(value, key.toByteArray())))
        }.apply()
    }

    fun clear() = prefs.edit().clear().apply()
}

/** X25519 seal keypair for screenshots; the private key is stored encrypted under the Keystore AES key. */
class SealKeyStore(private val prefs: SecurePrefs) {
    fun hasKey(): Boolean = prefs.getBytes(SK) != null

    fun ensureKey(): ByteArray {
        prefs.getBytes(PK)?.let { if (hasKey()) return it }
        val (sk, pk) = SealedBox.generateKeyPair()
        prefs.putBytes(SK, sk)
        prefs.putBytes(PK, pk)
        return pk
    }

    fun publicKey(): ByteArray = prefs.getBytes(PK) ?: ensureKey()

    fun open(sealed: ByteArray): ByteArray {
        val sk = prefs.getBytes(SK) ?: throw SealedBox.OpenException("no seal key on this phone")
        return try { SealedBox.open(sealed, sk, publicKey()) } finally { sk.fill(0) }
    }

    fun export(passphrase: CharArray): String {
        val sk = prefs.getBytes(SK) ?: throw IllegalStateException("no seal key")
        return try { SealKeyBackup.export(sk, passphrase) } finally { sk.fill(0) }
    }

    /** Replaces the local key with the backup; returns the restored public key. */
    fun import(backup: String, passphrase: CharArray): ByteArray {
        val sk = SealKeyBackup.import(backup, passphrase)
        val pk = SealedBox.publicKey(sk)
        prefs.putBytes(SK, sk)
        prefs.putBytes(PK, pk)
        sk.fill(0)
        return pk
    }

    private companion object {
        const val SK = "seal_sk"
        const val PK = "seal_pk"
    }
}
