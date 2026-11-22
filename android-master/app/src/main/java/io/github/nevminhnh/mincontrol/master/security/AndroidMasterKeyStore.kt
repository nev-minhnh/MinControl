package io.github.nevminhnh.mincontrol.master.security

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.github.nevminhnh.mincontrol.master.data.protocol.SigAlg
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Android Keystore implementation. Tries Ed25519 first (KeyMint, API 33+, TEE), else ECDSA P-256
 * (StrongBox when available, otherwise TEE). Keys are non-exportable.
 */
class AndroidMasterKeyStore(context: Context) : MasterKeyStore {
    private val prefs: SharedPreferences = context.getSharedPreferences("mc_keys", Context.MODE_PRIVATE)
    private val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun hasKeys(): Boolean =
        KeyRole.entries.all { ks.containsAlias(alias(it)) && prefs.contains(algPref(it)) }

    override fun ensureKeys() {
        // The read key goes first: it lets us test-sign to verify that Ed25519 really works here.
        for (role in listOf(KeyRole.READ, KeyRole.SIGN)) {
            if (ks.containsAlias(alias(role)) && prefs.contains(algPref(role))) continue
            if (ks.containsAlias(alias(role))) ks.deleteEntry(alias(role))
            val alg = generate(role)
            prefs.edit().putString(algPref(role), alg.name).apply()
        }
    }

    override fun publicKey(role: KeyRole): MasterPublicKey {
        val alg = alg(role)
        val pub: PublicKey = ks.getCertificate(alias(role))?.publicKey
            ?: throw KeySetupException("missing key ${role.wire}")
        val raw = when (alg) {
            SigAlg.ED25519 -> SigFormat.ed25519Raw(pub)
            SigAlg.ES256 -> SigFormat.p256Uncompressed(pub as ECPublicKey)
        }
        return MasterPublicKey(role, alg, SigFormat.keyId(raw), raw)
    }

    override fun signRead(data: ByteArray): ByteArray {
        val alg = alg(KeyRole.READ)
        val s = Signature.getInstance(jcaName(alg)).apply { initSign(privateKey(KeyRole.READ)); update(data) }
        return normalise(alg, s.sign())
    }

    override fun startSign(): SignSession {
        val alg = alg(KeyRole.SIGN)
        val s = Signature.getInstance(jcaName(alg)).apply { initSign(privateKey(KeyRole.SIGN)) }
        return SignSession(s, alg, publicKey(KeyRole.SIGN).keyId)
    }

    override fun deleteAll() {
        KeyRole.entries.forEach { if (ks.containsAlias(alias(it))) ks.deleteEntry(alias(it)) }
        prefs.edit().clear().apply()
    }

    private fun alg(role: KeyRole): SigAlg =
        prefs.getString(algPref(role), null)?.let { SigAlg.valueOf(it) } ?: throw KeySetupException("keys not generated")

    private fun privateKey(role: KeyRole): PrivateKey =
        ks.getKey(alias(role), null) as? PrivateKey ?: throw KeySetupException("missing key ${role.wire}")

    private fun generate(role: KeyRole): SigAlg {
        val auth = role == KeyRole.SIGN
        val preferEd = role == KeyRole.SIGN && prefs.getString(algPref(KeyRole.READ), null) == SigAlg.ED25519.name ||
            role == KeyRole.READ
        if (preferEd && Build.VERSION.SDK_INT >= 33) {
            try {
                genEd25519(alias(role), auth)
                if (!auth) selfTest(role, SigAlg.ED25519)
                return SigAlg.ED25519
            } catch (e: Exception) {
                if (ks.containsAlias(alias(role))) ks.deleteEntry(alias(role))
            }
        }
        try {
            try {
                genP256(alias(role), auth, strongBox = true)
            } catch (e: StrongBoxUnavailableException) {
                genP256(alias(role), auth, strongBox = false)
            } catch (e: java.security.ProviderException) {
                // Some devices report StrongBox problems as a generic ProviderException.
                if (ks.containsAlias(alias(role))) ks.deleteEntry(alias(role))
                genP256(alias(role), auth, strongBox = false)
            }
        } catch (e: IllegalStateException) {
            throw KeySetupException("secure lock screen required", e)
        } catch (e: java.security.InvalidAlgorithmParameterException) {
            throw KeySetupException("secure lock screen / biometrics required", e)
        }
        return SigAlg.ES256
    }

    private fun selfTest(role: KeyRole, alg: SigAlg) {
        val s = Signature.getInstance(jcaName(alg)).apply { initSign(privateKey(role)); update(byteArrayOf(1, 2, 3)) }
        require(s.sign().size == 64)
    }

    private fun builder(alias: String, auth: Boolean): KeyGenParameterSpec.Builder =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).apply {
            if (auth) {
                setUserAuthenticationRequired(true)
                setInvalidatedByBiometricEnrollment(false)
                if (Build.VERSION.SDK_INT >= 30) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
        }

    private fun genEd25519(alias: String, auth: Boolean) {
        val spec = builder(alias, auth)
            .setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
            .setDigests(KeyProperties.DIGEST_NONE)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply { initialize(spec) }.generateKeyPair()
    }

    private fun genP256(alias: String, auth: Boolean, strongBox: Boolean) {
        val spec = builder(alias, auth)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply { initialize(spec) }.generateKeyPair()
    }

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private fun alias(role: KeyRole) = "mc_master_${role.wire}_v1"
        private fun algPref(role: KeyRole) = "alg_${role.wire}"
        fun jcaName(alg: SigAlg) = when (alg) {
            SigAlg.ED25519 -> "Ed25519"
            SigAlg.ES256 -> "SHA256withECDSA"
        }
    }
}
