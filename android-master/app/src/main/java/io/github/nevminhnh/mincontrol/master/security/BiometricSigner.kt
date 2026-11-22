package io.github.nevminhnh.mincontrol.master.security

import android.os.Build
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class BiometricCancelledException(message: String) : Exception(message)

/** Result of a biometric-confirmed signature. */
class SignedBytes(val signature: ByteArray, val session: SignSession)

/**
 * Runs BiometricPrompt (BIOMETRIC_STRONG, or device credential on API 30+) with a CryptoObject wrapping
 * the `sign` key's [java.security.Signature], then signs [data] exactly once.
 */
class BiometricSigner(private val keys: MasterKeyStore) {

    suspend fun sign(activity: FragmentActivity, title: String, subtitle: String?, data: ByteArray): SignedBytes =
        withContext(Dispatchers.Main) {
            val session = keys.startSign()
            suspendCancellableCoroutine { cont ->
                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val sig = result.cryptoObject?.signature
                        if (sig == null) {
                            cont.resumeWithException(IllegalStateException("no crypto object"))
                            return
                        }
                        val out = runCatching { SignSession(sig, session.alg, session.keyId).finish(data) }
                        out.onSuccess { if (cont.isActive) cont.resume(SignedBytes(it, session)) }
                            .onFailure { if (cont.isActive) cont.resumeWithException(it) }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (cont.isActive) cont.resumeWithException(BiometricCancelledException(errString.toString()))
                    }
                }
                val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .apply { subtitle?.let(::setSubtitle) }
                    .apply {
                        if (Build.VERSION.SDK_INT >= 30) {
                            setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                        } else {
                            setAllowedAuthenticators(BIOMETRIC_STRONG)
                            setNegativeButtonText("Hủy")
                        }
                    }
                    .setConfirmationRequired(false)
                    .build()
                prompt.authenticate(info, BiometricPrompt.CryptoObject(session.signature))
                cont.invokeOnCancellation { prompt.cancelAuthentication() }
            }
        }
}
