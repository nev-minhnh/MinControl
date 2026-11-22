package io.github.nevminhnh.mincontrol.master.security

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * libsodium-compatible `crypto_box_seal` / `crypto_box_seal_open` (X25519 + XSalsa20-Poly1305),
 * built on BouncyCastle primitives.
 *
 * sealed = epk(32) || mac(16) || ciphertext; nonce = BLAKE2b-192(epk || recipientPk);
 * key = HSalsa20(X25519(sk, epk), 0^16) (= crypto_box_beforenm).
 */
object SealedBox {
    const val KEY_BYTES = 32
    const val MAC_BYTES = 16
    const val SEAL_BYTES = KEY_BYTES + MAC_BYTES

    class OpenException(message: String) : Exception(message)

    fun generateKeyPair(random: SecureRandom = SecureRandom()): Pair<ByteArray, ByteArray> {
        val sk = ByteArray(KEY_BYTES).also { X25519.generatePrivateKey(random, it) }
        return sk to publicKey(sk)
    }

    fun publicKey(sk: ByteArray): ByteArray = ByteArray(KEY_BYTES).also { X25519.generatePublicKey(sk, 0, it, 0) }

    fun open(sealed: ByteArray, recipientSk: ByteArray, recipientPk: ByteArray): ByteArray {
        if (sealed.size < SEAL_BYTES) throw OpenException("sealed box too short")
        val epk = sealed.copyOfRange(0, KEY_BYTES)
        val nonce = sealNonce(epk, recipientPk)
        val k = beforeNm(recipientSk, epk)
        return secretBoxOpen(sealed.copyOfRange(KEY_BYTES, sealed.size), nonce, k)
    }

    /** Sealing (device side); used by tests and kept for completeness. */
    fun seal(message: ByteArray, recipientPk: ByteArray, ephemeralSk: ByteArray? = null): ByteArray {
        val esk = ephemeralSk ?: generateKeyPair().first
        val epk = publicKey(esk)
        val nonce = sealNonce(epk, recipientPk)
        val k = beforeNm(esk, recipientPk)
        return epk + secretBox(message, nonce, k)
    }

    fun beforeNm(sk: ByteArray, pk: ByteArray): ByteArray {
        val shared = ByteArray(KEY_BYTES)
        if (!X25519.calculateAgreement(sk, 0, pk, 0, shared, 0)) throw OpenException("weak public key")
        return hSalsa20(shared, ByteArray(16))
    }

    fun secretBox(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        val engine = xsalsa(key, nonce)
        val polyKey = ByteArray(32).also { engine.processBytes(ByteArray(32), 0, 32, it, 0) }
        val c = ByteArray(message.size).also { engine.processBytes(message, 0, message.size, it, 0) }
        return poly1305(polyKey, c) + c
    }

    fun secretBoxOpen(box: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        if (box.size < MAC_BYTES) throw OpenException("box too short")
        val engine = xsalsa(key, nonce)
        val polyKey = ByteArray(32).also { engine.processBytes(ByteArray(32), 0, 32, it, 0) }
        val mac = box.copyOfRange(0, MAC_BYTES)
        val c = box.copyOfRange(MAC_BYTES, box.size)
        if (!MessageDigest.isEqual(mac, poly1305(polyKey, c))) throw OpenException("authentication failed")
        return ByteArray(c.size).also { engine.processBytes(c, 0, c.size, it, 0) }
    }

    fun sealNonce(epk: ByteArray, recipientPk: ByteArray): ByteArray {
        val d = Blake2bDigest(null, 24, null, null)
        d.update(epk, 0, epk.size)
        d.update(recipientPk, 0, recipientPk.size)
        return ByteArray(24).also { d.doFinal(it, 0) }
    }

    private fun xsalsa(key: ByteArray, nonce: ByteArray) =
        XSalsa20Engine().apply { init(true, ParametersWithIV(KeyParameter(key), nonce)) }

    private fun poly1305(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Poly1305()
        mac.init(KeyParameter(key))
        mac.update(msg, 0, msg.size)
        return ByteArray(16).also { mac.doFinal(it, 0) }
    }

    /** HSalsa20 core (20 rounds, no feed-forward), output words 0,5,10,15,6,7,8,9. */
    fun hSalsa20(key: ByteArray, input16: ByteArray): ByteArray {
        require(key.size == 32 && input16.size == 16)
        val x = IntArray(16)
        x[0] = 0x61707865; x[5] = 0x3320646e; x[10] = 0x79622d32; x[15] = 0x6b206574
        for (i in 0 until 4) {
            x[1 + i] = le32(key, 4 * i)
            x[11 + i] = le32(key, 16 + 4 * i)
            x[6 + i] = le32(input16, 4 * i)
        }
        repeat(10) {
            qr(x, 0, 4, 8, 12); qr(x, 5, 9, 13, 1); qr(x, 10, 14, 2, 6); qr(x, 15, 3, 7, 11)
            qr(x, 0, 1, 2, 3); qr(x, 5, 6, 7, 4); qr(x, 10, 11, 8, 9); qr(x, 15, 12, 13, 14)
        }
        val out = ByteArray(32)
        intArrayOf(0, 5, 10, 15, 6, 7, 8, 9).forEachIndexed { j, w -> putLe32(out, 4 * j, x[w]) }
        return out
    }

    private fun qr(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[b] = x[b] xor Integer.rotateLeft(x[a] + x[d], 7)
        x[c] = x[c] xor Integer.rotateLeft(x[b] + x[a], 9)
        x[d] = x[d] xor Integer.rotateLeft(x[c] + x[b], 13)
        x[a] = x[a] xor Integer.rotateLeft(x[d] + x[c], 18)
    }

    private fun le32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or
            ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)

    private fun putLe32(b: ByteArray, o: Int, v: Int) {
        b[o] = v.toByte(); b[o + 1] = (v ushr 8).toByte(); b[o + 2] = (v ushr 16).toByte(); b[o + 3] = (v ushr 24).toByte()
    }
}
