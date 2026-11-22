package io.github.nevminhnh.mincontrol.master.security

import io.github.nevminhnh.mincontrol.master.util.sha256
import io.github.nevminhnh.mincontrol.master.util.toHex
import java.math.BigInteger
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

/** Signature / key encodings required by protocol/README.md. Pure JVM so it is unit-testable. */
object SigFormat {

    /** keyId = first 16 hex chars of SHA-256 over the raw public key (Ed25519: 32 B, P-256: 65 B SEC1). */
    fun keyId(rawPublicKey: ByteArray): String = sha256(rawPublicKey).toHex().substring(0, 16)

    /** Human fingerprint shown on the pairing screen, e.g. `3F9A · C21D · 77E0`. */
    fun fingerprint(keyId: String): String = keyId.take(12).uppercase().chunked(4).joinToString(" · ")

    /**
     * Converts an ASN.1 DER ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }` into IEEE P1363 `r || s`
     * with each integer left-padded to [size] bytes (32 for P-256).
     */
    fun derToP1363(der: ByteArray, size: Int = 32): ByteArray {
        var i = 0
        require(der[i++].toInt() == 0x30) { "not a DER SEQUENCE" }
        val seqLen = readLen(der, i).also { i = it.second }.first
        require(i + seqLen == der.size) { "bad DER length" }
        val r = readInt(der, i).also { i = it.second }.first
        val s = readInt(der, i).also { i = it.second }.first
        require(i == der.size) { "trailing bytes in DER" }
        return toFixed(r, size) + toFixed(s, size)
    }

    /** Inverse of [derToP1363]; used by tests and for verifying with JCA. */
    fun p1363ToDer(sig: ByteArray): ByteArray {
        require(sig.size % 2 == 0)
        val half = sig.size / 2
        val r = BigInteger(1, sig.copyOfRange(0, half)).toByteArray()
        val s = BigInteger(1, sig.copyOfRange(half, sig.size)).toByteArray()
        val body = derInt(r) + derInt(s)
        return byteArrayOf(0x30) + derLen(body.size) + body
    }

    /** Uncompressed SEC1 point `04 || X || Y` (65 bytes) for a P-256 key. */
    fun p256Uncompressed(key: ECPublicKey): ByteArray =
        byteArrayOf(4) + toFixed(key.w.affineX.toByteArray(), 32) + toFixed(key.w.affineY.toByteArray(), 32)

    /** Raw 32-byte Ed25519 public key from its X.509 SubjectPublicKeyInfo encoding (last 32 bytes). */
    fun ed25519Raw(key: PublicKey): ByteArray {
        val enc = key.encoded
        require(enc.size >= 32)
        return enc.copyOfRange(enc.size - 32, enc.size)
    }

    private fun readLen(b: ByteArray, at: Int): Pair<Int, Int> {
        var i = at
        val first = b[i++].toInt() and 0xff
        if (first < 0x80) return first to i
        val n = first and 0x7f
        require(n in 1..2) { "unsupported DER length" }
        var len = 0
        repeat(n) { len = (len shl 8) or (b[i++].toInt() and 0xff) }
        return len to i
    }

    private fun readInt(b: ByteArray, at: Int): Pair<ByteArray, Int> {
        var i = at
        require(b[i++].toInt() == 0x02) { "not a DER INTEGER" }
        val (len, next) = readLen(b, i)
        i = next
        require(len in 1..33 && i + len <= b.size) { "bad INTEGER length" }
        return b.copyOfRange(i, i + len) to i + len
    }

    /** Strips sign/leading zero bytes and left-pads to [size]. */
    private fun toFixed(v: ByteArray, size: Int): ByteArray {
        var start = 0
        while (start < v.size - 1 && v[start].toInt() == 0) start++
        val trimmed = v.copyOfRange(start, v.size)
        require(trimmed.size <= size) { "integer too large" }
        return ByteArray(size - trimmed.size) + trimmed
    }

    private fun derInt(v: ByteArray): ByteArray = byteArrayOf(0x02) + derLen(v.size) + v
    private fun derLen(n: Int): ByteArray = if (n < 0x80) byteArrayOf(n.toByte()) else byteArrayOf(0x81.toByte(), n.toByte())
}
