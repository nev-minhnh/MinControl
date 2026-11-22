package io.github.nevminhnh.mincontrol.master.util

import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Base64

/** Base64url (RFC 4648 §5) without padding, as used everywhere on the wire. */
object B64Url {
    private val enc = Base64.getUrlEncoder().withoutPadding()
    private val dec = Base64.getUrlDecoder()
    fun encode(bytes: ByteArray): String = enc.encodeToString(bytes)
    fun decode(text: String): ByteArray = dec.decode(text.trimEnd('='))
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "odd hex length" }
    return ByteArray(length / 2) { i -> substring(2 * i, 2 * i + 2).toInt(16).toByte() }
}

fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** RFC 3339 UTC with `Z`, whole seconds (`2026-11-22T08:50:00Z`). */
fun Instant.toRfc3339(): String = truncatedTo(ChronoUnit.SECONDS).toString()

/** ULID: 48-bit ms timestamp + 80 random bits, Crockford base32 (26 chars). */
object Ulid {
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    private val random = SecureRandom()

    fun next(nowMs: Long = System.currentTimeMillis()): String {
        val rnd = ByteArray(10).also(random::nextBytes)
        return encode(nowMs, rnd)
    }

    fun encode(timeMs: Long, randomness: ByteArray): String {
        require(randomness.size == 10)
        val sb = StringBuilder(26)
        var t = timeMs
        val time = CharArray(10)
        for (i in 9 downTo 0) {
            time[i] = ALPHABET[(t and 31).toInt()]; t = t ushr 5
        }
        sb.append(time)
        // 80 bits -> 16 chars of 5 bits.
        var bits = 0L
        var nBits = 0
        for (b in randomness) {
            bits = (bits shl 8) or (b.toLong() and 0xff)
            nBits += 8
            while (nBits >= 5) {
                nBits -= 5
                sb.append(ALPHABET[((bits ushr nBits) and 31).toInt()])
            }
        }
        return sb.toString()
    }
}
