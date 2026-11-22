package io.github.nevminhnh.mincontrol.master.security

import io.github.nevminhnh.mincontrol.master.util.hexToBytes
import io.github.nevminhnh.mincontrol.master.util.toHex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Known-answer tests. Keys are the RFC 7748 §6.1 Alice/Bob pair (also used by NaCl's own tests);
 * the sealed box below was produced by an independent implementation (Python) and cross-checked
 * against NaCl's `firstkey` (core1) and `box` test vectors.
 */
class SealedBoxTest {
    private val aliceSk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".hexToBytes()
    private val alicePk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a".hexToBytes()
    private val bobSk = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb".hexToBytes()
    private val bobPk = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f".hexToBytes()

    @Test
    fun publicKeysMatchRfc7748() {
        assertArrayEquals(alicePk, SealedBox.publicKey(aliceSk))
        assertArrayEquals(bobPk, SealedBox.publicKey(bobSk))
    }

    @Test
    fun beforeNmMatchesNaclFirstKey() {
        assertEquals("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389", SealedBox.beforeNm(aliceSk, bobPk).toHex())
        assertEquals("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389", SealedBox.beforeNm(bobSk, alicePk).toHex())
    }

    @Test
    fun secretBoxMatchesNaclBoxVector() {
        val nonce = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37".hexToBytes()
        val msg = ("be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705").hexToBytes()
        val k = SealedBox.beforeNm(aliceSk, bobPk)
        val box = SealedBox.secretBox(msg, nonce, k)
        assertEquals("f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce", box.copyOfRange(0, 32).toHex())
        assertArrayEquals(msg, SealedBox.secretBoxOpen(box, nonce, k))
    }

    @Test
    fun opensKnownSealedBox() {
        val sealed = ("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f754675dc94fa83f98203038867d2f696c6c6e896afef3fca118e705b6c9750f421cd63df34b465c655b66093c2e8f8c8b7d0b6d0d2310abe7d54b48fa6115a147b93c12a78d454ef").hexToBytes()
        val expected = "4d696e436f6e74726f6c207365616c65642d626f78204b415420ffd8ffe0206a7065672d6973682062797465732030313233343536373839".hexToBytes()
        assertArrayEquals(expected, SealedBox.open(sealed, aliceSk, alicePk))
        // Sealing with the same ephemeral key must reproduce the exact bytes.
        assertArrayEquals(sealed, SealedBox.seal(expected, alicePk, ephemeralSk = bobSk))
    }

    @Test
    fun roundTripAndTamperDetection() {
        val (sk, pk) = SealedBox.generateKeyPair()
        val msg = ByteArray(5000) { (it * 7).toByte() }
        val sealed = SealedBox.seal(msg, pk)
        assertEquals(msg.size + SealedBox.SEAL_BYTES, sealed.size)
        assertArrayEquals(msg, SealedBox.open(sealed, sk, pk))
        sealed[100] = (sealed[100].toInt() xor 1).toByte()
        val failed = runCatching { SealedBox.open(sealed, sk, pk) }.exceptionOrNull()
        assertTrue(failed is SealedBox.OpenException)
    }

    @Test
    fun backupRoundTripAndWrongPassphrase() {
        val (sk, _) = SealedBox.generateKeyPair()
        val small = SealKeyBackup.Params(memoryKiB = 64, iterations = 1, parallelism = 1)
        val text = SealKeyBackup.export(sk, "correct horse battery".toCharArray(), small)
        assertArrayEquals(sk, SealKeyBackup.import(text, "correct horse battery".toCharArray()))
        val wrong = runCatching { SealKeyBackup.import(text, "wrong".toCharArray()) }.exceptionOrNull()
        assertTrue(wrong is SealKeyBackup.BadPassphrase)
    }
}
