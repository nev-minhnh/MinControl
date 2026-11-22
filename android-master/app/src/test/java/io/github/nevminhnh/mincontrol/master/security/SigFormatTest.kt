package io.github.nevminhnh.mincontrol.master.security

import io.github.nevminhnh.mincontrol.master.util.hexToBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class SigFormatTest {

    @Test
    fun keyIdIsFirst16HexOfSha256OfRawKey() {
        // RFC 8032 test 1 public key; expected value computed independently (Python hashlib).
        val pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".hexToBytes()
        assertEquals("21fe31dfa154a261", SigFormat.keyId(pk))
        assertEquals("21FE · 31DF · A154", SigFormat.fingerprint("21fe31dfa154a261"))
    }

    @Test
    fun derWithLeadingZeroAndShortIntegerConvertsToFixed64() {
        // r has its high bit set (DER adds 0x00), s is only 31 bytes long (needs left padding).
        val r = ByteArray(32) { 0x80.toByte() }
        val s = ByteArray(31) { 0x11 }
        val der = byteArrayOf(0x30, (2 + 33 + 2 + 31).toByte(), 0x02, 33, 0x00) + r + byteArrayOf(0x02, 31) + s
        val p1363 = SigFormat.derToP1363(der)
        assertEquals(64, p1363.size)
        assertArrayEquals(r, p1363.copyOfRange(0, 32))
        assertEquals(0, p1363[32].toInt())
        assertArrayEquals(s, p1363.copyOfRange(33, 64))
        assertArrayEquals(der, SigFormat.p1363ToDer(p1363))
    }

    @Test
    fun realEs256SignaturesRoundTripAndVerify() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val raw = SigFormat.p256Uncompressed(kp.public as ECPublicKey)
        assertEquals(65, raw.size)
        assertEquals(4, raw[0].toInt())
        repeat(50) { i ->
            val msg = "payload-$i".toByteArray()
            val der = Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(msg) }.sign()
            val p1363 = normalise(io.github.nevminhnh.mincontrol.master.data.protocol.SigAlg.ES256, der)
            assertEquals(64, p1363.size)
            val ok = Signature.getInstance("SHA256withECDSA").apply { initVerify(kp.public); update(msg) }.verify(SigFormat.p1363ToDer(p1363))
            assertTrue("signature $i must verify after P1363 round trip", ok)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsGarbage() {
        SigFormat.derToP1363(byteArrayOf(0x31, 0x00))
    }
}
