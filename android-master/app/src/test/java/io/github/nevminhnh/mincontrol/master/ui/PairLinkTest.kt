package io.github.nevminhnh.mincontrol.master.ui

import io.github.nevminhnh.mincontrol.master.data.api.AuthHeader
import io.github.nevminhnh.mincontrol.master.ui.pairing.ClaimCode
import io.github.nevminhnh.mincontrol.master.ui.pairing.Fingerprint
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairLink
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairLinkTest {
    private val id = "AbCdEfGhIjKlMnOpQrStUw"

    @Test fun parsesQr() {
        val p = PairLink.parse("mincontrol://pair?v=1&c=$id&f=3f9ac21d77e0")!!
        assertEquals(id, p.claimId)
        assertEquals("3F9AC21D77E0", p.fp)
    }

    @Test fun rejectsBadQr() {
        assertNull(PairLink.parse("mincontrol://pair?v=3&c=$id&f=3f9ac21d77e0"))
        assertNull(PairLink.parse("mincontrol://setup?v=1&c=$id&f=3f9ac21d77e0"))
        assertNull(PairLink.parse("https://pair?v=1&c=$id&f=3f9ac21d77e0"))
        assertNull(PairLink.parse("mincontrol://pair?v=1&c=$id"))
        assertNull(PairLink.parse("mincontrol://pair?v=1&c=$id&f=zzzz"))
        assertNull(PairLink.parse("mincontrol://pair?v=1&c=x&f=3f9ac21d77e0"))
        assertNull(PairLink.parse(null))
    }

    @Test fun fingerprintFormatAndCompare() {
        assertEquals("3F9A-C21D-77E0", Fingerprint.format("3f9ac21d77e0"))
        assertEquals("3F9A-C21D-77E0", Fingerprint.format("3F9A-C21D-77E0"))
        assertNull(Fingerprint.format("3f9ac21d77e"))
        assertTrue(Fingerprint.matches("3f9ac21d77e0", "3F9A-C21D-77E0"))
        assertFalse(Fingerprint.matches("3f9ac21d77e0", "3f9ac21d77e1"))
        assertFalse(Fingerprint.matches("", ""))
        assertFalse(Fingerprint.matches(null, "3f9ac21d77e0"))
    }

    @Test fun claimCodeNormalises() {
        assertEquals("7KQ3M9XA", ClaimCode.normalize("7kq3-m9xa"))
        assertEquals("11100000", ClaimCode.normalize("ILIOOOOO"))
        assertNull(ClaimCode.normalize("7KQ3M9X"))
        assertNull(ClaimCode.normalize("7KQ3M9XU"))
    }

    @Test fun approveIsSignedWithSignKeyOverCanonicalPost() {
        val c = AuthHeader.approveCanonical(id, "1795337400")
        assertEquals(
            "POST\n/v1/master/claims/$id/approve\n1795337400\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            c,
        )
        val h = AuthHeader.header("SIGNKEYID0000001", "1795337400", ByteArray(64))
        assertTrue(h.startsWith("v1;SIGNKEYID0000001;1795337400;"))
    }
}
