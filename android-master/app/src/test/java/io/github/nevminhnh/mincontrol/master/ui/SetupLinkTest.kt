package io.github.nevminhnh.mincontrol.master.ui

import io.github.nevminhnh.mincontrol.master.ui.setup.SetupLink
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class SetupLinkTest {
    @Test fun parsesEncodedUrl() {
        val p = SetupLink.parse("mincontrol://setup?v=1&u=https%3A%2F%2Fexample.com%3A8443&s=abc-123")!!
        assertEquals("https://example.com:8443", p.serverUrl)
        assertEquals("abc-123", p.secret)
    }
    @Test fun rejectsWrongVersionSchemeOrMissing() {
        assertNull(SetupLink.parse("mincontrol://setup?v=2&u=https%3A%2F%2Fa.b&s=x"))
        assertNull(SetupLink.parse("https://setup?v=1&u=https%3A%2F%2Fa.b&s=x"))
        assertNull(SetupLink.parse("mincontrol://setup?v=1&u=https%3A%2F%2Fa.b"))
        assertNull(SetupLink.parse("mincontrol://setup?v=1&u=ftp%3A%2F%2Fa.b&s=x"))
        assertNull(SetupLink.parse(null))
    }
    @Test fun toStringHidesSecret() {
        assertFalse(SetupLink.parse("mincontrol://setup?v=1&u=https%3A%2F%2Fa.b&s=topsecret")!!.toString().contains("topsecret"))
    }
}
