package io.github.nevminhnh.mincontrol.master.data.api

import io.github.nevminhnh.mincontrol.master.util.Ulid
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthHeaderTest {
    @Test
    fun canonicalStringUsesBodyHashAndUnixSeconds() {
        val c = AuthHeader.canonical("get", "/v1/master/devices", "1795337400", ByteArray(0))
        assertEquals(
            "GET\n/v1/master/devices\n1795337400\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            c,
        )
    }

    @Test
    fun pathIncludesEncodedQuery() {
        val url = "https://mc.example.workers.dev/v1/master/devices/01J/web?q=to%C3%A1n%206&limit=50".toHttpUrl()
        assertEquals("/v1/master/devices/01J/web?q=to%C3%A1n%206&limit=50", AuthHeader.pathWithQuery(url))
        assertEquals("/v1/master/alerts", AuthHeader.pathWithQuery("https://x.dev/v1/master/alerts".toHttpUrl()))
    }

    @Test
    fun headerFormat() {
        val h = AuthHeader.header("3f9ac21d77e0b14a", "1795337400", ByteArray(64))
        assertTrue(h.startsWith("v1;3f9ac21d77e0b14a;1795337400;"))
        assertEquals(86, h.substringAfterLast(';').length)
    }

    @Test
    fun ulidShape() {
        val id = Ulid.next()
        assertTrue(id, Regex("^[0-9A-HJKMNP-TV-Z]{26}$").matches(id))
        assertEquals("00000000000000000000000000", Ulid.encode(0, ByteArray(10)))
    }
}
