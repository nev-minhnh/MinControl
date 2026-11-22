package io.github.nevminhnh.mincontrol.master.data.protocol

import io.github.nevminhnh.mincontrol.master.ui.Fmt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class ApiRound2Test {
    @Test
    fun alertAckedAt() {
        val acked = ApiJson.decodeFromString(AlertItem.serializer(),
            """{"id":"a","deviceId":"d","ts":"2026-11-22T10:00:00Z","type":"request.exe_approval","ackedAt":1790000000,"data":{"sha256":"ab","title":"t","body":"b","eventId":"e"}}""")
        assertTrue(acked.isAcked)
        val open = ApiJson.decodeFromString(AlertItem.serializer(),
            """{"id":"a","deviceId":"d","ts":"2026-11-22T10:00:00Z","type":"x","ackedAt":null}""")
        assertFalse(open.isAcked)
        val legacy = ApiJson.decodeFromString(AlertItem.serializer(), """{"id":"a","deviceId":"d","ts":"2026-11-22T10:00:00Z","type":"x"}""")
        assertFalse(legacy.isAcked)
    }

    @Test
    fun searchItemAndForegroundStartedAt() {
        val w = ApiJson.decodeFromString(WebItem.serializer(), """{"ts":"2026-11-22T10:00:00Z","kind":"search","query":"minecraft skins","engine":"google"}""")
        assertEquals("minecraft skins", w.query)
        assertEquals("google", w.engine)
        val u = ApiJson.decodeFromString(UserState.serializer(), """{"sid":"S-1","foregroundExe":"zalo.exe","foregroundStartedAt":"2026-11-22T10:00:00Z"}""")
        assertEquals("2026-11-22T10:00:00Z", u.foregroundStartedAt)
        assertNull(ApiJson.decodeFromString(UserState.serializer(), """{"sid":"S-1"}""").foregroundStartedAt)
    }

    @Test
    fun openMinutesAndEngine() {
        val now = Instant.parse("2026-11-22T10:23:30Z")
        assertEquals(23, Fmt.openMinutes("2026-11-22T10:00:00Z", now))
        assertEquals(0, Fmt.openMinutes("2026-11-22T10:30:00Z", now))
        assertNull(Fmt.openMinutes(null, now))
        assertEquals("Google", Fmt.engineLabel("google"))
        assertEquals("Bing", Fmt.engineLabel(null, "www.bing.com"))
    }
}
