package io.github.nevminhnh.mincontrol.master.ui

import io.github.nevminhnh.mincontrol.master.data.protocol.ApiJson
import io.github.nevminhnh.mincontrol.master.data.protocol.CloudUsage
import io.github.nevminhnh.mincontrol.master.data.protocol.DomainsResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.MasterSettings
import io.github.nevminhnh.mincontrol.master.ui.activity.DomainAggregator
import io.github.nevminhnh.mincontrol.master.ui.settings.CloudUsageLogic
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class R16Test {
    private fun ev(id: String, host: String, exe: String, ts: String, n: Int = 1, allowed: Boolean = true, type: String = "net.domain") = EventItem(
        id = id, deviceId = "d", userSid = "S-1", ts = ts, type = type,
        data = JsonObject(mapOf("host" to JsonPrimitive(host), "exe" to JsonPrimitive(exe), "connections" to JsonPrimitive(n), "allowed" to JsonPrimitive(allowed))),
    )

    private val base = DomainAggregator.fromItems(ApiJson.decodeFromString(DomainsResponse.serializer(), """
        {"items":[{"host":"A.com","apps":["chrome.exe"],"connections":5,"bytesOut":1,"bytesIn":2,"blocked":false,"firstSeen":"2026-11-23T01:00:00Z","lastSeen":"2026-11-23T02:00:00Z"},
                  {"host":"b.com","apps":[],"connections":2,"blocked":true,"firstSeen":"2026-11-23T01:30:00Z","lastSeen":"2026-11-23T01:40:00Z","extra":1}]}""").items)

    @Test fun parsesDomains() {
        assertEquals(listOf("a.com", "b.com"), base.map { it.host })
        assertEquals(5, base[0].connections); assertTrue(base[1].blocked)
    }

    @Test fun liveMergesIntoAggregates() {
        val seen = HashSet<String>()
        val out = DomainAggregator.mergeLive(base, listOf(
            ev("1", "a.com", "zalo.exe", "2026-11-23T03:00:00Z", 2),
            ev("2", "new.com", "edge.exe", "2026-11-23T03:01:00Z", 9, allowed = false),
            ev("3", "x.com", "x.exe", "2026-11-23T03:02:00Z", type = "web.visit"),
        ), seen)
        assertEquals(listOf("new.com", "a.com", "b.com"), out.map { it.host })
        val a = out[1]
        assertEquals(7, a.connections); assertEquals(listOf("chrome.exe", "zalo.exe"), a.apps)
        assertEquals("2026-11-23T01:00:00Z", a.firstTs); assertEquals("2026-11-23T03:00:00Z", a.lastTs)
        assertTrue(out[0].blocked)
        val again = DomainAggregator.mergeLive(out, listOf(ev("1", "a.com", "zalo.exe", "2026-11-23T03:00:00Z", 2)), seen)
        assertEquals(out, again)
        assertEquals(listOf("a.com"), DomainAggregator.filter(out, "ZALO").map { it.host })
    }

    @Test fun settingsAndUsage() {
        val s = ApiJson.decodeFromString(MasterSettings.serializer(), """{"notifyLogon":true}""")
        assertTrue(s.notifyLogon); assertFalse(s.notifyLogoff)
        assertEquals("""{"notifyLogon":true,"notifyLogoff":false}""", ApiJson.encodeToString(MasterSettings.serializer(), s))
        val u = ApiJson.decodeFromString(CloudUsage.serializer(), """{"day":"2026-11-23","rowsWritten":72500,"limit":100000,"percent":72.5}""")
        assertEquals("72 500 / 100 000 dòng ghi", CloudUsageLogic.label(u))
        assertEquals(0.725f, CloudUsageLogic.fraction(u), 0.001f)
        assertEquals(1, CloudUsageLogic.level(u))
        assertEquals(2, CloudUsageLogic.level(u.copy(rowsWritten = 95000, percent = 95.0)))
    }
}
