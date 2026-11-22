package io.github.nevminhnh.mincontrol.master.ui.activity

import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.WebCategory
import io.github.nevminhnh.mincontrol.master.data.protocol.WebPolicy
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WebLogicTest {
    private fun ev(host: String, exe: String, ws: String, conn: Int, allowed: Boolean = true, type: String = "net.domain") = EventItem(
        id = "$host$ws$exe", deviceId = "d", userSid = "S-1", ts = ws, type = type,
        data = JsonObject(mapOf(
            "host" to JsonPrimitive(host), "exe" to JsonPrimitive(exe), "windowStart" to JsonPrimitive(ws),
            "connections" to JsonPrimitive(conn), "allowed" to JsonPrimitive(allowed),
        )),
    )

    @Test
    fun aggregatesByHostAndSortsByConnections() {
        val rows = DomainAggregator.aggregate(listOf(
            ev("a.com", "chrome.exe", "2026-11-22T08:00:00Z", 3),
            ev("B.com", "msedge.exe", "2026-11-22T09:00:00Z", 10),
            ev("a.com", "zalo.exe", "2026-11-22T07:00:00Z", 4),
            ev("a.com", "chrome.exe", "2026-11-22T10:00:00Z", 1, allowed = false),
            ev("skip.com", "x.exe", "2026-11-22T10:00:00Z", 99, type = "web.visit"),
        ))
        assertEquals(listOf("b.com", "a.com"), rows.map { it.host })
        val a = rows[1]
        assertEquals(8, a.connections)
        assertEquals(listOf("chrome.exe", "zalo.exe"), a.apps)
        assertEquals("2026-11-22T07:00:00Z", a.firstTs)
        assertEquals("2026-11-22T10:00:00Z", a.lastTs)
        assertTrue(a.blocked)
        assertFalse(rows[0].blocked)
    }

    @Test
    fun searchMatchesHostOrApp() {
        val evs = listOf(ev("poki.com", "chrome.exe", "2026-11-22T08:00:00Z", 2), ev("zalo.me", "zalo.exe", "2026-11-22T08:00:00Z", 5))
        assertEquals(listOf("poki.com"), DomainAggregator.aggregate(evs, "POK").map { it.host })
        assertEquals(listOf("zalo.me"), DomainAggregator.aggregate(evs, "zalo.exe").map { it.host })
        assertTrue(DomainAggregator.aggregate(evs, "nope").isEmpty())
    }

    @Test
    fun categoryAndReasonLabels() {
        assertEquals("Người lớn", WebLabels.category("adult"))
        assertEquals("VPN/Proxy", WebLabels.category("proxy-vpn"))
        assertEquals("Mã độc", WebLabels.category("malware"))
        assertEquals("lạ", WebLabels.category("lạ"))
        assertNull(WebLabels.category(null))
        assertEquals("DNS mã hoá", WebLabels.reason("doh"))
        assertEquals("Cổng không được phép", WebLabels.reason("port"))
        assertEquals("Ngoài giờ cho phép", WebLabels.reason("schedule"))
        assertEquals("Cờ bạc · Danh sách chặn", WebLabels.blockedSubtitle("gambling", "blocklist"))
        assertNull(WebLabels.blockedSubtitle(null, null))
    }

    @Test
    fun everyCategoryHasVietnameseNameAndDescription() {
        WebCategory.entries.forEach {
            assertTrue(it.label.isNotBlank())
            assertTrue(WebLabels.categoryDescription(it).isNotBlank())
        }
        assertEquals("VPN/Proxy", WebCategory.PROXY_VPN.label)
    }

    @Test
    fun domainQuickActionsMoveBetweenLists() {
        val w = WebPolicy(blockDomains = listOf("x.com"), allowDomains = listOf("y.com"))
        val blocked = DomainPolicy.block(w, "Y.com")
        assertEquals(listOf("x.com", "y.com"), blocked.blockDomains)
        assertTrue(blocked.allowDomains.isEmpty())
        val allowed = DomainPolicy.allow(w, "x.com")
        assertEquals(listOf("y.com", "x.com"), allowed.allowDomains)
        assertTrue(allowed.blockDomains.isEmpty())
        assertEquals(w.blockDomains, DomainPolicy.block(w, "x.com").blockDomains)
    }

    @Test
    fun registrableDomainHeuristic() {
        assertEquals("example.com", DomainPolicy.registrable("www.example.com"))
        assertEquals("example.com", DomainPolicy.registrable("a.b.example.com"))
        assertEquals("example.com", DomainPolicy.registrable("Example.com"))
        assertEquals("bbc.co.uk", DomainPolicy.registrable("news.bbc.co.uk"))
        assertEquals("vnexpress.net", DomainPolicy.registrable("m.vnexpress.net"))
        assertEquals("abc.com.vn", DomainPolicy.registrable("www.abc.com.vn"))
        assertEquals("hust.edu.vn", DomainPolicy.registrable("sis.hust.edu.vn"))
        assertEquals("mof.gov.vn", DomainPolicy.registrable("mof.gov.vn"))
        assertEquals("a.org.vn", DomainPolicy.registrable("x.y.a.org.vn"))
        assertEquals("a.net.vn", DomainPolicy.registrable("a.net.vn"))
        assertEquals("localhost", DomainPolicy.registrable("localhost"))
        assertEquals("*.example.com", DomainPolicy.wildcardFor("www.example.com"))
    }

    @Test
    fun blockedStateAndUnblock() {
        val w = WebPolicy(blockDomains = listOf("*.poki.com", "exact.org"))
        assertTrue(DomainPolicy.isBlocked(w, "poki.com"))
        assertTrue(DomainPolicy.isBlocked(w, "games.poki.com"))
        assertTrue(DomainPolicy.isBlocked(w, "exact.org"))
        assertFalse(DomainPolicy.isBlocked(w, "www.exact.org"))
        assertFalse(DomainPolicy.isBlocked(w, "notpoki.com"))
        assertEquals(listOf("exact.org"), DomainPolicy.unblock(w, "games.poki.com").blockDomains)
        assertEquals(listOf("*.poki.com", "exact.org", "*.example.co.uk"), DomainPolicy.blockRegistrable(w, "www.example.co.uk").blockDomains)
        assertEquals("www.a.com", DomainPolicy.hostOf("https://www.a.com:8080/x?y", null))
        assertEquals("h.com", DomainPolicy.hostOf("https://z.com/", "H.com"))
    }
}
