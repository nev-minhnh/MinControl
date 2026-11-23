package io.github.nevminhnh.mincontrol.master.ui.activity

import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.WebItem
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BlockTextTest {
    private fun web(vararg kv: Pair<String, Any?>) = BlockFields(app = false, ts = "2026-11-23T08:00:00Z").let { b ->
        val m = kv.toMap()
        b.copy(host = m["host"] as String?, url = m["url"] as String?, action = m["action"] as String?, title = m["title"] as String?,
            query = m["query"] as String?, engine = m["engine"] as String?, count = m["count"] as Int?, rule = m["rule"] as String?,
            keyword = m["keyword"] as String?, service = m["service"] as String?, category = m["category"] as String?,
            reason = m["reason"] as String?, exe = m["exe"] as String?)
    }

    private val names: (String) -> String? = { mapOf("tiktok" to "TikTok", "roblox" to "Roblox")[it] }

    @Test fun minimalWebBlock() {
        val t = BlockTextBuilder.build(web("host" to "poki.com"))
        assertEquals("Đã chặn", t.headline)
        assertEquals("poki.com", t.title)
        assertTrue(t.details.isEmpty())
    }

    @Test fun keywordTabCloseWithEverything() {
        val t = BlockTextBuilder.build(
            web("host" to "www.youtube.com", "action" to "close_tab", "title" to "Hướng dẫn đánh bài", "keyword" to "đánh bài",
                "reason" to "keyword", "exe" to "msedge.exe", "count" to 5), names,
        )
        assertEquals("Đã chặn · Đóng tab", t.headline)
        assertEquals("www.youtube.com", t.title)
        assertEquals(listOf("“Hướng dẫn đánh bài”", "Từ khóa: đánh bài", "Trình duyệt: Edge", "Đã chặn 5 lần"), t.details)
    }

    @Test fun searchQueryBlock() {
        val t = BlockTextBuilder.build(web("query" to "cá độ bóng đá", "engine" to "google", "keyword" to "cá độ", "reason" to "keyword", "exe" to "chrome.exe"))
        assertEquals("“cá độ bóng đá”", t.title)
        assertEquals(listOf("Tìm kiếm Google: “cá độ bóng đá”", "Từ khóa: cá độ", "Trình duyệt: Chrome"), t.details)
    }

    @Test fun searchWithUnknownEngine() {
        val t = BlockTextBuilder.build(web("host" to "search.example", "query" to "x"))
        assertEquals(listOf("Tìm kiếm: “x”"), t.details)
    }

    @Test fun serviceAndCategory() {
        val t = BlockTextBuilder.build(web("host" to "www.tiktok.com", "service" to "tiktok", "category" to "social", "reason" to "service"), names)
        assertEquals(listOf("Dịch vụ: TikTok", "Danh mục: Mạng xã hội"), t.details)
        val unknown = BlockTextBuilder.build(web("host" to "x.com", "service" to "newsvc"))
        assertEquals(listOf("Dịch vụ: Newsvc"), unknown.details)
    }

    @Test fun reasonShownOnlyWhenNotImplied() {
        assertEquals(listOf("Lý do: Danh sách chặn"), BlockTextBuilder.build(web("host" to "a.com", "reason" to "blocklist")).details)
        assertEquals(listOf("Danh mục: Cờ bạc"), BlockTextBuilder.build(web("host" to "a.com", "category" to "gambling", "reason" to "category")).details)
        assertEquals(listOf("Lý do: Từ khóa bị cấm"), BlockTextBuilder.build(web("host" to "a.com", "reason" to "keyword")).details)
        assertEquals(listOf("Lý do: DNS mã hoá"), BlockTextBuilder.build(web("host" to "a.com", "reason" to "doh")).details)
    }

    @Test fun ruleUnknownActionUnknownBrowserAndCountOne() {
        val t = BlockTextBuilder.build(web("host" to "a.com", "action" to "weird_action", "exe" to "zalo.exe", "rule" to "*.a.com", "count" to 1))
        assertEquals("Đã chặn · weird_action", t.headline)
        assertEquals(listOf("Trình duyệt: Zalo", "Quy tắc: *.a.com"), t.details)
    }

    @Test fun titleFallbacks() {
        assertEquals("Trang tin", BlockTextBuilder.build(web("title" to "Trang tin")).title)
        assertEquals("https://x.y/z", BlockTextBuilder.build(web("url" to "https://x.y/z")).title)
        assertEquals("Trang web", BlockTextBuilder.build(web()).title)
        // title is only a detail line when the host is the row title
        assertTrue(BlockTextBuilder.build(web("title" to "Trang tin")).details.isEmpty())
    }

    @Test fun appBlockDefaultsToKill() {
        val t = BlockTextBuilder.build(BlockFields(app = true, ts = "t", exe = "RobloxPlayerBeta.exe", rule = "Roblox*.exe", service = "roblox",
            path = "C:\\Users\\con\\AppData\\Local\\Roblox\\RobloxPlayerBeta.exe", count = 3), names)
        assertEquals("Đã chặn · Tắt ứng dụng", t.headline)
        assertEquals("Roblox", t.title)
        assertEquals(listOf("RobloxPlayerBeta.exe", "Dịch vụ: Roblox", "Quy tắc: Roblox*.exe", "C:\\Users\\con\\AppData\\Local\\Roblox\\RobloxPlayerBeta.exe", "Đã chặn 3 lần"), t.details)
    }

    @Test fun appBlockWithWindowCloseAndKeyword() {
        val t = BlockTextBuilder.build(BlockFields(app = true, ts = "t", exe = "Discord.exe", action = "close_window", title = "kênh cá độ", keyword = "cá độ"))
        assertEquals("Đã chặn · Đóng cửa sổ", t.headline)
        assertEquals(listOf("Discord.exe", "“kênh cá độ”", "Từ khóa: cá độ"), t.details)
    }

    @Test fun appBlockWithoutExeUsesPath() {
        val t = BlockTextBuilder.build(BlockFields(app = true, ts = "t", path = "D:\\x\\game.exe"))
        assertEquals("game", t.title)
    }

    // ---------------- events → rows ----------------

    private fun ev(id: String, type: String, ts: String, vararg kv: Pair<String, Any>) = EventItem(
        id = id, deviceId = "d", userSid = "S", type = type, ts = ts,
        data = JsonObject(kv.associate { (k, v) -> k to if (v is Int) JsonPrimitive(v) else JsonPrimitive(v.toString()) }),
    )

    @Test fun everyBlockEventIsItsOwnRowAndOthersHaveNoBadge() {
        val events = listOf(
            ev("1", "web.blocked", "2026-11-23T08:00:00Z", "host" to "poki.com", "reason" to "blocklist"),
            ev("2", "web.blocked", "2026-11-23T08:00:00Z", "host" to "poki.com", "reason" to "blocklist"),
            ev("3", "process.blocked", "2026-11-23T08:01:00Z", "exe" to "Roblox.exe", "action" to "kill"),
            ev("4", "process.blocked", "2026-11-23T08:01:00Z", "exe" to "Roblox.exe", "action" to "kill"),
            ev("5", "web.search", "2026-11-23T08:02:00Z", "query" to "toán lớp 5", "engine" to "google"),
            ev("6", "quota.exhausted", "2026-11-23T08:03:00Z"),
            ev("7", "usage.tick", "2026-11-23T07:00:00Z", "exe" to "Roblox.exe", "activeSec" to 600),
        )
        val rows = TimelineBuilder.build(events, "PC", emptyMap())
        val blocks = rows.filter { it.blocked }
        assertEquals(4, blocks.size)
        assertEquals(setOf("1", "2", "3", "4"), blocks.map { it.block!!.eventId }.toSet())
        assertTrue(blocks.all { it.blockHeadline!!.startsWith("Đã chặn") })
        val others = rows.filterNot { it.blocked }
        assertEquals(3, others.size)
        assertTrue(others.all { it.block == null && it.blockHeadline == null })
    }

    @Test fun webItemOnlyBlockedKindIsABlock() {
        assertNull(BlockFields.of(WebItem("t", "visit", host = "poki.com")))
        assertNull(BlockFields.of(WebItem("t", "search", query = "x")))
        val b = BlockFields.of(WebItem("t", "blocked", host = "poki.com", keyword = "k", count = 2, action = "close_tab", exe = "msedge.exe"))!!
        assertFalse(b.app)
        assertEquals("Đã chặn · Đóng tab", BlockTextBuilder.build(b).headline)
    }
}
