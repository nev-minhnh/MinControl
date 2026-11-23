package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMode
import io.github.nevminhnh.mincontrol.master.data.protocol.AppRule
import io.github.nevminhnh.mincontrol.master.data.protocol.RuleAction
import io.github.nevminhnh.mincontrol.master.data.protocol.WebMode
import io.github.nevminhnh.mincontrol.master.ui.policy.GroupKeys
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ServicesDropdownTest {
    private val up = PolicyDefaults.user("Bin", AppGroupCatalog.BUILTIN)
    private val catalog = ServiceCatalog(
        listOf(
            Service("youtube", "YouTube", "video"), Service("tiktok", "TikTok", "video"), Service("zalo", "Zalo", "chat"),
            Service("chatgpt", "ChatGPT", "ai"), Service("roblox", "Roblox", "games"), Service("facebook", "Facebook", "social"),
            Service("shopee", "Shopee", "shopping"),
        ),
    )

    @Test fun threeOptionsAllowNoteOnlyOutsideAllowlist() {
        val off = BlockingV2.serviceOptions(allowlist = false)
        assertEquals(listOf(ServiceState.NONE, ServiceState.BLOCKED, ServiceState.ALLOWED), off.map { it.state })
        assertEquals(listOf("Không áp dụng", "Chặn", "Cho phép"), off.map { it.label })
        assertEquals(BlockingV2.ALLOW_ONLY_IN_ALLOWLIST, off.last().note)
        assertEquals("Luôn được dùng", BlockingV2.serviceOptions(allowlist = true).last().note)
        assertTrue(BlockingV2.SERVICES_HELP.contains("Cho phép"))
    }

    @Test fun dropdownStateRoundTrip() {
        var u = BlockingV2.setServiceState(up, "tiktok", ServiceState.BLOCKED)
        assertEquals(ServiceState.BLOCKED, BlockingV2.serviceState(u.web, "tiktok"))
        assertEquals(listOf("tiktok"), u.web.blockedServices)
        u = BlockingV2.setServiceState(u, "tiktok", ServiceState.ALLOWED)
        assertEquals(ServiceState.ALLOWED, BlockingV2.serviceState(u.web, "tiktok"))
        assertNull(u.web.blockedServices)
        assertEquals(listOf("tiktok"), u.web.allowedServices)
        u = BlockingV2.setServiceState(u, "tiktok", ServiceState.NONE)
        assertEquals(ServiceState.NONE, BlockingV2.serviceState(u.web, "tiktok"))
        assertNull(u.web.allowedServices)
        assertEquals(up.web, u.web)
    }

    @Test fun allowlistDetection() {
        assertEquals(false, BlockingV2.allowlistActive(up))
        assertTrue(BlockingV2.allowlistActive(BlockingV2.setWebMode(up, WebMode.ALLOWLIST)))
        assertTrue(BlockingV2.allowlistActive(BlockingV2.setAppMode(up, AppMode.ALLOWLIST)))
    }

    @Test fun groupedByCategoryInFixedOrder() {
        val g = BlockingV2.groupedServices(catalog)
        assertEquals(listOf("social", "chat", "video", "games", "ai", "shopping"), g.map { it.first })
        assertEquals(listOf("TikTok", "YouTube"), g.first { it.first == "video" }.second.map { it.name })
    }

    @Test fun summary() {
        assertEquals("Chưa chặn dịch vụ nào", BlockingV2.servicesSummary(up.web))
        val b = BlockingV2.setServiceState(BlockingV2.setServiceState(up, "tiktok", ServiceState.BLOCKED), "roblox", ServiceState.BLOCKED)
        assertEquals("Đang chặn 2 dịch vụ", BlockingV2.servicesSummary(b.web))
        assertEquals("Chặn 2 · cho phép 1 dịch vụ", BlockingV2.servicesSummary(BlockingV2.setServiceState(b, "zalo", ServiceState.ALLOWED).web))
    }

    @Test fun ruleSectionsKeepEvaluationIndex() {
        val rules = listOf(
            AppRule(RuleAction.BLOCK, AppMatch(exe = "a.exe")), AppRule(RuleAction.ALLOW, AppMatch(exe = "b.exe")),
            AppRule(RuleAction.BLOCK, AppMatch(exe = "c.exe")),
        )
        val (allowed, blocked) = AppRules.sections(rules)
        assertEquals(listOf(1), allowed.map { it.index })
        assertEquals(listOf(0, 2), blocked.map { it.index })
    }

    @Test fun groupKeysFromVietnameseNames() {
        assertEquals("tro-choi-dien-tu", GroupKeys.slug("Trò chơi điện tử", emptySet()))
        assertEquals("games-2", GroupKeys.slug("Games", setOf("games")))
        assertEquals("nhom-123", GroupKeys.slug("123", emptySet()))
        assertEquals("nhom", GroupKeys.slug("", emptySet()))
        assertTrue(Regex("^[a-z][a-z0-9_-]{0,31}$").matches(GroupKeys.slug("Ứng dụng học tập rất rất rất dài dài dài", emptySet())))
        assertNotNull(GroupKeys.slug("Mạng xã hội & Chat", setOf("mang-xa-hoi-chat")))
    }
}
