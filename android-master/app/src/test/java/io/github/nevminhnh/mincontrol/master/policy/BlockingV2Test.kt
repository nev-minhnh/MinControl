package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMode
import io.github.nevminhnh.mincontrol.master.data.protocol.AppRule
import io.github.nevminhnh.mincontrol.master.data.protocol.InventoryApp
import io.github.nevminhnh.mincontrol.master.data.protocol.Keywords
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyJson
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolSchemas
import io.github.nevminhnh.mincontrol.master.data.protocol.RuleAction
import io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy
import io.github.nevminhnh.mincontrol.master.data.protocol.WebMode
import kotlinx.serialization.encodeToString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

class BlockingV2Test {
    private val sid = "S-1-5-21-111-222-333-1001"
    private val base: Policy = PolicyDefaults.policy(mapOf(sid to "Con"))
    private val up: UserPolicy = base.users.getValue(sid)

    private fun with(u: UserPolicy) = base.copy(users = mapOf(sid to u))
    private fun json(u: UserPolicy) = PolicyJson.encodeToString(with(u))

    /** Property names of `$defs.userPolicy` (path = nested property names, e.g. ["web"]). */
    private fun schemaHas(vararg path: String, field: String): Boolean {
        val f = File(ProtocolSchemas.dir, "policy.schema.json")
        if (!f.isFile) return false
        var node = ProtocolSchemas.readTree(f).path("\$defs").path("userPolicy")
        for (p in path) node = node.path("properties").path(p)
        return node.path("properties").has(field)
    }

    // ---------------- serialization stays valid against the current schema ----------------

    @Test fun defaultsOmitNewFieldsSoOldSchemaStaysValid() {
        val s = json(up)
        assertFalse(s.contains("appMode"))
        assertFalse(s.contains("keywords"))
        assertFalse(s.contains("blockedServices"))
        assertFalse(s.contains("allowedServices"))
        assertTrue(ProtocolSchemas.validate("policy", s).isEmpty())
    }

    @Test fun blocklistModeIsStoredAsOmitted() {
        val a = BlockingV2.setAppMode(up, AppMode.ALLOWLIST)
        assertEquals(AppMode.ALLOWLIST, a.appMode)
        assertTrue(json(a).contains("\"appMode\":\"allowlist\""))
        val b = BlockingV2.setAppMode(a, AppMode.BLOCKLIST)
        assertNull(b.appMode)
        assertEquals(AppMode.BLOCKLIST, b.effectiveAppMode)
    }

    @Test fun appModeIsSchemaValidWhenSchemaKnowsIt() {
        assumeTrue("appMode not in policy.schema.json yet", schemaHas(field = "appMode"))
        val errs = ProtocolSchemas.validate("policy", json(BlockingV2.setAppMode(up, AppMode.ALLOWLIST)))
        assertTrue(errs.toString(), errs.isEmpty())
    }

    @Test fun keywordsAreSchemaValidWhenSchemaKnowsThem() {
        assumeTrue("keywords not in policy.schema.json yet", schemaHas(field = "keywords"))
        val u = BlockingV2.setKeywordFlags(BlockingV2.addKeywords(up, "đánh bài, cá độ\nphim người lớn"), matchTitles = false)
        val errs = ProtocolSchemas.validate("policy", json(u))
        assertTrue(errs.toString(), errs.isEmpty())
    }

    @Test fun servicesAreSchemaValidWhenSchemaKnowsThem() {
        assumeTrue("blockedServices not in policy.schema.json yet", schemaHas("web", field = "blockedServices"))
        val catalog = File(ProtocolSchemas.dir, "services.json").takeIf { it.isFile }?.readText()?.let { ServiceCatalog.parse(it) }
        val ids = catalog?.services?.map { it.id }?.take(2)?.ifEmpty { null } ?: listOf("youtube", "tiktok")
        var u = BlockingV2.toggleService(up, ids[0])
        if (ids.size > 1) u = u.copy(web = BlockingV2.setService(u.web, ids[1], ServiceState.ALLOWED))
        u = BlockingV2.setWebMode(u, WebMode.ALLOWLIST)
        val errs = ProtocolSchemas.validate("policy", json(u))
        assertTrue(errs.toString(), errs.isEmpty())
    }

    // ---------------- services ----------------

    @Test fun serviceToggleBlocklistMode() {
        val a = BlockingV2.toggleService(up, "tiktok")
        assertEquals(listOf("tiktok"), a.web.blockedServices)
        assertEquals(ServiceState.BLOCKED, BlockingV2.serviceState(a.web, "tiktok"))
        val b = BlockingV2.toggleService(a, "tiktok")
        assertNull(b.web.blockedServices)
        assertNull(b.web.allowedServices)
    }

    @Test fun serviceToggleCyclesThroughAllowedInAllowlistMode() {
        val al = BlockingV2.setAppMode(up, AppMode.ALLOWLIST)
        val a = BlockingV2.toggleService(al, "youtube")
        assertEquals(listOf("youtube"), a.web.allowedServices)
        val b = BlockingV2.toggleService(a, "youtube")
        assertEquals(listOf("youtube"), b.web.blockedServices)
        assertNull(b.web.allowedServices)
        val c = BlockingV2.toggleService(b, "youtube")
        assertEquals(ServiceState.NONE, BlockingV2.serviceState(c.web, "youtube"))
    }

    @Test fun serviceNeverInBothLists() {
        val w = BlockingV2.setService(up.web.copy(allowedServices = listOf("zalo")), "zalo", ServiceState.BLOCKED)
        assertEquals(listOf("zalo"), w.blockedServices)
        assertNull(w.allowedServices)
        assertTrue(BlockingV2.errors(up.copy(web = up.web.copy(blockedServices = listOf("a"), allowedServices = listOf("a")))).isNotEmpty())
    }

    @Test fun catalogParsesBothShapesAndGarbage() {
        val arr = ServiceCatalog.parse("""[{"id":"youtube","name":"YouTube","category":"video","domains":["*.youtube.com"],"apps":[]}]""")
        assertEquals("YouTube", arr.byId("youtube")?.name)
        val obj = ServiceCatalog.parse("""{"version":3,"services":[{"id":"tiktok","name":"TikTok","category":"social","domains":["*.tiktok.com"],"apps":[{"exe":"TikTok*.exe"}],"extra":1}]}""")
        assertEquals(listOf("tiktok"), obj.services.map { it.id })
        assertEquals(ServiceCatalog.EMPTY, ServiceCatalog.parse("{\"version\":0,\"services\":[]}").let { if (it.services.isEmpty()) ServiceCatalog.EMPTY else it })
        assertTrue(ServiceCatalog.parse("not json").services.isEmpty())
        assertTrue(ServiceCatalog.parse(null).services.isEmpty())
    }

    @Test fun shippedCatalogParsesWhenPresent() {
        val f = File(ProtocolSchemas.dir, "services.json")
        assumeTrue("protocol/services.json not present yet", f.isFile)
        val c = ServiceCatalog.parse(f.readText())
        assertTrue(c.services.isNotEmpty())
        assertTrue(c.services.all { it.id.isNotBlank() && it.name.isNotBlank() })
    }

    @Test fun currentlyBlockedHostAndExe() {
        val cat = ServiceCatalog(listOf(Service("tiktok", "TikTok", "social", listOf("*.tiktok.com"), listOf(AppMatch(exe = "TikTok*.exe")))))
        val u = BlockingV2.toggleService(up.copy(web = up.web.copy(blockDomains = listOf("poki.com"))), "tiktok")
        assertTrue(BlockingV2.isHostBlockedNow(u, "poki.com", cat))
        assertTrue(BlockingV2.isHostBlockedNow(u, "www.tiktok.com", cat))
        assertFalse(BlockingV2.isHostBlockedNow(u, "google.com", cat))
        assertTrue(BlockingV2.isExeBlockedNow(u, "TikTokLive.exe", cat))
        assertFalse(BlockingV2.isExeBlockedNow(u, "chrome.exe", cat))
        val r = u.copy(appRules = listOf(AppRule(RuleAction.BLOCK, AppMatch(exe = "Minecraft*.exe"))))
        assertTrue(BlockingV2.isExeBlockedNow(r, "C:\\Games\\MinecraftLauncher.exe", cat))
    }

    // ---------------- keywords ----------------

    @Test fun parseKeywordsSplitsTrimsDedupes() {
        assertEquals(listOf("đánh bài", "cá độ", "SEX"), BlockingV2.parseKeywords(" đánh bài ,cá độ\n\nSEX;sex\r\nĐÁNH BÀI , ,"))
        assertTrue(BlockingV2.parseKeywords("x".repeat(65)).isEmpty())
    }

    @Test fun addAndRemoveKeywords() {
        val a = BlockingV2.addKeywords(up, "game, Game, cờ bạc")
        assertEquals(Keywords(listOf("game", "cờ bạc")), a.keywords)
        val b = BlockingV2.addKeywords(a, "GAME\nvpn")
        assertEquals(listOf("game", "cờ bạc", "vpn"), b.keywords!!.words)
        val c = BlockingV2.removeKeyword(b, "CỜ BẠC")
        assertEquals(listOf("game", "vpn"), c.keywords!!.words)
        val d = BlockingV2.removeKeyword(BlockingV2.removeKeyword(c, "game"), "vpn")
        assertNull(d.keywords)
        assertEquals(up, BlockingV2.addKeywords(up, " , \n"))
    }

    @Test fun keywordFlagsAndDiff() {
        val a = BlockingV2.setKeywordFlags(BlockingV2.addKeywords(up, "bài"), matchSearches = false)
        assertFalse(a.keywords!!.matchSearches)
        assertTrue(a.keywords!!.matchTitles)
        val changes = PolicyDiff.diffUser(up, a).map { it.title }
        assertTrue(changes.toString(), "Từ khóa bị cấm" in changes)
        assertTrue(changes.toString(), "Chặn khi tìm kiếm từ khóa" in changes)
    }

    @Test fun diffShowsModesAndServices() {
        val a = BlockingV2.toggleService(BlockingV2.setAppMode(up, AppMode.ALLOWLIST), "roblox")
        val changes = PolicyDiff.diffUser(up, a)
        assertTrue(changes.any { it.title == "Chế độ ứng dụng" && it.to == "Chỉ ứng dụng cho phép" })
        assertTrue(changes.any { it.title == "Dịch vụ được phép" && it.to == "roblox" })
        assertTrue(PolicyDiff.diffUser(up, up).isEmpty())
    }

    @Test fun validationCatchesBadKeywords() {
        val bad = up.copy(keywords = Keywords(listOf(" ")))
        assertTrue(PolicyValidation.errors(with(bad)).isNotEmpty())
        assertTrue(PolicyValidation.errors(with(BlockingV2.addKeywords(up, "ok"))).isEmpty())
    }

    // ---------------- picker: opposite-list filtering ----------------

    private fun app(id: String, name: String, exe: String? = null, dir: String? = null, pub: String? = null, cat: String? = null) =
        InventoryApp(id = id, name = name, installDir = dir, exe = exe, publisher = pub, category = cat)

    private val apps = listOf(
        app("1", "Minecraft", exe = "MinecraftLauncher.exe", dir = "C:\\Games\\Minecraft"),
        app("2", "Roblox", exe = "RobloxPlayerBeta.exe", pub = "Roblox Corporation"),
        app("3", "Zoom", exe = "Zoom.exe", dir = "C:\\Program Files\\Zoom"),
        app("4", "Notepad", exe = "notepad.exe", cat = "system"),
    )

    @Test fun addingToBlockHidesAllowedApps() {
        val rules = AppRules.add(emptyList(), RuleAction.ALLOW, listOf(AppMatch(path = "C:\\Program Files\\Zoom\\*")))
        val l = AppPicker.pickerList(apps, "", rules, RuleAction.BLOCK, showAll = false)
        assertEquals(listOf("Minecraft", "Roblox"), l.apps.map { it.name }.sorted())
        assertEquals(1, l.hiddenOpposite)
        assertEquals(1, l.hiddenSystem)
    }

    @Test fun addingToAllowHidesBlockedAppsEvenWithShowAll() {
        val rules = listOf(
            AppRule(RuleAction.BLOCK, AppMatch(exe = "Minecraft*.exe")),
            AppRule(RuleAction.BLOCK, AppMatch(publisher = "Roblox*")),
        )
        val l = AppPicker.pickerList(apps, "", rules, RuleAction.ALLOW, showAll = true)
        assertEquals(listOf("Notepad", "Zoom"), l.apps.map { it.name }.sorted())
        assertEquals(2, l.hiddenOpposite)
        assertEquals(0, l.hiddenSystem)
        // Same-side rules are not hidden (re-adding is a no-op in AppRules.add).
        val same = AppPicker.pickerList(apps, "", rules, RuleAction.BLOCK, showAll = true)
        assertEquals(0, same.hiddenOpposite)
        assertEquals(4, same.apps.size)
    }

    @Test fun groupPickerWithoutActionHidesNothingOpposite() {
        val rules = listOf(AppRule(RuleAction.ALLOW, AppMatch(exe = "Zoom.exe")))
        val l = AppPicker.pickerList(apps, "zo", rules, null, showAll = false)
        assertEquals(listOf("Zoom"), l.apps.map { it.name })
        assertEquals(0, l.hiddenOpposite)
    }

    @Test fun unblockAndAllowExe() {
        val u = up.copy(appRules = listOf(AppRule(RuleAction.BLOCK, AppMatch(exe = "Roblox*.exe")), AppRule(RuleAction.BLOCK, AppMatch(exe = "steam.exe"))))
        val a = AppRules.unblockExe(u, "RobloxPlayerBeta.exe")
        assertEquals(listOf("steam.exe"), a.appRules.map { it.match.exe })
        val b = AppRules.allowExe(u, "steam.exe")
        assertEquals(listOf(RuleAction.BLOCK to "Roblox*.exe", RuleAction.ALLOW to "steam.exe"), b.appRules.map { it.action to it.match.exe })
    }
}
