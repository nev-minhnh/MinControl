package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.AppRule
import io.github.nevminhnh.mincontrol.master.data.protocol.InventoryApp
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyJson
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolSchemas
import io.github.nevminhnh.mincontrol.master.data.protocol.RuleAction
import kotlinx.serialization.encodeToString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRulesTest {
    private val sid = "S-1-5-21-111-222-333-1001"
    private val base = PolicyDefaults.policy(mapOf(sid to "Con"))

    private fun schemaErrors(rules: List<AppRule>): Set<*> {
        val p = base.copy(users = mapOf(sid to base.users.getValue(sid).copy(appRules = rules)))
        return ProtocolSchemas.validate("policy", PolicyJson.encodeToString(p))
    }

    @Test
    fun blockRuleSerializesPerSchema() {
        val rules = AppRules.add(emptyList(), RuleAction.BLOCK, listOf(AppMatch(exe = "Minecraft*.exe")))
        val json = PolicyJson.encodeToString(rules)
        assertEquals("""[{"action":"block","match":{"exe":"Minecraft*.exe"}}]""", json)
        assertTrue(schemaErrors(rules).isEmpty())
    }

    @Test
    fun everyKindOfMatchIsSchemaValid() {
        val rules = AppRules.add(
            emptyList(), RuleAction.BLOCK,
            listOf(AppMatch(exe = "a.exe"), AppMatch(path = "C:\\Games\\*"), AppMatch(publisher = "Valve*"), AppMatch(sha256 = "AB".repeat(32))),
        ) + AppRule(RuleAction.ALLOW, AppMatch(exe = "b.exe"), except = listOf(AppMatch(publisher = "X")))
        assertTrue(AppRules.errors(rules).isEmpty())
        assertTrue(schemaErrors(rules).isEmpty())
        assertEquals("ab".repeat(32), rules.first { it.match.sha256 != null }.match.sha256)
    }

    @Test
    fun invalidMatchesAreReported() {
        assertNotNull(AppRules.matchError(AppMatch()))
        assertNotNull(AppRules.matchError(AppMatch(sha256 = "xyz")))
        assertNotNull(AppRules.matchError(AppMatch(exe = "C:\\x\\a.exe")))
        assertNotNull(AppRules.matchError(AppMatch(exe = "a".repeat(261))))
        assertNull(AppRules.matchError(AppMatch(exe = "a.exe")))
    }

    @Test
    fun blockGoesBeforeFirstAllowAllowIsAppended() {
        var r = AppRules.add(emptyList(), RuleAction.ALLOW, listOf(AppMatch(exe = "ok.exe")))
        r = AppRules.add(r, RuleAction.BLOCK, listOf(AppMatch(exe = "bad.exe")))
        assertEquals(listOf("bad.exe", "ok.exe"), r.map { it.match.exe })
        r = AppRules.add(r, RuleAction.ALLOW, listOf(AppMatch(exe = "ok2.exe")))
        assertEquals(listOf("bad.exe", "ok.exe", "ok2.exe"), r.map { it.match.exe })
    }

    @Test
    fun duplicatesAreIgnoredAndContradictionsReplaced() {
        var r = AppRules.add(emptyList(), RuleAction.BLOCK, listOf(AppMatch(exe = "a.exe"), AppMatch(exe = "a.exe")))
        assertEquals(1, r.size)
        r = AppRules.add(r, RuleAction.ALLOW, listOf(AppMatch(exe = "a.exe")))
        assertEquals(listOf(RuleAction.ALLOW), r.map { it.action })
    }

    @Test
    fun moveAndRemove() {
        val r = AppRules.add(emptyList(), RuleAction.BLOCK, listOf(AppMatch(exe = "1.exe"), AppMatch(exe = "2.exe"), AppMatch(exe = "3.exe")))
        assertEquals(listOf("1.exe", "3.exe", "2.exe"), AppRules.move(r, 1, 1).map { it.match.exe })
        assertEquals(r, AppRules.move(r, 0, -1))
        assertEquals(r, AppRules.move(r, 2, 1))
        assertEquals(listOf("1.exe", "3.exe"), AppRules.remove(r, 1).map { it.match.exe })
    }

    @Test
    fun quickBlockFromUsageOrEvent() {
        val up = base.users.getValue(sid)
        val blocked = AppRules.blockExe(up, "C:\\Games\\Roblox.exe")
        assertEquals(listOf(AppRule(RuleAction.BLOCK, AppMatch(exe = "Roblox.exe"))), blocked.appRules)
        assertTrue(AppRules.isBlocked(blocked.appRules, "roblox.exe"))
        assertFalse(AppRules.isBlocked(up.appRules, "roblox.exe"))
        assertEquals(up, AppRules.blockExe(up, "  "))
        assertEquals(blocked.appRules, AppRules.blockExe(blocked, "Roblox.exe").appRules)
        assertTrue(PolicyValidation.errors(base.copy(users = mapOf(sid to blocked))).isEmpty())
    }

    @Test
    fun pickerMatchesBecomeRules() {
        val app = InventoryApp(id = "1", name = "Minecraft", exe = "Minecraft.exe", publisher = "Mojang", kind = "seen")
        val rules = AppRules.add(emptyList(), RuleAction.BLOCK, AppPicker.merge(emptyList(), listOf(app)))
        assertEquals(AppMatch(exe = "Minecraft.exe", publisher = "Mojang"), rules.single().match)
        assertTrue(schemaErrors(rules).isEmpty())
    }

    @Test
    fun invalidRuleBlocksApply() {
        val up = base.users.getValue(sid).copy(appRules = listOf(AppRule(RuleAction.BLOCK, AppMatch())))
        assertTrue(PolicyValidation.errors(base.copy(users = mapOf(sid to up))).isNotEmpty())
    }
}
