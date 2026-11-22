package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyJson
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolSchemas
import io.github.nevminhnh.mincontrol.master.data.protocol.WebCategory
import io.github.nevminhnh.mincontrol.master.data.protocol.WebMode
import io.github.nevminhnh.mincontrol.master.data.protocol.Weekday
import io.github.nevminhnh.mincontrol.master.data.protocol.WeekdayWindows
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PolicyDiffTest {
    private val sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
    private val base = PolicyDefaults.policy(mapOf(sid to "Bin"), version = 7)

    private fun edit(p: Policy, f: (io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy) -> io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy) =
        p.copy(users = p.users.mapValues { f(it.value) })

    @Test
    fun identicalPoliciesHaveNoChanges() {
        assertTrue(PolicyDiff.diff(base, base.copy()).isEmpty())
    }

    @Test
    fun mockupScenarioGivesThreeChanges() {
        // Policy.dc.html: weekday quota, weekday windows and blocked categories changed -> "3 thay đổi".
        val weekdays = listOf(Weekday.MON, Weekday.TUE, Weekday.WED, Weekday.THU, Weekday.FRI)
        val next = edit(base) { u ->
            u.copy(
                screenTime = u.screenTime.copy(
                    dailyQuotaMin = weekdays.fold(u.screenTime.dailyQuotaMin) { m, d -> m.with(d, 150) },
                    allowedWindows = weekdays.fold(u.screenTime.allowedWindows) { w, d -> w.with(d, listOf("15:30-21:00")) },
                ),
                web = u.web.copy(categorySchedules = mapOf(WebCategory.GAMES to WeekdayWindows.of(listOf("07:00-11:30"), emptyList()))),
            )
        }
        val changes = PolicyDiff.diff(base, next)
        assertEquals(changes.joinToString("\n"), 3, changes.size)
        assertEquals("Thời gian sử dụng · Ngày thường", changes[0].title)
        assertEquals("2 giờ", changes[0].from)
        assertEquals("2 giờ 30", changes[0].to)
        assertEquals("Khung giờ được dùng · Ngày thường", changes[1].title)
    }

    @Test
    fun weekdayChangesGroupByOldAndNewValue() {
        val next = edit(base) { u ->
            u.copy(screenTime = u.screenTime.copy(dailyQuotaMin = u.screenTime.dailyQuotaMin.with(Weekday.MON, 60).with(Weekday.WED, 60).with(Weekday.SUN, 240)))
        }
        val titles = PolicyDiff.diff(base, next).map { it.title }
        assertEquals(listOf("Thời gian sử dụng · T2, T4", "Thời gian sử dụng · CN"), titles)
    }

    @Test
    fun userAddedAndRemoved() {
        val other = "S-1-5-21-1111111111-2222222222-3333333333-1002"
        val two = PolicyDefaults.policy(mapOf(sid to "Bin", other to "Na"), version = 8)
        assertEquals(listOf("Bắt đầu quản lý"), PolicyDiff.diff(base, two).map { it.title })
        assertEquals(listOf("Ngừng quản lý"), PolicyDiff.diff(two, base).map { it.title })
        assertEquals(1, PolicyDiff.diff(null, base).size)
    }

    @Test
    fun defaultPolicyIsSchemaValidAndRoundTrips() {
        val json = PolicyJson.encodeToString(Policy.serializer(), PolicyDefaults.policy(mapOf(sid to "Bin")))
        assertTrue(ProtocolSchemas.validate("policy", json).toString(), ProtocolSchemas.validate("policy", json).isEmpty())
        assertTrue(PolicyValidation.errors(PolicyDefaults.policy(mapOf(sid to "Bin"))).isEmpty())
    }

    @Test
    fun validFixturesDecodeLosslessly() {
        File(ProtocolSchemas.dir, "fixtures/policy/valid").listFiles { f -> f.extension == "json" }!!.forEach { f ->
            val text = f.readText()
            val p = PolicyJson.decodeFromString(Policy.serializer(), text)
            assertEquals(f.name, Json.parseToJsonElement(text), Json.parseToJsonElement(PolicyJson.encodeToString(Policy.serializer(), p)))
            assertTrue("${f.name}: ${PolicyValidation.errors(p)}", PolicyValidation.errors(p).isEmpty())
        }
    }

    @Test
    fun semanticInvalidFixturesAreRejected() {
        val files = File(ProtocolSchemas.dir, "fixtures/policy/semantic-invalid").listFiles { f -> f.extension == "json" }!!
        assertTrue(files.isNotEmpty())
        files.forEach { f ->
            val p = PolicyJson.decodeFromString(Policy.serializer(), f.readText())
            assertTrue("${f.name} must be rejected", PolicyValidation.errors(p).isNotEmpty())
        }
    }

    @Test
    fun windowValidation() {
        assertNull(PolicyValidation.windowsError(listOf("08:00-11:30", "13:30-24:00")))
        assertNotNull(PolicyValidation.windowsError(listOf("21:00-02:00")))
        assertNotNull(PolicyValidation.windowsError(listOf("08:00-12:00", "11:00-13:00")))
        assertNotNull(PolicyValidation.windowsError(listOf("8:00-12:00")))
    }

    @Test
    fun allDayAndNoUseWindows() {
        assertNull(PolicyValidation.windowsError(listOf(ALL_DAY_WINDOW)))
        assertNull(PolicyValidation.windowsError(emptyList()))
        assertEquals("Cả ngày", formatWindows(listOf("00:00-24:00")))
        assertEquals("Không dùng", formatWindows(emptyList()))
        val next = edit(base) { u -> u.copy(screenTime = u.screenTime.copy(allowedWindows = u.screenTime.allowedWindows.with(Weekday.SAT, emptyList()))) }
        val change = PolicyDiff.diff(base, next).first()
        assertEquals("Không dùng", change.to)
        assertTrue(PolicyValidation.errors(next).isEmpty())
    }

    @Test
    fun netExemptRequiresFullPath() {
        assertNull(PolicyValidation.pathError("C:\\Program Files\\App\\app.exe"))
        assertNull(PolicyValidation.pathError("\\\\srv\\share\\app.exe"))
        assertNotNull(PolicyValidation.pathError("app.exe"))
        val bad = edit(base) { u -> u.copy(web = u.web.copy(netExemptApps = listOf(AppMatch(exe = "app.exe")))) }
        assertTrue(PolicyValidation.errors(bad).isNotEmpty())
        val ok = edit(base) { u -> u.copy(web = u.web.copy(netExemptApps = listOf(AppMatch(path = "C:\\Tools\\vpn.exe")))) }
        assertTrue(PolicyValidation.errors(ok).isEmpty())
    }

    @Test
    fun semanticChecks() {
        assertTrue(PolicyValidation.errors(base.copy(timezone = "Mars/Olympus")).isNotEmpty())
        val warn = edit(base) { u -> u.copy(screenTime = u.screenTime.copy(warnAtMin = listOf(500))) }
        assertTrue(PolicyValidation.errors(warn).isNotEmpty())
        val allow = edit(base) { u -> u.copy(web = u.web.copy(mode = WebMode.ALLOWLIST, allowDomains = emptyList())) }
        assertTrue(PolicyValidation.errors(allow).isNotEmpty())
    }
}
