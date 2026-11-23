package io.github.nevminhnh.mincontrol.master.ui.settings

import io.github.nevminhnh.mincontrol.master.data.protocol.AlertSetting
import io.github.nevminhnh.mincontrol.master.data.protocol.ApiJson
import io.github.nevminhnh.mincontrol.master.data.protocol.MasterSettings
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AlertSettingsLogicTest {
    private val types = listOf(
        "tamper", "request.exe_approval", "quota.exhausted", "quota.warning", "blocked.burst",
        "web.blocked", "process.blocked", "device.offline", "session.logon", "session.logoff",
    )

    @Test fun allTenTypesInOrder() {
        assertEquals(types, AlertSettingsLogic.TYPES.map { it.type })
    }

    @Test fun defaultsOnlyTamper() {
        val e = AlertSettingsLogic.effective(MasterSettings(alerts = emptyMap()))
        assertEquals(setOf("tamper"), e.filterValues { it.enabled }.keys)
        assertEquals(0, e.getValue("tamper").minIntervalMin)
        assertEquals(AlertSettingsLogic.DEFAULTS, e)
    }

    @Test fun legacyServerCarriesLogonSwitches() {
        val e = AlertSettingsLogic.effective(MasterSettings(notifyLogon = true, notifyLogoff = false, alerts = null))
        assertTrue(e.getValue("session.logon").enabled)
        assertFalse(e.getValue("session.logoff").enabled)
        assertTrue(e.getValue("tamper").enabled)
    }

    @Test fun updateWritesFullMapAndMirrorsLogon() {
        val s = AlertSettingsLogic.update(MasterSettings(), "session.logon", enabled = true)
        assertEquals(types.toSet(), s.alerts!!.keys)
        assertTrue(s.notifyLogon)
        val s2 = AlertSettingsLogic.update(s, "web.blocked", enabled = true, minIntervalMin = 15)
        assertEquals(AlertSetting(true, 15), s2.alerts!!.getValue("web.blocked"))
        assertTrue(s2.alerts!!.getValue("session.logon").enabled)
        val s3 = AlertSettingsLogic.update(s2, "tamper", enabled = false)
        assertFalse(s3.alerts!!.getValue("tamper").enabled)
        assertEquals(15, s3.alerts!!.getValue("web.blocked").minIntervalMin)
    }

    @Test fun frequenciesSnapAndLabel() {
        assertEquals(listOf(0, 5, 15, 60, 1440), AlertSettingsLogic.FREQUENCIES.map { it.first })
        assertEquals(0, AlertSettingsLogic.snap(-3))
        assertEquals(5, AlertSettingsLogic.snap(7))
        assertEquals(60, AlertSettingsLogic.snap(45))
        assertEquals(1440, AlertSettingsLogic.snap(5000))
        assertEquals("Mỗi lần", AlertSettingsLogic.frequencyLabel(0))
        assertEquals("Tối đa 1 lần mỗi 1 giờ", AlertSettingsLogic.frequencyLabel(60))
        val e = AlertSettingsLogic.effective(MasterSettings(alerts = mapOf("quota.warning" to AlertSetting(true, 30))))
        assertEquals(15, e.getValue("quota.warning").minIntervalMin) // 30 min is not a choice: nearest is 15
    }

    @Test fun wireShape() {
        val s = AlertSettingsLogic.update(MasterSettings(), "device.offline", enabled = true, minIntervalMin = 60)
        val o = Json.parseToJsonElement(ApiJson.encodeToString(MasterSettings.serializer(), s)).jsonObject
        val a = o["alerts"]!!.jsonObject
        assertEquals(10, a.size)
        assertTrue(a["device.offline"]!!.jsonObject["enabled"]!!.jsonPrimitive.boolean)
        assertEquals(60, a["device.offline"]!!.jsonObject["minIntervalMin"]!!.jsonPrimitive.int)
        // an old server answer without `alerts` parses, and the sent map is kept
        val old = ApiJson.decodeFromString(MasterSettings.serializer(), """{"notifyLogon":false,"notifyLogoff":false}""")
        assertNull(old.alerts)
        assertEquals(s.alerts, AlertSettingsLogic.merged(s, old).alerts)
        val fresh = old.copy(alerts = mapOf("tamper" to AlertSetting(true, 5)))
        assertEquals(fresh, AlertSettingsLogic.merged(s, fresh))
    }
}
