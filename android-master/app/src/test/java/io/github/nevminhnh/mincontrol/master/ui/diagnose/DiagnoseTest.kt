package io.github.nevminhnh.mincontrol.master.ui.diagnose

import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolJson
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolSchemas
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnoseTest {
    private val id = "01JDQ4000000000000000DGNS1"

    @Test
    fun diagnoseCommandSerializesPerSchema() {
        val json = ProtocolJson.encodeToString<Command>(Command.Diagnose(id))
        assertEquals(Json.parseToJsonElement("""{"type":"diagnose","commandId":"$id"}"""), Json.parseToJsonElement(json))
        assertTrue(ProtocolSchemas.validate("command", json).isEmpty())
        assertEquals(Command.Diagnose(id), ProtocolJson.decodeFromString<Command>(json))
    }

    private fun event(cmd: String, ts: String, body: String = """{"service":{"version":"1.2"}}""") = EventItem(
        id = "e$ts", deviceId = "d", ts = ts, type = "diag.report",
        data = Json.parseToJsonElement("""{"commandId":"$cmd","sections":$body}""").jsonObject,
    )

    @Test
    fun picksOnlyTheReportAnsweringOurCommand() {
        val items = listOf(event("OTHER", "2026-11-23T10:00:05Z"), event(id, "2026-11-23T10:00:03Z"), event(id, "2026-11-23T10:00:09Z"))
        assertEquals("e2026-11-23T10:00:09Z", DiagnoseLogic.pick(items, id)?.id)
        assertNull(DiagnoseLogic.pick(listOf(event("OTHER", "2026-11-23T10:00:05Z")), id))
    }

    @Test
    fun sectionsAreOrderedAndFlattened() {
        val data = Json.parseToJsonElement(
            """{"commandId":"$id","sections":{"zzz":{"a":1},"logs":{"lines":["x","y"]},"service":{"version":"1.2","hosted":{"proxy":"running","wfp":"ok"}},"wfp":{"filters":[{"sid":"S1","action":"block"}],"empty":[]}}}""",
        ).jsonObject
        val s = DiagnoseLogic.sections(data)
        assertEquals(listOf("service", "wfp", "logs", "zzz"), s.map { it.name })
        assertEquals(listOf("version" to "1.2", "hosted.proxy" to "running", "hosted.wfp" to "ok"), s[0].rows)
        assertEquals(listOf("filters[0].sid" to "S1", "filters[0].action" to "block", "empty" to "(trống)"), s[1].rows)
        assertEquals(listOf("lines" to "x, y"), s[2].rows)
        assertNotNull(Json.parseToJsonElement(s[0].raw))
        assertEquals("Dịch vụ", DiagnoseLogic.title("service"))
        assertEquals("zzz", DiagnoseLogic.title("zzz"))
    }

    @Test
    fun noSectionsGivesEmptyList() {
        assertTrue(DiagnoseLogic.sections(JsonObject(emptyMap())).isEmpty())
        assertEquals(60_000L, DiagnoseLogic.POLL_TIMEOUT_MS)
    }
}
