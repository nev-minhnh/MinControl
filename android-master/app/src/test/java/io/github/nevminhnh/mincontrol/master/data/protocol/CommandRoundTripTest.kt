package io.github.nevminhnh.mincontrol.master.data.protocol

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class CommandRoundTripTest {
    private val dir = File(ProtocolSchemas.dir, "fixtures/command/valid")

    @Test
    fun everyValidCommandFixtureRoundTrips() {
        val files = dir.listFiles { f -> f.extension == "json" }.orEmpty()
        assertTrue("no command fixtures", files.isNotEmpty())
        for (f in files) {
            val text = f.readText()
            val cmd = ProtocolJson.decodeFromString<Command>(text)
            val encoded = ProtocolJson.encodeToString(cmd)
            assertTrue("${f.name} re-encoded is invalid", ProtocolSchemas.validate("command", encoded).isEmpty())
            assertEquals("${f.name} differs after round trip", Json.parseToJsonElement(text), Json.parseToJsonElement(encoded))
        }
    }

    @Test
    fun sealedHierarchyDecodesByType() {
        val c = ProtocolJson.decodeFromString<Command>(File(dir, "add-time-group.json").readText())
        assertTrue(c is Command.AddTime && c.minutes == 15 && c.group == "games")
    }
}
