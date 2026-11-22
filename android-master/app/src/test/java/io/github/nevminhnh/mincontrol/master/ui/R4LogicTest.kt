package io.github.nevminhnh.mincontrol.master.ui

import io.github.nevminhnh.mincontrol.master.data.AlertView
import io.github.nevminhnh.mincontrol.master.data.protocol.AlertItem
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.UserState
import io.github.nevminhnh.mincontrol.master.envelope.EnvelopeBuilder
import io.github.nevminhnh.mincontrol.master.ui.activity.ApprovalState
import io.github.nevminhnh.mincontrol.master.ui.activity.Approvals
import io.github.nevminhnh.mincontrol.master.ui.activity.TimelineBuilder
import io.github.nevminhnh.mincontrol.master.ui.overview.LockUi
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Duration
import java.time.Instant

class R4LogicTest {
    private val dev = "DEV1"
    private val sid = "S-1-5-21-1001"
    private val ts = "2026-11-22T09:00:00Z"

    private fun approvalData(sha: String) = buildJsonObject { put("exe", "Roblox.exe"); put("sha256", sha) }

    private fun alert(id: String, sha: String, acked: Boolean = false) =
        AlertView(AlertItem(id, dev, sid, ts, "request.exe_approval", "warn", approvalData(sha)), acked)

    private fun ev(id: String, type: String, userSid: String?, data: JsonObject = JsonObject(emptyMap())) =
        EventItem(id, dev, userSid, ts, 1, type, data)

    // ---- B3
    @Test fun pendingHidesDecidedShaIncludingDuplicates() {
        val alerts = listOf(alert("a1", "aa"), alert("a2", "aa"), alert("a3", "bb"))
        assertEquals(listOf("a1", "a2", "a3"), Approvals.pending(alerts, emptyMap(), dev, sid).map { it.item.id })
        val left = Approvals.pending(alerts, mapOf("aa" to ApprovalState.ALLOWED), dev, sid)
        assertEquals(listOf("a3"), left.map { it.item.id })
    }

    @Test fun ackedAlertCountsAsHandledAndLocalDecisionWins() {
        val alerts = listOf(alert("a1", "aa", acked = true), alert("a2", "bb", acked = true))
        val d = Approvals.decided(alerts, mapOf("bb" to ApprovalState.BLOCKED))
        assertEquals(ApprovalState.HANDLED, d["aa"])
        assertEquals(ApprovalState.BLOCKED, d["bb"])
    }

    @Test fun timelineMarksDecidedApproval() {
        val e = ev("e1", "request.exe_approval", sid, approvalData("aa"))
        val pending = TimelineBuilder.build(listOf(e), "PC", emptyMap()).single()
        assertTrue(pending.approve); assertEquals("Chờ duyệt: Roblox.exe", pending.title)
        val allowed = TimelineBuilder.build(listOf(e), "PC", emptyMap(), mapOf("aa" to ApprovalState.ALLOWED)).single()
        assertFalse(allowed.approve); assertEquals("Đã cho phép: Roblox.exe", allowed.title)
        val blocked = TimelineBuilder.build(listOf(e), "PC", emptyMap(), mapOf("aa" to ApprovalState.BLOCKED)).single()
        assertEquals("Đã chặn: Roblox.exe", blocked.title)
    }

    // ---- B4
    @Test fun newAppSubFormats() {
        val full = buildJsonObject { put("publisher", "Roblox Corporation"); put("signed", true); put("sizeBytes", 5_452_595L) }
        assertEquals("Ứng dụng mới · Roblox Corporation · ${Fmt.bytes(5_452_595L)}", TimelineBuilder.newAppSub(full))
        val unsigned = buildJsonObject { put("signed", false); put("sizeBytes", 1024L) }
        assertEquals("Ứng dụng mới · không có chữ ký · ${Fmt.bytes(1024L)}", TimelineBuilder.newAppSub(unsigned))
        assertEquals("Ứng dụng mới", TimelineBuilder.newAppSub(JsonObject(emptyMap())))
    }

    @Test fun deviceLevelTamperIsMergedAndTagged() {
        val mine = listOf(ev("1", "web.search", sid))
        val deviceLevel = listOf(
            ev("2", "tamper.clock_jump", null),
            ev("3", "tamper.clock_jump", "S-other"), // another child's: not merged
            ev("4", "device.something", null),        // not tamper: not merged
            ev("1", "web.search", sid),                // duplicate id
        )
        val merged = TimelineBuilder.mergeDeviceEvents(mine, deviceLevel)
        assertEquals(listOf("1", "2"), merged.map { it.id })
        val rows = TimelineBuilder.build(merged, "PC", emptyMap())
        assertTrue(rows.single { it.title == "Phát hiện can thiệp" }.device)
        assertFalse(rows.single { it.title.startsWith("Tìm kiếm") }.device)
    }

    // ---- B5
    @Test fun lockUiShowsUnlockWhenLocked() {
        val free = LockUi.of(UserState(sid, loggedOn = true))
        assertFalse(free.unlock); assertEquals("Khóa", free.label); assertNull(free.untilText)
        val locked = LockUi.of(UserState(sid, locked = true, lockedUntil = "2026-11-22T10:54:47Z"))
        assertTrue(locked.unlock); assertEquals("Mở khóa", locked.label)
        assertEquals("Khóa đến ${Fmt.time("2026-11-22T10:54:47Z")}", locked.untilText)
        assertNull(LockUi.of(UserState(sid, locked = true)).untilText)
        assertFalse(LockUi.of(null).unlock)
    }

    // ---- B6: expiresAt = max(issuedAt + 24h, until + 1h)
    @Test fun lockNowExpiry() {
        val now = Instant.parse("2026-11-22T09:54:47Z")
        fun ttl(until: String?) = EnvelopeBuilder.commandTtl(Command.LockNow("c", sid, until), now)
        assertEquals(Duration.ofHours(24), ttl(null))
        assertEquals(Duration.ofHours(24), ttl("2026-11-22T10:54:47Z")) // until + 1h < issuedAt + 24h
        assertEquals(Duration.ofHours(39), ttl("2026-11-23T23:54:47Z")) // until (38 h ahead) + 1 h is later
        assertEquals(Duration.ofHours(24), EnvelopeBuilder.commandTtl(Command.Unlock("c", sid), now))
    }
}
