package io.github.nevminhnh.mincontrol.master.ui.activity

import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import io.github.nevminhnh.mincontrol.master.ui.alerts.str
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

enum class DotKind { LIVE, INFO, BLOCK, APP, NEUTRAL }

data class TimelineRow(val ts: String, val dot: DotKind, val title: String, val sub: String, val red: Boolean = false, val approve: Boolean = false, val device: Boolean = false)

/** Turns raw events (newest first, as returned by the API) into timeline rows (newest first). */
object TimelineBuilder {

    /** Adds device-level tamper events (no userSid) to the child's own events; dedupes by id. */
    fun mergeDeviceEvents(events: List<EventItem>, deviceLevel: List<EventItem>): List<EventItem> {
        val ids = events.mapTo(HashSet()) { it.id }
        return events + deviceLevel.filter { it.userSid == null && it.type.startsWith("tamper.") && ids.add(it.id) }
    }

    /** "Ứng dụng mới · <publisher | không có chữ ký> · <size>"; missing fields are left out. */
    fun newAppSub(d: kotlinx.serialization.json.JsonObject): String {
        val signed = (d["signed"] as? JsonPrimitive)?.content?.toBooleanStrictOrNull()
        val pub = d.str("publisher")?.takeIf { it.isNotBlank() }
        val sig = when { pub != null && signed != false -> pub; signed == false -> "không có chữ ký"; else -> null }
        val size = (d["sizeBytes"] as? JsonPrimitive)?.content?.toLongOrNull()?.let { Fmt.bytes(it) }
        return listOfNotNull("Ứng dụng mới", sig, size).joinToString(" · ")
    }

    fun build(events: List<EventItem>, hostname: String, groupLabels: Map<String, String>, decided: Map<String, ApprovalState> = emptyMap()): List<TimelineRow> {
        val asc = events.sortedBy { it.ts }
        val rows = mutableListOf<TimelineRow>()
        // Collapse consecutive usage.tick events of the same exe into one "app session".
        var sessionStart: EventItem? = null
        var sessionSec = 0
        var sessionTitle: String? = null
        fun flush() {
            val s = sessionStart ?: return
            val exe = s.data.str("exe")
            val group = s.data.str("group")
            val min = (sessionSec + 30) / 60
            if (min >= 1) {
                val name = Fmt.appName(exe)
                val groupText = group?.let { "Nhóm ${groupLabels[it] ?: it}" }
                rows += TimelineRow(
                    s.ts, if (group == "games") DotKind.APP else DotKind.INFO,
                    "$name · ${Fmt.duration(min)}",
                    listOfNotNull(groupText, sessionTitle?.takeIf { it.isNotBlank() }).joinToString(" · ").ifEmpty { exe ?: "" },
                )
            }
            sessionStart = null; sessionSec = 0; sessionTitle = null
        }
        for (e in asc) {
            if (e.type == "usage.tick") {
                val exe = e.data.str("exe")
                if (sessionStart?.data?.str("exe") != exe) { flush(); sessionStart = e }
                sessionSec += (e.data["activeSec"] as? JsonPrimitive)?.intOrNull ?: 0
                e.data.str("title")?.let { sessionTitle = it }
                continue
            }
            row(e, hostname, decided)?.let { flush(); rows += it }
        }
        flush()
        return rows.sortedByDescending { it.ts }
    }

    private fun row(e: EventItem, hostname: String, decided: Map<String, ApprovalState>): TimelineRow? {
        val d = e.data
        return when (e.type) {
            "session.logon" -> TimelineRow(e.ts, DotKind.NEUTRAL, "Đăng nhập $hostname", "Phiên ${d["sessionId"] ?: ""}".trim())
            "session.logoff" -> TimelineRow(e.ts, DotKind.NEUTRAL, "Đăng xuất $hostname", "")
            "session.lock" -> TimelineRow(e.ts, DotKind.NEUTRAL, "Khóa màn hình", "")
            "session.unlock" -> TimelineRow(e.ts, DotKind.NEUTRAL, "Mở khóa màn hình", "")
            "process.blocked" -> TimelineRow(e.ts, DotKind.BLOCK, "Chặn: ${d.str("exe") ?: "ứng dụng"}",
                listOfNotNull(d.str("path"), d.str("rule")).joinToString(" · "), red = true)
            "request.exe_approval" -> {
                val exe = d.str("exe") ?: "ứng dụng"
                val state = d.str("sha256")?.let { decided[it] }
                if (state != null) TimelineRow(e.ts, if (state == ApprovalState.BLOCKED) DotKind.BLOCK else DotKind.INFO, "${state.label}: $exe", newAppSub(d))
                else TimelineRow(e.ts, DotKind.INFO, "Chờ duyệt: $exe", newAppSub(d), approve = true)
            }
            "web.blocked" -> TimelineRow(e.ts, DotKind.BLOCK, "Chặn web: ${d.str("host") ?: ""}",
                WebLabels.blockedSubtitle(d.str("category"), d.str("reason")) ?: "", red = true)
            "web.search" -> TimelineRow(e.ts, DotKind.INFO, "Tìm kiếm ${engineLabel(d.str("engine"))}", "“${d.str("query") ?: ""}”")
            "quota.warning" -> TimelineRow(e.ts, DotKind.INFO, "Sắp hết giờ", "Còn ${d["remainingMin"] ?: "?"} phút")
            "quota.exhausted" -> TimelineRow(e.ts, DotKind.BLOCK, "Hết giờ", "Đã đăng xuất tự động", red = true)
            "install.detected" -> TimelineRow(e.ts, DotKind.INFO, "Cài đặt: ${d.str("product") ?: ""}", d.str("publisher") ?: "")
            "download.completed" -> TimelineRow(e.ts, DotKind.INFO, "Tải xuống: ${d.str("fileName") ?: ""}", d.str("url") ?: "")
            "usb.attached" -> TimelineRow(e.ts, DotKind.NEUTRAL, "Cắm USB: ${d.str("deviceName") ?: ""}", d.str("volumeLabel") ?: "")
            "usb.detached" -> TimelineRow(e.ts, DotKind.NEUTRAL, "Rút USB: ${d.str("deviceName") ?: ""}", "")
            "screenshot.taken" -> TimelineRow(e.ts, DotKind.NEUTRAL, "Ảnh màn hình", Fmt.appName(d.str("foregroundExe")))
            else -> if (e.type.startsWith("tamper.")) TimelineRow(e.ts, DotKind.BLOCK, "Phát hiện can thiệp", d.str("detail") ?: e.type, red = true, device = e.userSid == null) else null
        }
    }

    private fun engineLabel(e: String?) = Fmt.engineLabel(e)
}
