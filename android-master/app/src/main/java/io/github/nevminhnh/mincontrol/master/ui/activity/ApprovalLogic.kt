package io.github.nevminhnh.mincontrol.master.ui.activity

import io.github.nevminhnh.mincontrol.master.data.AlertView
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Local knowledge about an `approve_exe` decision, keyed by the app's sha256 (B3). */
enum class ApprovalState(val label: String) {
    ALLOWED("Đã cho phép"), BLOCKED("Đã chặn"),
    /** The alert was acknowledged (here or elsewhere) but we do not know allow vs block. */
    HANDLED("Đã xử lý"),
}

object Approvals {
    private fun sha(data: JsonObject): String? = (data["sha256"] as? JsonPrimitive)?.takeIf { it.isString }?.content

    /**
     * sha256 -> state. Acked `request.exe_approval` alerts count as handled; decisions made through this app
     * ([local], recorded when the cloud accepted the command) override with the precise outcome.
     */
    fun decided(alerts: List<AlertView>, local: Map<String, ApprovalState>): Map<String, ApprovalState> {
        val out = mutableMapOf<String, ApprovalState>()
        for (a in alerts) {
            if (a.item.type != "request.exe_approval" || !a.acked) continue
            sha(a.item.data)?.let { out[it] = ApprovalState.HANDLED }
        }
        out.putAll(local)
        return out
    }

    /** Unacked approval requests of one child whose sha256 has not been decided yet. */
    fun pending(alerts: List<AlertView>, local: Map<String, ApprovalState>, deviceId: String?, sid: String?): List<AlertView> {
        val done = decided(alerts, local)
        return alerts.filter {
            !it.acked && it.item.type == "request.exe_approval" && it.item.deviceId == deviceId && it.item.userSid == sid &&
                sha(it.item.data) !in done
        }
    }
}
