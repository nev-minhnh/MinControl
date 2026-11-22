package io.github.nevminhnh.mincontrol.master.ui.alerts

import android.app.Application
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.nevminhnh.mincontrol.master.data.AlertView
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.AlertItem
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.Decision
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

enum class AlertFilter(val label: String) { ALL("Tất cả"), TAMPER("Can thiệp"), REQUEST("Yêu cầu"), WEB("Web") }

enum class AlertKind { TAMPER, REQUEST, WEB, QUOTA, OFFLINE, OTHER }

/** Display model of one alert. */
data class AlertCard(
    val view: AlertView,
    val kind: AlertKind,
    val title: String,
    val body: String,
    val time: String,
    val day: String,
    val child: Child?,
    val sha256: String?,
)

fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

class AlertsViewModel(app: Application) : AndroidViewModel(app) {
    private val graph = app.graph
    private val repo = graph.repo

    val filter = MutableStateFlow(AlertFilter.ALL)
    val message = MutableStateFlow<String?>(null)
    val refreshing = MutableStateFlow(false)
    val busy = MutableStateFlow<Set<String>>(emptySet())

    val cards: StateFlow<List<AlertCard>> = combine(repo.alerts, repo.children, filter) { alerts, children, f ->
        alerts.map { toCard(it, children) }.filter { c ->
            when (f) {
                AlertFilter.ALL -> true
                AlertFilter.TAMPER -> c.kind == AlertKind.TAMPER
                AlertFilter.REQUEST -> c.kind == AlertKind.REQUEST
                AlertFilter.WEB -> c.kind == AlertKind.WEB
            }
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val unackedCount: StateFlow<Int> = combine(repo.alerts, filter) { a, _ -> a.count { !it.acked } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, 0)

    init { refresh() }

    fun refresh() = viewModelScope.launch {
        refreshing.value = true
        try { repo.refreshAlerts() } catch (e: Exception) { message.value = e.userMessage() } finally { refreshing.value = false }
    }

    fun ack(card: AlertCard) = viewModelScope.launch {
        try { repo.ackAlert(card.view.item.id) } catch (e: Exception) { message.value = e.userMessage() }
    }

    /** Sends `approve_exe` (biometric) and acknowledges the alert. */
    fun decide(activity: FragmentActivity, card: AlertCard, allow: Boolean) = viewModelScope.launch {
        val item = card.view.item
        val sid = item.userSid
        val sha = card.sha256
        if (sid == null || sha == null) {
            message.value = "Cảnh báo thiếu thông tin ứng dụng (sha256)."
            return@launch
        }
        busy.value = busy.value + item.id
        try {
            val cmd = Command.ApproveExe(repo.newCommandId(), sid, sha, if (allow) Decision.ALLOW else Decision.BLOCK)
            val exe = item.data.str("exe") ?: "ứng dụng"
            repo.sendCommand(activity, item.deviceId, cmd, if (allow) "Cho phép $exe" else "Chặn $exe", card.child?.label)
            repo.recordDecision(sha, allow)
            repo.ackAlert(item.id)
            message.value = if (allow) "Đã cho phép $exe." else "Đã chặn $exe."
        } catch (e: BiometricCancelledException) {
        } catch (e: Exception) {
            message.value = e.userMessage()
        } finally {
            busy.value = busy.value - item.id
        }
    }

    companion object {
        fun kindOf(type: String): AlertKind = when {
            type.startsWith("tamper.") || type == "process.blocked" -> AlertKind.TAMPER
            type.startsWith("request.") -> AlertKind.REQUEST
            type.startsWith("web.") -> AlertKind.WEB
            type.startsWith("quota.") -> AlertKind.QUOTA
            type.contains("offline") -> AlertKind.OFFLINE
            else -> AlertKind.OTHER
        }

        fun toCard(v: AlertView, children: List<Child>): AlertCard {
            val a: AlertItem = v.item
            val child = children.firstOrNull { it.deviceId == a.deviceId && it.sid == a.userSid }
            val host = children.firstOrNull { it.deviceId == a.deviceId }?.hostname ?: "Máy tính"
            val who = child?.label ?: "Con"
            val d = a.data
            val exe = d.str("exe")
            val count = (d["count"] as? JsonPrimitive)?.longOrNull
            val hosts = runCatching { d["hosts"]?.jsonArray?.mapNotNull { it.jsonPrimitive.content } }.getOrNull()
            val kind = kindOf(a.type)
            val (title, body) = when {
                a.type == "request.exe_approval" -> {
                    val signed = (d["signed"] as? JsonPrimitive)?.booleanOrNull
                    val pub = d.str("publisher")
                    val parts = listOfNotNull(
                        exe,
                        when { pub != null && signed != false -> "có chữ ký $pub"; signed == false -> "không có chữ ký"; else -> null },
                        (d["sizeBytes"] as? JsonPrimitive)?.longOrNull?.let { Fmt.bytes(it) },
                    )
                    "$who muốn chạy ứng dụng mới" to parts.joinToString(" · ")
                }
                a.type == "tamper.proxy_bypass_attempt" -> "Phát hiện cố vượt chặn" to (d.str("detail") ?: "$who cố vượt bộ lọc mạng${exe?.let { " bằng “$it”" } ?: ""}.")
                a.type == "tamper.agent_killed" -> "Ứng dụng giám sát bị tắt" to (d.str("detail") ?: "Trên $host.")
                a.type == "tamper.service_stopped" -> "Dịch vụ MinControl bị dừng" to (d.str("detail") ?: "Trên $host.")
                a.type == "tamper.wfp_filter_missing" -> "Bộ lọc mạng bị gỡ" to (d.str("detail") ?: "Trên $host.")
                a.type == "tamper.timezone_changed" -> "Múi giờ bị thay đổi" to (d.str("detail") ?: "Trên $host.")
                a.type == "tamper.clock_jump" -> "Đồng hồ máy bị chỉnh" to (d.str("detail") ?: "Trên $host.")
                a.type == "tamper.managed_user_is_admin" -> "Tài khoản của $who có quyền admin" to "Hãy chuyển tài khoản này về Standard user."
                a.type == "tamper.extension_missing" -> "Tiện ích trình duyệt bị gỡ" to (d.str("detail") ?: "Trên $host.")
                a.type == "tamper.offline_gap" -> "Máy mất kết nối bất thường" to (d.str("detail") ?: "Trên $host.")
                a.type.startsWith("tamper.") -> "Phát hiện can thiệp" to (d.str("detail") ?: a.type)
                a.type == "process.blocked" -> "${count ?: 1} ứng dụng bị chặn" to listOfNotNull(exe ?: hosts?.firstOrNull(), "$who · $host").joinToString(" · ")
                a.type.startsWith("web.") -> {
                    val n = count ?: hosts?.size?.toLong() ?: 1
                    val first = hosts?.firstOrNull() ?: d.str("host")
                    val rest = if (first != null && n > 1) "$first và ${n - 1} trang khác" else first ?: "$who · $host"
                    "$n trang web bị chặn" to (rest + (d.str("category")?.let { " · danh mục $it" } ?: ""))
                }
                a.type == "quota.exhausted" -> "$who dùng hết giờ" to "Đã đăng xuất tự động."
                kind == AlertKind.OFFLINE -> "$host offline" to (d.str("detail") ?: "Máy không kết nối hơn 2 giờ.")
                else -> a.type to (d.str("detail") ?: "")
            }
            val date = Fmt.localDate(a.ts)
            val today = java.time.LocalDate.now()
            val day = when (date) {
                today -> "Hôm nay"
                today.minusDays(1) -> "Hôm qua"
                null -> "Khác"
                else -> Fmt.dayMonth(date)
            }
            return AlertCard(v, kind, title, body, Fmt.time(a.ts), day, child, d.str("sha256"))
        }
    }
}
