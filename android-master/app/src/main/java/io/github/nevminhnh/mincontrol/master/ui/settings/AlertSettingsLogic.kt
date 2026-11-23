package io.github.nevminhnh.mincontrol.master.ui.settings

import io.github.nevminhnh.mincontrol.master.data.protocol.AlertSetting
import io.github.nevminhnh.mincontrol.master.data.protocol.MasterSettings

/** One row of "Cảnh báo" (API.md §19 alert types). */
data class AlertTypeInfo(val type: String, val title: String, val description: String)

/** Pure mapping between the `alerts` object of `/v1/master/settings` and the "Cảnh báo" screen. */
object AlertSettingsLogic {
    const val TAMPER = "tamper"
    const val LOGON = "session.logon"
    const val LOGOFF = "session.logoff"

    val TYPES: List<AlertTypeInfo> = listOf(
        AlertTypeInfo(TAMPER, "Can thiệp / vượt rào", "Con tìm cách tắt, gỡ hoặc qua mặt MinControl (đổi giờ, tắt dịch vụ, dùng VPN…)"),
        AlertTypeInfo("request.exe_approval", "Xin duyệt ứng dụng", "Con mở một ứng dụng lạ và đang chờ anh cho phép"),
        AlertTypeInfo("quota.exhausted", "Hết giờ", "Con đã dùng hết thời gian trong ngày"),
        AlertTypeInfo("quota.warning", "Sắp hết giờ", "Còn vài phút trước khi hết thời gian"),
        AlertTypeInfo("blocked.burst", "Bị chặn nhiều lần", "Con liên tục vào trang hoặc ứng dụng bị chặn trong thời gian ngắn"),
        AlertTypeInfo("web.blocked", "Mỗi lần chặn web", "Mỗi khi một trang web bị chặn (có thể rất nhiều)"),
        AlertTypeInfo("process.blocked", "Mỗi lần chặn ứng dụng", "Mỗi khi một ứng dụng bị chặn chạy"),
        AlertTypeInfo("device.offline", "Máy offline", "Máy tính mất kết nối lâu bất thường"),
        AlertTypeInfo(LOGON, "Đăng nhập", "Con đăng nhập vào máy tính"),
        AlertTypeInfo(LOGOFF, "Đăng xuất", "Con đăng xuất khỏi máy tính"),
    )

    /** Frequency choices: minutes → label. 0 = every time. */
    val FREQUENCIES: List<Pair<Int, String>> = listOf(
        0 to "Mỗi lần",
        5 to "Tối đa 1 lần mỗi 5 phút",
        15 to "Tối đa 1 lần mỗi 15 phút",
        60 to "Tối đa 1 lần mỗi 1 giờ",
        1440 to "Tối đa 1 lần mỗi 1 ngày",
    )

    /** §19 defaults: only tamper on (every time); everything else off. */
    fun default(type: String): AlertSetting = AlertSetting(enabled = type == TAMPER, minIntervalMin = 0)

    val DEFAULTS: Map<String, AlertSetting> = TYPES.associate { it.type to default(it.type) }

    /**
     * Full map for every known type. Missing types get the default; when the server has no `alerts` yet the old
     * logon/logoff switches (API.md 16) are carried over so turning on §19 does not silently change them.
     */
    fun effective(s: MasterSettings): Map<String, AlertSetting> {
        val a = s.alerts
        return TYPES.associate { t ->
            val v = a?.get(t.type) ?: when {
                a == null && t.type == LOGON -> AlertSetting(s.notifyLogon, 0)
                a == null && t.type == LOGOFF -> AlertSetting(s.notifyLogoff, 0)
                else -> default(t.type)
            }
            t.type to v.copy(minIntervalMin = snap(v.minIntervalMin))
        }
    }

    /** Returns the settings to PUT after changing one type; logon/logoff stay mirrored in the legacy booleans. */
    fun update(s: MasterSettings, type: String, enabled: Boolean? = null, minIntervalMin: Int? = null): MasterSettings {
        val cur = effective(s)
        val old = cur[type] ?: default(type)
        val next = old.copy(enabled = enabled ?: old.enabled, minIntervalMin = snap(minIntervalMin ?: old.minIntervalMin))
        val map = cur + (type to next)
        return s.copy(
            alerts = map,
            notifyLogon = map[LOGON]?.enabled ?: s.notifyLogon,
            notifyLogoff = map[LOGOFF]?.enabled ?: s.notifyLogoff,
        )
    }

    /** Server values outside the list snap to the nearest choice (never below 0). */
    fun snap(min: Int): Int = FREQUENCIES.minBy { kotlin.math.abs(it.first - min.coerceAtLeast(0)) }.first

    fun frequencyLabel(min: Int): String = FREQUENCIES.first { it.first == snap(min) }.second

    /** A PUT answered by a server that predates §19 has no `alerts`: keep what we sent so the switches do not jump back. */
    fun merged(sent: MasterSettings, answer: MasterSettings): MasterSettings =
        if (answer.alerts == null) answer.copy(alerts = sent.alerts) else answer
}
