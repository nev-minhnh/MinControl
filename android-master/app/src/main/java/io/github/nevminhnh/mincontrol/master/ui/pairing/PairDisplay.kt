package io.github.nevminhnh.mincontrol.master.ui.pairing

import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo
import java.time.Duration
import java.time.Instant

/** "10.0.26100" -> "Windows 11 (10.0.26100)" (build >= 22000) or "Windows 10 (...)"; unparseable text is returned as is. */
fun osDisplay(os: String): String {
    val v = os.trim()
    if (v.isEmpty() || v.startsWith("Windows", ignoreCase = true)) return v
    val build = v.split('.').getOrNull(2)?.takeWhile { it.isDigit() }?.toIntOrNull() ?: return v
    return (if (build >= 22000) "Windows 11" else "Windows 10") + " ($v)"
}

/** Devices sharing a hostname get " · <last 4 of deviceId>" appended so chips/cards stay distinguishable. */
fun disambiguateHostnames(list: List<DeviceInfo>): List<DeviceInfo> {
    val dup = list.groupingBy { it.hostname }.eachCount().filterValues { it > 1 }.keys
    if (dup.isEmpty()) return list
    return list.map { if (it.hostname in dup) it.copy(hostname = "${it.hostname} · ${it.deviceId.takeLast(4)}") else it }
}

/** Jump to "Thêm máy tính" after registration when there is no device, or every device has been offline > 7 days. */
fun shouldJumpToPairing(devices: List<DeviceInfo>, now: Instant): Boolean =
    devices.all { d ->
        if (d.online) return@all false
        val seen = d.lastSeen?.let { runCatching { Instant.parse(it) }.getOrNull() } ?: return@all true
        Duration.between(seen, now) > Duration.ofDays(7)
    }
