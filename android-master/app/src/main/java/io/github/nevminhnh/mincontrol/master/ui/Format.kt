package io.github.nevminhnh.mincontrol.master.ui

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/** Vietnamese display helpers. */
object Fmt {
    private val zone: ZoneId get() = ZoneId.systemDefault()
    private val hm = DateTimeFormatter.ofPattern("HH:mm")
    private val dm = DateTimeFormatter.ofPattern("dd/MM")
    private val dayNames = listOf("Thứ hai", "Thứ ba", "Thứ tư", "Thứ năm", "Thứ sáu", "Thứ bảy", "Chủ nhật")

    fun parse(ts: String?): Instant? = ts?.let { runCatching { Instant.parse(it) }.getOrNull() }

    fun time(ts: String?): String = parse(ts)?.let { hm.format(it.atZone(zone)) } ?: "--:--"
    fun time(i: Instant): String = hm.format(i.atZone(zone))

    /** "Chủ nhật, 22/11 · 15:50" */
    fun headerNow(now: ZonedDateTime = ZonedDateTime.now()): String =
        "${dayNames[now.dayOfWeek.value - 1]}, ${dm.format(now)} · ${hm.format(now)}"

    fun dayMonth(d: LocalDate): String = dm.format(d)

    /** "1:12" from minutes. */
    fun hMm(min: Int): String = "${min / 60}:${"%02d".format(min % 60)}"

    /** "48 phút", "2 giờ", "1 giờ 30 phút" */
    fun duration(min: Int): String = when {
        min < 60 -> "$min phút"
        min % 60 == 0 -> "${min / 60} giờ"
        else -> "${min / 60} giờ ${min % 60} phút"
    }

    fun shortDuration(sec: Int): String {
        val m = sec / 60
        return if (m < 60) "${m}p" else "${m / 60}g${if (m % 60 > 0) "%02d".format(m % 60) else ""}"
    }

    /** "hôm qua 18:40", "15:50", "20/11 18:40" */
    fun relativeDayTime(ts: String?): String {
        val i = parse(ts) ?: return "không rõ"
        val z = i.atZone(zone)
        val today = LocalDate.now(zone)
        return when (z.toLocalDate()) {
            today -> hm.format(z)
            today.minusDays(1) -> "hôm qua ${hm.format(z)}"
            else -> "${dm.format(z)} ${hm.format(z)}"
        }
    }

    fun dayStart(d: LocalDate): Instant = d.atStartOfDay(zone).toInstant()
    fun dayEnd(d: LocalDate): Instant = d.plusDays(1).atStartOfDay(zone).toInstant()
    fun localDate(ts: String?): LocalDate? = parse(ts)?.atZone(zone)?.toLocalDate()

    private val knownApps = mapOf(
        "msedge.exe" to "Microsoft Edge", "chrome.exe" to "Google Chrome", "firefox.exe" to "Firefox",
        "explorer.exe" to "File Explorer", "zalo.exe" to "Zalo", "minecraft.exe" to "Minecraft",
        "javaw.exe" to "Minecraft (Java)", "robloxplayerbeta.exe" to "Roblox", "winword.exe" to "Microsoft Word",
        "excel.exe" to "Microsoft Excel", "powerpnt.exe" to "PowerPoint", "code.exe" to "VS Code",
        "discord.exe" to "Discord", "steam.exe" to "Steam", "teams.exe" to "Microsoft Teams", "ms-teams.exe" to "Microsoft Teams",
    )

    fun appName(exe: String?): String {
        if (exe.isNullOrBlank()) return "Không rõ"
        knownApps[exe.lowercase()]?.let { return it }
        return exe.removeSuffix(".exe").removeSuffix(".EXE")
    }

    /** "N phút" the foreground app has been open, from [startedAt] (RFC3339) to [now]; null when unknown. */
    fun openMinutes(startedAt: String?, now: Instant = Instant.now()): Int? =
        parse(startedAt)?.let { ((now.epochSecond - it.epochSecond) / 60).toInt().coerceAtLeast(0) }

    fun engineLabel(engine: String?, host: String? = null): String {
        val e = (engine ?: host.orEmpty()).lowercase()
        return when {
            "google" in e -> "Google"; "bing" in e -> "Bing"; "youtube" in e -> "YouTube"
            "coccoc" in e || "cốc" in e -> "Cốc Cốc"; "duckduckgo" in e -> "DuckDuckGo"
            else -> engine.orEmpty()
        }
    }

    fun bytes(n: Long?): String = when {
        n == null -> ""
        n >= 1_000_000 -> "%.1f MB".format(n / 1_000_000.0).replace('.', ',')
        n >= 1_000 -> "${n / 1000} KB"
        else -> "$n B"
    }
}
