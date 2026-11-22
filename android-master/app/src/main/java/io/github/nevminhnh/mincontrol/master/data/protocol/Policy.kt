package io.github.nevminhnh.mincontrol.master.data.protocol

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Policy JSON: strict on unknown keys, **encodes defaults** (required fields), omits nulls (optional fields). */
@OptIn(ExperimentalSerializationApi::class)
val PolicyJson: Json = Json {
    ignoreUnknownKeys = false
    explicitNulls = false
    encodeDefaults = true
}

/** Mirrors `protocol/policy.schema.json`. */
@Serializable
data class Policy(
    val version: Int,
    val timezone: String = "Asia/Ho_Chi_Minh",
    val users: Map<String, UserPolicy>,
    val retentionDays: RetentionDays = RetentionDays(),
)

@Serializable
data class RetentionDays(val events: Int = 180, val web: Int = 180, val screenshots: Int = 30)

@Serializable
data class WeekdayMinutes(
    val mon: Int, val tue: Int, val wed: Int, val thu: Int, val fri: Int, val sat: Int, val sun: Int,
) {
    fun get(day: Weekday): Int = when (day) {
        Weekday.MON -> mon; Weekday.TUE -> tue; Weekday.WED -> wed; Weekday.THU -> thu
        Weekday.FRI -> fri; Weekday.SAT -> sat; Weekday.SUN -> sun
    }

    fun with(day: Weekday, v: Int): WeekdayMinutes = when (day) {
        Weekday.MON -> copy(mon = v); Weekday.TUE -> copy(tue = v); Weekday.WED -> copy(wed = v)
        Weekday.THU -> copy(thu = v); Weekday.FRI -> copy(fri = v); Weekday.SAT -> copy(sat = v); Weekday.SUN -> copy(sun = v)
    }

    companion object {
        fun of(weekday: Int, weekend: Int) = WeekdayMinutes(weekday, weekday, weekday, weekday, weekday, weekend, weekend)
    }
}

@Serializable
data class WeekdayWindows(
    val mon: List<String>, val tue: List<String>, val wed: List<String>, val thu: List<String>,
    val fri: List<String>, val sat: List<String>, val sun: List<String>,
) {
    fun get(day: Weekday): List<String> = when (day) {
        Weekday.MON -> mon; Weekday.TUE -> tue; Weekday.WED -> wed; Weekday.THU -> thu
        Weekday.FRI -> fri; Weekday.SAT -> sat; Weekday.SUN -> sun
    }

    fun with(day: Weekday, v: List<String>): WeekdayWindows = when (day) {
        Weekday.MON -> copy(mon = v); Weekday.TUE -> copy(tue = v); Weekday.WED -> copy(wed = v)
        Weekday.THU -> copy(thu = v); Weekday.FRI -> copy(fri = v); Weekday.SAT -> copy(sat = v); Weekday.SUN -> copy(sun = v)
    }

    companion object {
        fun of(weekday: List<String>, weekend: List<String>) =
            WeekdayWindows(weekday, weekday, weekday, weekday, weekday, weekend, weekend)
    }
}

enum class Weekday(val label: String, val short: String) {
    MON("Thứ 2", "T2"), TUE("Thứ 3", "T3"), WED("Thứ 4", "T4"), THU("Thứ 5", "T5"),
    FRI("Thứ 6", "T6"), SAT("Thứ 7", "T7"), SUN("Chủ nhật", "CN");

    companion object {
        fun of(d: java.time.DayOfWeek): Weekday = entries[d.value - 1]
    }
}

@Serializable
data class AppMatch(
    val exe: String? = null,
    val path: String? = null,
    val publisher: String? = null,
    val sha256: String? = null,
    val pathUnderUserWritable: Boolean? = null,
)

@Serializable
data class ScreenTime(
    val dailyQuotaMin: WeekdayMinutes,
    val allowedWindows: WeekdayWindows,
    val warnAtMin: List<Int> = listOf(5, 1),
    val graceSec: Int = 60,
    val countIdle: Boolean = false,
    val idleThresholdSec: Int = 300,
)

@Serializable
data class AppGroup(
    val label: String,
    val match: List<AppMatch>,
    val dailyQuotaMin: WeekdayMinutes? = null,
)

@Serializable
enum class RuleAction { @SerialName("block") BLOCK, @SerialName("allow") ALLOW }

@Serializable
data class AppRule(val action: RuleAction, val match: AppMatch, val except: List<AppMatch>? = null)

@Serializable
enum class NewExecutable { @SerialName("allow") ALLOW, @SerialName("block") BLOCK, @SerialName("ask") ASK }

@Serializable
enum class WebMode { @SerialName("blocklist") BLOCKLIST, @SerialName("allowlist") ALLOWLIST }

@Serializable
enum class YouTubeMode { @SerialName("off") OFF, @SerialName("moderate") MODERATE, @SerialName("strict") STRICT }

@Serializable
enum class WebCategory(val label: String) {
    @SerialName("adult") ADULT("Người lớn"),
    @SerialName("gambling") GAMBLING("Cờ bạc"),
    @SerialName("proxy-vpn") PROXY_VPN("VPN"),
    @SerialName("games") GAMES("Trò chơi"),
    @SerialName("social") SOCIAL("Mạng xã hội"),
    @SerialName("video") VIDEO("Video"),
    @SerialName("violence") VIOLENCE("Bạo lực"),
    @SerialName("drugs") DRUGS("Chất cấm"),
    @SerialName("dating") DATING("Hẹn hò"),
    @SerialName("malware") MALWARE("Mã độc"),
}

@Serializable
data class WebPolicy(
    val mode: WebMode = WebMode.BLOCKLIST,
    val blockedCategories: List<WebCategory> = emptyList(),
    /** Keys limited to games / social / video by the schema. */
    val categorySchedules: Map<WebCategory, WeekdayWindows>? = null,
    val blockDomains: List<String> = emptyList(),
    val allowDomains: List<String> = emptyList(),
    val safeSearch: Boolean = true,
    val youtube: YouTubeMode = YouTubeMode.STRICT,
    val allowedBrowsers: List<String> = listOf("msedge.exe", "chrome.exe"),
    val netExemptApps: List<AppMatch> = emptyList(),
)

@Serializable
data class ScreenshotSettings(
    val intervalMin: Int = 5,
    val onlyWhenActive: Boolean = true,
    val maxWidth: Int = 1280,
    val jpegQuality: Int = 60,
)

@Serializable
data class Monitoring(
    val foregroundTitles: Boolean = true,
    val browserHistory: Boolean = true,
    val domainLog: Boolean = true,
    val downloads: Boolean = true,
    val usb: Boolean = true,
    val screenshots: ScreenshotSettings = ScreenshotSettings(),
)

@Serializable
data class UserPolicy(
    val label: String,
    val screenTime: ScreenTime,
    val appGroups: Map<String, AppGroup> = emptyMap(),
    val appRules: List<AppRule> = emptyList(),
    val newExecutable: NewExecutable = NewExecutable.ASK,
    val web: WebPolicy = WebPolicy(),
    val monitoring: Monitoring = Monitoring(),
)
