package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppGroup
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.NewExecutable
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.ScreenTime
import io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy
import io.github.nevminhnh.mincontrol.master.data.protocol.WebCategory
import io.github.nevminhnh.mincontrol.master.data.protocol.WebMode
import io.github.nevminhnh.mincontrol.master.data.protocol.WebPolicy
import io.github.nevminhnh.mincontrol.master.data.protocol.Weekday
import io.github.nevminhnh.mincontrol.master.data.protocol.WeekdayMinutes
import io.github.nevminhnh.mincontrol.master.data.protocol.WeekdayWindows
import io.github.nevminhnh.mincontrol.master.data.protocol.YouTubeMode

/** Defaults for a newly managed child (policy v1 from the pairing flow). */
object PolicyDefaults {
    fun user(label: String) = UserPolicy(
        label = label.take(40).ifBlank { "Con" },
        screenTime = ScreenTime(
            dailyQuotaMin = WeekdayMinutes.of(120, 180),
            allowedWindows = WeekdayWindows.of(listOf("15:00-21:00"), listOf("08:00-21:30")),
        ),
        appGroups = mapOf(
            "games" to AppGroup(
                label = "Game",
                match = listOf(AppMatch(publisher = "Valve*"), AppMatch(exe = "Minecraft*.exe"), AppMatch(exe = "Roblox*.exe")),
                dailyQuotaMin = WeekdayMinutes.of(60, 60),
            ),
        ),
        newExecutable = NewExecutable.ASK,
        web = WebPolicy(
            mode = WebMode.BLOCKLIST,
            blockedCategories = listOf(WebCategory.ADULT, WebCategory.GAMBLING, WebCategory.PROXY_VPN, WebCategory.MALWARE),
            safeSearch = true,
            youtube = YouTubeMode.STRICT,
        ),
    )

    fun policy(users: Map<String, String>, version: Int = 1) =
        Policy(version = version, users = users.mapValues { (_, label) -> user(label) })
}

/** One human-readable change between two policies. */
data class PolicyChange(val userLabel: String?, val title: String, val from: String, val to: String) {
    override fun toString() = (userLabel?.let { "$it · " } ?: "") + "$title: $from → $to"
}

fun formatMinutes(min: Int): String = when {
    min <= 0 -> "0 phút"
    min % 60 == 0 -> "${min / 60} giờ"
    min < 60 -> "$min phút"
    else -> "${min / 60} giờ ${min % 60}"
}

/** "Cả ngày" window written by the editor (`allowedWindows`: empty list = no screen time that day). */
const val ALL_DAY_WINDOW = "00:00-24:00"

fun formatWindows(list: List<String>): String = when {
    list.isEmpty() -> "Không dùng"
    list == listOf(ALL_DAY_WINDOW) -> "Cả ngày"
    else -> list.joinToString(", ") { it.replace("-", " – ") }
}

fun dayGroupLabel(days: Set<Weekday>): String {
    val weekdays = setOf(Weekday.MON, Weekday.TUE, Weekday.WED, Weekday.THU, Weekday.FRI)
    val weekend = setOf(Weekday.SAT, Weekday.SUN)
    return when (days) {
        Weekday.entries.toSet() -> "Cả tuần"
        weekdays -> "Ngày thường"
        weekend -> "Cuối tuần"
        else -> Weekday.entries.filter { it in days }.joinToString(", ") { it.short }
    }
}

/**
 * Computes the list of changes shown as "N thay đổi" before signing. Weekday maps are collapsed: days whose
 * (old, new) pair is identical form one change labelled "Ngày thường", "Cuối tuần", "Cả tuần" or "T2, T4".
 */
object PolicyDiff {

    fun diff(old: Policy?, new: Policy): List<PolicyChange> {
        val out = mutableListOf<PolicyChange>()
        if (old == null) {
            new.users.values.forEach { out += PolicyChange(it.label, "Bắt đầu quản lý", "—", "Có") }
            return out
        }
        if (old.timezone != new.timezone) out += PolicyChange(null, "Múi giờ", old.timezone, new.timezone)
        if (old.retentionDays != new.retentionDays) {
            out += PolicyChange(null, "Thời gian lưu dữ liệu",
                "${old.retentionDays.events}/${old.retentionDays.web}/${old.retentionDays.screenshots} ngày",
                "${new.retentionDays.events}/${new.retentionDays.web}/${new.retentionDays.screenshots} ngày")
        }
        for (sid in (old.users.keys + new.users.keys).distinct()) {
            val a = old.users[sid]
            val b = new.users[sid]
            when {
                a == null && b != null -> out += PolicyChange(b.label, "Bắt đầu quản lý", "Không", "Có")
                a != null && b == null -> out += PolicyChange(a.label, "Ngừng quản lý", "Có", "Không")
                a != null && b != null -> out += diffUser(a, b)
            }
        }
        return out
    }

    fun diffUser(a: UserPolicy, b: UserPolicy): List<PolicyChange> {
        val who = b.label
        val out = mutableListOf<PolicyChange>()
        fun add(title: String, from: Any?, to: Any?) {
            if (from != to) out += PolicyChange(who, title, from?.toString() ?: "—", to?.toString() ?: "—")
        }
        add("Tên", a.label, b.label)
        out += weekdays(who, "Thời gian sử dụng", { a.screenTime.dailyQuotaMin.get(it) }, { b.screenTime.dailyQuotaMin.get(it) }, ::formatMinutes)
        out += weekdays(who, "Khung giờ được dùng", { a.screenTime.allowedWindows.get(it) }, { b.screenTime.allowedWindows.get(it) }, ::formatWindows)
        add("Nhắc trước khi hết giờ", a.screenTime.warnAtMin.joinToString(", ") { "$it phút" }, b.screenTime.warnAtMin.joinToString(", ") { "$it phút" })
        add("Thời gian chờ đăng xuất", "${a.screenTime.graceSec} giây", "${b.screenTime.graceSec} giây")
        add("Tính cả lúc không dùng", onOff(a.screenTime.countIdle), onOff(b.screenTime.countIdle))
        add("Ngưỡng không dùng", "${a.screenTime.idleThresholdSec / 60} phút", "${b.screenTime.idleThresholdSec / 60} phút")

        for (g in (a.appGroups.keys + b.appGroups.keys).distinct()) {
            val ga = a.appGroups[g]
            val gb = b.appGroups[g]
            val name = (gb ?: ga)!!.label
            when {
                ga == null -> out += PolicyChange(who, "Nhóm $name", "—", "Thêm mới")
                gb == null -> out += PolicyChange(who, "Nhóm $name", "Có", "Đã xóa")
                else -> {
                    add("Tên nhóm $g", ga.label, gb.label)
                    if (ga.match != gb.match) out += PolicyChange(who, "Ứng dụng trong nhóm $name", "${ga.match.size} mẫu", "${gb.match.size} mẫu")
                    out += weekdays(who, "Hạn mức $name", { ga.dailyQuotaMin?.get(it) }, { gb.dailyQuotaMin?.get(it) }) {
                        it?.let(::formatMinutes) ?: "Không giới hạn"
                    }
                }
            }
        }
        if (a.appRules != b.appRules) {
            val added = b.appRules.filterNot { it in a.appRules }.joinToString { "${AppRules.actionLabel(it.action)} ${AppRules.describe(it)}" }
            val removed = a.appRules.filterNot { it in b.appRules }.joinToString { "${AppRules.actionLabel(it.action)} ${AppRules.describe(it)}" }
            out += PolicyChange(who, "Quy tắc ứng dụng",
                "${a.appRules.size} quy tắc" + if (removed.isNotEmpty()) " (bỏ: $removed)" else "",
                "${b.appRules.size} quy tắc" + if (added.isNotEmpty()) " (thêm: $added)" else "")
        }
        add("Ứng dụng lạ", newExeLabel(a.newExecutable), newExeLabel(b.newExecutable))

        val wa = a.web
        val wb = b.web
        add("Chế độ web", webModeLabel(wa.mode), webModeLabel(wb.mode))
        if (wa.blockedCategories.toSet() != wb.blockedCategories.toSet()) {
            out += PolicyChange(who, "Danh mục chặn", categories(wa.blockedCategories), categories(wb.blockedCategories))
        }
        if (wa.categorySchedules.orEmpty() != wb.categorySchedules.orEmpty()) {
            out += PolicyChange(who, "Chặn theo giờ",
                categories(wa.categorySchedules.orEmpty().keys.toList()), categories(wb.categorySchedules.orEmpty().keys.toList()))
        }
        if (wa.blockDomains.toSet() != wb.blockDomains.toSet()) out += PolicyChange(who, "Trang bị chặn", "${wa.blockDomains.size} trang", "${wb.blockDomains.size} trang")
        if (wa.allowDomains.toSet() != wb.allowDomains.toSet()) out += PolicyChange(who, "Trang được phép", "${wa.allowDomains.size} trang", "${wb.allowDomains.size} trang")
        add("SafeSearch", onOff(wa.safeSearch), onOff(wb.safeSearch))
        add("YouTube", youtubeLabel(wa.youtube), youtubeLabel(wb.youtube))
        if (wa.allowedBrowsers.toSet() != wb.allowedBrowsers.toSet()) add("Trình duyệt được phép", wa.allowedBrowsers.joinToString(), wb.allowedBrowsers.joinToString())
        if (wa.netExemptApps != wb.netExemptApps) out += PolicyChange(who, "Ứng dụng miễn lọc mạng", "${wa.netExemptApps.size}", "${wb.netExemptApps.size}")

        val ma = a.monitoring
        val mb = b.monitoring
        add("Ghi tiêu đề cửa sổ", onOff(ma.foregroundTitles), onOff(mb.foregroundTitles))
        add("Lịch sử trình duyệt", onOff(ma.browserHistory), onOff(mb.browserHistory))
        add("Nhật ký tên miền", onOff(ma.domainLog), onOff(mb.domainLog))
        add("Theo dõi tải xuống", onOff(ma.downloads), onOff(mb.downloads))
        add("Theo dõi USB", onOff(ma.usb), onOff(mb.usb))
        add("Ảnh màn hình định kỳ", screenshotLabel(ma.screenshots.intervalMin), screenshotLabel(mb.screenshots.intervalMin))
        add("Chỉ chụp khi đang dùng", onOff(ma.screenshots.onlyWhenActive), onOff(mb.screenshots.onlyWhenActive))
        add("Độ phân giải ảnh", "${ma.screenshots.maxWidth}px", "${mb.screenshots.maxWidth}px")
        add("Chất lượng ảnh", "${ma.screenshots.jpegQuality}", "${mb.screenshots.jpegQuality}")
        return out
    }

    private fun <T> weekdays(
        who: String, title: String, old: (Weekday) -> T, new: (Weekday) -> T, fmt: (T) -> String,
    ): List<PolicyChange> {
        val groups = LinkedHashMap<Pair<T, T>, MutableSet<Weekday>>()
        for (d in Weekday.entries) {
            val o = old(d)
            val n = new(d)
            if (o != n) groups.getOrPut(o to n) { linkedSetOf() } += d
        }
        return groups.map { (pair, days) -> PolicyChange(who, "$title · ${dayGroupLabel(days)}", fmt(pair.first), fmt(pair.second)) }
    }

    fun onOff(b: Boolean) = if (b) "Bật" else "Tắt"
    fun newExeLabel(v: NewExecutable) = when (v) {
        NewExecutable.ASK -> "Hỏi tôi"; NewExecutable.ALLOW -> "Cho phép"; NewExecutable.BLOCK -> "Chặn"
    }
    fun webModeLabel(v: WebMode) = when (v) {
        WebMode.BLOCKLIST -> "Chặn theo danh sách"; WebMode.ALLOWLIST -> "Chỉ trang cho phép"
    }
    fun youtubeLabel(v: YouTubeMode) = when (v) {
        YouTubeMode.OFF -> "Tắt"; YouTubeMode.MODERATE -> "Hạn chế vừa phải"; YouTubeMode.STRICT -> "Hạn chế nghiêm ngặt"
    }
    fun screenshotLabel(min: Int) = if (min == 0) "Chỉ khi yêu cầu" else "Mỗi $min phút"
    fun categories(list: Collection<WebCategory>) = if (list.isEmpty()) "Không" else list.joinToString(", ") { it.label }
}

/** Semantic checks the device validators also enforce (see protocol/fixtures/policy/semantic-invalid). */
object PolicyValidation {
    private val windowRe = Regex("^([01][0-9]|2[0-3]):([0-5][0-9])-(([01][0-9]|2[0-3]):([0-5][0-9])|24:00)$")
    private val domainRe = Regex("^(\\*\\.)?([a-z0-9-]+\\.)+[a-z0-9-]+$")

    fun minutesOf(hhmm: String): Int = hhmm.substring(0, 2).toInt() * 60 + hhmm.substring(3, 5).toInt()

    /** Returns an error message (Vietnamese) or null when the window list is valid. */
    fun windowsError(list: List<String>): String? {
        if (list.size > 8) return "Tối đa 8 khung giờ mỗi ngày"
        val ranges = mutableListOf<IntRange>()
        for (w in list) {
            if (!windowRe.matches(w)) return "Khung giờ \"$w\" không hợp lệ (HH:MM-HH:MM)"
            val start = minutesOf(w.substringBefore('-'))
            val end = minutesOf(w.substringAfter('-'))
            if (end <= start) return "Khung giờ \"$w\": giờ kết thúc phải sau giờ bắt đầu"
            ranges += start until end
        }
        val sorted = ranges.sortedBy { it.first }
        for (i in 1 until sorted.size) if (sorted[i].first <= sorted[i - 1].last) return "Các khung giờ bị chồng nhau"
        return null
    }

    // Drive letter, UNC, or an environment variable the Windows agent expands (e.g. %ProgramFiles%\App\app.exe).
    private val absPathRe = Regex("^([A-Za-z]:[\\\\/]|\\\\\\\\|%[A-Za-z_()0-9]+%[\\\\/])[^\\\\/].*")

    /** netExemptApps entries need a full path (drive letter, UNC or %ENVVAR%\...), not just an exe name. */
    fun pathError(p: String): String? = if (absPathRe.matches(p.trim())) null else "Cần đường dẫn đầy đủ, vd: C:\\Program Files\\App\\app.exe (\"$p\")"

    fun domainError(d: String): String? = if (domainRe.matches(d)) null else "Tên miền \"$d\" không hợp lệ"

    fun errors(p: Policy): List<String> {
        val out = mutableListOf<String>()
        if (p.timezone !in java.time.ZoneId.getAvailableZoneIds()) out += "Múi giờ \"${p.timezone}\" không tồn tại"
        for ((_, u) in p.users) {
            val warnTooBig = Weekday.entries.any { d ->
                val q = u.screenTime.dailyQuotaMin.get(d)
                q > 0 && u.screenTime.warnAtMin.any { it >= q }
            }
            if (warnTooBig) out += "${u.label}: thời điểm nhắc phải nhỏ hơn hạn mức của ngày"
            if (u.web.mode == WebMode.ALLOWLIST && u.web.allowDomains.isEmpty()) out += "${u.label}: chế độ chỉ trang cho phép cần ít nhất một tên miền"
            Weekday.entries.forEach { d ->
                windowsError(u.screenTime.allowedWindows.get(d))?.let { out += "${u.label} · ${d.label}: $it" }
                u.web.categorySchedules?.values?.forEach { ws -> windowsError(ws.get(d))?.let { out += "${u.label}: $it" } }
            }
            (u.web.blockDomains + u.web.allowDomains).forEach { dom -> domainError(dom)?.let { out += "${u.label}: $it" } }
            u.web.netExemptApps.forEach { m ->
                val path = m.path
                if (path == null) out += "${u.label}: ứng dụng miễn lọc mạng cần đường dẫn đầy đủ"
                else pathError(path)?.let { out += "${u.label}: $it" }
            }
            AppRules.errors(u.appRules).forEach { out += "${u.label}: $it" }
            val both = u.web.categorySchedules.orEmpty().keys.intersect(u.web.blockedCategories.toSet())
            if (both.isNotEmpty()) out += "${u.label}: danh mục vừa chặn hẳn vừa chặn theo giờ"
            val overlap = u.web.blockDomains.toSet().intersect(u.web.allowDomains.toSet())
            if (overlap.isNotEmpty()) out += "${u.label}: tên miền vừa chặn vừa cho phép (${overlap.first()})"
        }
        return out
    }
}
