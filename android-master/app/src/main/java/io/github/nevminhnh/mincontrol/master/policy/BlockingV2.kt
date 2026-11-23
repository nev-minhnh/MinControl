package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMode
import io.github.nevminhnh.mincontrol.master.data.protocol.Keywords
import io.github.nevminhnh.mincontrol.master.data.protocol.RuleAction
import io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy
import io.github.nevminhnh.mincontrol.master.data.protocol.WebMode
import io.github.nevminhnh.mincontrol.master.data.protocol.WebPolicy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** One entry of `protocol/services.json` (API.md §17). */
@Serializable
data class Service(
    val id: String,
    val name: String,
    val category: String = "other",
    val domains: List<String> = emptyList(),
    val apps: List<AppMatch> = emptyList(),
)

/** The service catalog shipped in assets (copied from ../protocol/services.json at build time; empty if missing). */
data class ServiceCatalog(val services: List<Service>) {
    fun byId(id: String): Service? = services.firstOrNull { it.id == id }

    companion object {
        val EMPTY = ServiceCatalog(emptyList())
        private val json = Json { ignoreUnknownKeys = true }

        /** Accepts either a bare array or `{"version":…, "services":[…]}`; anything unparsable yields [EMPTY]. */
        fun parse(text: String?): ServiceCatalog {
            if (text.isNullOrBlank()) return EMPTY
            return runCatching {
                val root = json.parseToJsonElement(text)
                val arr: JsonElement? = when (root) {
                    is JsonArray -> root
                    is JsonObject -> root["services"]
                    else -> null
                }
                val list = (arr as? JsonArray).orEmpty().mapNotNull { el -> runCatching { json.decodeFromJsonElement(Service.serializer(), el) }.getOrNull() }
                ServiceCatalog(list.distinctBy { it.id })
            }.getOrDefault(EMPTY)
        }

        fun load(context: android.content.Context): ServiceCatalog =
            parse(runCatching { context.assets.open("services.json").bufferedReader(Charsets.UTF_8).use { it.readText() } }.getOrNull())
    }
}

enum class ServiceState { NONE, BLOCKED, ALLOWED }

/** Pure policy edits for blocking v2 (modes, services, keywords). */
object BlockingV2 {
    const val APP_BLOCKLIST_TITLE = "Cho phép tất cả, chặn theo danh sách"
    const val APP_ALLOWLIST_TITLE = "Chặn tất cả, chỉ cho phép theo danh sách"
    const val APP_BLOCKLIST_HELP = "Mọi ứng dụng đều chạy được, trừ các ứng dụng và dịch vụ bị chặn bên dưới. Ứng dụng mới cài theo mục “Ứng dụng lạ”."
    const val APP_ALLOWLIST_HELP = "Chỉ ứng dụng trong danh sách “Cho phép” (và dịch vụ được phép) mới chạy được. " +
        "Luôn được phép: ứng dụng hệ thống Windows (thư mục Windows, Start, Tìm kiếm, Cài đặt, màn hình khóa, bàn phím) và chính MinControl."
    const val WEB_BLOCKLIST_HELP = "Mọi trang đều vào được, trừ danh mục, dịch vụ và tên miền bị chặn."
    const val WEB_ALLOWLIST_HELP = "Chỉ vào được các tên miền trong “Trang luôn cho phép” và dịch vụ được phép."
    const val MAX_KEYWORD_LEN = 64
    const val MAX_KEYWORDS = 500

    fun setAppMode(up: UserPolicy, mode: AppMode): UserPolicy = up.copy(appMode = if (mode == AppMode.BLOCKLIST) null else mode)

    fun setWebMode(up: UserPolicy, mode: WebMode): UserPolicy = up.copy(web = up.web.copy(mode = mode))

    /** True when allowing a service makes sense (apps or web are in allowlist mode). */
    fun allowlistActive(up: UserPolicy): Boolean = up.effectiveAppMode == AppMode.ALLOWLIST || up.web.mode == WebMode.ALLOWLIST

    fun serviceState(w: WebPolicy, id: String): ServiceState = when {
        w.blockedServices.orEmpty().contains(id) -> ServiceState.BLOCKED
        w.allowedServices.orEmpty().contains(id) -> ServiceState.ALLOWED
        else -> ServiceState.NONE
    }

    /** Next state on tap: blocklist → none ↔ blocked; with an allowlist active → none → blocked → allowed → none. */
    fun nextState(current: ServiceState, allowlist: Boolean): ServiceState = when (current) {
        ServiceState.NONE -> if (allowlist) ServiceState.ALLOWED else ServiceState.BLOCKED
        ServiceState.ALLOWED -> ServiceState.BLOCKED
        ServiceState.BLOCKED -> ServiceState.NONE
    }

    /** Puts [id] in exactly one list (or none). Empty lists become null so the field is omitted. */
    fun setService(w: WebPolicy, id: String, state: ServiceState): WebPolicy {
        val blocked = w.blockedServices.orEmpty().filterNot { it == id } + if (state == ServiceState.BLOCKED) listOf(id) else emptyList()
        val allowed = w.allowedServices.orEmpty().filterNot { it == id } + if (state == ServiceState.ALLOWED) listOf(id) else emptyList()
        return w.copy(blockedServices = blocked.ifEmpty { null }, allowedServices = allowed.ifEmpty { null })
    }

    fun toggleService(up: UserPolicy, id: String): UserPolicy =
        up.copy(web = setService(up.web, id, nextState(serviceState(up.web, id), allowlistActive(up))))

    /** Splits pasted text on comma, semicolon or newline; trims; drops blanks and case-insensitive duplicates. */
    fun parseKeywords(text: String): List<String> {
        val seen = HashSet<String>()
        return text.split(',', ';', '\n', '\r').map { it.trim().replace(Regex("\\s+"), " ") }
            .filter { it.isNotEmpty() && it.length <= MAX_KEYWORD_LEN && seen.add(it.lowercase()) }
    }

    fun addKeywords(up: UserPolicy, text: String): UserPolicy {
        val cur = up.keywords ?: Keywords()
        val existing = cur.words.mapTo(HashSet()) { it.lowercase() }
        val added = parseKeywords(text).filter { existing.add(it.lowercase()) }
        if (added.isEmpty()) return up
        return up.copy(keywords = cur.copy(words = (cur.words + added).take(MAX_KEYWORDS)))
    }

    /** Removing the last word drops the whole `keywords` object. */
    fun removeKeyword(up: UserPolicy, word: String): UserPolicy {
        val cur = up.keywords ?: return up
        val words = cur.words.filterNot { it.equals(word, ignoreCase = true) }
        return up.copy(keywords = if (words.isEmpty()) null else cur.copy(words = words))
    }

    fun setKeywordFlags(up: UserPolicy, matchSearches: Boolean? = null, matchTitles: Boolean? = null): UserPolicy {
        val cur = up.keywords ?: Keywords()
        return up.copy(keywords = cur.copy(matchSearches = matchSearches ?: cur.matchSearches, matchTitles = matchTitles ?: cur.matchTitles))
    }

    fun errors(up: UserPolicy, catalog: ServiceCatalog? = null): List<String> {
        val out = mutableListOf<String>()
        up.keywords?.words?.forEach { if (it.isBlank() || it.length > MAX_KEYWORD_LEN) out += "${up.label}: từ khóa “$it” không hợp lệ" }
        val both = up.web.blockedServices.orEmpty().intersect(up.web.allowedServices.orEmpty().toSet())
        if (both.isNotEmpty()) out += "${up.label}: dịch vụ vừa chặn vừa cho phép (${both.first()})"
        if (catalog != null && catalog.services.isNotEmpty()) {
            (up.web.blockedServices.orEmpty() + up.web.allowedServices.orEmpty()).filter { catalog.byId(it) == null }
                .forEach { out += "${up.label}: dịch vụ “$it” không có trong danh mục" }
        }
        return out
    }

    // ---------- what the CURRENT policy blocks (used for a neutral "Đang chặn" hint, never the red "Đã chặn") ----------

    /** Case-insensitive `*` / `?` glob. */
    fun glob(pattern: String, value: String): Boolean {
        val re = buildString {
            append("^")
            pattern.lowercase().forEach { c ->
                when (c) { '*' -> append(".*"); '?' -> append('.'); else -> append(Regex.escape(c.toString())) }
            }
            append("$")
        }
        return Regex(re).matches(value.lowercase())
    }

    fun domainCovers(pattern: String, host: String): Boolean {
        val p = pattern.trim().lowercase()
        val h = host.trim().lowercase().trimEnd('.')
        return if (p.startsWith("*.")) { val b = p.removePrefix("*."); h == b || h.endsWith(".$b") } else p == h || glob(p, h)
    }

    fun isHostBlockedNow(up: UserPolicy, host: String, catalog: ServiceCatalog): Boolean =
        up.web.blockDomains.any { domainCovers(it, host) } ||
            up.web.blockedServices.orEmpty().mapNotNull { catalog.byId(it) }.any { s -> s.domains.any { domainCovers(it, host) } }

    fun isExeBlockedNow(up: UserPolicy, exe: String?, catalog: ServiceCatalog): Boolean {
        val name = AppRules.matchForExe(exe)?.exe ?: return false
        if (AppRules.isBlocked(up.appRules, name)) return true
        if (up.appRules.any { it.action == RuleAction.BLOCK && it.except.isNullOrEmpty() && it.match.exe != null && glob(it.match.exe, name) }) return true
        return up.web.blockedServices.orEmpty().mapNotNull { catalog.byId(it) }
            .any { s -> s.apps.any { m -> m.exe != null && glob(m.exe, name) } }
    }
}
