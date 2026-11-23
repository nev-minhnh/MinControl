package io.github.nevminhnh.mincontrol.master.ui.activity

import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.WebItem
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

/**
 * Every field a `web.blocked` / `process.blocked` event can carry (API.md §17 + event.schema.json optional fields).
 * One instance per event: block events are never collapsed.
 */
data class BlockFields(
    val app: Boolean,
    val ts: String,
    val host: String? = null,
    val url: String? = null,
    val action: String? = null,
    val title: String? = null,
    val query: String? = null,
    val engine: String? = null,
    val count: Int? = null,
    val rule: String? = null,
    val keyword: String? = null,
    val service: String? = null,
    val category: String? = null,
    val reason: String? = null,
    val exe: String? = null,
    val path: String? = null,
    val eventId: String? = null,
) {
    companion object {
        private fun JsonObject.s(k: String) = (this[k] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }

        fun of(e: EventItem): BlockFields? {
            val app = when (e.type) { "process.blocked" -> true; "web.blocked" -> false; else -> return null }
            val d = e.data
            return BlockFields(
                app = app, ts = e.ts, host = d.s("host"), url = d.s("url"), action = d.s("action"), title = d.s("title"),
                query = d.s("query"), engine = d.s("engine"), count = (d["count"] as? JsonPrimitive)?.intOrNull,
                rule = d.s("rule"), keyword = d.s("keyword"), service = d.s("service"), category = d.s("category"),
                reason = d.s("reason"), exe = d.s("exe"), path = d.s("path"), eventId = e.id,
            )
        }

        fun of(w: WebItem): BlockFields? = if (w.kind != "blocked") null else BlockFields(
            app = false, ts = w.ts, host = w.host, url = w.url, action = w.action, title = w.title, query = w.query, engine = w.engine,
            count = w.count, rule = w.rule, keyword = w.keyword, service = w.service, category = w.category, reason = w.reason, exe = w.exe,
        )
    }
}

/** Display text of one block event. */
data class BlockText(
    /** "Đã chặn · Đóng tab" */
    val headline: String,
    /** Main row title: host / query / page title for web, app name for apps. */
    val title: String,
    /** Detail lines, most important first ("Từ khóa: …", "Dịch vụ: TikTok", "Đã chặn 5 lần"…). */
    val details: List<String>,
)

object BlockTextBuilder {
    private val actions = mapOf(
        "close_tab" to "Đóng tab", "closetab" to "Đóng tab", "tab_closed" to "Đóng tab",
        "close_window" to "Đóng cửa sổ", "window_closed" to "Đóng cửa sổ",
        "kill" to "Tắt ứng dụng", "terminate" to "Tắt ứng dụng", "terminated" to "Tắt ứng dụng", "killed" to "Tắt ứng dụng",
        "prevent_start" to "Không cho mở", "deny" to "Chặn truy cập", "block" to "Chặn truy cập", "blocked_page" to "Trang chặn",
        "dns" to "Chặn tên miền", "dns_block" to "Chặn tên miền", "redirect" to "Chuyển về trang chặn",
    )

    fun actionLabel(a: String?): String? = a?.trim()?.takeIf { it.isNotEmpty() }?.let { actions[it.lowercase()] ?: it }

    /** "Edge" from msedge.exe etc.; null when not a known browser (then the raw app name is used). */
    fun browserLabel(exe: String?): String? {
        val e = exe?.lowercase()?.substringAfterLast('\\') ?: return null
        return when (e) {
            "msedge.exe" -> "Edge"; "chrome.exe" -> "Chrome"; "firefox.exe" -> "Firefox"; "browser.exe" -> "Cốc Cốc"
            "brave.exe" -> "Brave"; "opera.exe" -> "Opera"; "vivaldi.exe" -> "Vivaldi"
            else -> null
        }
    }

    fun build(f: BlockFields, serviceName: (String) -> String? = { null }): BlockText {
        val action = actionLabel(f.action) ?: if (f.app) "Tắt ứng dụng" else null
        val headline = "Đã chặn" + (action?.let { " · $it" } ?: "")
        val svc = f.service?.let { serviceName(it) ?: it.replaceFirstChar { c -> c.uppercase() } }
        val details = mutableListOf<String>()
        val title: String
        if (f.app) {
            title = Fmt.appName(f.exe ?: f.path?.substringAfterLast('\\'))
            f.exe?.let { details += it }
            f.title?.let { details += "“$it”" }
            f.keyword?.let { details += "Từ khóa: $it" }
            svc?.let { details += "Dịch vụ: $it" }
            f.rule?.let { details += "Quy tắc: $it" }
            f.path?.let { details += it }
        } else {
            title = f.host ?: f.query?.let { "“$it”" } ?: f.title ?: f.url ?: "Trang web"
            f.title?.takeIf { f.host != null }?.let { details += "“$it”" }
            f.query?.let { q -> details += "Tìm kiếm ${Fmt.engineLabel(f.engine, f.host).ifBlank { "" }}".trimEnd() + ": “$q”" }
            f.keyword?.let { details += "Từ khóa: $it" }
            svc?.let { details += "Dịch vụ: $it" }
            WebLabels.category(f.category)?.let { details += "Danh mục: $it" }
            if (f.exe != null) details += "Trình duyệt: ${browserLabel(f.exe) ?: Fmt.appName(f.exe)}"
            f.rule?.let { details += "Quy tắc: $it" }
            // The reason is implied by keyword / service / category when those are shown.
            val implied = when (f.reason) { "keyword" -> f.keyword != null; "service" -> f.service != null; "category" -> f.category != null; else -> false }
            if (!implied) WebLabels.reason(f.reason)?.let { details += "Lý do: $it" }
        }
        if ((f.count ?: 0) > 1) details += "Đã chặn ${f.count} lần"
        return BlockText(headline, title, details)
    }
}
