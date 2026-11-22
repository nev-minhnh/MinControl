package io.github.nevminhnh.mincontrol.master.ui.diagnose

import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** One expandable card of the "Chẩn đoán máy" report. */
data class DiagSection(val name: String, val rows: List<Pair<String, String>>, val raw: String)

object DiagnoseLogic {
    const val POLL_INTERVAL_MS = 3_000L
    const val POLL_TIMEOUT_MS = 60_000L
    const val LOOKBACK_SEC = 60L

    private val pretty = Json { prettyPrint = true }

    val sectionTitles = mapOf(
        "service" to "Dịch vụ", "users" to "Tài khoản", "policy" to "Chính sách", "wfp" to "Bộ lọc mạng (WFP)",
        "proxy" to "Proxy", "browser" to "Trình duyệt", "categories" to "Danh mục web", "monitor" to "Giám sát", "logs" to "Nhật ký lỗi",
    )

    fun title(name: String) = sectionTitles[name] ?: name

    /** The report answering [commandId] (newest first when several), or null. */
    fun pick(items: List<EventItem>, commandId: String): EventItem? =
        items.filter { it.type == "diag.report" && (it.data["commandId"] as? JsonPrimitive)?.content == commandId }.maxByOrNull { it.ts }

    /** Known sections first (API.md §14 order), then the rest alphabetically. */
    fun sections(data: JsonObject): List<DiagSection> {
        val secs = data["sections"] as? JsonObject ?: return emptyList()
        val order = sectionTitles.keys.toList()
        return secs.entries
            .sortedWith(compareBy({ order.indexOf(it.key).let { i -> if (i < 0) Int.MAX_VALUE else i } }, { it.key }))
            .map { (k, v) -> DiagSection(k, flatten(v), pretty.encodeToString(JsonElement.serializer(), v)) }
    }

    /** Key/value rows; nested objects use dotted keys, arrays of scalars are joined, other arrays use `key[i]`. */
    fun flatten(e: JsonElement, prefix: String = ""): List<Pair<String, String>> = when (e) {
        is JsonObject -> e.entries.flatMap { (k, v) -> flatten(v, if (prefix.isEmpty()) k else "$prefix.$k") }
        is JsonArray -> when {
            e.isEmpty() -> listOf(prefix to "(trống)")
            e.all { it is JsonPrimitive } -> listOf(prefix to e.joinToString(", ") { scalar(it) })
            else -> e.flatMapIndexed { i, v -> flatten(v, "$prefix[$i]") }
        }
        else -> listOf(prefix to scalar(e))
    }

    private fun scalar(e: JsonElement) = when (e) {
        is JsonNull -> "null"
        is JsonPrimitive -> e.content
        else -> e.toString()
    }

    /** Whole report, as text for "Sao chép để gửi hỗ trợ". */
    fun rawReport(data: JsonObject): String = pretty.encodeToString(JsonElement.serializer(), data)
}
