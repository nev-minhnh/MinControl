package io.github.nevminhnh.mincontrol.master.live

import io.github.nevminhnh.mincontrol.master.data.protocol.ApiJson
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceState
import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.WebItem
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Frames pushed by `GET /v1/master/live` (API.md section 15). */
sealed interface LiveMessage {
    val deviceId: String
    data class State(override val deviceId: String, val state: DeviceState) : LiveMessage
    data class Events(override val deviceId: String, val events: List<EventItem>) : LiveMessage
    data class Online(override val deviceId: String, val online: Boolean) : LiveMessage
}

object LiveParser {
    /** Null for unknown/garbled frames (ignored, never fatal). */
    fun parse(text: String): LiveMessage? = runCatching {
        val o = ApiJson.parseToJsonElement(text).jsonObject
        val id = o["deviceId"]?.jsonPrimitive?.contentOrNull ?: return null
        when (o["t"]?.jsonPrimitive?.contentOrNull) {
            "state" -> LiveMessage.State(id, ApiJson.decodeFromJsonElement(DeviceState.serializer(), o["state"] ?: return null))
            "events" -> LiveMessage.Events(id, o["events"]!!.jsonArray.mapNotNull {
                runCatching { ApiJson.decodeFromJsonElement(EventItem.serializer(), it) }.getOrNull()
            })
            "online" -> LiveMessage.Online(id, o["online"]?.jsonPrimitive?.booleanOrNull ?: return null)
            else -> null
        }
    }.getOrNull()
}

/** Reconnect delay: base * 2^attempt capped at [maxMs], plus 0..[jitterPct]% jitter; [reset] after a successful open. */
class ReconnectBackoff(
    private val baseMs: Long = 1_000,
    private val maxMs: Long = 30_000,
    private val jitterPct: Int = 20,
    private val random: () -> Double = Math::random,
) {
    private var attempt = 0

    fun nextDelayMs(): Long {
        val raw = minOf(maxMs, baseMs shl minOf(attempt, 20))
        attempt++
        return raw + (raw * jitterPct / 100.0 * random()).toLong()
    }

    fun reset() { attempt = 0 }
}

/** Auto-refresh cadence: while a live socket is healthy polling is only a 60 s safety net. */
object PollingPolicy {
    const val LIVE_INTERVAL_MS = 60_000L
    fun intervalMs(baseMs: Long, liveHealthy: Boolean, liveMs: Long = LIVE_INTERVAL_MS): Long =
        if (liveHealthy) maxOf(baseMs, liveMs) else baseMs
}

object LiveMerge {
    /** Alert-worthy event types (API.md section 6) -> refresh the alerts list. */
    fun isAlertEvent(type: String): Boolean =
        type.startsWith("tamper.") || type.startsWith("request.") || type == "quota.exhausted" ||
            type == "process.blocked" || type == "web.blocked" || type == "blocked.burst" || type == "device.offline"

    /**
     * New events on top, dedupe by id (an already-listed id keeps its existing row), newest first by [EventItem.ts];
     * only items accepted by [accept]. Returns [existing] itself when nothing is added.
     */
    fun mergeEvents(existing: List<EventItem>, incoming: List<EventItem>, accept: (EventItem) -> Boolean = { true }, limit: Int = 5_000): List<EventItem> {
        val seen = existing.mapTo(HashSet()) { it.id }
        val fresh = incoming.filter { accept(it) && seen.add(it.id) }
        if (fresh.isEmpty()) return existing
        return (fresh + existing).sortedByDescending { it.ts }.take(limit)
    }

    /** Timeline rule: the child's own events (or device-level tamper), minus the noisy types, within [from, to) ISO strings. */
    fun timelineAccept(sid: String, dayPrefix: (String) -> Boolean): (EventItem) -> Boolean = { e ->
        e.type != "usage.tick" && e.type != "net.domain" && dayPrefix(e.ts) &&
            (e.userSid == sid || (e.userSid == null && e.type.startsWith("tamper.")))
    }

    fun domainAccept(sid: String, dayPrefix: (String) -> Boolean): (EventItem) -> Boolean = { e ->
        e.type == "net.domain" && e.userSid == sid && dayPrefix(e.ts)
    }

    private fun JsonObject.s(k: String) = (this[k] as? JsonPrimitive)?.takeIf { it.isString }?.content

    /** web.visit / web.search / web.blocked event -> the Web tab row; null for other types. */
    fun toWebItem(e: EventItem): WebItem? {
        val kind = when (e.type) { "web.visit" -> "visit"; "web.search" -> "search"; "web.blocked" -> "blocked"; else -> return null }
        val d = e.data
        return WebItem(
            ts = e.ts, kind = kind, url = d.s("url"), host = d.s("host"), title = d.s("title"),
            durationSec = (d["durationSec"] as? JsonPrimitive)?.intOrNull, category = d.s("category"),
            query = d.s("query"), engine = d.s("engine"), reason = d.s("reason"),
            action = d.s("action"), count = (d["count"] as? JsonPrimitive)?.intOrNull, rule = d.s("rule"),
            keyword = d.s("keyword"), service = d.s("service"), exe = d.s("exe"),
        )
    }

    private fun webKey(w: WebItem) = listOf(w.ts, w.kind, w.url, w.host, w.query, w.title, w.keyword, w.service, w.action, w.exe, w.count).joinToString("|")

    /** Prepends matching new web rows (query = substring of url/host/title/query, kind = filter or null), deduped, newest first. */
    fun mergeWeb(existing: List<WebItem>, incoming: List<EventItem>, sid: String, query: String, kind: String?, dayPrefix: (String) -> Boolean): List<WebItem> {
        val seen = existing.mapTo(HashSet()) { webKey(it) }
        val q = query.trim().lowercase()
        val fresh = incoming.filter { it.userSid == sid && dayPrefix(it.ts) }.mapNotNull { toWebItem(it) }
            .filter { kind == null || it.kind == kind }
            .filter { q.isEmpty() || listOfNotNull(it.url, it.host, it.title, it.query).any { s -> s.lowercase().contains(q) } }
            .filter { seen.add(webKey(it)) }
        if (fresh.isEmpty()) return existing
        return (fresh + existing).sortedByDescending { it.ts }
    }

    fun applyState(d: DeviceInfo, state: DeviceState): DeviceInfo = d.copy(state = state, lastSeen = state.ts)

    fun applyOnline(d: DeviceInfo, online: Boolean): DeviceInfo = d.copy(online = online)
}
