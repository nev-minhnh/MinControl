package io.github.nevminhnh.mincontrol.master.ui.activity

import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.WebCategory
import io.github.nevminhnh.mincontrol.master.data.protocol.WebPolicy
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull

/** Vietnamese labels for web categories and block reasons. */
object WebLabels {
    private val categories = mapOf(
        "adult" to "Người lớn", "gambling" to "Cờ bạc", "proxy-vpn" to "VPN/Proxy", "games" to "Trò chơi",
        "social" to "Mạng xã hội", "video" to "Video", "violence" to "Bạo lực", "drugs" to "Chất cấm",
        "dating" to "Hẹn hò", "malware" to "Mã độc", "ai" to "Trí tuệ nhân tạo (AI)",
    )
    private val reasons = mapOf(
        "doh" to "DNS mã hoá", "port" to "Cổng không được phép", "blocklist" to "Danh sách chặn",
        "allowlist_miss" to "Ngoài danh sách cho phép", "schedule" to "Ngoài giờ cho phép",
        "keyword" to "Từ khóa bị cấm", "service" to "Dịch vụ bị chặn", "category" to "Danh mục bị chặn",
    )

    fun category(key: String?): String? = key?.takeIf { it.isNotBlank() }?.let { categories[it] ?: it }
    fun reason(key: String?): String? = key?.takeIf { it.isNotBlank() }?.let { reasons[it] ?: it }

    /** "Cờ bạc · Danh sách chặn", or null when neither is known. */
    fun blockedSubtitle(category: String?, reason: String?): String? =
        listOfNotNull(category(category), reason(reason)).joinToString(" · ").ifEmpty { null }

    fun categoryDescription(c: WebCategory): String = when (c) {
        WebCategory.ADULT -> "Trang nội dung người lớn, khiêu dâm"
        WebCategory.GAMBLING -> "Cá cược, casino, xổ số trực tuyến"
        WebCategory.PROXY_VPN -> "Trang và dịch vụ vượt chặn, VPN, proxy"
        WebCategory.GAMES -> "Trang chơi game trực tuyến"
        WebCategory.SOCIAL -> "Facebook, TikTok và các mạng xã hội khác"
        WebCategory.VIDEO -> "Trang xem và chia sẻ video"
        WebCategory.VIOLENCE -> "Nội dung bạo lực, kinh dị, thù hận"
        WebCategory.DRUGS -> "Ma tuý, chất kích thích, thuốc lá"
        WebCategory.DATING -> "Trang và ứng dụng hẹn hò"
        WebCategory.MALWARE -> "Trang lừa đảo, phần mềm độc hại"
        WebCategory.AI -> "ChatGPT, Claude, Gemini, Copilot, DeepSeek, Qwen, Kimi… và các trang AI khác"
    }

    const val CATEGORY_SOURCE_NOTE = io.github.nevminhnh.mincontrol.master.policy.PolicyHelp.CATEGORY_SOURCE
    const val WEB_EMPTY = "Chưa có lịch sử. Lịch sử được đọc từ Edge/Chrome trên máy tính, cập nhật mỗi ~15 giây."
}

data class DomainRow(
    val host: String,
    val connections: Int,
    val apps: List<String>,
    val firstTs: String,
    val lastTs: String,
    /** True when at least one window was blocked. */
    val blocked: Boolean,
)

object DomainAggregator {
    fun fromItems(items: List<io.github.nevminhnh.mincontrol.master.data.protocol.DomainItem>): List<DomainRow> =
        items.map { DomainRow(it.host.lowercase(), it.connections, it.apps, it.firstSeen, it.lastSeen, it.blocked) }

    /** Case-insensitive substring filter on host or exe. */
    fun filter(rows: List<DomainRow>, query: String): List<DomainRow> {
        val q = query.trim().lowercase()
        return if (q.isEmpty()) rows else rows.filter { it.host.contains(q) || it.apps.any { x -> x.lowercase().contains(q) } }
    }

    /**
     * API.md 16: folds live `net.domain` [events] into already aggregated [rows] (connections += n, lastSeen extended,
     * exe added, blocked sticky). Ids in [seen] are skipped and new ones added. Result sorted connections desc, host.
     */
    fun mergeLive(rows: List<DomainRow>, events: List<EventItem>, seen: MutableSet<String>): List<DomainRow> {
        val map = LinkedHashMap<String, DomainRow>()
        rows.forEach { map[it.host] = it }
        var changed = false
        for (e in events) {
            if (e.type != "net.domain" || !seen.add(e.id)) continue
            val d = e.data
            val host = (d["host"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: continue
            val exe = (d["exe"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }
            val n = (d["connections"] as? JsonPrimitive)?.intOrNull ?: 1
            val blocked = (d["allowed"] as? JsonPrimitive)?.booleanOrNull == false
            val ts = (d["windowStart"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: e.ts
            val cur = map[host]
            map[host] = if (cur == null) DomainRow(host, n, listOfNotNull(exe), ts, maxOf(ts, e.ts), blocked)
            else cur.copy(
                connections = cur.connections + n,
                apps = if (exe != null && exe !in cur.apps) cur.apps + exe else cur.apps,
                firstTs = if (cur.firstTs.isEmpty() || ts < cur.firstTs) ts else cur.firstTs,
                lastTs = if (e.ts > cur.lastTs) e.ts else cur.lastTs,
                blocked = cur.blocked || blocked,
            )
            changed = true
        }
        if (!changed) return rows
        return map.values.sortedWith(compareByDescending<DomainRow> { it.connections }.thenBy { it.host })
    }

    /** Aggregates `net.domain` events by lower-cased host; connections desc, then host. Optional substring [query] on host or exe. */
    fun aggregate(events: List<EventItem>, query: String = ""): List<DomainRow> {
        class Acc(var conn: Int = 0, val apps: LinkedHashSet<String> = linkedSetOf(), var first: String = "", var last: String = "", var blocked: Boolean = false)
        val map = LinkedHashMap<String, Acc>()
        for (e in events) {
            if (e.type != "net.domain") continue
            val d: JsonObject = e.data
            val host = (d["host"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: continue
            val a = map.getOrPut(host) { Acc() }
            a.conn += (d["connections"] as? JsonPrimitive)?.intOrNull ?: 1
            (d["exe"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }?.let { a.apps += it }
            val ts = (d["windowStart"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: e.ts
            if (a.first.isEmpty() || ts < a.first) a.first = ts
            if (ts > a.last) a.last = ts
            if ((d["allowed"] as? JsonPrimitive)?.booleanOrNull == false) a.blocked = true
        }
        val q = query.trim().lowercase()
        return map.entries
            .filter { q.isEmpty() || it.key.contains(q) || it.value.apps.any { x -> x.lowercase().contains(q) } }
            .map { (h, a) -> DomainRow(h, a.conn, a.apps.toList(), a.first, a.last, a.blocked) }
            .sortedWith(compareByDescending<DomainRow> { it.connections }.thenBy { it.host })
    }
}

enum class DomainAction { BLOCK_HOST, BLOCK_REGISTRABLE, ALLOW, UNBLOCK }

/** Pure policy edits for the domain quick actions. */
object DomainPolicy {
    private val multiPartSuffixes = setOf(
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.kr", "co.nz", "co.in", "com.br", "com.cn",
        "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "ac.vn", "info.vn", "biz.vn", "name.vn",
    )

    fun normalize(host: String): String = host.trim().lowercase().removePrefix("*.").trimEnd('.')

    /** Simple eTLD+1 heuristic: last two labels, or last three when the last two form a known multi-part suffix. */
    fun registrable(host: String): String {
        val labels = normalize(host).split('.').filter { it.isNotEmpty() }
        if (labels.size <= 2) return labels.joinToString(".")
        val tail2 = labels.takeLast(2).joinToString(".")
        return labels.takeLast(if (tail2 in multiPartSuffixes) 3 else 2).joinToString(".")
    }

    fun wildcardFor(host: String): String = "*." + registrable(host)

    /** Does a policy entry (exact or `*.domain`) cover [host]? */
    fun covers(entry: String, host: String): Boolean {
        val e = entry.trim().lowercase()
        val h = normalize(host)
        return if (e.startsWith("*.")) { val b = e.removePrefix("*."); h == b || h.endsWith(".$b") } else e == h
    }

    fun isBlocked(w: WebPolicy, host: String): Boolean = w.blockDomains.any { covers(it, host) }

    fun block(w: WebPolicy, host: String): WebPolicy = addBlock(w, normalize(host))
    fun blockRegistrable(w: WebPolicy, host: String): WebPolicy = addBlock(w, wildcardFor(host))

    private fun addBlock(w: WebPolicy, entry: String) =
        w.copy(blockDomains = (w.blockDomains + entry).distinct(), allowDomains = w.allowDomains.filterNot { it.equals(entry, true) })

    fun allow(w: WebPolicy, host: String): WebPolicy {
        val h = normalize(host)
        return w.copy(allowDomains = (w.allowDomains + h).distinct(), blockDomains = w.blockDomains.filterNot { it.equals(h, true) })
    }

    /** Removes every block entry that covers [host]. */
    fun unblock(w: WebPolicy, host: String): WebPolicy = w.copy(blockDomains = w.blockDomains.filterNot { covers(it, host) })

    fun apply(w: WebPolicy, host: String, action: DomainAction): WebPolicy = when (action) {
        DomainAction.BLOCK_HOST -> block(w, host)
        DomainAction.BLOCK_REGISTRABLE -> blockRegistrable(w, host)
        DomainAction.ALLOW -> allow(w, host)
        DomainAction.UNBLOCK -> unblock(w, host)
    }

    fun hostOf(url: String?, host: String?): String? =
        (host?.takeIf { it.isNotBlank() } ?: url?.substringAfter("://")?.substringBefore('/')?.substringBefore(':')?.substringAfter('@'))
            ?.let { normalize(it) }?.takeIf { it.isNotEmpty() }
}
