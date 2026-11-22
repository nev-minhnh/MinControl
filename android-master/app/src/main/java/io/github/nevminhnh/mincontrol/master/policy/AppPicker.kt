package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.InventoryApp

/** Pure logic behind the "Chọn từ máy tính" picker (API.md §11). */
object AppPicker {
    /** win32/appx with installDir -> `<dir>\*`; otherwise exe (+ publisher when known). Null when nothing usable. */
    fun toMatch(a: InventoryApp): AppMatch? {
        val dir = a.installDir?.trim()?.trimEnd('\\', '/')?.takeIf { it.isNotEmpty() }
        if (dir != null && a.kind != "seen") return AppMatch(path = "$dir\\*")
        val exe = a.exe?.trim()?.takeIf { it.isNotEmpty() }
            ?: a.exePath?.trim()?.substringAfterLast('\\')?.substringAfterLast('/')?.takeIf { it.isNotEmpty() }
            ?: return dir?.let { AppMatch(path = "$it\\*") }
        return AppMatch(exe = exe, publisher = a.publisher?.trim()?.takeIf { it.isNotEmpty() })
    }

    /** Sorted by minutes7d desc then name (case-insensitive); filtered by name/publisher/exe substring. */
    fun sortFilter(apps: List<InventoryApp>, query: String): List<InventoryApp> {
        val q = query.trim().lowercase()
        return apps
            .filter { q.isEmpty() || listOfNotNull(it.name, it.publisher, it.exe).any { s -> q in s.lowercase() } }
            .sortedWith(compareByDescending<InventoryApp> { it.minutes7d ?: 0 }.thenBy { it.name.lowercase() })
    }

    fun isGameGroup(label: String): Boolean {
        val l = label.lowercase()
        return "game" in l || "trò chơi" in l || "tro choi" in l
    }

    /** Ids of apps with category=game ("Gợi ý"). */
    fun suggestGames(apps: List<InventoryApp>): Set<String> = apps.filter { it.category == "game" }.map { it.id }.toSet()

    /** Maps picked apps to distinct matches, appended to [existing] without duplicates. */
    fun merge(existing: List<AppMatch>, picked: Collection<InventoryApp>): List<AppMatch> {
        val out = existing.toMutableList()
        picked.mapNotNull { toMatch(it) }.forEach { if (it !in out) out += it }
        return out
    }

    fun describe(m: AppMatch): String =
        m.path ?: m.exe?.let { e -> m.publisher?.let { "$e ($it)" } ?: e } ?: m.publisher?.let { "publisher:$it" } ?: m.sha256?.let { "sha256:${it.take(8)}…" } ?: "?"

    fun categoryLabel(c: String?): String? = when (c) {
        "game" -> "Game"; "browser" -> "Trình duyệt"; "social" -> "Mạng xã hội"; "video" -> "Video"
        "study" -> "Học tập"; "system" -> "Hệ thống"; "other" -> "Khác"; else -> null
    }

    /** "Nhập tay" lines: `exe:`/`publisher:`/`path:`/`sha256:` prefix, bare line = exe. */
    fun parseManual(text: String): List<AppMatch> = text.lines().map { it.trim() }.filter { it.isNotEmpty() }.map { line ->
        val i = line.indexOf(':')
        val (k, v) = if (i > 1) line.substring(0, i).lowercase() to line.substring(i + 1).trim() else "exe" to line
        when (k) {
            "publisher" -> AppMatch(publisher = v); "path" -> AppMatch(path = v); "sha256" -> AppMatch(sha256 = v.lowercase()); else -> AppMatch(exe = v)
        }
    }
}
