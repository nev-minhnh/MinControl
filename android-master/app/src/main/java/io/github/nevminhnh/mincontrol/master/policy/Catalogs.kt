package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppGroup
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** One default app group from `protocol/app-groups.json` (API.md §19). */
data class DefaultAppGroup(val id: String, val label: String, val description: String, val match: List<AppMatch>) {
    /** As a policy group: no quota (= "Không giới hạn"); the parent turns a limit on per group. */
    fun toPolicyGroup() = AppGroup(label = label, match = match, dailyQuotaMin = null)
}

/**
 * Default app groups (API.md §19). Loaded from assets/app-groups.json (copied from ../protocol at build time);
 * when that file is missing or empty the small built-in list below is used, so the app never ships without groups.
 */
data class AppGroupCatalog(val groups: List<DefaultAppGroup>) {
    fun byId(id: String): DefaultAppGroup? = groups.firstOrNull { it.id == id }

    companion object {
        private val ID = Regex("^[a-z][a-z0-9_-]{0,31}$")
        private val json = Json { ignoreUnknownKeys = true }

        /** Labels/order requested by Minh; also the fallback when app-groups.json is not there yet. */
        val BUILTIN = AppGroupCatalog(
            listOf(
                DefaultAppGroup(
                    "games", "Game", "Game và trình chạy game (Steam, Epic, Riot, Garena, Roblox, Minecraft…)",
                    listOf(
                        AppMatch(exe = "steam.exe"), AppMatch(publisher = "Valve*"), AppMatch(exe = "EpicGamesLauncher.exe"),
                        AppMatch(exe = "RiotClientServices.exe"), AppMatch(exe = "LeagueClient.exe"), AppMatch(exe = "Roblox*.exe"),
                        AppMatch(exe = "Minecraft*.exe"), AppMatch(exe = "javaw.exe", path = "*\\.minecraft\\*"),
                    ),
                ),
                DefaultAppGroup(
                    "social-chat", "Mạng xã hội & Chat", "Zalo, Messenger, Discord, Telegram…",
                    listOf(AppMatch(exe = "Zalo.exe"), AppMatch(exe = "Discord.exe"), AppMatch(exe = "Telegram.exe"), AppMatch(exe = "Messenger.exe")),
                ),
                DefaultAppGroup(
                    "video-entertainment", "Video & Giải trí", "Ứng dụng xem phim, video",
                    listOf(AppMatch(exe = "vlc.exe"), AppMatch(exe = "PotPlayer*.exe")),
                ),
                DefaultAppGroup("music", "Nhạc", "Spotify, iTunes…", listOf(AppMatch(exe = "Spotify.exe"), AppMatch(exe = "iTunes.exe"))),
                DefaultAppGroup(
                    "browsers-other", "Trình duyệt khác", "Trình duyệt ngoài Edge và Chrome",
                    listOf(AppMatch(exe = "firefox.exe"), AppMatch(exe = "opera.exe"), AppMatch(exe = "brave.exe"), AppMatch(exe = "vivaldi.exe")),
                ),
                DefaultAppGroup(
                    "study", "Học tập", "Word, Excel, PowerPoint, OneNote… (thường không cần giới hạn)",
                    listOf(AppMatch(exe = "WINWORD.EXE"), AppMatch(exe = "EXCEL.EXE"), AppMatch(exe = "POWERPNT.EXE"), AppMatch(exe = "ONENOTE.EXE")),
                ),
                DefaultAppGroup(
                    "creative", "Sáng tạo", "Vẽ, dựng phim, lập trình…",
                    listOf(AppMatch(exe = "Photoshop.exe"), AppMatch(exe = "Canva.exe"), AppMatch(exe = "blender.exe"), AppMatch(exe = "krita.exe")),
                ),
            ),
        )

        /**
         * Parses `{"version","groups":[{"id","label","description","match":[AppMatch…]}]}` (or a bare array).
         * Invalid groups/matches are dropped; returns null when nothing usable is left (caller falls back to [BUILTIN]).
         */
        fun parse(text: String?): AppGroupCatalog? {
            if (text.isNullOrBlank()) return null
            return runCatching {
                val root = json.parseToJsonElement(text)
                val arr = when (root) { is JsonArray -> root; is JsonObject -> root["groups"] as? JsonArray; else -> null } ?: return null
                val list = arr.mapNotNull { el ->
                    val o = el as? JsonObject ?: return@mapNotNull null
                    val id = (o["id"] as? JsonPrimitive)?.contentOrNull?.trim() ?: return@mapNotNull null
                    val label = (o["label"] as? JsonPrimitive)?.contentOrNull?.trim()?.take(40) ?: return@mapNotNull null
                    if (!ID.matches(id) || label.isEmpty()) return@mapNotNull null
                    val desc = (o["description"] as? JsonPrimitive)?.contentOrNull?.trim().orEmpty()
                    val match = (o["match"] as? JsonArray).orEmpty().mapNotNull { m -> matchOf(m as? JsonObject) }.distinct()
                    if (match.isEmpty()) null else DefaultAppGroup(id, label, desc, match)
                }.distinctBy { it.id }
                list.takeIf { it.isNotEmpty() }?.let { AppGroupCatalog(it) }
            }.getOrNull()
        }

        /** Keeps only the schema's appMatch keys (extra keys in the catalog would break the strict policy schema). */
        private fun matchOf(o: JsonObject?): AppMatch? {
            if (o == null) return null
            fun s(k: String) = (o[k] as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()?.takeIf { it.isNotEmpty() && it.length <= 260 }
            val m = AppMatch(
                exe = s("exe"), path = s("path"), publisher = s("publisher"),
                sha256 = s("sha256")?.lowercase()?.takeIf { Regex("^[0-9a-f]{64}$").matches(it) },
                pathUnderUserWritable = (o["pathUnderUserWritable"] as? JsonPrimitive)?.contentOrNull?.takeIf { it == "true" }?.let { true },
            )
            return m.takeIf { AppRules.matchError(it) == null }
        }

        fun load(context: android.content.Context): AppGroupCatalog =
            parse(runCatching { context.assets.open("app-groups.json").bufferedReader(Charsets.UTF_8).use { it.readText() } }.getOrNull()) ?: BUILTIN

        /** Set once at app start from assets; tests and previews use [BUILTIN] (or parse the protocol file themselves). */
        @Volatile var current: AppGroupCatalog = BUILTIN
    }
}

/** `protocol/search-engines.json` (API.md §19): engines blocked while SafeSearch is on. Only names are needed in the app. */
object SearchEngines {
    val FALLBACK = listOf("DuckDuckGo", "Yandex", "Yahoo", "Brave Search", "Ecosia", "Startpage", "Qwant", "Baidu")
    private val json = Json { ignoreUnknownKeys = true }

    fun parseNames(text: String?): List<String> {
        if (text.isNullOrBlank()) return emptyList()
        return runCatching {
            val root = json.parseToJsonElement(text)
            val arr = when (root) { is JsonArray -> root; is JsonObject -> root["engines"] as? JsonArray; else -> null } ?: return emptyList()
            arr.mapNotNull { ((it as? JsonObject)?.get("name") as? JsonPrimitive)?.contentOrNull?.trim()?.takeIf { n -> n.isNotEmpty() } }.distinct()
        }.getOrDefault(emptyList())
    }

    fun load(context: android.content.Context): List<String> =
        parseNames(runCatching { context.assets.open("search-engines.json").bufferedReader(Charsets.UTF_8).use { it.readText() } }.getOrNull())
            .ifEmpty { FALLBACK }
}
