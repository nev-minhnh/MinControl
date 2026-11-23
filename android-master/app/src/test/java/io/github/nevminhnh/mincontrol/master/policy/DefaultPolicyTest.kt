package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyJson
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolSchemas
import io.github.nevminhnh.mincontrol.master.data.protocol.WebCategory
import io.github.nevminhnh.mincontrol.master.data.protocol.WebMode
import io.github.nevminhnh.mincontrol.master.data.protocol.YouTubeMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** API.md §19: default policy for a newly managed user + the app-groups / search-engines catalogs. */
class DefaultPolicyTest {
    private val sid = "S-1-5-21-111-222-333-1001"

    /** The real catalog when the parallel protocol stream has landed it, else the built-in fallback. */
    private val catalog: AppGroupCatalog =
        File(ProtocolSchemas.dir, "app-groups.json").takeIf { it.isFile }?.readText()?.let { AppGroupCatalog.parse(it) } ?: AppGroupCatalog.BUILTIN

    @Test fun everyCategoryBlockedIncludingAi() {
        val up = PolicyDefaults.user("Bin", catalog)
        assertEquals(WebCategory.entries.toSet(), up.web.blockedCategories.toSet())
        assertTrue(WebCategory.AI in up.web.blockedCategories)
        assertEquals(11, up.web.blockedCategories.size)
        assertNull(up.web.categorySchedules)
    }

    @Test fun safeSearchOnYoutubeStrictBlocklist() {
        val up = PolicyDefaults.user("Bin", catalog)
        assertTrue(up.web.safeSearch)
        assertEquals(YouTubeMode.STRICT, up.web.youtube)
        assertEquals(WebMode.BLOCKLIST, up.web.mode)
    }

    @Test fun defaultGroupsArePrefilledAndUnlimited() {
        val up = PolicyDefaults.user("Bin", catalog)
        assertEquals(catalog.groups.map { it.id }, up.appGroups.keys.toList())
        assertTrue(up.appGroups.values.all { it.dailyQuotaMin == null })
        assertTrue(up.appGroups.values.all { it.match.isNotEmpty() })
        for (id in listOf("games", "social-chat", "video-entertainment", "music", "browsers-other", "study", "creative")) {
            assertNotNull("builtin group $id", AppGroupCatalog.BUILTIN.byId(id))
        }
        assertEquals(
            listOf("Game", "Mạng xã hội & Chat", "Video & Giải trí", "Nhạc", "Trình duyệt khác", "Học tập", "Sáng tạo"),
            AppGroupCatalog.BUILTIN.groups.map { it.label },
        )
    }

    @Test fun defaultPolicyIsSchemaAndSemanticallyValid() {
        for (c in listOf(catalog, AppGroupCatalog.BUILTIN)) {
            val p: Policy = PolicyDefaults.policy(mapOf(sid to "Bin"), version = 1, groups = c)
            assertTrue(ProtocolSchemas.validate("policy", PolicyJson.encodeToString(Policy.serializer(), p)).isEmpty())
            assertTrue(PolicyValidation.errors(p).isEmpty())
        }
    }

    @Test fun catalogParsingIsTolerant() {
        assertNull(AppGroupCatalog.parse(null))
        assertNull(AppGroupCatalog.parse("not json"))
        assertNull(AppGroupCatalog.parse("{\"version\":0,\"groups\":[]}"))
        val c = AppGroupCatalog.parse(
            """{"version":1,"groups":[
              {"id":"games","label":"Game","description":"d","match":[{"exe":"steam.exe","note":"x"},{"exe":"C:\\bad\\a.exe"},{}]},
              {"id":"Bad Id","label":"x","match":[{"exe":"a.exe"}]},
              {"id":"empty","label":"Rỗng","match":[]},
              {"id":"games","label":"Dup","match":[{"exe":"b.exe"}]}
            ]}""",
        )!!
        assertEquals(listOf("games"), c.groups.map { it.id })
        assertEquals(listOf("steam.exe"), c.groups.single().match.map { it.exe })
        // unknown keys inside a match never reach the strict policy schema
        val p = PolicyDefaults.policy(mapOf(sid to "Bin"), groups = c)
        assertTrue(ProtocolSchemas.validate("policy", PolicyJson.encodeToString(Policy.serializer(), p)).isEmpty())
    }

    @Test fun searchEngineNames() {
        assertEquals(listOf("DuckDuckGo", "Yandex"),
            SearchEngines.parseNames("""{"version":1,"engines":[{"id":"ddg","name":"DuckDuckGo","domains":["*.duckduckgo.com"]},{"id":"y","name":"Yandex","domains":[]}]}"""))
        assertTrue(SearchEngines.parseNames("garbage").isEmpty())
        val f = File(ProtocolSchemas.dir, "search-engines.json")
        if (f.isFile) {
            val names = SearchEngines.parseNames(f.readText())
            assertTrue(names.isNotEmpty())
            assertFalse(names.any { it.contains("Google", true) || it.contains("Bing", true) })
        }
    }

    @Test fun helpTexts() {
        val ss = PolicyHelp.safeSearch(listOf("DuckDuckGo", "Yandex"))
        assertTrue(ss.contains("công cụ tìm kiếm khác bị chặn"))
        assertTrue(ss.contains("DuckDuckGo"))
        assertTrue(ss.contains("Không làm"))
        assertTrue(PolicyHelp.YOUTUBE.contains("Không làm"))
        assertTrue(PolicyHelp.YOUTUBE.contains("chặn hẳn dịch vụ YouTube"))
        assertEquals("Danh mục từ UT1 Blacklist (Đại học Toulouse Capitole, Pháp) – cập nhật hằng ngày", PolicyHelp.CATEGORY_SOURCE)
    }
}
