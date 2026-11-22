package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.ApiJson
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.InventoryApp
import io.github.nevminhnh.mincontrol.master.data.protocol.InventoryResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppPickerTest {
    private fun app(id: String, name: String, kind: String = "win32", min: Int? = null, cat: String? = null, dir: String? = null, exe: String? = null, pub: String? = null) =
        InventoryApp(id, name, kind, publisher = pub, installDir = dir, exe = exe, minutes7d = min, category = cat)

    @Test fun installDirMapsToPathGlob() {
        assertEquals(AppMatch(path = "C:\\Games\\Minecraft\\*"), AppPicker.toMatch(app("1", "MC", dir = "C:\\Games\\Minecraft\\", exe = "mc.exe")))
        assertEquals(AppMatch(path = "C:\\Pkg\\X\\*"), AppPicker.toMatch(app("2", "X", kind = "appx", dir = "C:\\Pkg\\X")))
    }

    @Test fun noInstallDirMapsToExeWithPublisher() {
        assertEquals(AppMatch(exe = "zalo.exe", publisher = "VNG"), AppPicker.toMatch(app("3", "Zalo", exe = "zalo.exe", pub = "VNG")))
        assertEquals(AppMatch(exe = "a.exe"), AppPicker.toMatch(app("4", "A", kind = "seen", exe = "a.exe")))
        assertEquals(AppMatch(exe = "b.exe"), AppPicker.toMatch(InventoryApp("5", "B", "seen", exePath = "C:\\x\\b.exe")))
        assertNull(AppPicker.toMatch(app("6", "none")))
    }

    @Test fun sortsByMinutesThenName() {
        val l = listOf(app("a", "zeta", min = 5), app("b", "Alpha"), app("c", "beta", min = 5), app("d", "Top", min = 90))
        assertEquals(listOf("d", "c", "a", "b"), AppPicker.sortFilter(l, "").map { it.id })
    }

    @Test fun filtersByNamePublisherExe() {
        val l = listOf(app("a", "Steam", pub = "Valve"), app("b", "Chrome", exe = "chrome.exe"))
        assertEquals(listOf("a"), AppPicker.sortFilter(l, " valve ").map { it.id })
        assertEquals(listOf("b"), AppPicker.sortFilter(l, "CHROME").map { it.id })
    }

    @Test fun suggestAndGroupName() {
        assertTrue(AppPicker.isGameGroup("Trò chơi") && AppPicker.isGameGroup("Games") && !AppPicker.isGameGroup("Học"))
        assertEquals(setOf("g"), AppPicker.suggestGames(listOf(app("g", "G", cat = "game"), app("s", "S", cat = "social"))))
    }

    @Test fun mergeDedupes() {
        val out = AppPicker.merge(listOf(AppMatch(path = "C:\\G\\*")), listOf(app("1", "G", dir = "C:\\G"), app("2", "H", dir = "C:\\H")))
        assertEquals(listOf(AppMatch(path = "C:\\G\\*"), AppMatch(path = "C:\\H\\*")), out)
    }

    @Test fun parseManualAndDecode() {
        assertEquals(
            listOf(AppMatch(exe = "a*.exe"), AppMatch(publisher = "Valve*"), AppMatch(path = "C:\\x\\*")),
            AppPicker.parseManual("a*.exe\npublisher:Valve*\npath:C:\\x\\*"),
        )
        val r = ApiJson.decodeFromString(InventoryResponse.serializer(), """{"generatedAt":"2026-11-22T00:00:00Z","apps":[{"id":"1","name":"N","kind":"seen","minutes7d":3,"extra":1}]}""")
        assertEquals(3, r.apps[0].minutes7d)
    }
}
