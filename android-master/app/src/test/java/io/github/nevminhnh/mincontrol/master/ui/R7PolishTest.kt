package io.github.nevminhnh.mincontrol.master.ui

import io.github.nevminhnh.mincontrol.master.data.api.ApiException
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo
import io.github.nevminhnh.mincontrol.master.ui.pairing.disambiguateHostnames
import io.github.nevminhnh.mincontrol.master.ui.pairing.osDisplay
import io.github.nevminhnh.mincontrol.master.ui.pairing.shouldJumpToPairing
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class R7PolishTest {
    private fun http(status: Int, code: String) = ApiException.Http(status, code, null).userMessage()

    @Test fun osWindows11() = assertEquals("Windows 11 (10.0.26100)", osDisplay("10.0.26100"))
    @Test fun osWindows10() = assertEquals("Windows 10 (10.0.19045)", osDisplay("10.0.19045"))
    @Test fun osBoundary() = assertEquals("Windows 11 (10.0.22000)", osDisplay("10.0.22000"))
    @Test fun osUnknownKept() {
        assertEquals("", osDisplay(""))
        assertEquals("Windows 11 Pro", osDisplay("Windows 11 Pro"))
        assertEquals("abc", osDisplay("abc"))
    }

    @Test fun errorCodes() {
        assertEquals("Máy này đã được duyệt rồi", http(409, "already_approved"))
        assertEquals("Mã đã hết hạn, hãy tạo mã mới trên máy tính", http(410, "expired"))
        assertEquals("Máy này đã bị từ chối", http(410, "rejected"))
        assertEquals("Không tìm thấy mã này", http(404, "not_found"))
        assertEquals("Mã không đúng, hãy kiểm tra lại", http(400, "invalid_code"))
        assertEquals("Có lỗi, thử lại", http(400, "weird_code"))
        assertTrue(http(400, "sign_key_required").isNotBlank())
    }

    @Test fun duplicateHostnamesGetSuffix() {
        val l = disambiguateHostnames(listOf(DeviceInfo("dev-aaaa1111", "PC"), DeviceInfo("dev-bbbb2222", "PC"), DeviceInfo("dev-cccc3333", "Other")))
        assertEquals(listOf("PC · 1111", "PC · 2222", "Other"), l.map { it.hostname })
    }

    @Test fun jumpRule() {
        val now = Instant.parse("2026-11-22T00:00:00Z")
        assertTrue(shouldJumpToPairing(emptyList(), now))
        assertFalse(shouldJumpToPairing(listOf(DeviceInfo("a", "A", online = true)), now))
        assertFalse(shouldJumpToPairing(listOf(DeviceInfo("a", "A", lastSeen = "2026-11-20T00:00:00Z")), now))
        assertTrue(shouldJumpToPairing(listOf(DeviceInfo("a", "A", lastSeen = "2026-11-01T00:00:00Z")), now))
    }
}
