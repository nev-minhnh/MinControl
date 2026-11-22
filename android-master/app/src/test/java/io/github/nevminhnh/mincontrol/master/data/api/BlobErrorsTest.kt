package io.github.nevminhnh.mincontrol.master.data.api

import org.junit.Assert.assertEquals
import org.junit.Test

class BlobErrorsTest {
    private fun http(status: Int, code: String) = ApiException.Http(status, code, null)

    @Test fun offline() = assertEquals("Máy đang tắt — mở lại khi máy online", blobErrorMessage(http(409, "device_offline")))
    @Test fun timeout() = assertEquals("Máy không phản hồi, thử lại", blobErrorMessage(http(504, "device_timeout")))
    @Test fun notFound() = assertEquals("Ảnh đã bị xoá trên máy (quá hạn lưu)", blobErrorMessage(http(404, "not_found")))
    @Test fun lruEvictsOldest() {
        val c = LruCache<Int, Int>(2)
        c[1] = 1; c[2] = 2; c[1]; c[3] = 3
        assertEquals(setOf(1, 3), c.snapshot().keys)
    }
}
