package io.github.nevminhnh.mincontrol.master.data.api

/** Vietnamese message for a failed on-demand screenshot fetch (API.md §9). */
fun blobErrorMessage(t: Throwable): String = when {
    t is ApiException.Http && (t.code == "device_offline" || t.status == 409) -> "Máy đang tắt — mở lại khi máy online"
    t is ApiException.Http && (t.code == "device_timeout" || t.status == 504) -> "Máy không phản hồi, thử lại"
    t is ApiException.Http && (t.code == "not_found" || t.status == 404 || t.status == 410) -> "Ảnh đã bị xoá trên máy (quá hạn lưu)"
    t is ApiException.Network -> "Máy không phản hồi, thử lại"
    t is ApiException -> t.userMessage()
    else -> "Không giải mã được ảnh: ${t.message ?: "lỗi không xác định"}"
}

const val BLOB_PROGRESS_TEXT = "Đang lấy ảnh từ máy…"
const val BLOB_CACHE_SIZE = 20

/** Small in-memory LRU; images are never written to disk unencrypted. */
class LruCache<K, V>(private val max: Int) {
    private val map = object : LinkedHashMap<K, V>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?) = size > max
    }
    @Synchronized operator fun get(k: K): V? = map[k]
    @Synchronized operator fun set(k: K, v: V) { map[k] = v }
    @Synchronized fun snapshot(): Map<K, V> = LinkedHashMap(map)
    val size: Int @Synchronized get() = map.size
}
