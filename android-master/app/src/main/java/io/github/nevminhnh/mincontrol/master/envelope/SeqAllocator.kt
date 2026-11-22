package io.github.nevminhnh.mincontrol.master.envelope

import android.content.Context
import io.github.nevminhnh.mincontrol.master.data.protocol.BodyKind

/** Persists the highest seq this phone has used per (deviceId, kind). */
interface SeqStore {
    fun localMax(deviceId: String, kind: BodyKind): Long
    fun setLocalMax(deviceId: String, kind: BodyKind, seq: Long)
}

class InMemorySeqStore : SeqStore {
    private val map = HashMap<String, Long>()
    override fun localMax(deviceId: String, kind: BodyKind) = map["$deviceId/$kind"] ?: 0L
    override fun setLocalMax(deviceId: String, kind: BodyKind, seq: Long) { map["$deviceId/$kind"] = seq }
}

class PrefsSeqStore(context: Context) : SeqStore {
    private val prefs = context.getSharedPreferences("mc_seq", Context.MODE_PRIVATE)
    override fun localMax(deviceId: String, kind: BodyKind) = prefs.getLong(key(deviceId, kind), 0L)
    override fun setLocalMax(deviceId: String, kind: BodyKind, seq: Long) {
        prefs.edit().putLong(key(deviceId, kind), seq).commit()
    }
    private fun key(deviceId: String, kind: BodyKind) = "$deviceId/${kind.name.lowercase()}"
}

/**
 * seq is strictly increasing per (device, kind). next = max(server last seq, local max) + 1.
 * The allocation is persisted immediately, so a request that reached the server but whose response
 * was lost never causes the same seq to be reused.
 */
class SeqAllocator(private val store: SeqStore) {
    @Synchronized
    fun next(deviceId: String, kind: BodyKind, serverLast: Long): Long {
        require(serverLast >= 0)
        val n = maxOf(serverLast, store.localMax(deviceId, kind)) + 1
        store.setLocalMax(deviceId, kind, n)
        return n
    }
}
