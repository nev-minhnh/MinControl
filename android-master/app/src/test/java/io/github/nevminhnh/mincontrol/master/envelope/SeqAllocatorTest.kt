package io.github.nevminhnh.mincontrol.master.envelope

import io.github.nevminhnh.mincontrol.master.data.protocol.BodyKind
import org.junit.Assert.assertEquals
import org.junit.Test

class SeqAllocatorTest {
    private val dev = "01JDQ8X5ZK3V9T6R2M4N7P8Q0W"

    @Test
    fun startsAfterServerSeq() {
        val a = SeqAllocator(InMemorySeqStore())
        assertEquals(1L, a.next(dev, BodyKind.COMMAND, 0))
        assertEquals(8L, SeqAllocator(InMemorySeqStore()).next(dev, BodyKind.COMMAND, 7))
    }

    @Test
    fun localMaxWinsWhenServerIsBehind() {
        val store = InMemorySeqStore()
        val a = SeqAllocator(store)
        assertEquals(5L, a.next(dev, BodyKind.COMMAND, 4))
        // The request with seq 5 may have been lost: server still reports 4, we must not reuse 5.
        assertEquals(6L, a.next(dev, BodyKind.COMMAND, 4))
        assertEquals(6L, store.localMax(dev, BodyKind.COMMAND))
    }

    @Test
    fun serverAheadWins() {
        val a = SeqAllocator(InMemorySeqStore())
        a.next(dev, BodyKind.COMMAND, 2)
        assertEquals(21L, a.next(dev, BodyKind.COMMAND, 20))
    }

    @Test
    fun kindsAndDevicesAreIndependent() {
        val a = SeqAllocator(InMemorySeqStore())
        assertEquals(10L, a.next(dev, BodyKind.COMMAND, 9))
        assertEquals(1L, a.next(dev, BodyKind.POLICY, 0))
        assertEquals(1L, a.next("01JDQ8X5ZK3V9T6R2M4N7P8Q0Z", BodyKind.COMMAND, 0))
    }
}
