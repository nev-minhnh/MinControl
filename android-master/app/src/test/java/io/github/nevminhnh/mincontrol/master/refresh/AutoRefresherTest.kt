package io.github.nevminhnh.mincontrol.master.refresh

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.ZoneOffset
import java.util.concurrent.atomic.AtomicInteger

class AutoRefresherTest {
    private fun scope() = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private suspend fun until(timeoutMs: Long = 3_000, cond: () -> Boolean) = withTimeout(timeoutMs) { while (!cond()) delay(5) }

    @Test
    fun refreshesOnResumeThenPeriodicallyAndStopsWhenHidden() = runBlocking {
        val s = scope(); val n = AtomicInteger()
        val r = AutoRefresher(s, 60, MutableSharedFlow()) { n.incrementAndGet() }
        assertEquals(0, n.get())
        r.setVisible(true)
        until { n.get() >= 1 }                       // immediate refresh on resume
        until { n.get() >= 3 }                       // then periodic
        r.setVisible(false)
        delay(30)
        val frozen = n.get()
        delay(250)
        assertEquals("no refresh while hidden", frozen, n.get())
        r.setVisible(true)
        until { n.get() > frozen }                   // resume again refreshes
        s.cancel()
    }

    @Test
    fun overviewAndDefaultIntervals() {
        assertEquals(10_000L, RefreshIntervals.OVERVIEW_MS)
        assertEquals(20_000L, RefreshIntervals.DEFAULT_MS)
    }

    @Test
    fun requestsDoNotStackAndOneFollowUpRunsAfterBurst() = runBlocking {
        val s = scope(); val n = AtomicInteger(); val gate = CompletableDeferred<Unit>()
        val r = AutoRefresher(s, 60_000, MutableSharedFlow()) { n.incrementAndGet(); gate.await() }
        r.trigger()
        until { n.get() == 1 }                         // first run started and is blocked
        r.trigger(); r.trigger(manual = true); r.trigger()
        delay(50)
        assertEquals("only one in flight", 1, n.get())
        assertTrue(r.refreshing.value)
        gate.complete(Unit)
        until { r.runs == 2 && !r.refreshing.value }   // a single coalesced follow-up
        delay(50)
        assertEquals(2, r.runs)
        assertNotNull(r.lastUpdated.value)
        s.cancel()
    }

    @Test
    fun alertEventTriggersOnlyWhileVisible() = runBlocking {
        val s = scope(); val n = AtomicInteger(); val ev = MutableSharedFlow<Unit>(extraBufferCapacity = 4)
        val r = AutoRefresher(s, 60_000, ev) { n.incrementAndGet() }
        delay(50)
        ev.emit(Unit); delay(80)
        assertEquals("hidden screen ignores FCM event", 0, n.get())
        r.setVisible(true)
        until { n.get() == 1 }
        ev.emit(Unit)
        until { n.get() == 2 }
        s.cancel()
    }

    @Test
    fun failedRunKeepsLastUpdatedAndKeepsGoing() = runBlocking {
        val s = scope(); val n = AtomicInteger()
        val r = AutoRefresher(s, 40, MutableSharedFlow(), { 1_000L * n.get() }) { if (n.incrementAndGet() == 1) error("net") }
        r.setVisible(true)
        until { n.get() >= 2 && r.lastUpdated.value != null }
        assertTrue(r.lastUpdated.value!! >= 1_000L)
        s.cancel()
    }

    @Test
    fun updatedLabel() {
        assertNull(UpdatedFormat.label(null))
        assertEquals("Cập nhật lúc 14:05:09", UpdatedFormat.label(((14 * 60 + 5) * 60 + 9) * 1000L, ZoneOffset.UTC))
    }
}
