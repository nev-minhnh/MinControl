package io.github.nevminhnh.mincontrol.master.live

import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceState
import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.refresh.AutoRefresher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class LiveTest {
    private fun ev(id: String, ts: String, type: String = "app.focus", sid: String? = "S-1", data: Map<String, String> = emptyMap()) =
        EventItem(id = id, deviceId = "D1", userSid = sid, ts = ts, type = type, data = JsonObject(data.mapValues { JsonPrimitive(it.value) }))

    private val anyDay: (String) -> Boolean = { true }

    // ---- merge / dedupe ----
    @Test
    fun mergeEventsPutsNewOnTopAndDedupesById() {
        val old = listOf(ev("e2", "2026-11-23T10:00:02Z"), ev("e1", "2026-11-23T10:00:01Z"))
        val merged = LiveMerge.mergeEvents(old, listOf(ev("e3", "2026-11-23T10:00:03Z"), ev("e2", "2026-11-23T10:00:02Z")))
        assertEquals(listOf("e3", "e2", "e1"), merged.map { it.id })
        assertSame("nothing new -> same list", old, LiveMerge.mergeEvents(old, listOf(ev("e1", "2026-11-23T10:00:01Z"))))
    }

    @Test
    fun mergeEventsAppliesTimelineAndDomainRules() {
        val tl = LiveMerge.timelineAccept("S-1", anyDay)
        assertTrue(tl(ev("a", "t", "app.focus")))
        assertFalse(tl(ev("b", "t", "usage.tick")))
        assertFalse(tl(ev("c", "t", "net.domain")))
        assertFalse(tl(ev("d", "t", "app.focus", sid = "S-2")))
        assertTrue(tl(ev("e", "t", "tamper.clock_jump", sid = null)))
        assertFalse(tl(ev("f", "t", "app.focus", sid = null)))
        val dm = LiveMerge.domainAccept("S-1", anyDay)
        assertTrue(dm(ev("g", "t", "net.domain")))
        assertFalse(dm(ev("h", "t", "web.visit")))
        assertFalse(LiveMerge.domainAccept("S-1") { false }(ev("i", "t", "net.domain")))
    }

    @Test
    fun mergeWebDedupesFiltersAndKeepsNewestFirst() {
        val v1 = ev("w1", "2026-11-23T10:00:01Z", "web.visit", data = mapOf("url" to "https://a.com/x", "host" to "a.com", "title" to "Alpha"))
        val first = LiveMerge.mergeWeb(emptyList(), listOf(v1), "S-1", "", null, anyDay)
        assertEquals(listOf("visit"), first.map { it.kind })
        // same event delivered twice -> no duplicate
        assertSame(first, LiveMerge.mergeWeb(first, listOf(v1), "S-1", "", null, anyDay))
        val blocked = ev("w2", "2026-11-23T10:00:05Z", "web.blocked", data = mapOf("host" to "bad.com", "reason" to "blocklist"))
        val both = LiveMerge.mergeWeb(first, listOf(blocked, ev("x", "2026-11-23T10:00:06Z", "app.focus")), "S-1", "", null, anyDay)
        assertEquals(listOf("blocked", "visit"), both.map { it.kind })
        // filters: kind and search text
        assertTrue(LiveMerge.mergeWeb(emptyList(), listOf(blocked), "S-1", "", "search", anyDay).isEmpty())
        assertTrue(LiveMerge.mergeWeb(emptyList(), listOf(blocked), "S-1", "zzz", null, anyDay).isEmpty())
        assertEquals(1, LiveMerge.mergeWeb(emptyList(), listOf(blocked), "S-1", "BAD", null, anyDay).size)
        assertTrue(LiveMerge.mergeWeb(emptyList(), listOf(blocked), "S-2", "", null, anyDay).isEmpty())
    }

    @Test
    fun alertEventTypes() {
        assertTrue(LiveMerge.isAlertEvent("tamper.agent_killed"))
        assertTrue(LiveMerge.isAlertEvent("request.exe_approval"))
        assertTrue(LiveMerge.isAlertEvent("quota.exhausted"))
        assertFalse(LiveMerge.isAlertEvent("app.focus"))
        assertFalse(LiveMerge.isAlertEvent("net.domain"))
    }

    // ---- parser / state ----
    @Test
    fun parsesFrames() {
        val st = LiveParser.parse("""{"t":"state","deviceId":"D1","state":{"ts":"2026-11-23T10:00:00Z","users":[{"sid":"S-1","locked":true}]}}""") as LiveMessage.State
        assertTrue(st.state.users.single().locked)
        val on = LiveParser.parse("""{"t":"online","deviceId":"D1","online":false}""") as LiveMessage.Online
        assertFalse(on.online)
        val es = LiveParser.parse("""{"t":"events","deviceId":"D1","events":[{"id":"e1","deviceId":"D1","ts":"2026-11-23T10:00:00Z","type":"web.visit"},{"bad":1}]}""") as LiveMessage.Events
        assertEquals(listOf("e1"), es.events.map { it.id })
        assertNull(LiveParser.parse("not json"))
        assertNull(LiveParser.parse("""{"t":"wat","deviceId":"D1"}"""))
    }

    @Test
    fun applyStateAndOnlineToDevice() {
        val d = DeviceInfo(deviceId = "D1", hostname = "PC", online = true)
        val s = DeviceState(ts = "2026-11-23T10:00:00Z")
        assertEquals(s, LiveMerge.applyState(d, s).state)
        assertFalse(LiveMerge.applyOnline(d, false).online)
    }

    // ---- backoff ----
    @Test
    fun backoffDoublesCapsAndResets() {
        val b = ReconnectBackoff(baseMs = 1_000, maxMs = 30_000, jitterPct = 0)
        assertEquals(listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 30_000L, 30_000L), List(7) { b.nextDelayMs() })
        b.reset()
        assertEquals(1_000L, b.nextDelayMs())
    }

    @Test
    fun backoffJitterStaysWithinBounds() {
        assertEquals(1_200L, ReconnectBackoff(jitterPct = 20, random = { 1.0 }).nextDelayMs())
        assertEquals(1_000L, ReconnectBackoff(jitterPct = 20, random = { 0.0 }).nextDelayMs())
    }

    // ---- polling interval ----
    @Test
    fun pollingIntervalSwitchesToSixtySecondsWhileLive() {
        assertEquals(10_000L, PollingPolicy.intervalMs(10_000, liveHealthy = false))
        assertEquals(60_000L, PollingPolicy.intervalMs(10_000, liveHealthy = true))
        assertEquals(60_000L, PollingPolicy.intervalMs(20_000, liveHealthy = true))
        assertEquals(90_000L, PollingPolicy.intervalMs(90_000, liveHealthy = true))
    }

    @Test
    fun autoRefresherPollsSlowlyWhileLiveAndFastAgainWhenItDrops() = runBlocking {
        val s = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val n = AtomicInteger()
        val live = MutableStateFlow(true)
        val r = AutoRefresher(s, 100, MutableSharedFlow(), live = live) { n.incrementAndGet() }
        r.setVisible(true)
        withTimeout(2_000) { while (n.get() < 1) delay(5) }
        delay(1_300)                          // 100 ms base, but live -> 60 s: still just the first run
        assertEquals(1, n.get())
        live.value = false                    // socket dropped -> back to 100 ms polling
        withTimeout(3_000) { while (n.get() < 3) delay(10) }
        s.cancel()
    }

    // ---- hub reconnect ----
    private class FakeConnector : LiveConnector {
        val listeners = ArrayList<LiveListener>()
        val closedSockets = AtomicInteger()
        override fun connect(deviceId: String, listener: LiveListener): LiveSocket {
            listeners += listener
            return object : LiveSocket { override fun close() { closedSockets.incrementAndGet() } }
        }
    }

    private suspend fun until(cond: () -> Boolean) = withTimeout(3_000) { while (!cond()) delay(5) }

    @Test
    fun hubConnectsOnlyInForegroundReconnectsAndPublishes() = runBlocking {
        val s = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val fake = FakeConnector()
        val alerts = AtomicInteger()
        val hub = LiveHub(s, fake, onAlertEvent = { alerts.incrementAndGet() }, backoffFactory = { ReconnectBackoff(10, 20, 0) })
        hub.setDevices(setOf("D1"))
        delay(50)
        assertTrue("background: no socket", fake.listeners.isEmpty())
        hub.setForeground(true)
        until { fake.listeners.size == 1 }
        assertFalse(hub.healthy.value)
        fake.listeners[0].onOpen()
        until { hub.healthy.value }
        // events are re-emitted; an alert-type event asks for an alerts refresh
        val got = CompletableDeferredBox()
        val job = s.launch { hub.events.collect { got.value = it } }
        delay(50)
        fake.listeners[0].onMessage("""{"t":"events","deviceId":"D1","events":[{"id":"e9","deviceId":"D1","ts":"2026-11-23T10:00:00Z","type":"tamper.agent_killed"}]}""")
        until { got.value != null }
        assertEquals(1, alerts.get())
        job.cancel()
        // drop -> reconnect after backoff
        fake.listeners[0].onClosed()
        until { !hub.healthy.value }
        until { fake.listeners.size == 2 }
        // going to background closes everything and stops reconnecting
        hub.setForeground(false)
        delay(100)
        val count = fake.listeners.size
        delay(100)
        assertEquals(count, fake.listeners.size)
        assertFalse(hub.healthy.value)
        assertNotNull(fake.closedSockets)
        s.cancel()
    }

    private class CompletableDeferredBox { @Volatile var value: LiveMessage.Events? = null }
}
