package io.github.nevminhnh.mincontrol.master.refresh

import io.github.nevminhnh.mincontrol.master.live.PollingPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** In-app events. [alertArrived] fires when an FCM alert is received while the app process is alive. */
object AppEvents {
    val alertArrived = MutableSharedFlow<Unit>(extraBufferCapacity = 8)
}

/**
 * Refresh scheduling shared by every screen's ViewModel.
 *
 *  - while [setVisible] is true: refresh immediately, then every [intervalMs];
 *  - [trigger] (pull-to-refresh, FCM event) never stacks: when a refresh is already running it only marks the
 *    state dirty so exactly one more run follows the current one;
 *  - the screen keeps showing its current data while [action] runs (the action must not clear lists);
 *  - [lastUpdated] is the epoch-millis of the last successful run (drives "Cập nhật lúc HH:mm:ss").
 */
class AutoRefresher(
    private val scope: CoroutineScope,
    val intervalMs: Long,
    events: Flow<Unit> = AppEvents.alertArrived,
    private val clock: () -> Long = System::currentTimeMillis,
    /** True while a live socket is healthy: the poll interval then becomes [PollingPolicy.LIVE_INTERVAL_MS]. */
    private val live: StateFlow<Boolean>? = null,
    private val action: suspend () -> Unit,
) {
    val lastUpdated: StateFlow<Long?> get() = _lastUpdated
    /** True only while a user-initiated (pull-to-refresh) run is in flight. */
    val refreshing: StateFlow<Boolean> get() = _refreshing

    private val _lastUpdated = MutableStateFlow<Long?>(null)
    private val _refreshing = MutableStateFlow(false)
    private val lock = Any()
    private var visible = false
    private var loop: Job? = null
    private var running: Job? = null
    private var dirty = false
    private var manualPending = false

    /** Number of times [action] was started (for tests/diagnostics). */
    @Volatile var runs = 0
        private set

    init {
        scope.launch { events.collect { if (visible) trigger() } }
    }

    fun setVisible(v: Boolean): Unit = synchronized(lock) {
        if (v == visible) return
        visible = v
        loop?.cancel()
        loop = null
        if (v) {
            loop = scope.launch {
                while (true) {
                    trigger()
                    // re-evaluated every tick so a socket going up/down changes the cadence at once
                    var waited = 0L
                    while (true) {
                        val target = PollingPolicy.intervalMs(intervalMs, live?.value == true)
                        if (waited >= target) break
                        val tick = minOf(1_000L, target - waited)
                        delay(tick)
                        waited += tick
                    }
                }
            }
        }
    }

    /** Starts a refresh unless one is already running (then schedules one follow-up run). */
    fun trigger(manual: Boolean = false): Unit = synchronized(lock) {
        if (manual) { manualPending = true; _refreshing.value = true }
        if (running?.isActive == true) { dirty = true; return }
        running = scope.launch {
            do {
                synchronized(lock) { dirty = false }
                runs++
                try {
                    action()
                    _lastUpdated.value = clock()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    // quiet: the action reports its own user-visible errors when it chooses to
                }
                val again = synchronized(lock) {
                    if (!dirty) { running = null; if (manualPending) { manualPending = false; _refreshing.value = false } }
                    dirty
                }
            } while (again)
        }
    }
}

object UpdatedFormat {
    private val fmt = DateTimeFormatter.ofPattern("HH:mm:ss")

    /** "Cập nhật lúc 14:05:09", or null before the first successful refresh. */
    fun label(epochMillis: Long?, zone: ZoneId = ZoneId.systemDefault()): String? =
        epochMillis?.let { "Cập nhật lúc " + fmt.format(Instant.ofEpochMilli(it).atZone(zone)) }
}

object RefreshIntervals {
    const val OVERVIEW_MS = 10_000L
    const val DEFAULT_MS = 20_000L
}
