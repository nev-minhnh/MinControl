package io.github.nevminhnh.mincontrol.master.live

import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** One open live socket. */
interface LiveSocket { fun close() }

interface LiveListener {
    fun onOpen()
    fun onMessage(text: String)
    /** Closed or failed - the hub reconnects after a backoff. */
    fun onClosed()
}

/** Opens a socket to `/v1/master/live?deviceId=` (OkHttp in production, a fake in tests). May throw. */
fun interface LiveConnector { fun connect(deviceId: String, listener: LiveListener): LiveSocket }

/**
 * Foreground-only realtime hub (API.md section 15): one socket per enrolled device with reconnect backoff.
 * State and online frames go to [sink] (writes the device cache, so every screen updates); events are re-emitted on [events].
 */
class LiveHub(
    private val scope: CoroutineScope,
    private val connector: LiveConnector,
    private val sink: suspend (LiveMessage) -> Unit = {},
    private val onAlertEvent: () -> Unit = {},
    private val backoffFactory: () -> ReconnectBackoff = { ReconnectBackoff() },
) {
    private val _connected = MutableStateFlow<Set<String>>(emptySet())
    /** Device ids whose socket is currently open. */
    val connected: StateFlow<Set<String>> = _connected.asStateFlow()
    /** True while at least one socket is open: shows the "Truc tiep" dot and slows polling to 60 s. */
    val healthy: StateFlow<Boolean> = _connected.map { it.isNotEmpty() }.stateIn(scope, SharingStarted.Eagerly, false)

    private val _online = MutableStateFlow<Map<String, Boolean>>(emptyMap())
    val online: StateFlow<Map<String, Boolean>> = _online.asStateFlow()
    private val _states = MutableStateFlow<Map<String, DeviceState>>(emptyMap())
    val states: StateFlow<Map<String, DeviceState>> = _states.asStateFlow()
    private val _events = MutableSharedFlow<LiveMessage.Events>(extraBufferCapacity = 64)
    val events: SharedFlow<LiveMessage.Events> = _events.asSharedFlow()

    private val lock = Any()
    private var foreground = false
    private var wanted: Set<String> = emptySet()
    private val jobs = HashMap<String, Job>()

    fun setForeground(v: Boolean) { synchronized(lock) { foreground = v; reconcile() } }
    fun setDevices(ids: Set<String>) { synchronized(lock) { wanted = ids; reconcile() } }

    private fun reconcile() {
        val target = if (foreground) wanted else emptySet()
        for (id in jobs.keys.toList()) if (id !in target) { jobs.remove(id)?.cancel(); setConnected(id, false) }
        for (id in target) if (id !in jobs) jobs[id] = scope.launch { run(id) }
    }

    private fun setConnected(id: String, up: Boolean) {
        _connected.value = if (up) _connected.value + id else _connected.value - id
    }

    private suspend fun run(id: String) {
        val backoff = backoffFactory()
        while (true) {
            val closed = CompletableDeferred<Unit>()
            val socket = try {
                connector.connect(id, object : LiveListener {
                    override fun onOpen() { backoff.reset(); setConnected(id, true) }
                    override fun onMessage(text: String) { handle(text) }
                    override fun onClosed() { closed.complete(Unit) }
                })
            } catch (e: Exception) { null }
            if (socket != null) {
                try { closed.await() } finally { runCatching { socket.close() }; setConnected(id, false) }
            }
            delay(backoff.nextDelayMs())
        }
    }

    private fun handle(text: String) {
        val m = LiveParser.parse(text) ?: return
        when (m) {
            is LiveMessage.State -> _states.value = _states.value + (m.deviceId to m.state)
            is LiveMessage.Online -> _online.value = _online.value + (m.deviceId to m.online)
            is LiveMessage.Events -> {
                if (m.events.isEmpty()) return
                _events.tryEmit(m)
                if (m.events.any { LiveMerge.isAlertEvent(it.type) }) onAlertEvent()
            }
        }
        if (m !is LiveMessage.Events) scope.launch { runCatching { sink(m) } }
    }
}
