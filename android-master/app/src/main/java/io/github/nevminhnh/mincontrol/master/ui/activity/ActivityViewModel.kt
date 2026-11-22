package io.github.nevminhnh.mincontrol.master.ui.activity

import android.app.Application
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.Decision
import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.ScreenshotItem
import io.github.nevminhnh.mincontrol.master.data.protocol.UsageResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.WebItem
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import io.github.nevminhnh.mincontrol.master.ui.alerts.AlertCard
import io.github.nevminhnh.mincontrol.master.ui.alerts.AlertsViewModel
import io.github.nevminhnh.mincontrol.master.ui.pick
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.time.LocalDate

enum class ActivityTab(val label: String) { Timeline("Dòng TG"), Web("Web"), Apps("Ứng dụng"), Shots("Ảnh") }

enum class WebFilter(val label: String, val kind: String?) { ALL("Tất cả", null), BLOCKED("Bị chặn", "blocked"), SEARCH("Tìm kiếm", "search") }

/** Server-side noise filter for the timeline (API round 2: comma list / `prefix.*`). */
const val TIMELINE_EXCLUDE = "usage.tick,net.domain"

class ActivityViewModel(app: Application) : AndroidViewModel(app) {
    private val graph = app.graph
    private val repo = graph.repo

    val children: StateFlow<List<Child>> = repo.children.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val child: StateFlow<Child?> = combine(repo.children, graph.selectedChild) { list, key -> list.pick(key) }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)
    val date = MutableStateFlow(LocalDate.now())
    val tab = MutableStateFlow(ActivityTab.Timeline)
    val message = MutableStateFlow<String?>(null)
    val loading = MutableStateFlow(false)

    // timeline
    val events = MutableStateFlow<List<EventItem>>(emptyList())
    val usage = MutableStateFlow<UsageResponse?>(null)
    val policy = MutableStateFlow<Policy?>(null)

    // web
    val webQuery = MutableStateFlow("")
    val webFilter = MutableStateFlow(WebFilter.ALL)
    val webItems = MutableStateFlow<List<WebItem>>(emptyList())
    private var webNext: String? = null
    val webHasMore = MutableStateFlow(false)
    private var webJob: Job? = null

    // apps
    val pendingApprovals: StateFlow<List<AlertCard>> = combine(repo.alerts, repo.children, child) { alerts, kids, c ->
        alerts.filter { !it.acked && it.item.type == "request.exe_approval" && it.item.deviceId == c?.deviceId && it.item.userSid == c?.sid }
            .map { AlertsViewModel.toCard(it, kids) }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val busy = MutableStateFlow<Set<String>>(emptySet())

    // screenshots
    val shots = MutableStateFlow<List<ScreenshotItem>>(emptyList())
    private var shotsNext: String? = null
    val shotsHasMore = MutableStateFlow(false)
    val decrypted = MutableStateFlow<Map<String, Bitmap>>(emptyMap())
    val decrypting = MutableStateFlow<Set<String>>(emptySet())

    init {
        viewModelScope.launch {
            combine(child.map { it?.key }.distinctUntilChanged(), date) { k, d -> k to d }.collect { reloadAll() }
        }
    }

    fun select(c: Child) { graph.selectedChild.value = c.key }

    fun reloadAll() {
        events.value = emptyList(); usage.value = null; webItems.value = emptyList(); shots.value = emptyList()
        loadTimeline(); loadWeb(reset = true); loadShots(reset = true)
    }

    fun loadTimeline() = viewModelScope.launch {
        val c = child.value ?: return@launch
        val d = date.value
        loading.value = true
        try {
            policy.value = runCatching { repo.loadPolicy(c.deviceId, preferCache = true).policy }.getOrNull()
            usage.value = runCatching { repo.usage(c.deviceId, c.sid, d.toString()) }.getOrNull()
            val all = mutableListOf<EventItem>()
            var cursor: String? = null
            for (i in 0 until 5) {
                val page = repo.events(c.deviceId, c.sid, Fmt.dayStart(d), Fmt.dayEnd(d), cursor, exclude = TIMELINE_EXCLUDE)
                all += page.items
                cursor = page.next ?: break
            }
            events.value = all
        } catch (e: Exception) {
            message.value = e.userMessage()
        } finally {
            loading.value = false
        }
    }

    fun setWebQuery(q: String) {
        webQuery.value = q
        webJob?.cancel()
        webJob = viewModelScope.launch { delay(350); loadWebNow(reset = true) }
    }

    fun setWebFilter(f: WebFilter) { webFilter.value = f; loadWeb(reset = true) }

    fun loadWeb(reset: Boolean = false) {
        webJob?.cancel()
        webJob = viewModelScope.launch { loadWebNow(reset) }
    }

    private suspend fun loadWebNow(reset: Boolean) {
        val c = child.value ?: return
        val d = date.value
        if (!reset && webNext == null) return
        try {
            val page = repo.web(c.deviceId, c.sid, Fmt.dayStart(d), Fmt.dayEnd(d), webQuery.value, webFilter.value.kind, if (reset) null else webNext)
            webItems.value = if (reset) page.items else webItems.value + page.items
            webNext = page.next
            webHasMore.value = page.next != null
        } catch (e: Exception) {
            if (reset) webItems.value = emptyList()
            message.value = e.userMessage()
        }
    }

    fun loadShots(reset: Boolean = false) = viewModelScope.launch {
        val c = child.value ?: return@launch
        val d = date.value
        if (!reset && shotsNext == null) return@launch
        try {
            val page = repo.screenshots(c.deviceId, c.sid, Fmt.dayStart(d), Fmt.dayEnd(d), if (reset) null else shotsNext)
            shots.value = if (reset) page.items else shots.value + page.items
            shotsNext = page.next
            shotsHasMore.value = page.next != null
        } catch (e: Exception) {
            message.value = e.userMessage()
        }
    }

    fun decrypt(item: ScreenshotItem) = viewModelScope.launch {
        if (item.eventId in decrypted.value || item.eventId in decrypting.value) return@launch
        decrypting.value = decrypting.value + item.eventId
        try {
            val jpeg = repo.decryptScreenshot(item.blobKey)
            val bmp = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size) ?: error("Ảnh hỏng")
            decrypted.value = decrypted.value + (item.eventId to bmp)
        } catch (e: Exception) {
            message.value = "Không giải mã được ảnh: ${e.userMessage()}"
        } finally {
            decrypting.value = decrypting.value - item.eventId
        }
    }

    fun captureNow(activity: FragmentActivity) = viewModelScope.launch {
        val c = child.value ?: return@launch
        try {
            val r = repo.sendCommand(activity, c.deviceId, Command.Screenshot(repo.newCommandId(), c.sid), "Chụp màn hình của ${c.label}", c.hostname)
            message.value = if (r.delivered) "Đã yêu cầu chụp, ảnh sẽ xuất hiện sau ít giây." else "Máy đang offline, sẽ chụp khi online lại."
            delay(8_000)
            loadShots(reset = true)
        } catch (e: BiometricCancelledException) {
        } catch (e: Exception) {
            message.value = e.userMessage()
        }
    }

    fun decide(activity: FragmentActivity, card: AlertCard, allow: Boolean) = viewModelScope.launch {
        val item = card.view.item
        val sid = item.userSid ?: return@launch
        val sha = card.sha256 ?: run { message.value = "Thiếu sha256 của ứng dụng."; return@launch }
        busy.value = busy.value + item.id
        try {
            val cmd = Command.ApproveExe(repo.newCommandId(), sid, sha, if (allow) Decision.ALLOW else Decision.BLOCK)
            repo.sendCommand(activity, item.deviceId, cmd, if (allow) "Cho phép ứng dụng" else "Chặn ứng dụng", card.body)
            repo.ackAlert(item.id)
        } catch (e: BiometricCancelledException) {
        } catch (e: Exception) {
            message.value = e.userMessage()
        } finally {
            busy.value = busy.value - item.id
        }
    }
}
