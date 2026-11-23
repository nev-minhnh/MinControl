package io.github.nevminhnh.mincontrol.master.ui.overview

import android.app.Application
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.Weekday
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.util.toRfc3339
import io.github.nevminhnh.mincontrol.master.widget.WidgetUpdater
import io.github.nevminhnh.mincontrol.master.refresh.AutoRefresher
import io.github.nevminhnh.mincontrol.master.refresh.RefreshIntervals
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.LocalDate

class OverviewViewModel(app: Application) : AndroidViewModel(app) {
    private val graph = app.graph
    private val repo = graph.repo

    val parentName: String get() = graph.settings.parentName
    val children: StateFlow<List<Child>> = repo.children.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val alertCount: StateFlow<Int> = repo.alerts.map { l -> l.count { !it.acked } }.stateIn(viewModelScope, SharingStarted.Eagerly, 0)
    val policies = MutableStateFlow<Map<String, Policy>>(emptyMap())
    val message = MutableStateFlow<String?>(null)
    val refreshing = MutableStateFlow(false)
    val pending = MutableStateFlow<Set<String>>(emptySet())

    /** Resume + every 10 s while visible + FCM alert + pull-to-refresh. */
    val refresher = AutoRefresher(viewModelScope, RefreshIntervals.OVERVIEW_MS, live = graph.live.healthy) { load(quiet = true) }

    fun refresh(quiet: Boolean = false) = viewModelScope.launch { load(quiet) }

    private suspend fun load(quiet: Boolean) {
        if (!quiet) refreshing.value = true
        try {
            val devices = repo.refreshDevices()
            runCatching { repo.refreshAlerts() }
            val map = policies.value.toMutableMap()
            for (d in devices) runCatching { repo.loadPolicy(d.deviceId).policy }.getOrNull()?.let { map[d.deviceId] = it }
            policies.value = map
            WidgetUpdater.update(getApplication())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (!quiet) message.value = e.userMessage()
            else throw e
        } finally {
            refreshing.value = false
        }
    }

    fun quotaToday(child: Child): Int? =
        policies.value[child.deviceId]?.users?.get(child.sid)?.screenTime?.dailyQuotaMin?.get(Weekday.of(LocalDate.now().dayOfWeek))

    fun graceSec(child: Child): Int = policies.value[child.deviceId]?.users?.get(child.sid)?.screenTime?.graceSec ?: 60

    /** End of today's last allowed window ("21:00"), or null. */
    fun bedtime(child: Child): String? {
        val w = policies.value[child.deviceId]?.users?.get(child.sid)?.screenTime?.allowedWindows?.get(Weekday.of(LocalDate.now().dayOfWeek))
        return w?.lastOrNull()?.substringAfter('-')
    }

    fun addTime(activity: FragmentActivity, child: Child, minutes: Int) = viewModelScope.launch {
        pending.value = pending.value + child.sid
        try {
            val cmd = Command.AddTime(repo.newCommandId(), child.sid, minutes)
            val r = repo.sendCommand(activity, child.deviceId, cmd, "Thêm $minutes phút cho ${child.label}", child.hostname)
            message.value = if (r.delivered) "Đã thêm $minutes phút cho ${child.label}." else "Đã gửi: +$minutes phút, sẽ áp dụng khi máy online."
            refresh(quiet = true)
        } catch (e: BiometricCancelledException) {
        } catch (e: Exception) {
            message.value = e.userMessage()
        } finally {
            pending.value = pending.value - child.sid
        }
    }

    /** Returns `delivered`. Throws on failure (the sheet shows the message). */
    suspend fun lock(activity: FragmentActivity, child: Child, until: Instant?): Boolean {
        val cmd = Command.LockNow(repo.newCommandId(), child.sid, until?.toRfc3339())
        val r = repo.sendCommand(activity, child.deviceId, cmd, "Khóa máy của ${child.label}", child.hostname)
        refresh(quiet = true)
        return r.delivered
    }

    /** Direct unlock from the card (biometric prompt is the confirmation). */
    fun unlockNow(activity: FragmentActivity, child: Child) = viewModelScope.launch {
        pending.value = pending.value + child.sid
        try { unlock(activity, child) }
        catch (e: BiometricCancelledException) { }
        catch (e: Exception) { message.value = e.userMessage() }
        finally { pending.value = pending.value - child.sid }
    }

    suspend fun unlock(activity: FragmentActivity, child: Child) {
        val cmd = Command.Unlock(repo.newCommandId(), child.sid)
        repo.sendCommand(activity, child.deviceId, cmd, "Mở khóa cho ${child.label}", child.hostname)
        message.value = "Đã gửi lệnh mở khóa."
        refresh(quiet = true)
    }

    fun select(child: Child) { graph.selectedChild.value = child.key }
}
