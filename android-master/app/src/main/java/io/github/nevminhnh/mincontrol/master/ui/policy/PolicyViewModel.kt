package io.github.nevminhnh.mincontrol.master.ui.policy

import android.app.Application
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.policy.PolicyChange
import io.github.nevminhnh.mincontrol.master.policy.PolicyDefaults
import io.github.nevminhnh.mincontrol.master.policy.PolicyDiff
import io.github.nevminhnh.mincontrol.master.policy.PolicyValidation
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.ui.pick
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** Editing state for one device policy. */
data class PolicyDraft(val deviceId: String, val original: Policy?, val draft: Policy)

class PolicyViewModel(app: Application) : AndroidViewModel(app) {
    private val graph = app.graph
    private val repo = graph.repo

    val children: StateFlow<List<Child>> = repo.children.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val child: StateFlow<Child?> = combine(repo.children, graph.selectedChild) { l, k -> l.pick(k) }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)
    private val drafts = MutableStateFlow<Map<String, PolicyDraft>>(emptyMap())
    val loading = MutableStateFlow(false)
    val applying = MutableStateFlow(false)
    val message = MutableStateFlow<String?>(null)

    val current: StateFlow<PolicyDraft?> = combine(child, drafts) { c, d -> c?.let { d[it.deviceId] } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    val changes: StateFlow<List<PolicyChange>> = current.map { d -> d?.let { PolicyDiff.diff(it.original, it.draft) }.orEmpty() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    init {
        viewModelScope.launch {
            child.map { it?.deviceId }.distinctUntilChanged().collect { id -> if (id != null && id !in drafts.value) load(id) }
        }
    }

    fun select(c: Child) { graph.selectedChild.value = c.key }

    fun reload() { child.value?.deviceId?.let { load(it) } }

    private fun load(deviceId: String) = viewModelScope.launch {
        loading.value = true
        try {
            val loaded = repo.loadPolicy(deviceId)
            val original = loaded.policy
            val draft = original ?: run {
                val managed = children.value.filter { it.deviceId == deviceId }.associate { it.sid to it.label }
                PolicyDefaults.policy(managed, version = 1)
            }
            drafts.value = drafts.value + (deviceId to PolicyDraft(deviceId, original, draft))
        } catch (e: Exception) {
            message.value = e.userMessage()
        } finally {
            loading.value = false
        }
    }

    /** Applies [f] to the selected child's user policy in the draft. */
    fun edit(f: (UserPolicy) -> UserPolicy) {
        val c = child.value ?: return
        val d = drafts.value[c.deviceId] ?: return
        val up = d.draft.users[c.sid] ?: return
        drafts.value = drafts.value + (c.deviceId to d.copy(draft = d.draft.copy(users = d.draft.users + (c.sid to f(up)))))
    }

    fun discard() {
        val c = child.value ?: return
        val d = drafts.value[c.deviceId] ?: return
        d.original?.let { drafts.value = drafts.value + (c.deviceId to d.copy(draft = it)) }
    }

    fun errors(): List<String> = current.value?.let { PolicyValidation.errors(it.draft) }.orEmpty()

    /** Signs the draft as version original+1 and PUTs it. */
    fun apply(activity: FragmentActivity, onDone: () -> Unit) = viewModelScope.launch {
        val c = child.value ?: return@launch
        val d = drafts.value[c.deviceId] ?: return@launch
        val errs = PolicyValidation.errors(d.draft)
        if (errs.isNotEmpty()) { message.value = errs.first(); return@launch }
        applying.value = true
        try {
            val serverVersion = runCatching { repo.loadPolicy(c.deviceId).response?.version }.getOrNull()
            val next = maxOf(d.original?.version ?: 0, serverVersion ?: 0) + 1
            val policy = d.draft.copy(version = next)
            val r = repo.applyPolicy(activity, c.deviceId, policy, "Áp dụng quy tắc cho ${c.hostname}")
            drafts.value = drafts.value + (c.deviceId to PolicyDraft(c.deviceId, policy, policy))
            message.value = "Đã áp dụng quy tắc phiên bản ${r.version}."
            onDone()
        } catch (e: BiometricCancelledException) {
        } catch (e: Exception) {
            message.value = e.userMessage()
        } finally {
            applying.value = false
        }
    }
}
