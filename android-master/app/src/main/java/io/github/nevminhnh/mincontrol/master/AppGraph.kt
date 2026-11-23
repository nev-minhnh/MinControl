package io.github.nevminhnh.mincontrol.master

import android.app.Application
import android.content.Context
import io.github.nevminhnh.mincontrol.master.data.ChildKey
import io.github.nevminhnh.mincontrol.master.data.Repository
import io.github.nevminhnh.mincontrol.master.data.api.MasterApi
import io.github.nevminhnh.mincontrol.master.data.api.RequestSigner
import io.github.nevminhnh.mincontrol.master.data.db.CacheDb
import io.github.nevminhnh.mincontrol.master.envelope.PrefsSeqStore
import io.github.nevminhnh.mincontrol.master.envelope.SeqAllocator
import io.github.nevminhnh.mincontrol.master.push.Notifications
import io.github.nevminhnh.mincontrol.master.push.PushRegistrar
import io.github.nevminhnh.mincontrol.master.security.AndroidMasterKeyStore
import io.github.nevminhnh.mincontrol.master.security.BiometricSigner
import io.github.nevminhnh.mincontrol.master.security.KeyRole
import io.github.nevminhnh.mincontrol.master.security.SealKeyStore
import io.github.nevminhnh.mincontrol.master.security.SecurePrefs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/** App settings kept in [SecurePrefs] (server URL is sensitive enough: it names the Worker). */
class Settings(private val prefs: SecurePrefs) {
    private val _registered = MutableStateFlow(prefs.getString(K_REGISTERED) == "1")
    val registered: StateFlow<Boolean> = _registered.asStateFlow()

    var serverUrl: String?
        get() = prefs.getString(K_SERVER)
        set(v) = prefs.putString(K_SERVER, v)

    var parentName: String
        get() = prefs.getString(K_NAME) ?: "Bố/Mẹ"
        set(v) = prefs.putString(K_NAME, v)

    var fcmTokenSent: String?
        get() = prefs.getString(K_FCM)
        set(v) = prefs.putString(K_FCM, v)

    fun setRegistered(v: Boolean) {
        prefs.putString(K_REGISTERED, if (v) "1" else null)
        _registered.value = v
    }

    private companion object {
        const val K_SERVER = "server_url"
        const val K_NAME = "parent_name"
        const val K_REGISTERED = "registered"
        const val K_FCM = "fcm_token_sent"
    }
}

/** Manual dependency graph (no DI framework). */
class AppGraph(context: Context) {
    val appContext: Context = context.applicationContext
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val securePrefs = SecurePrefs(appContext)
    val settings = Settings(securePrefs)
    val keys = AndroidMasterKeyStore(appContext)
    val sealKeys = SealKeyStore(securePrefs)
    val db = CacheDb.create(appContext)
    val api = MasterApi(
        baseUrl = { settings.serverUrl },
        signer = RequestSigner { data -> keys.publicKey(KeyRole.READ).keyId to keys.signRead(data) },
    )
    val signer = BiometricSigner(keys)
    private val seqAllocator = SeqAllocator(PrefsSeqStore(appContext))
    val repo = Repository(api, db, keys, sealKeys, seqAllocator, signer)
    val transfers = io.github.nevminhnh.mincontrol.master.transfer.TransferManager(
        api, repo, db, keys, sealKeys, seqAllocator, signer, settings, securePrefs,
    )
    val push = PushRegistrar(this)

    /** API.md 15: foreground-only realtime sockets. */
    val live = io.github.nevminhnh.mincontrol.master.live.LiveHub(
        scope, io.github.nevminhnh.mincontrol.master.live.OkLiveConnector(api),
        sink = { repo.applyLive(it) },
        onAlertEvent = { scope.launch { runCatching { repo.refreshAlerts() } } },
    )

    /** Child selected on the overview (drives the Activity and Rules tabs). */
    val selectedChild = MutableStateFlow<ChildKey?>(null)
}

class MinControlApplication : Application() {
    lateinit var graph: AppGraph
        private set

    override fun onCreate() {
        super.onCreate()
        graph = AppGraph(this)
        Notifications.createChannels(this)
        // A transfer that wiped the keys but died before leaving the screen: back to first-run.
        if (graph.settings.registered.value && !runCatching { graph.keys.hasKeys() }.getOrDefault(true)) graph.settings.setRegistered(false)
        if (graph.settings.registered.value) graph.push.syncToken()
        // API.md 15: live sockets only while the app is in the foreground and a phone is registered.
        graph.scope.launch {
            combine(graph.repo.devices, graph.settings.registered) { d, reg -> if (reg) d.map { it.deviceId }.toSet() else emptySet() }
                .collect { graph.live.setDevices(it) }
        }
        androidx.lifecycle.ProcessLifecycleOwner.get().lifecycle.addObserver(androidx.lifecycle.LifecycleEventObserver { _, e ->
            when (e) {
                androidx.lifecycle.Lifecycle.Event.ON_START -> graph.live.setForeground(true)
                androidx.lifecycle.Lifecycle.Event.ON_STOP -> graph.live.setForeground(false)
                else -> {}
            }
        })
    }
}

val Context.graph: AppGraph get() = (applicationContext as MinControlApplication).graph
