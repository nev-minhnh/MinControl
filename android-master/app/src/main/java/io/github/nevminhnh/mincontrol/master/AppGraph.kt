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
    val repo = Repository(api, db, keys, sealKeys, SeqAllocator(PrefsSeqStore(appContext)), signer)
    val push = PushRegistrar(this)

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
        if (graph.settings.registered.value) graph.push.syncToken()
    }
}

val Context.graph: AppGraph get() = (applicationContext as MinControlApplication).graph
