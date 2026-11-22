package io.github.nevminhnh.mincontrol.master.ui.setup

import kotlinx.coroutines.flow.MutableStateFlow
import java.net.URI
import java.net.URLDecoder

/** Parsed `mincontrol://setup?v=1&u=<url>&s=<secret>`. toString never exposes the secret. */
data class SetupPayload(val serverUrl: String, val secret: String) {
    override fun toString() = "SetupPayload(serverUrl=$serverUrl, secret=***)"
}

object SetupLink {
    /** Pending payload from a deep link or scan; consumed by SetupScreen. */
    val pending = MutableStateFlow<SetupPayload?>(null)

    /** Set after a successful registration so the app can jump to "Thêm máy tính" when nothing is enrolled. */
    @Volatile var justRegistered = false

    fun parse(link: String?): SetupPayload? {
        if (link.isNullOrBlank()) return null
        val uri = runCatching { URI(link.trim()) }.getOrNull() ?: return null
        if (!uri.scheme.equals("mincontrol", ignoreCase = true) || !uri.host.equals("setup", ignoreCase = true)) return null
        val q = uri.rawQuery ?: return null
        val params = q.split('&').mapNotNull { kv ->
            val i = kv.indexOf('=')
            if (i <= 0) null else kv.substring(0, i) to runCatching { URLDecoder.decode(kv.substring(i + 1), "UTF-8") }.getOrNull()
        }.toMap()
        if (params["v"] != "1") return null
        val url = params["u"]?.trim().orEmpty()
        val secret = params["s"].orEmpty()
        if (!(url.startsWith("https://") || url.startsWith("http://")) || secret.isBlank()) return null
        return SetupPayload(url, secret)
    }
}
