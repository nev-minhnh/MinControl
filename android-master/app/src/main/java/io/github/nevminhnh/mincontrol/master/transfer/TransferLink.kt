package io.github.nevminhnh.mincontrol.master.transfer

import kotlinx.coroutines.flow.MutableStateFlow
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder

/** Parsed `mincontrol://transfer?v=1&u=<server URL>&t=<token>` (API.md 13). toString never exposes the token. */
data class TransferPayload(val serverUrl: String, val token: String) {
    override fun toString() = "TransferPayload(serverUrl=$serverUrl, token=***)"
}

object TransferLink {
    /** Pending payload from a deep link; consumed by the first-run screen. */
    val pending = MutableStateFlow<TransferPayload?>(null)

    /** token = base64url (no padding) of 32 random bytes = 43 chars; accept a little slack for future sizes. */
    private val TOKEN = Regex("^[A-Za-z0-9_-]{32,128}$")

    fun parse(link: String?): TransferPayload? {
        if (link.isNullOrBlank()) return null
        val uri = runCatching { URI(link.trim()) }.getOrNull() ?: return null
        if (!uri.scheme.equals("mincontrol", ignoreCase = true) || !uri.host.equals("transfer", ignoreCase = true)) return null
        val params = (uri.rawQuery ?: return null).split('&').mapNotNull { kv ->
            val i = kv.indexOf('=')
            if (i <= 0) null else kv.substring(0, i) to runCatching { URLDecoder.decode(kv.substring(i + 1), "UTF-8") }.getOrNull()
        }.toMap()
        if (params["v"] != "1") return null
        val url = params["u"]?.trim()?.trimEnd('/').orEmpty()
        val token = params["t"]?.trim().orEmpty()
        if (!(url.startsWith("https://") || url.startsWith("http://")) || url.length <= "https://".length) return null
        if (!TOKEN.matches(token)) return null
        return TransferPayload(url, token)
    }

    /** QR text shown by the old phone. */
    fun build(serverUrl: String, token: String): String =
        "mincontrol://transfer?v=1&u=" + URLEncoder.encode(serverUrl.trimEnd('/'), "UTF-8") + "&t=" + token
}
