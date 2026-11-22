package io.github.nevminhnh.mincontrol.master.ui.pairing

import kotlinx.coroutines.flow.MutableStateFlow
import java.net.URI
import java.net.URLDecoder

/** Parsed `mincontrol://pair?v=1&c=<claimId>&f=<12 hex>` (API.md §10). [fp] is normalised: 12 upper-case hex chars. */
data class PairPayload(val claimId: String, val fp: String)

object PairLink {
    /** Pending payload from a deep link or scan; consumed by PairingScreen. */
    val pending = MutableStateFlow<PairPayload?>(null)

    private val CLAIM_ID = Regex("^[A-Za-z0-9_-]{16,64}$")

    fun parse(link: String?): PairPayload? {
        if (link.isNullOrBlank()) return null
        val uri = runCatching { URI(link.trim()) }.getOrNull() ?: return null
        if (!uri.scheme.equals("mincontrol", ignoreCase = true) || !uri.host.equals("pair", ignoreCase = true)) return null
        val params = (uri.rawQuery ?: return null).split('&').mapNotNull { kv ->
            val i = kv.indexOf('=')
            if (i <= 0) null else kv.substring(0, i) to runCatching { URLDecoder.decode(kv.substring(i + 1), "UTF-8") }.getOrNull()
        }.toMap()
        if (params["v"] != "1") return null
        val c = params["c"]?.trim().orEmpty()
        val f = Fingerprint.normalize(params["f"])
        if (!CLAIM_ID.matches(c) || f == null) return null
        return PairPayload(c, f)
    }
}

/** Device-key fingerprint: first 12 hex chars of sha256(pubkey), shown as `XXXX-XXXX-XXXX`. */
object Fingerprint {
    private val HEX12 = Regex("^[0-9A-F]{12}$")

    /** Strips dashes/spaces, upper-cases; null unless exactly 12 hex chars. */
    fun normalize(raw: String?): String? =
        raw?.filterNot { it == '-' || it == ' ' || it == '·' }?.uppercase()?.takeIf { HEX12.matches(it) }

    fun format(raw: String?): String? = normalize(raw)?.chunked(4)?.joinToString("-")

    /** True only when both are valid fingerprints and equal (case/dash-insensitive). */
    fun matches(a: String?, b: String?): Boolean {
        val x = normalize(a) ?: return false
        return x == normalize(b)
    }
}

/** Manual 8-char Crockford base32 pairing code. */
object ClaimCode {
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /** Upper-cases, drops dashes/spaces, maps I/L->1 and O->0; null unless 8 valid chars. */
    fun normalize(raw: String?): String? {
        val s = raw?.filterNot { it == '-' || it == ' ' }?.uppercase()
            ?.map { when (it) { 'I', 'L' -> '1'; 'O' -> '0'; else -> it } }?.joinToString("") ?: return null
        return s.takeIf { it.length == 8 && it.all { c -> c in ALPHABET } }
    }
}
