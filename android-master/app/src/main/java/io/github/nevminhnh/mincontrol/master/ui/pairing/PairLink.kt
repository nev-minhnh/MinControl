package io.github.nevminhnh.mincontrol.master.ui.pairing

import kotlinx.coroutines.flow.MutableStateFlow
import java.net.URI
import java.net.URLDecoder

/** Parsed `mincontrol://pair?v=1|2&c=<claimId>&f=<12 hex>[&u=<server URL, v2>]` (API.md 10/12). [fp] is normalised: 12 upper-case hex chars. */
data class PairPayload(val claimId: String, val fp: String, val serverUrl: String? = null, val version: Int = 1)

object PairLink {
    /** Pending payload from a deep link or scan; consumed by PairingScreen. */
    val pending = MutableStateFlow<PairPayload?>(null)

    /** Set by the first-run flow after register-with-claim; consumed by PairingScreen to go on to "choose users". */
    val afterRegister = MutableStateFlow<AfterRegister?>(null)

    private val CLAIM_ID = Regex("^[A-Za-z0-9_-]{16,64}$")

    fun parse(link: String?): PairPayload? {
        if (link.isNullOrBlank()) return null
        val uri = runCatching { URI(link.trim()) }.getOrNull() ?: return null
        if (!uri.scheme.equals("mincontrol", ignoreCase = true) || !uri.host.equals("pair", ignoreCase = true)) return null
        val params = (uri.rawQuery ?: return null).split('&').mapNotNull { kv ->
            val i = kv.indexOf('=')
            if (i <= 0) null else kv.substring(0, i) to runCatching { URLDecoder.decode(kv.substring(i + 1), "UTF-8") }.getOrNull()
        }.toMap()
        val v = params["v"]?.toIntOrNull()
        if (v != 1 && v != 2) return null
        val c = params["c"]?.trim().orEmpty()
        val f = Fingerprint.normalize(params["f"])
        if (!CLAIM_ID.matches(c) || f == null) return null
        val u = params["u"]?.trim()?.trimEnd('/')?.takeIf { v == 2 && (it.startsWith("https://") || it.startsWith("http://")) }
        return PairPayload(c, f, u, v)
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

/** First-run registration finished: continue with the approved claim's device. */
data class AfterRegister(val claimId: String, val deviceId: String, val fp: String? = null)

/** Where the first run goes after register-with-claim (which already approved the claim: no second scan, ever). */
sealed interface ResumeStep {
    data class ChooseUsers(val device: io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo) : ResumeStep
    /** The device row is not visible yet (or the network failed): show "Thử lại", never the scan screen. */
    data class Retry(val message: String) : ResumeStep
}

/**
 * Root cause of the old double scan: after register-with-claim the claim is already approved, so
 * `GET /v1/master/claims/<id>` answers `410 already_approved`; the old code treated that as an error and fell back
 * to the "Thêm máy tính" home stage, which asks to scan again. The device list is the source of truth instead.
 */
object FirstRunResume {
    const val RETRY_MESSAGE = "Máy tính đã được ghép nối. Chưa tải được danh sách tài khoản của máy — kiểm tra mạng rồi bấm Thử lại."

    fun step(a: AfterRegister, devices: List<io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo>?): ResumeStep =
        devices?.firstOrNull { it.deviceId == a.deviceId }?.let { ResumeStep.ChooseUsers(it) } ?: ResumeStep.Retry(RETRY_MESSAGE)
}

/** What the app does with a scanned/opened `mincontrol://pair` link (API.md 12). */
sealed interface PairRoute {
    /** Phone already set up: show the 10 confirmation (approve with the sign key). */
    data object Approve : PairRoute
    /** Phone not set up, link has the server URL: show fingerprint check, then register-with-claim. */
    data class FirstRun(val serverUrl: String) : PairRoute
    /** Phone not set up and the link is v1 / has no `u`: the PC installer is too old. */
    data object UpdateInstaller : PairRoute
}

object PairRouting {
    fun route(registered: Boolean, p: PairPayload): PairRoute = when {
        registered -> PairRoute.Approve
        p.serverUrl != null -> PairRoute.FirstRun(p.serverUrl)
        else -> PairRoute.UpdateInstaller
    }

    const val UPDATE_INSTALLER_MESSAGE =
        "Mã QR này từ bản MinControl-Setup cũ nên chưa có địa chỉ máy chủ. Hãy cập nhật MinControl-Setup trên máy tính " +
            "lên bản mới nhất rồi quét lại mã QR."
}

/** Request construction for `POST /v1/master/register-with-claim` (API.md 12). */
object PairingRegister {
    fun signText(claimId: String): ByteArray = ("register|" + claimId).toByteArray(Charsets.UTF_8)

    fun request(
        claimId: String,
        keys: List<io.github.nevminhnh.mincontrol.master.data.protocol.RegisterKey>,
        sealPubKeyB64: String,
        sigB64: String,
    ) = io.github.nevminhnh.mincontrol.master.data.protocol.RegisterWithClaimRequest(claimId, keys, sealPubKeyB64, sigB64)

    /** True for the `409 master_exists` response (a master is already registered on the server). */
    fun isMasterExists(e: Throwable) =
        e is io.github.nevminhnh.mincontrol.master.data.api.ApiException.Http && e.status == 409 && e.code == "master_exists"
}
