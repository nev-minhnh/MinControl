package io.github.nevminhnh.mincontrol.master.data.api

import io.github.nevminhnh.mincontrol.master.data.protocol.AlertItem
import io.github.nevminhnh.mincontrol.master.data.protocol.ApproveResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.ClaimInfo
import io.github.nevminhnh.mincontrol.master.data.protocol.CreateTransferResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferClaimRequest
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferClaimResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferCompleteRequest
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferStatus
import io.github.nevminhnh.mincontrol.master.data.protocol.InventoryResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.ApiErrorBody
import io.github.nevminhnh.mincontrol.master.data.protocol.ApiJson
import io.github.nevminhnh.mincontrol.master.data.protocol.CloudUsage
import io.github.nevminhnh.mincontrol.master.data.protocol.DomainsResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.MasterSettings
import io.github.nevminhnh.mincontrol.master.data.protocol.CommandResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.CommandStatus
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceList
import io.github.nevminhnh.mincontrol.master.data.protocol.EventItem
import io.github.nevminhnh.mincontrol.master.data.protocol.Page
import io.github.nevminhnh.mincontrol.master.data.protocol.PairingCode
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolJson
import io.github.nevminhnh.mincontrol.master.data.protocol.PushSubscribe
import io.github.nevminhnh.mincontrol.master.data.protocol.PutPolicyResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterRequest
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterWithClaimRequest
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterWithClaimResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.ScreenshotItem
import io.github.nevminhnh.mincontrol.master.data.protocol.SeqResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.SignedEnvelope
import io.github.nevminhnh.mincontrol.master.data.protocol.UsageResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.WebItem
import io.github.nevminhnh.mincontrol.master.util.B64Url
import io.github.nevminhnh.mincontrol.master.util.sha256
import io.github.nevminhnh.mincontrol.master.util.toHex
import io.github.nevminhnh.mincontrol.master.util.toRfc3339
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.time.Instant
import java.util.concurrent.TimeUnit

/** Typed failure of a master API call. */
sealed class ApiException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class Network(cause: IOException) : ApiException("network: ${cause.message}", cause)
    class Http(val status: Int, val code: String, val detail: String?) : ApiException("HTTP $status $code ${detail.orEmpty()}")
    class NotConfigured : ApiException("server not configured")
}

const val MASTER_EXISTS_MESSAGE =
    "Máy chủ đang có điện thoại quản lý khác. Dùng điện thoại đó để quét, hoặc gỡ MinControl trên các máy tính của con " +
        "(bằng tài khoản admin) rồi cài lại và quét lại."

const val RECOVERY_CODE_USED_MESSAGE = "Mã khôi phục đã được dùng. Tạo mã mới trên máy chủ."

/** Vietnamese text for a server error code; null when not specifically mapped. */
fun serverErrorMessage(code: String): String? = when (code) {
    "already_approved" -> "Máy này đã được duyệt rồi"
    "expired" -> "Mã đã hết hạn, hãy tạo mã mới trên máy tính"
    "rejected" -> "Máy này đã bị từ chối"
    "sign_key_required" -> "Điện thoại chưa có khóa ký, hãy thiết lập lại"
    "master_exists" -> MASTER_EXISTS_MESSAGE
    "recovery_code_used" -> RECOVERY_CODE_USED_MESSAGE
    "transfer_claimed", "already_claimed" -> "Mã chuyển máy đã được một điện thoại khác dùng. Tạo mã mới trên điện thoại cũ."
    "not_found" -> "Không tìm thấy mã này"
    "invalid_code" -> "Mã không đúng, hãy kiểm tra lại"
    else -> null
}

/** Vietnamese message for UI snackbars. */
fun Throwable.userMessage(): String = when (this) {
    is ApiException.Network -> "Không kết nối được máy chủ. Kiểm tra mạng rồi thử lại."
    is ApiException.Http -> when {
        serverErrorMessage(code) != null -> serverErrorMessage(code)!!
        status == 401 || code == "unauthorized" || code == "bad_auth" -> "Máy chủ từ chối chữ ký của điện thoại này."
        status == 404 -> "Không tìm thấy dữ liệu trên máy chủ."
        status == 409 || code == "stale_seq" -> "Số thứ tự lệnh đã cũ, hãy thử lại."
        status == 429 -> "Thao tác quá nhanh, hãy đợi một chút."
        status >= 500 -> "Máy chủ đang gặp lỗi ($status)."
        else -> "Có lỗi, thử lại"
    }
    is ApiException.NotConfigured -> "Chưa cấu hình máy chủ."
    is io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException -> "Đã hủy xác nhận."
    else -> message ?: "Lỗi không xác định"
}

/** Computes the `X-MC-Auth` header (API.md §4; ts = unix seconds, decimal). Pure so it is unit-testable. */
object AuthHeader {
    fun canonical(method: String, pathWithQuery: String, ts: String, body: ByteArray): String =
        method.uppercase() + "\n" + pathWithQuery + "\n" + ts + "\n" + sha256(body).toHex()

    fun pathWithQuery(url: HttpUrl): String = url.encodedPath + (url.encodedQuery?.let { "?$it" } ?: "")

    /** Canonical string of `POST /v1/master/claims/<claimId>/approve` (empty body) - signed by the `sign` key. */
    fun approveCanonical(claimId: String, ts: String): String =
        canonical("POST", "/v1/master/claims/$claimId/approve", ts, ByteArray(0))

    fun header(keyId: String, ts: String, signature: ByteArray) = "v1;$keyId;$ts;${B64Url.encode(signature)}"
}

/** Signs request headers with the non-biometric `read` key. */
fun interface RequestSigner {
    /** Returns keyId and the 64-byte signature. */
    fun sign(data: ByteArray): Pair<String, ByteArray>
}

/** Signs with the biometric `sign` key (suspends while the prompt is shown). Returns keyId and 64-byte signature. */
fun interface SignRoleSigner {
    suspend fun sign(data: ByteArray): Pair<String, ByteArray>
}

/**
 * OkHttp client for every endpoint of API.md §5. All calls run on [Dispatchers.IO].
 * [baseUrl] is read lazily so the server can be configured on first run.
 */
class MasterApi(
    private val baseUrl: () -> String?,
    private val signer: RequestSigner,
    private val clock: () -> Instant = Instant::now,
    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build(),
) {
    private val jsonType = "application/json; charset=utf-8".toMediaType()

    // --- §4 registration (unauthenticated) ---
    suspend fun register(server: String, req: RegisterRequest): Unit = withContext(Dispatchers.IO) {
        val body = ApiJson.encodeToString(RegisterRequest.serializer(), req).toByteArray()
        exec(build(server.trimEnd('/').toHttpUrl().newBuilder().addPathSegments("v1/master/register").build(), "POST", body, auth = false))
    }

    /** 12: first phone registers and approves the PC claim in one call (no X-MC-Auth). */
    suspend fun registerWithClaim(server: String, req: RegisterWithClaimRequest): RegisterWithClaimResponse = withContext(Dispatchers.IO) {
        val body = ApiJson.encodeToString(RegisterWithClaimRequest.serializer(), req).toByteArray()
        val url = server.trimEnd('/').toHttpUrl().newBuilder().addPathSegments("v1/master/register-with-claim").build()
        ApiJson.decodeFromString(RegisterWithClaimResponse.serializer(), exec(build(url, "POST", body, auth = false)).toString(Charsets.UTF_8))
    }

    // --- §5 endpoints ---
    suspend fun createPairingCode(): PairingCode = call("POST", "v1/master/pairing-codes", body = ByteArray(0), out = PairingCode.serializer())
    suspend fun devices(): DeviceList = call("GET", "v1/master/devices", out = DeviceList.serializer())
    /** "Xóa máy": removes the device and all of its history on the server (API.md §18). */
    suspend fun deleteDevice(id: String) { callUnit("DELETE", "v1/master/devices/$id") }
    suspend fun seq(id: String): SeqResponse = call("GET", "v1/master/devices/$id/seq", out = SeqResponse.serializer())

    /** null when the device has no policy yet (404). */
    suspend fun policy(id: String): PolicyResponse? = try {
        call("GET", "v1/master/devices/$id/policy", out = PolicyResponse.serializer())
    } catch (e: ApiException.Http) {
        if (e.status == 404) null else throw e
    }

    /** null when the device has not uploaded an inventory yet (404). */
    suspend fun apps(id: String, user: String): InventoryResponse? = try {
        call("GET", "v1/master/devices/$id/apps", listOf("user" to user), out = InventoryResponse.serializer())
    } catch (e: ApiException.Http) {
        if (e.status == 404) null else throw e
    }

    suspend fun putPolicy(id: String, env: SignedEnvelope): PutPolicyResponse =
        call("PUT", "v1/master/devices/$id/policy", body = envelopeBytes(env), out = PutPolicyResponse.serializer())

    suspend fun postCommand(id: String, env: SignedEnvelope): CommandResponse =
        call("POST", "v1/master/devices/$id/commands", body = envelopeBytes(env), out = CommandResponse.serializer())

    suspend fun commandStatus(id: String, commandId: String): CommandStatus =
        call("GET", "v1/master/devices/$id/commands/$commandId", out = CommandStatus.serializer())

    suspend fun events(
        id: String, type: String? = null, user: String? = null, from: Instant? = null, to: Instant? = null,
        cursor: String? = null, limit: Int = 200, exclude: String? = null,
    ): Page<EventItem> = call(
        "GET", "v1/master/devices/$id/events",
        query = listOf("type" to type, "exclude" to exclude, "user" to user, "from" to from?.toRfc3339(), "to" to to?.toRfc3339(),
            "cursor" to cursor, "limit" to limit.coerceAtMost(200).toString()),
        out = Page.serializer(EventItem.serializer()),
    )

    suspend fun domains(id: String, user: String?, day: String): DomainsResponse =
        call("GET", "v1/master/devices/$id/domains", query = listOf("user" to user, "day" to day), out = DomainsResponse.serializer())

    suspend fun settings(): MasterSettings = call("GET", "v1/master/settings", out = MasterSettings.serializer())

    suspend fun putSettings(s: MasterSettings): MasterSettings =
        call("PUT", "v1/master/settings", body = ApiJson.encodeToString(MasterSettings.serializer(), s).toByteArray(), out = MasterSettings.serializer())

    suspend fun cloudUsage(): CloudUsage = call("GET", "v1/master/usage", out = CloudUsage.serializer())

    suspend fun web(
        id: String, user: String? = null, from: Instant? = null, to: Instant? = null, q: String? = null,
        kind: String? = null, cursor: String? = null, limit: Int = 50,
    ): Page<WebItem> = call(
        "GET", "v1/master/devices/$id/web",
        query = listOf("user" to user, "from" to from?.toRfc3339(), "to" to to?.toRfc3339(), "q" to q,
            "kind" to kind, "cursor" to cursor, "limit" to limit.toString()),
        out = Page.serializer(WebItem.serializer()),
    )

    suspend fun usage(id: String, user: String?, day: String): UsageResponse =
        call("GET", "v1/master/devices/$id/usage", query = listOf("user" to user, "day" to day), out = UsageResponse.serializer())

    suspend fun screenshots(id: String, user: String?, from: Instant?, to: Instant?, cursor: String? = null): Page<ScreenshotItem> =
        call("GET", "v1/master/devices/$id/screenshots",
            query = listOf("user" to user, "from" to from?.toRfc3339(), "to" to to?.toRfc3339(), "cursor" to cursor),
            out = Page.serializer(ScreenshotItem.serializer()))

    suspend fun blob(key: String): ByteArray = withContext(Dispatchers.IO) {
        exec(build(url("v1/master/blobs/$key"), "GET", null, auth = true))
    }

    suspend fun alerts(cursor: String? = null, limit: Int = 100, unacked: Boolean = false, deviceId: String? = null): Page<AlertItem> =
        call("GET", "v1/master/alerts",
            query = listOf("cursor" to cursor, "limit" to limit.toString(), "unacked" to if (unacked) "1" else null, "deviceId" to deviceId),
            out = Page.serializer(AlertItem.serializer()))

    suspend fun ackAlert(id: String) { callUnit("POST", "v1/master/alerts/$id/ack", body = ByteArray(0)) }

    suspend fun subscribePush(token: String) {
        callUnit("POST", "v1/master/push/subscribe",
            body = ApiJson.encodeToString(PushSubscribe.serializer(), PushSubscribe(token)).toByteArray())
    }

    // --- §10 QR pairing initiated by the device ---
    suspend fun claim(claimId: String): ClaimInfo =
        call("GET", "v1/master/claims/${claimId.encodeSeg()}", out = ClaimInfo.serializer())

    suspend fun claimByCode(code: String): ClaimInfo =
        call("GET", "v1/master/claims/by-code/${code.encodeSeg()}", out = ClaimInfo.serializer())

    /** Approval MUST be authenticated with a `sign`-role key (biometric), unlike every other call. */
    suspend fun approveClaim(claimId: String, signWith: SignRoleSigner): ApproveResponse =
        ApiJson.decodeFromString(ApproveResponse.serializer(),
            signedPost(url("v1/master/claims/${claimId.encodeSeg()}/approve"), ByteArray(0), signWith).toString(Charsets.UTF_8))

    /** API.md §18 "Đặt lại toàn bộ": wipes everything on the server (sign-key auth). */
    suspend fun resetAll(signWith: SignRoleSigner) { signedPost(url("v1/master/reset"), ByteArray(0), signWith) }

    // --- §13 phone transfer ---
    /** Old phone: creates a transfer (sign-key auth). */
    suspend fun createTransfer(signWith: SignRoleSigner): CreateTransferResponse =
        ApiJson.decodeFromString(CreateTransferResponse.serializer(),
            signedPost(url("v1/master/transfers"), ByteArray(0), signWith).toString(Charsets.UTF_8))

    /** Both phones poll with their own read key (the new phone's keys work once the transfer is done). */
    suspend fun transferStatus(id: String): TransferStatus =
        call("GET", "v1/master/transfers/${id.encodeSeg()}", out = TransferStatus.serializer())

    /** New phone: claims the transfer (no auth; the body is signed instead). */
    suspend fun claimTransfer(server: String, req: TransferClaimRequest): TransferClaimResponse = withContext(Dispatchers.IO) {
        val body = ApiJson.encodeToString(TransferClaimRequest.serializer(), req).toByteArray()
        val url = server.trimEnd('/').toHttpUrl().newBuilder().addPathSegments("v1/master/transfers/claim").build()
        ApiJson.decodeFromString(TransferClaimResponse.serializer(), exec(build(url, "POST", body, auth = false)).toString(Charsets.UTF_8))
    }

    /** Old phone: completes the transfer (sign-key auth over the body). */
    suspend fun completeTransfer(id: String, req: TransferCompleteRequest, signWith: SignRoleSigner) {
        val body = ProtocolJson.encodeToString(TransferCompleteRequest.serializer(), req).toByteArray()
        signedPost(url("v1/master/transfers/${id.encodeSeg()}/complete"), body, signWith)
    }

    /** POST authenticated with the biometric `sign` key instead of the read key. */
    private suspend fun signedPost(url: HttpUrl, body: ByteArray, signWith: SignRoleSigner): ByteArray {
        val ts = clock().epochSecond.toString()
        val canon = AuthHeader.canonical("POST", AuthHeader.pathWithQuery(url), ts, body).toByteArray()
        val (keyId, sig) = signWith.sign(canon)
        return withContext(Dispatchers.IO) {
            val req = Request.Builder().url(url).method("POST", body.toRequestBody(jsonType))
                .header("X-MC-Auth", AuthHeader.header(keyId, ts, sig)).build()
            exec(req)
        }
    }

    suspend fun rejectClaim(claimId: String) { callUnit("POST", "v1/master/claims/${claimId.encodeSeg()}/reject", body = ByteArray(0)) }

    private fun String.encodeSeg(): String = java.net.URLEncoder.encode(this, "UTF-8").replace("+", "%20")

    // --- plumbing ---
    private fun envelopeBytes(env: SignedEnvelope) =
        ProtocolJson.encodeToString(SignedEnvelope.serializer(), env.copy(v = 1)).toByteArray()

    private fun url(path: String, query: List<Pair<String, String?>> = emptyList()): HttpUrl {
        val base = baseUrl()?.trimEnd('/') ?: throw ApiException.NotConfigured()
        return base.toHttpUrl().newBuilder().addPathSegments(path).apply {
            query.forEach { (k, v) -> if (v != null) addQueryParameter(k, v) }
        }.build()
    }

    private suspend fun <T> call(
        method: String, path: String, query: List<Pair<String, String?>> = emptyList(),
        body: ByteArray? = null, out: KSerializer<T>,
    ): T = withContext(Dispatchers.IO) {
        val bytes = exec(build(url(path, query), method, body, auth = true))
        ApiJson.decodeFromString(out, bytes.toString(Charsets.UTF_8))
    }

    private suspend fun callUnit(method: String, path: String, body: ByteArray? = null) = withContext(Dispatchers.IO) {
        exec(build(url(path), method, body, auth = true))
        Unit
    }

    private val liveHttp: OkHttpClient by lazy {
        http.newBuilder().pingInterval(25, TimeUnit.SECONDS).readTimeout(0, TimeUnit.SECONDS).build()
    }

    /** API.md 15: read-key signed WebSocket upgrade to `/v1/master/live?deviceId=`; a fresh signature per attempt. */
    fun openLive(deviceId: String, listener: okhttp3.WebSocketListener): okhttp3.WebSocket {
        val base = baseUrl()?.trimEnd('/') ?: throw ApiException.NotConfigured()
        val url = base.toHttpUrl().newBuilder().addPathSegments("v1/master/live").addQueryParameter("deviceId", deviceId).build()
        return liveHttp.newWebSocket(build(url, "GET", null, auth = true), listener)
    }

    private fun build(url: HttpUrl, method: String, body: ByteArray?, auth: Boolean): Request {
        val b = Request.Builder().url(url)
        val payload = body ?: ByteArray(0)
        when (method) {
            "GET" -> b.get()
            "DELETE" -> b.delete()
            else -> b.method(method, payload.toRequestBody(jsonType))
        }
        if (auth) {
            val ts = clock().epochSecond.toString()
            val (keyId, sig) = signer.sign(AuthHeader.canonical(method, AuthHeader.pathWithQuery(url), ts, payload).toByteArray())
            b.header("X-MC-Auth", AuthHeader.header(keyId, ts, sig))
        }
        return b.build()
    }

    private fun exec(req: Request): ByteArray {
        try {
            http.newCall(req).execute().use { resp ->
                val bytes = resp.body?.bytes() ?: ByteArray(0)
                if (!resp.isSuccessful) {
                    val err = runCatching { ApiJson.decodeFromString(ApiErrorBody.serializer(), bytes.toString(Charsets.UTF_8)) }.getOrNull()
                    throw ApiException.Http(resp.code, err?.error ?: "http_${resp.code}", err?.message)
                }
                return bytes
            }
        } catch (e: IOException) {
            throw ApiException.Network(e)
        }
    }
}
