package io.github.nevminhnh.mincontrol.master.data.protocol

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject

/**
 * Response/request bodies of protocol/API.md §4–§6. Responses are decoded leniently
 * (unknown keys ignored) so server additions do not break the phone.
 */
@OptIn(ExperimentalSerializationApi::class)
val ApiJson: Json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = true
    coerceInputValues = true
}

@Serializable
data class ApiErrorBody(val error: String = "unknown", val message: String? = null)

@Serializable
data class RegisterKey(val keyId: String, val alg: SigAlg, val publicKey: String, val role: String)

@Serializable
data class RegisterRequest(val bootstrapSecret: String, val keys: List<RegisterKey>, val sealPubKey: String)

@Serializable
data class PairingCode(val code: String, val expiresAt: String)

/** Local Windows account reported by the device in its pairing claim (API.md §10). */
@Serializable
data class ClaimUser(val sid: String = "", val name: String = "", val isAdmin: Boolean = false)

/** `GET /v1/master/claims/<id>` (and by-code, which also carries [claimId]). */
@Serializable
data class ClaimInfo(
    val hostname: String = "",
    val osVersion: String = "",
    val localUsers: List<ClaimUser> = emptyList(),
    val fp: String = "",
    val expiresAt: String? = null,
    val claimId: String? = null,
)

@Serializable
data class ApproveResponse(val deviceId: String)

@Serializable
data class GroupState(val usedMin: Int = 0, val remainingMin: Int? = null)

@Serializable
data class UserState(
    val sid: String,
    val loggedOn: Boolean = false,
    val active: Boolean = false,
    val locked: Boolean = false,
    val lockedUntil: String? = null,
    val remainingMin: Int? = null,
    val usedMin: Int = 0,
    val groups: Map<String, GroupState> = emptyMap(),
    val foregroundExe: String? = null,
    val foregroundTitle: String? = null,
    /** RFC3339 Z: when the current foreground app got focus (optional, API round 2). */
    val foregroundStartedAt: String? = null,
)

@Serializable
data class DeviceState(
    val ts: String,
    val agentVersion: String? = null,
    val policyVersion: Int? = null,
    val users: List<UserState> = emptyList(),
)

@Serializable
data class DeviceUser(
    val sid: String,
    val name: String,
    val isAdmin: Boolean = false,
    val managed: Boolean = false,
    val label: String? = null,
)

@Serializable
data class DeviceInfo(
    val deviceId: String,
    val hostname: String,
    val online: Boolean = false,
    val lastSeen: String? = null,
    val state: DeviceState? = null,
    val users: List<DeviceUser> = emptyList(),
    val policyVersion: Int? = null,
)

@Serializable
data class DeviceList(val items: List<DeviceInfo> = emptyList())

@Serializable
data class SeqResponse(val policy: Long = 0, val command: Long = 0)

@Serializable
data class PolicyResponse(val version: Int, val seq: Long, val envelope: SignedEnvelope)

@Serializable
data class PutPolicyResponse(val version: Int, val seq: Long)

@Serializable
data class CommandResponse(val commandId: String, val delivered: Boolean = false)

@Serializable
data class CommandStatus(val status: String, val error: String? = null)

@Serializable
data class EventItem(
    val id: String,
    val deviceId: String,
    val userSid: String? = null,
    val ts: String,
    val monoMs: Long = 0,
    val type: String,
    val data: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class Page<T>(val items: List<T> = emptyList(), val next: String? = null)

@Serializable
data class WebItem(
    val ts: String,
    val kind: String,
    val url: String? = null,
    val host: String? = null,
    val title: String? = null,
    val durationSec: Int? = null,
    val category: String? = null,
    /** `kind=search` only. */
    val query: String? = null,
    val engine: String? = null,
    /** `kind=blocked` only: doh, port, blocklist, allowlist_miss, schedule. */
    val reason: String? = null,
)

@Serializable
data class AppUsage(val exe: String, val group: String? = null, val activeSec: Int = 0)

@Serializable
data class UsageResponse(val totalSec: Int = 0, val apps: List<AppUsage> = emptyList())

@Serializable
data class ScreenshotItem(
    val eventId: String,
    val ts: String,
    val blobKey: String,
    val width: Int = 0,
    val height: Int = 0,
    val foregroundExe: String? = null,
)

@Serializable
data class AlertItem(
    val id: String,
    val deviceId: String,
    val userSid: String? = null,
    val ts: String,
    val type: String,
    val severity: String = "info",
    val data: JsonObject = JsonObject(emptyMap()),
    /** Server-side ack time (unix seconds or RFC3339, whatever the server sends); null = not acknowledged. */
    val ackedAt: JsonElement? = null,
) {
    val isAcked: Boolean get() = ackedAt != null && ackedAt !is JsonNull
}

@Serializable
data class PushSubscribe(val fcmToken: String)

/** FCM data message (API.md §6). */
data class PushAlert(
    val alertId: String?,
    val deviceId: String?,
    val userSid: String?,
    val severity: String,
    val title: String,
    val body: String,
)

/** `GET /v1/master/devices/:id/apps` (API.md §11). */
@Serializable
data class InventoryApp(
    val id: String,
    val name: String,
    val kind: String = "win32",
    val publisher: String? = null,
    val version: String? = null,
    val installDir: String? = null,
    val exe: String? = null,
    val exePath: String? = null,
    val lastUsed: String? = null,
    val minutes7d: Int? = null,
    val category: String? = null,
)

@Serializable
data class InventoryResponse(val generatedAt: String? = null, val apps: List<InventoryApp> = emptyList())
