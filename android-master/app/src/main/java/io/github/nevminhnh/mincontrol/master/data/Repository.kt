package io.github.nevminhnh.mincontrol.master.data

import androidx.fragment.app.FragmentActivity
import io.github.nevminhnh.mincontrol.master.data.api.MasterApi
import io.github.nevminhnh.mincontrol.master.data.db.AlertRow
import io.github.nevminhnh.mincontrol.master.data.db.CacheDb
import io.github.nevminhnh.mincontrol.master.data.db.DeviceRow
import io.github.nevminhnh.mincontrol.master.data.db.PolicyRow
import io.github.nevminhnh.mincontrol.master.data.db.WebRow
import io.github.nevminhnh.mincontrol.master.data.protocol.AlertItem
import io.github.nevminhnh.mincontrol.master.data.protocol.ApiJson
import io.github.nevminhnh.mincontrol.master.data.protocol.BodyKind
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.CommandResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo
import io.github.nevminhnh.mincontrol.master.data.protocol.Page
import io.github.nevminhnh.mincontrol.master.data.protocol.Policy
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.PutPolicyResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterKey
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterRequest
import io.github.nevminhnh.mincontrol.master.data.protocol.SignedEnvelope
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairingRegister
import io.github.nevminhnh.mincontrol.master.data.protocol.UserState
import io.github.nevminhnh.mincontrol.master.data.protocol.WebItem
import io.github.nevminhnh.mincontrol.master.envelope.EnvelopeBuilder
import io.github.nevminhnh.mincontrol.master.envelope.SeqAllocator
import io.github.nevminhnh.mincontrol.master.security.BiometricSigner
import io.github.nevminhnh.mincontrol.master.security.KeyRole
import io.github.nevminhnh.mincontrol.master.security.MasterKeyStore
import io.github.nevminhnh.mincontrol.master.security.SealKeyStore
import io.github.nevminhnh.mincontrol.master.util.B64Url
import io.github.nevminhnh.mincontrol.master.util.Ulid
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.time.Instant
import io.github.nevminhnh.mincontrol.master.ui.pairing.disambiguateHostnames

/** A managed Windows user on one PC = one "child card". */
data class Child(
    val deviceId: String,
    val hostname: String,
    val sid: String,
    val label: String,
    val online: Boolean,
    val lastSeen: String?,
    val state: UserState?,
) {
    val key get() = ChildKey(deviceId, sid)
}

data class ChildKey(val deviceId: String, val sid: String)

fun DeviceInfo.children(): List<Child> = users.filter { it.managed }.map { u ->
    Child(deviceId, hostname, u.sid, u.label ?: u.name, online, lastSeen, state?.users?.firstOrNull { it.sid == u.sid })
}

class Repository(
    private val api: MasterApi,
    private val db: CacheDb,
    private val keys: MasterKeyStore,
    private val sealKeys: SealKeyStore,
    private val seq: SeqAllocator,
    private val signer: BiometricSigner,
) {
    private val dao = db.dao()

    // ---------- registration ----------
    suspend fun register(server: String, bootstrapSecret: String) {
        withContext(Dispatchers.Default) { keys.ensureKeys() }
        val sealPk = sealKeys.ensureKey()
        val req = RegisterRequest(
            bootstrapSecret = bootstrapSecret,
            keys = KeyRole.entries.map { r ->
                val k = keys.publicKey(r)
                RegisterKey(keyId = k.keyId, alg = k.alg, publicKey = B64Url.encode(k.raw), role = r.wire)
            },
            sealPubKey = B64Url.encode(sealPk),
        )
        api.register(server, req)
    }

    /**
     * API.md 12: creates keys, signs `"register|"+claimId` with the biometric sign key and registers + approves the claim.
     * Returns the new deviceId.
     */
    suspend fun registerWithClaim(activity: FragmentActivity, server: String, claimId: String): String {
        withContext(Dispatchers.Default) { keys.ensureKeys() }
        val sealPk = sealKeys.ensureKey()
        val signed = signer.sign(activity, "Thiết lập MinControl", "Ghép điện thoại này với máy tính", PairingRegister.signText(claimId))
        val req = PairingRegister.request(
            claimId,
            KeyRole.entries.map { r ->
                val k = keys.publicKey(r)
                RegisterKey(keyId = k.keyId, alg = k.alg, publicKey = B64Url.encode(k.raw), role = r.wire)
            },
            B64Url.encode(sealPk), B64Url.encode(signed.signature),
        )
        return api.registerWithClaim(server, req).deviceId
    }

    // ---------- devices ----------
    val devices: Flow<List<DeviceInfo>> = dao.devicesFlow().map { rows ->
        rows.mapNotNull { runCatching { ApiJson.decodeFromString(DeviceInfo.serializer(), it.json) }.getOrNull() }
            .let { disambiguateHostnames(it) }
            .sortedBy { it.hostname }
    }

    val children: Flow<List<Child>> = devices.map { list -> list.flatMap { it.children() } }

    suspend fun refreshDevices(): List<DeviceInfo> {
        val list = api.devices().items
        val now = System.currentTimeMillis()
        dao.replaceDevices(list.map { DeviceRow(it.deviceId, ApiJson.encodeToString(DeviceInfo.serializer(), it), now) })
        return list
    }

    private val liveMutex = kotlinx.coroutines.sync.Mutex()

    /** API.md 15: a pushed `state` / `online` frame updates the cached device row, so every screen sees it at once. */
    suspend fun applyLive(msg: io.github.nevminhnh.mincontrol.master.live.LiveMessage) = liveMutex.withLock {
        val row = dao.devices().firstOrNull { it.deviceId == msg.deviceId } ?: return@withLock
        val cur = runCatching { ApiJson.decodeFromString(DeviceInfo.serializer(), row.json) }.getOrNull() ?: return@withLock
        val next = when (msg) {
            is io.github.nevminhnh.mincontrol.master.live.LiveMessage.State -> io.github.nevminhnh.mincontrol.master.live.LiveMerge.applyState(cur, msg.state)
            is io.github.nevminhnh.mincontrol.master.live.LiveMessage.Online -> io.github.nevminhnh.mincontrol.master.live.LiveMerge.applyOnline(cur, msg.online)
            else -> return@withLock
        }
        dao.putDevices(listOf(row.copy(json = ApiJson.encodeToString(DeviceInfo.serializer(), next))))
    }

    suspend fun cachedDevices(): List<DeviceInfo> =
        dao.devices().mapNotNull { runCatching { ApiJson.decodeFromString(DeviceInfo.serializer(), it.json) }.getOrNull() }

    suspend fun deleteDevice(deviceId: String) {
        api.deleteDevice(deviceId)
        refreshDevices()
    }

    /** "Đặt lại toàn bộ": `POST /v1/master/reset` signed with the biometric sign key. The caller wipes local data. */
    suspend fun resetAll(activity: FragmentActivity) {
        api.resetAll { data ->
            val s = signer.sign(activity, "Đặt lại toàn bộ MinControl", "Xóa mọi dữ liệu trên máy chủ", data)
            s.session.keyId to s.signature
        }
    }

    suspend fun createPairingCode() = api.createPairingCode()

    // ---------- QR pairing (API.md §10) ----------
    suspend fun claim(claimId: String) = api.claim(claimId)
    suspend fun claimByCode(code: String) = api.claimByCode(code)
    suspend fun rejectClaim(claimId: String) = api.rejectClaim(claimId)

    /** Approves a claim; the request is signed with the biometric `sign` key. Returns the new deviceId. */
    suspend fun approveClaim(activity: FragmentActivity, claimId: String, hostname: String): String =
        api.approveClaim(claimId) { data ->
            val s = signer.sign(activity, "Cho phép máy này", hostname, data)
            s.session.keyId to s.signature
        }.deviceId

    // ---------- signing ----------
    private suspend fun signEnvelope(activity: FragmentActivity, title: String, subtitle: String?, build: (Long) -> io.github.nevminhnh.mincontrol.master.data.protocol.SignedBody, kind: BodyKind, deviceId: String): SignedEnvelope {
        val serverSeq = api.seq(deviceId)
        val next = seq.next(deviceId, kind, if (kind == BodyKind.POLICY) serverSeq.policy else serverSeq.command)
        return EnvelopeBuilder.build(build(next)) { payload ->
            val signed = signer.sign(activity, title, subtitle, payload)
            Triple(signed.session.alg, signed.session.keyId, signed.signature)
        }
    }

    /** Signs [command] with the biometric `sign` key and posts it. */
    suspend fun sendCommand(activity: FragmentActivity, deviceId: String, command: Command, title: String, subtitle: String? = null): CommandResponse {
        val env = signEnvelope(activity, title, subtitle, { s -> EnvelopeBuilder.commandBody(deviceId, s, command) }, BodyKind.COMMAND, deviceId)
        return api.postCommand(deviceId, env)
    }

    suspend fun commandStatus(deviceId: String, commandId: String) = api.commandStatus(deviceId, commandId)

    suspend fun apps(deviceId: String, sid: String) = api.apps(deviceId, sid)

    fun newCommandId(): String = Ulid.next()

    // ---------- policy ----------
    data class LoadedPolicy(val response: PolicyResponse?, val policy: Policy?)

    suspend fun loadPolicy(deviceId: String, preferCache: Boolean = false): LoadedPolicy {
        if (preferCache) cachedPolicy(deviceId)?.let { return it }
        return try {
            val r = api.policy(deviceId)
            if (r != null) {
                dao.putPolicy(PolicyRow(deviceId, r.version, r.seq, ApiJson.encodeToString(SignedEnvelope.serializer(), r.envelope)))
            }
            LoadedPolicy(r, r?.let { EnvelopeBuilder.decodePolicy(it.envelope) })
        } catch (e: Exception) {
            cachedPolicy(deviceId) ?: throw e
        }
    }

    private suspend fun cachedPolicy(deviceId: String): LoadedPolicy? = dao.policy(deviceId)?.let { row ->
        val env = ApiJson.decodeFromString(SignedEnvelope.serializer(), row.envelopeJson)
        LoadedPolicy(PolicyResponse(row.version, row.seq, env), EnvelopeBuilder.decodePolicy(env))
    }

    suspend fun applyPolicy(activity: FragmentActivity, deviceId: String, policy: Policy, title: String): PutPolicyResponse {
        val env = signEnvelope(activity, title, "Chính sách phiên bản ${policy.version}", { s -> EnvelopeBuilder.policyBody(deviceId, s, policy) }, BodyKind.POLICY, deviceId)
        val r = api.putPolicy(deviceId, env)
        dao.putPolicy(PolicyRow(deviceId, r.version, r.seq, ApiJson.encodeToString(SignedEnvelope.serializer(), env)))
        return r
    }

    // ---------- alerts ----------
    val alerts: Flow<List<AlertView>> = dao.alertsFlow().map { rows ->
        rows.mapNotNull { row ->
            runCatching { ApiJson.decodeFromString(AlertItem.serializer(), row.json) }.getOrNull()?.let { AlertView(it, row.acked || it.isAcked) }
        }
    }

    suspend fun refreshAlerts() {
        // The server is the source of truth for ack state (`ackedAt`); the Room flag mirrors it.
        val page = api.alerts(limit = 200)
        dao.putAlerts(page.items.map {
            AlertRow(it.id, it.deviceId, it.userSid, it.ts, it.type, it.severity,
                ApiJson.encodeToString(AlertItem.serializer(), it), acked = it.isAcked)
        })
    }

    /** B3: sha256 -> decision made through this app (set once the cloud accepted the `approve_exe` command). */
    val localDecisions = kotlinx.coroutines.flow.MutableStateFlow<Map<String, io.github.nevminhnh.mincontrol.master.ui.activity.ApprovalState>>(emptyMap())

    fun recordDecision(sha256: String, allow: Boolean) {
        val s = if (allow) io.github.nevminhnh.mincontrol.master.ui.activity.ApprovalState.ALLOWED else io.github.nevminhnh.mincontrol.master.ui.activity.ApprovalState.BLOCKED
        localDecisions.value = localDecisions.value + (sha256 to s)
    }

    suspend fun ackAlert(id: String) {
        api.ackAlert(id)
        dao.markAcked(id)
    }

    // ---------- activity ----------
    suspend fun events(deviceId: String, sid: String?, from: Instant, to: Instant, cursor: String? = null, exclude: String? = null, type: String? = null) =
        api.events(deviceId, type = type, user = sid, from = from, to = to, cursor = cursor, exclude = exclude)

    suspend fun usage(deviceId: String, sid: String, day: String) = api.usage(deviceId, sid, day)

    suspend fun web(deviceId: String, sid: String, from: Instant, to: Instant, q: String?, kind: String?, cursor: String?): Page<WebItem> {
        return try {
            val page = api.web(deviceId, user = sid, from = from, to = to, q = q?.ifBlank { null }, kind = kind, cursor = cursor)
            dao.putWeb(page.items.map { WebRow(deviceId, sid, it.ts, it.url ?: it.host ?: "", it.kind, it.host, it.title, it.durationSec, it.category, it.query, it.engine) })
            page
        } catch (e: Exception) {
            if (cursor != null) throw e
            val rows = dao.web(deviceId, sid, from.toString(), to.toString(), kind, q?.ifBlank { null }, 200)
            if (rows.isEmpty()) throw e
            Page(rows.map { WebItem(it.ts, it.kind, it.url, it.host, it.title, it.durationSec, it.category, it.query, it.engine) }, null)
        }
    }

    suspend fun screenshots(deviceId: String, sid: String, from: Instant, to: Instant, cursor: String? = null) =
        api.screenshots(deviceId, sid, from, to, cursor)

    /** Downloads and opens a sealed screenshot; returns JPEG bytes. */
    suspend fun decryptScreenshot(blobKey: String): ByteArray {
        val sealed = api.blob(blobKey)
        return withContext(Dispatchers.Default) { sealKeys.open(sealed) }
    }

    suspend fun subscribePush(token: String) = api.subscribePush(token)

    suspend fun domains(deviceId: String, sid: String?, day: String) = api.domains(deviceId, sid, day).items
    suspend fun masterSettings() = api.settings()
    suspend fun saveMasterSettings(s: io.github.nevminhnh.mincontrol.master.data.protocol.MasterSettings) = api.putSettings(s)
    suspend fun cloudUsage() = api.cloudUsage()
}

data class AlertView(val item: AlertItem, val acked: Boolean)
