package io.github.nevminhnh.mincontrol.master.transfer

import androidx.fragment.app.FragmentActivity
import io.github.nevminhnh.mincontrol.master.Settings
import io.github.nevminhnh.mincontrol.master.data.Repository
import io.github.nevminhnh.mincontrol.master.data.api.ApiException
import io.github.nevminhnh.mincontrol.master.data.api.MasterApi
import io.github.nevminhnh.mincontrol.master.data.db.CacheDb
import io.github.nevminhnh.mincontrol.master.data.protocol.BodyKind
import io.github.nevminhnh.mincontrol.master.data.protocol.CreateTransferResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterKey
import io.github.nevminhnh.mincontrol.master.data.protocol.SignedEnvelope
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferClaimRequest
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferCompleteRequest
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferStatus
import io.github.nevminhnh.mincontrol.master.envelope.EnvelopeBuilder
import io.github.nevminhnh.mincontrol.master.envelope.SeqAllocator
import io.github.nevminhnh.mincontrol.master.security.BiometricSigner
import io.github.nevminhnh.mincontrol.master.security.KeyRole
import io.github.nevminhnh.mincontrol.master.security.MasterKeyStore
import io.github.nevminhnh.mincontrol.master.security.SealKeyStore
import io.github.nevminhnh.mincontrol.master.security.SealedBox
import io.github.nevminhnh.mincontrol.master.security.SecurePrefs
import io.github.nevminhnh.mincontrol.master.util.B64Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** New phone's in-flight transfer, persisted so a process restart can resume polling. */
class PendingTransfer(val transferId: String, val serverUrl: String, val transportSk: ByteArray, val fingerprint: String)

/** Result of re-signing every device policy with the new phone's key. */
data class RepublishResult(val total: Int, val updated: Int, val skipped: Int, val failed: List<String>) {
    val message: String
        get() = when {
            total == 0 -> "Chưa có máy tính nào để cập nhật."
            failed.isEmpty() -> "Đã cập nhật quy tắc cho $updated/$total máy" + (if (skipped > 0) " ($skipped máy chưa có quy tắc)." else ".")
            else -> "Đã cập nhật $updated/$total máy. Chưa cập nhật được: ${failed.joinToString(", ")} — mở Quy tắc và bấm Áp dụng lại."
        }
}

/** Phone transfer, API.md 13 (old phone: [start]/[complete]; new phone: [claim]/[poll]/[finish]/[republishPolicies]). */
class TransferManager(
    private val api: MasterApi,
    private val repo: Repository,
    private val db: CacheDb,
    private val keys: MasterKeyStore,
    private val sealKeys: SealKeyStore,
    private val seq: SeqAllocator,
    private val signer: BiometricSigner,
    private val settings: Settings,
    private val prefs: SecurePrefs,
) {
    // ---------------- old phone ----------------

    suspend fun start(activity: FragmentActivity): CreateTransferResponse =
        api.createTransfer { data ->
            val s = signer.sign(activity, "Chuyển sang điện thoại mới", "Xác nhận để tạo mã chuyển máy", data)
            s.session.keyId to s.signature
        }

    suspend fun status(transferId: String): TransferStatus = api.transferStatus(transferId)

    /**
     * After the parent confirmed the fingerprint: signs one `master_keys` envelope per device (the sign key needs a
     * prompt per signature), seals the current seal private key to the new phone's transport key and completes
     * (one more prompt). Then wipes every local key.
     */
    suspend fun complete(activity: FragmentActivity, transferId: String, claimed: TransferStatus, onProgress: (String) -> Unit) {
        val transportPk = claimed.transportPubKey ?: throw IllegalStateException("Thiếu khóa truyền của điện thoại mới")
        val sealPk = claimed.sealPubKey ?: throw IllegalStateException("Máy chủ chưa gửi khóa ảnh của điện thoại mới")
        val body = TransferProtocol.masterKeysBody(claimed.newKeys, sealPk)
        onProgress("Đang tải danh sách máy tính…")
        val devices = repo.refreshDevices()
        val envelopes = LinkedHashMap<String, SignedEnvelope>()
        devices.forEachIndexed { i, d ->
            onProgress("Ký khóa mới cho ${d.hostname} (${i + 1}/${devices.size})…")
            val last = api.seq(d.deviceId).masterKeys
            val n = seq.next(d.deviceId, BodyKind.MASTER_KEYS, last)
            envelopes[d.deviceId] = EnvelopeBuilder.build(TransferProtocol.signedBody(d.deviceId, n, body)) { payload ->
                val s = signer.sign(activity, "Giao quyền cho điện thoại mới", "${d.hostname} (${i + 1}/${devices.size})", payload)
                Triple(s.session.alg, s.session.keyId, s.signature)
            }
        }
        val sk = sealKeys.privateKey()
        val sealed = try { TransferProtocol.sealSealKey(sk, transportPk) } finally { sk.fill(0) }
        onProgress("Đang hoàn tất…")
        api.completeTransfer(transferId, TransferCompleteRequest(envelopes, sealed)) { data ->
            val s = signer.sign(activity, "Hoàn tất chuyển máy", "Điện thoại này sẽ mất quyền quản lý", data)
            s.session.keyId to s.signature
        }
        wipeLocal()
    }

    /** Removes every key and cached data; the caller then flips `registered` off to return to first-run. */
    suspend fun wipeLocal() {
        withContext(Dispatchers.IO) {
            runCatching { keys.deleteAll() }
            runCatching { sealKeys.clear() }
            runCatching { db.clearAllTables() }
        }
        settings.fcmTokenSent = null
        clearPending()
    }

    // ---------------- new phone ----------------

    /** Creates keys + a transport key, signs `"transfer|"+token` (biometric) and claims. Returns the pending transfer. */
    suspend fun claim(activity: FragmentActivity, payload: TransferPayload): PendingTransfer {
        withContext(Dispatchers.Default) { keys.ensureKeys() }
        val sealPk = sealKeys.ensureKey()
        val (transportSk, transportPk) = SealedBox.generateKeyPair()
        val signed = signer.sign(activity, "Nhận quyền quản lý", "Chuyển từ điện thoại cũ sang điện thoại này",
            TransferProtocol.claimSignText(payload.token))
        val regKeys = KeyRole.entries.map { r ->
            val k = keys.publicKey(r)
            RegisterKey(keyId = k.keyId, alg = k.alg, publicKey = B64Url.encode(k.raw), role = r.wire)
        }
        val resp = api.claimTransfer(payload.serverUrl, TransferClaimRequest(
            token = payload.token, keys = regKeys, sealPubKey = B64Url.encode(sealPk),
            transportPubKey = B64Url.encode(transportPk), sig = B64Url.encode(signed.signature),
        ))
        settings.serverUrl = payload.serverUrl
        val p = PendingTransfer(resp.transferId, payload.serverUrl, transportSk,
            TransferProtocol.displayFingerprint(keys.publicKey(KeyRole.SIGN).raw))
        savePending(p)
        return p
    }

    /** Polls with the new read key; 401/403 (keys not active yet) count as still pending. */
    suspend fun poll(p: PendingTransfer): TransferStatus = try {
        api.transferStatus(p.transferId)
    } catch (e: ApiException.Http) {
        if (e.status == 401 || e.status == 403) TransferStatus(status = "pending") else throw e
    }

    /** Status `done`: opens `sealedSealKey` and keeps the old seal key as an extra decryption key. */
    fun finish(p: PendingTransfer, done: TransferStatus) {
        done.sealedSealKey?.let { sealed ->
            val old = TransferProtocol.openSealedSealKey(sealed, p.transportSk)
            try { sealKeys.addOldKey(old) } finally { old.fill(0) }
        }
        clearPending()
    }

    /**
     * Re-signs the current policy of every device with this phone's sign key (version + 1, next policy seq), so no
     * device keeps depending on a policy signed by the retired key. The Keystore sign key is per-use
     * (auth timeout 0, fixed at key creation), so this is one prompt per device.
     */
    suspend fun republishPolicies(activity: FragmentActivity, onProgress: (String) -> Unit): RepublishResult {
        val devices = repo.refreshDevices()
        var updated = 0
        var skipped = 0
        val failed = ArrayList<String>()
        devices.forEachIndexed { i, d ->
            onProgress("Đang cập nhật quy tắc cho ${devices.size} máy… (${i + 1}/${devices.size}: ${d.hostname})")
            try {
                val current = api.policy(d.deviceId)
                if (current == null) {
                    skipped++
                } else {
                    repo.applyPolicy(activity, d.deviceId, TransferProtocol.republishedPolicy(current), "Ký lại quy tắc cho ${d.hostname}")
                    updated++
                }
            } catch (e: Exception) {
                failed += d.hostname
            }
        }
        return RepublishResult(devices.size, updated, skipped, failed)
    }

    fun pending(): PendingTransfer? {
        val id = prefs.getString(K_ID) ?: return null
        val url = prefs.getString(K_URL) ?: return null
        val sk = prefs.getBytes(K_SK)?.takeIf { it.size == SealedBox.KEY_BYTES } ?: return null
        val fp = prefs.getString(K_FP) ?: return null
        return PendingTransfer(id, url, sk, fp)
    }

    private fun savePending(p: PendingTransfer) {
        prefs.putString(K_ID, p.transferId)
        prefs.putString(K_URL, p.serverUrl)
        prefs.putBytes(K_SK, p.transportSk)
        prefs.putString(K_FP, p.fingerprint)
    }

    fun clearPending() {
        listOf(K_ID, K_URL, K_FP).forEach { prefs.putString(it, null) }
        prefs.putBytes(K_SK, null)
    }

    private companion object {
        const val K_ID = "transfer_id"
        const val K_URL = "transfer_url"
        const val K_SK = "transfer_transport_sk"
        const val K_FP = "transfer_fp"
    }
}
