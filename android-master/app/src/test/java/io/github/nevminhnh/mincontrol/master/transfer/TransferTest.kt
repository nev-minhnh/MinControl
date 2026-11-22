package io.github.nevminhnh.mincontrol.master.transfer

import io.github.nevminhnh.mincontrol.master.data.api.ApiException
import io.github.nevminhnh.mincontrol.master.data.api.RECOVERY_CODE_USED_MESSAGE
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.ApiJson
import io.github.nevminhnh.mincontrol.master.data.protocol.BodyKind
import io.github.nevminhnh.mincontrol.master.data.protocol.PolicyResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolJson
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolSchemas
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterKey
import io.github.nevminhnh.mincontrol.master.data.protocol.SeqResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.SigAlg
import io.github.nevminhnh.mincontrol.master.data.protocol.SignedEnvelope
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferStatus
import io.github.nevminhnh.mincontrol.master.envelope.EnvelopeBuilder
import io.github.nevminhnh.mincontrol.master.policy.PolicyDefaults
import io.github.nevminhnh.mincontrol.master.security.SealKeyRing
import io.github.nevminhnh.mincontrol.master.security.SealedBox
import io.github.nevminhnh.mincontrol.master.security.SigFormat
import io.github.nevminhnh.mincontrol.master.util.B64Url
import io.github.nevminhnh.mincontrol.master.util.hexToBytes
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class TransferTest {
    private val token = B64Url.encode(ByteArray(32) { it.toByte() })
    private val deviceId = "01JDQ8X5ZK3V9T6R2M4N7P8Q0W"
    private val now = Instant.parse("2026-11-23T08:00:00Z")

    // Old phone sign key (RFC 8032 test 1) and new phone sign key (RFC 8032 test 2).
    private val oldSk = Ed25519PrivateKeyParameters("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".hexToBytes(), 0)
    private val newSk = Ed25519PrivateKeyParameters("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb".hexToBytes(), 0)
    private val oldPk = oldSk.generatePublicKey().encoded
    private val newPk = newSk.generatePublicKey().encoded

    private fun sign(sk: Ed25519PrivateKeyParameters, data: ByteArray) = Ed25519Signer().run { init(true, sk); update(data, 0, data.size); generateSignature() }
    private fun verify(pk: ByteArray, data: ByteArray, sig: ByteArray) = Ed25519Signer().run {
        init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(pk, 0)); update(data, 0, data.size); verifySignature(sig)
    }

    private val newKeys = listOf(
        RegisterKey(SigFormat.keyId(newPk), SigAlg.ED25519, B64Url.encode(newPk), "sign"),
        RegisterKey(SigFormat.keyId(oldPk.reversedArray()), SigAlg.ED25519, B64Url.encode(oldPk.reversedArray()), "read"),
    )
    private val newSealPk = B64Url.encode(SealedBox.generateKeyPair().second)

    // ---------- QR parsing ----------

    @Test
    fun parsesTransferQrAndRoundTripsBuild() {
        val link = TransferLink.build("https://mc.example.workers.dev/", token)
        assertTrue(link.startsWith("mincontrol://transfer?v=1&u=https%3A%2F%2Fmc.example.workers.dev&t="))
        val p = TransferLink.parse(link)!!
        assertEquals("https://mc.example.workers.dev", p.serverUrl)
        assertEquals(token, p.token)
        assertFalse(p.toString().contains(token))
        // case-insensitive scheme/host, surrounding whitespace
        assertNotNull(TransferLink.parse("  MinControl://TRANSFER?v=1&u=https%3A%2F%2Fa.b&t=$token \n"))
    }

    @Test
    fun rejectsBadTransferQr() {
        val u = "u=https%3A%2F%2Fa.b"
        listOf(
            null, "", "https://a.b",
            "mincontrol://pair?v=1&$u&t=$token",
            "mincontrol://transfer?v=2&$u&t=$token",
            "mincontrol://transfer?$u&t=$token",
            "mincontrol://transfer?v=1&t=$token",
            "mincontrol://transfer?v=1&u=ftp%3A%2F%2Fa.b&t=$token",
            "mincontrol://transfer?v=1&$u",
            "mincontrol://transfer?v=1&$u&t=short",
            "mincontrol://transfer?v=1&$u&t=${token.dropLast(2)}%2B%2B",
        ).forEach { assertNull(it, TransferLink.parse(it)) }
    }

    // ---------- fingerprint ----------

    @Test
    fun fingerprintIsFirst12HexOfSha256FormattedInGroups() {
        val fp = TransferProtocol.displayFingerprint(newPk)
        assertTrue(fp, Regex("^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$").matches(fp))
        // = keyId (first 16 hex of sha256) truncated to 12
        assertEquals(SigFormat.keyId(newPk).take(12).uppercase().chunked(4).joinToString("-"), fp)
        // old phone recomputes it from the claimed keys; server fp may be lower-case / dashed
        assertEquals(fp, TransferProtocol.claimedFingerprint(newKeys, fp.lowercase()))
        assertEquals(fp, TransferProtocol.claimedFingerprint(newKeys, null))
        assertThrows(IllegalArgumentException::class.java) { TransferProtocol.claimedFingerprint(newKeys, "000000000000") }
        assertThrows(IllegalArgumentException::class.java) { TransferProtocol.claimedFingerprint(newKeys.filter { it.role == "read" }, null) }
    }

    @Test
    fun claimSignatureCoversTransferPrefixAndToken() {
        val text = TransferProtocol.claimSignText(token)
        assertEquals("transfer|$token", text.toString(Charsets.UTF_8))
        assertTrue(verify(newPk, text, sign(newSk, text)))
    }

    // ---------- master_keys envelope ----------

    @Test
    fun masterKeysEnvelopeIsSchemaValidAndSignedByOldKey() = runBlocking {
        val body = TransferProtocol.masterKeysBody(newKeys, newSealPk)
        assertEquals(listOf("sign"), body.keys.map { it.role })
        val signed = TransferProtocol.signedBody(deviceId, 3, body, now)
        assertEquals(BodyKind.MASTER_KEYS, signed.kind)
        assertEquals("2026-12-23T08:00:00Z", signed.expiresAt)
        val env = EnvelopeBuilder.build(signed) { payload -> Triple(SigAlg.ED25519, SigFormat.keyId(oldPk), sign(oldSk, payload)) }

        val envJson = ProtocolJson.encodeToString(SignedEnvelope.serializer(), env)
        assertTrue(ProtocolSchemas.validate("signed-envelope", envJson).toString(), ProtocolSchemas.validate("signed-envelope", envJson).isEmpty())
        val payload = B64Url.decode(env.payload)
        val bodyJson = payload.toString(Charsets.UTF_8)
        assertTrue(bodyJson, bodyJson.contains("\"kind\":\"master_keys\"") && bodyJson.contains("\"role\":\"sign\""))
        assertTrue(ProtocolSchemas.validate("signed-body", bodyJson).toString(), ProtocolSchemas.validate("signed-body", bodyJson).isEmpty())
        assertTrue(verify(oldPk, payload, B64Url.decode(env.sig)))
        assertEquals(3L, EnvelopeBuilder.decodePayload(env).seq)
    }

    @Test
    fun masterKeysBodyRejectsBadInput() {
        assertThrows(IllegalArgumentException::class.java) { TransferProtocol.masterKeysBody(newKeys.filter { it.role == "read" }, newSealPk) }
        assertThrows(IllegalArgumentException::class.java) { TransferProtocol.masterKeysBody(newKeys, B64Url.encode(ByteArray(31))) }
        assertThrows(IllegalArgumentException::class.java) {
            TransferProtocol.masterKeysBody(listOf(newKeys[0].copy(keyId = "XYZ")), newSealPk)
        }
    }

    @Test
    fun schemaRejectsReadRoleInMasterKeysBody() {
        val bad = """{"deviceId":"$deviceId","kind":"master_keys","seq":1,"issuedAt":"2026-11-23T08:00:00Z","expiresAt":"2026-12-23T08:00:00Z",
            "body":{"keys":[{"keyId":"${newKeys[1].keyId}","alg":"ed25519","publicKey":"${newKeys[1].publicKey}","role":"read"}],"sealPubKey":"$newSealPk"}}"""
        assertFalse(ProtocolSchemas.validate("signed-body", bad).isEmpty())
    }

    @Test
    fun seqAndTransferStatusDecodeLeniently() {
        assertEquals(7L, ApiJson.decodeFromString(SeqResponse.serializer(), """{"policy":1,"command":2,"master_keys":7}""").masterKeys)
        assertEquals(5L, ApiJson.decodeFromString(SeqResponse.serializer(), """{"policy":1,"command":2,"masterKeys":5}""").masterKeys)
        assertEquals(0L, ApiJson.decodeFromString(SeqResponse.serializer(), """{"policy":1,"command":2}""").masterKeys)
        val st = ApiJson.decodeFromString(TransferStatus.serializer(),
            """{"status":"claimed","newKeys":[{"keyId":"${newKeys[0].keyId}","alg":"ed25519","publicKey":"${newKeys[0].publicKey}","role":"sign"}],"transportPubKey":"x","newSealPubKey":"$newSealPk","fp":"abc","extra":1}""")
        assertEquals("claimed", st.status)
        assertEquals(newSealPk, st.sealPubKey)
    }

    // ---------- seal keys ----------

    @Test
    fun oldSealKeyTravelsSealedToTransportKey() {
        val (oldSealSk, _) = SealedBox.generateKeyPair()
        val (transportSk, transportPk) = SealedBox.generateKeyPair()
        val sealed = TransferProtocol.sealSealKey(oldSealSk, B64Url.encode(transportPk))
        assertArrayEquals(oldSealSk, TransferProtocol.openSealedSealKey(sealed, transportSk))
        val (otherSk, _) = SealedBox.generateKeyPair()
        assertThrows(SealedBox.OpenException::class.java) { TransferProtocol.openSealedSealKey(sealed, otherSk) }
    }

    @Test
    fun screenshotsTryNewKeyThenOldKeys() {
        val (newSeal, newSealPub) = SealedBox.generateKeyPair()
        val (old1, old1Pub) = SealedBox.generateKeyPair()
        val (old2, old2Pub) = SealedBox.generateKeyPair()
        val ring = listOf(newSeal, old1, old2)
        val jpegNew = "new-shot".toByteArray()
        val jpegOld = "old-shot".toByteArray()
        val jpegOlder = "older-shot".toByteArray()
        assertArrayEquals(jpegNew, SealKeyRing.open(SealedBox.seal(jpegNew, newSealPub), ring))
        assertArrayEquals(jpegOld, SealKeyRing.open(SealedBox.seal(jpegOld, old1Pub), ring))
        assertArrayEquals(jpegOlder, SealKeyRing.open(SealedBox.seal(jpegOlder, old2Pub), ring))
        val (_, strangerPub) = SealedBox.generateKeyPair()
        assertThrows(SealedBox.OpenException::class.java) { SealKeyRing.open(SealedBox.seal(jpegNew, strangerPub), ring) }
        assertThrows(SealedBox.OpenException::class.java) { SealKeyRing.open(SealedBox.seal(jpegNew, newSealPub), emptyList()) }
    }

    @Test
    fun keyRingPersistenceFormatRoundTrips() {
        val keys = List(3) { SealedBox.generateKeyPair().first }
        val back = SealKeyRing.split(SealKeyRing.join(keys))
        assertEquals(3, back.size)
        keys.zip(back).forEach { (a, b) -> assertArrayEquals(a, b) }
        assertTrue(SealKeyRing.split(null).isEmpty())
        assertTrue(SealKeyRing.split(ByteArray(33)).isEmpty())
    }

    // ---------- policy re-sign on the new phone ----------

    @Test
    fun republishedPolicyBumpsVersionAndKeepsContent() = runBlocking {
        val sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
        val policy = PolicyDefaults.policy(mapOf(sid to "Bin"), version = 4)
        val env = EnvelopeBuilder.build(EnvelopeBuilder.policyBody(deviceId, 9, policy, now)) { p ->
            Triple(SigAlg.ED25519, SigFormat.keyId(oldPk), sign(oldSk, p))
        }
        val next = TransferProtocol.republishedPolicy(PolicyResponse(version = 4, seq = 9, envelope = env))
        assertEquals(5, next.version)
        assertEquals(policy.copy(version = 5), next)
    }

    @Test
    fun errorMessagesAndCountdown() {
        assertEquals(RECOVERY_CODE_USED_MESSAGE, ApiException.Http(403, "recovery_code_used", null).userMessage())
        assertEquals("Mã khôi phục đã được dùng. Tạo mã mới trên máy chủ.", RECOVERY_CODE_USED_MESSAGE)
        assertEquals("9:05", TransferProtocol.countdown(545))
        assertEquals(600L, TransferProtocol.secondsLeft("2026-11-23T08:10:00Z", now))
        assertEquals(0L, TransferProtocol.secondsLeft("2026-11-23T07:00:00Z", now))
        assertNull(TransferProtocol.secondsLeft("nope", now))
    }
}
