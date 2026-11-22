package io.github.nevminhnh.mincontrol.master.envelope

import io.github.nevminhnh.mincontrol.master.data.protocol.BodyKind
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolJson
import io.github.nevminhnh.mincontrol.master.data.protocol.ProtocolSchemas
import io.github.nevminhnh.mincontrol.master.data.protocol.SigAlg
import io.github.nevminhnh.mincontrol.master.data.protocol.SignedEnvelope
import io.github.nevminhnh.mincontrol.master.policy.PolicyDefaults
import io.github.nevminhnh.mincontrol.master.security.SigFormat
import io.github.nevminhnh.mincontrol.master.security.normalise
import io.github.nevminhnh.mincontrol.master.util.B64Url
import io.github.nevminhnh.mincontrol.master.util.hexToBytes
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant

class EnvelopeBuilderTest {
    private val deviceId = "01JDQ8X5ZK3V9T6R2M4N7P8Q0W"
    private val sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
    private val now = Instant.parse("2026-11-22T08:50:00Z")

    // RFC 8032 test 1 key.
    private val edSk = Ed25519PrivateKeyParameters("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".hexToBytes(), 0)
    private val edPk = edSk.generatePublicKey().encoded

    private fun edSign(data: ByteArray): ByteArray = Ed25519Signer().run { init(true, edSk); update(data, 0, data.size); generateSignature() }
    private fun edVerify(data: ByteArray, sig: ByteArray): Boolean =
        Ed25519Signer().run { init(false, edSk.generatePublicKey()); update(data, 0, data.size); verifySignature(sig) }

    @Test
    fun commandEnvelopeIsSchemaValidAndSignatureCoversExactPayloadBytes() = runBlocking {
        val body = EnvelopeBuilder.commandBody(deviceId, 12, Command.AddTime("01JDQ8X5ZK3V9T6R2M4N7P8Q0X", sid, 30), now)
        var signed: ByteArray? = null
        val env = EnvelopeBuilder.build(body) { payload ->
            signed = payload
            Triple(SigAlg.ED25519, SigFormat.keyId(edPk), edSign(payload))
        }
        val envJson = ProtocolJson.encodeToString(SignedEnvelope.serializer(), env)
        assertTrue(ProtocolSchemas.validate("signed-envelope", envJson).toString(), ProtocolSchemas.validate("signed-envelope", envJson).isEmpty())

        val payload = B64Url.decode(env.payload)
        assertArrayEquals("payload must be the exact signed bytes", signed, payload)
        assertTrue(edVerify(payload, B64Url.decode(env.sig)))

        val bodyJson = payload.toString(Charsets.UTF_8)
        assertTrue(ProtocolSchemas.validate("signed-body", bodyJson).toString(), ProtocolSchemas.validate("signed-body", bodyJson).isEmpty())
        val decoded = EnvelopeBuilder.decodePayload(env)
        assertEquals(BodyKind.COMMAND, decoded.kind)
        assertEquals(12L, decoded.seq)
        assertEquals("2026-11-22T08:50:00Z", decoded.issuedAt)
        assertEquals("2026-11-23T08:50:00Z", decoded.expiresAt)
    }

    @Test
    fun policyEnvelopeWithEs256IsValid() = runBlocking {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val keyId = SigFormat.keyId(SigFormat.p256Uncompressed(kp.public as ECPublicKey))
        val policy = PolicyDefaults.policy(mapOf(sid to "Bin"), version = 3)
        val env = EnvelopeBuilder.build(EnvelopeBuilder.policyBody(deviceId, 5, policy, now)) { payload ->
            val der = Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(payload) }.sign()
            Triple(SigAlg.ES256, keyId, normalise(SigAlg.ES256, der))
        }
        val envJson = ProtocolJson.encodeToString(SignedEnvelope.serializer(), env)
        assertTrue(ProtocolSchemas.validate("signed-envelope", envJson).isEmpty())
        val payload = B64Url.decode(env.payload)
        val bodyJson = payload.toString(Charsets.UTF_8)
        assertTrue(ProtocolSchemas.validate("signed-body", bodyJson).toString(), ProtocolSchemas.validate("signed-body", bodyJson).isEmpty())
        val ok = Signature.getInstance("SHA256withECDSA").apply { initVerify(kp.public); update(payload) }
            .verify(SigFormat.p1363ToDer(B64Url.decode(env.sig)))
        assertTrue(ok)
        assertEquals(policy, EnvelopeBuilder.decodePolicy(env))
        assertEquals("policy TTL is long (cloud drops expired policies)", "2027-11-22T08:50:00Z", EnvelopeBuilder.decodePayload(env).expiresAt)
    }

    @Test
    fun lockUntilExtendsCommandExpiry() {
        val until = now.plus(Duration.ofHours(30))
        val ttl = EnvelopeBuilder.commandTtl(Command.LockNow("01JDQ8X5ZK3V9T6R2M4N7P8Q0X", sid, until.toString()), now)
        assertEquals(Duration.ofHours(31), ttl)
        assertEquals(EnvelopeBuilder.COMMAND_TTL, EnvelopeBuilder.commandTtl(Command.LockNow("01JDQ8X5ZK3V9T6R2M4N7P8Q0X", sid, null), now))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsWrongSignatureLength() {
        EnvelopeBuilder.envelope(SigAlg.ED25519, "0123456789abcdef", "{}".toByteArray(), ByteArray(70))
    }
}
