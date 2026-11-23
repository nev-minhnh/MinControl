package io.github.nevminhnh.mincontrol.master.ui

import io.github.nevminhnh.mincontrol.master.data.api.ApiException
import io.github.nevminhnh.mincontrol.master.data.api.MASTER_EXISTS_MESSAGE
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.ApiJson
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterKey
import io.github.nevminhnh.mincontrol.master.data.protocol.RegisterWithClaimRequest
import io.github.nevminhnh.mincontrol.master.data.protocol.SigAlg
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairLink
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairRoute
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairRouting
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairingRegister
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SingleQrFlowTest {
    private val id = "AbCdEfGhIjKlMnOpQrStUw"
    private val fp = "3f9ac21d77e0"

    @Test fun parsesV2WithServerUrl() {
        val p = PairLink.parse("mincontrol://pair?v=2&u=https%3A%2F%2Fmc.example.workers.dev%2F&c=$id&f=$fp")!!
        assertEquals(2, p.version)
        assertEquals("https://mc.example.workers.dev", p.serverUrl)
        assertEquals(id, p.claimId)
        assertEquals("3F9AC21D77E0", p.fp)
    }

    @Test fun v1HasNoServerUrl() {
        val p = PairLink.parse("mincontrol://pair?v=1&c=$id&f=$fp")!!
        assertNull(p.serverUrl)
        assertEquals(1, p.version)
        // a stray u on v1 is ignored; a non-http u on v2 is dropped
        assertNull(PairLink.parse("mincontrol://pair?v=1&u=https%3A%2F%2Fx.dev&c=$id&f=$fp")!!.serverUrl)
        assertNull(PairLink.parse("mincontrol://pair?v=2&u=ftp%3A%2F%2Fx&c=$id&f=$fp")!!.serverUrl)
        assertNull(PairLink.parse("mincontrol://pair?v=2&c=$id&f=$fp")!!.serverUrl)
        assertNull(PairLink.parse("mincontrol://pair?v=3&c=$id&f=$fp"))
    }

    @Test fun registerSignatureStringIsRegisterPipeClaimId() {
        assertEquals("register|$id", String(PairingRegister.signText(id), Charsets.UTF_8))
    }

    @Test fun registerWithClaimRequestJson() {
        val req = PairingRegister.request(
            id, listOf(RegisterKey("KID1", SigAlg.ES256, "PUB1", "sign"), RegisterKey("KID2", SigAlg.ES256, "PUB2", "read")),
            "SEAL", "SIG",
        )
        val o = Json.parseToJsonElement(ApiJson.encodeToString(RegisterWithClaimRequest.serializer(), req)).jsonObject
        assertEquals(id, o["claimId"]!!.jsonPrimitive.content)
        assertEquals("SEAL", o["sealPubKey"]!!.jsonPrimitive.content)
        assertEquals("SIG", o["sig"]!!.jsonPrimitive.content)
        assertEquals(setOf("claimId", "keys", "sealPubKey", "sig"), o.keys)
        assertFalse(o.containsKey("bootstrapSecret"))
    }

    @Test fun routingDecisions() {
        val v2 = PairLink.parse("mincontrol://pair?v=2&u=https%3A%2F%2Fmc.dev&c=$id&f=$fp")!!
        val v1 = PairLink.parse("mincontrol://pair?v=1&c=$id&f=$fp")!!
        assertEquals(PairRoute.FirstRun("https://mc.dev"), PairRouting.route(registered = false, v2))
        assertEquals(PairRoute.UpdateInstaller, PairRouting.route(registered = false, v1))
        assertEquals(PairRoute.Approve, PairRouting.route(registered = true, v2))
        assertEquals(PairRoute.Approve, PairRouting.route(registered = true, v1))
    }

    private fun dev(id: String) = io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo(
        deviceId = id, hostname = "PC-CON",
        users = listOf(io.github.nevminhnh.mincontrol.master.data.protocol.DeviceUser(sid = "S-1", name = "Bin", isAdmin = false)),
    )

    /** Root cause of the double scan: after register-with-claim the flow must never go back to a scan stage. */
    @Test fun afterRegisterGoesStraightToChooseUsers() {
        val a = io.github.nevminhnh.mincontrol.master.ui.pairing.AfterRegister(id, "DEV1", "3F9AC21D77E0")
        val step = io.github.nevminhnh.mincontrol.master.ui.pairing.FirstRunResume.step(a, listOf(dev("OTHER"), dev("DEV1")))
        assertTrue(step is io.github.nevminhnh.mincontrol.master.ui.pairing.ResumeStep.ChooseUsers)
        assertEquals("DEV1", (step as io.github.nevminhnh.mincontrol.master.ui.pairing.ResumeStep.ChooseUsers).device.deviceId)
        assertEquals(1, step.device.users.size)
    }

    @Test fun afterRegisterWithoutDeviceRowOffersRetryNotScan() {
        val a = io.github.nevminhnh.mincontrol.master.ui.pairing.AfterRegister(id, "DEV1")
        for (list in listOf(null, emptyList(), listOf(dev("OTHER")))) {
            val step = io.github.nevminhnh.mincontrol.master.ui.pairing.FirstRunResume.step(a, list)
            assertTrue(step is io.github.nevminhnh.mincontrol.master.ui.pairing.ResumeStep.Retry)
            val msg = (step as io.github.nevminhnh.mincontrol.master.ui.pairing.ResumeStep.Retry).message
            assertFalse(msg.contains("Quét", ignoreCase = true))
            assertTrue(msg.contains("Thử lại"))
        }
    }

    @Test fun firstRunScanRoutesToFingerprintCheckOnce() {
        // One scan of a v2 QR on a fresh phone = FirstRun (fingerprint check → biometric → register-with-claim, which
        // also approves the claim). Nothing after that routes back to Approve/scan.
        val v2 = PairLink.parse("mincontrol://pair?v=2&u=https%3A%2F%2Fmc.dev&c=$id&f=$fp")!!
        assertEquals(PairRoute.FirstRun("https://mc.dev"), PairRouting.route(registered = false, v2))
    }

    @Test fun masterExistsIsRecognisedAndExplained() {
        val e = ApiException.Http(409, "master_exists", null)
        assertTrue(PairingRegister.isMasterExists(e))
        assertEquals(MASTER_EXISTS_MESSAGE, e.userMessage())
        assertTrue(MASTER_EXISTS_MESSAGE.startsWith("Máy chủ đang có điện thoại quản lý khác."))
        assertFalse(MASTER_EXISTS_MESSAGE.contains("khôi phục"))
        assertFalse(PairingRegister.isMasterExists(ApiException.Http(409, "stale_seq", null)))
        assertFalse(PairingRegister.isMasterExists(ApiException.Http(410, "expired", null)))
    }
}
