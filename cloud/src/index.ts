// MinControl API Worker: routing for device enrolment, device uploads/WebSocket and master endpoints
// (protocol/API.md), plus the hourly cron.
import { runCron } from "./cron";
import { DeviceHub } from "./device-hub";
import type { Env } from "./env";
import { json } from "./lib/http";
import { Router } from "./router";
import { deviceWs, postEvents, putBlob, putInventory } from "./routes/device";
import { approveClaim, enrollStart, getClaim, getClaimByCode, pollClaim, registerWithClaim, rejectClaim } from "./routes/claims";
import { createPairingCode, enroll } from "./routes/enroll";
import * as m from "./routes/master";

export { DeviceHub };
export type { Env };

export const router = new Router()
  .add("GET", "/health", "none", async () => json({ ok: true }))
  // device
  .add("POST", "/v1/enroll", "none", enroll)
  .add("POST", "/v1/enroll/start", "none", enrollStart)
  .add("GET", "/v1/enroll/claim/:claimId", "none", pollClaim) // device signature checked in the handler
  .add("GET", "/v1/device/ws", "none", deviceWs)
  .add("POST", "/v1/device/events", "none", postEvents) // upload token checked in the handler
  .add("PUT", "/v1/device/blobs/*key", "none", putBlob) // upload token checked in the handler
  .add("PUT", "/v1/device/inventory", "none", putInventory) // upload token checked in the handler
  // master
  .add("POST", "/v1/master/register", "none", m.register) // bootstrap secret checked in the handler
  .add("POST", "/v1/master/register-with-claim", "none", registerWithClaim) // TOFU; sig checked in the handler
  .add("POST", "/v1/master/pairing-codes", "master", createPairingCode)
  .add("GET", "/v1/master/claims/by-code/:code", "master", getClaimByCode)
  .add("GET", "/v1/master/claims/:claimId", "master", getClaim)
  .add("POST", "/v1/master/claims/:claimId/approve", "master", approveClaim)
  .add("POST", "/v1/master/claims/:claimId/reject", "master", rejectClaim)
  .add("GET", "/v1/master/devices", "master", m.listDevices)
  .add("DELETE", "/v1/master/devices/:id", "master", m.revokeDevice)
  .add("GET", "/v1/master/devices/:id/seq", "master", m.getSeq)
  .add("GET", "/v1/master/devices/:id/policy", "master", m.getPolicy)
  .add("PUT", "/v1/master/devices/:id/policy", "master", m.putPolicy)
  .add("POST", "/v1/master/devices/:id/commands", "master", m.postCommand)
  .add("GET", "/v1/master/devices/:id/commands/:commandId", "master", m.getCommand)
  .add("GET", "/v1/master/devices/:id/events", "master", m.listEvents)
  .add("GET", "/v1/master/devices/:id/web", "master", m.listWeb)
  .add("GET", "/v1/master/devices/:id/usage", "master", m.getUsage)
  .add("GET", "/v1/master/devices/:id/apps", "master", m.getApps)
  .add("GET", "/v1/master/devices/:id/screenshots", "master", m.listScreenshots)
  .add("GET", "/v1/master/blobs/*key", "master", m.getBlob)
  .add("GET", "/v1/master/alerts", "master", m.listAlerts)
  .add("POST", "/v1/master/alerts/:id/ack", "master", m.ackAlert)
  .add("POST", "/v1/master/push/subscribe", "master", m.pushSubscribe);

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return router.handle(request, env, ctx);
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    await runCron(env, ctx, controller.scheduledTime);
  },
} satisfies ExportedHandler<Env>;
