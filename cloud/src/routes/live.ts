// Master live socket (API.md section 15): GET /v1/master/live?deviceId=<ULID>, X-MC-Auth verified by the router
// on the upgrade request (any active master key, read role is enough), then handed to the device's DeviceHub.
import { MASTER_KEY_HEADER, MASTER_LIVE_PATH } from "../device-hub";
import type { Env } from "../env";
import { HttpError, errorResponse } from "../lib/http";
import { ULID_RE } from "../lib/ulid";
import type { Ctx } from "../router";

export async function masterLive(c: Ctx): Promise<Response> {
  if (c.request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return errorResponse(426, "upgrade_required", "expected a WebSocket upgrade");
  }
  const deviceId = c.url.searchParams.get("deviceId") ?? "";
  if (!ULID_RE.test(deviceId)) throw new HttpError(400, "invalid_query", "deviceId must be a ULID");
  const row = await c.env.DB.prepare("SELECT revoked_at FROM devices WHERE id = ?").bind(deviceId).first<{ revoked_at: string | null }>();
  if (!row || row.revoked_at) throw new HttpError(404, "not_found", "unknown device");
  const headers = new Headers({ upgrade: "websocket", [MASTER_KEY_HEADER]: c.master!.key_id });
  const fwd = new Request(`https://device-hub${MASTER_LIVE_PATH}?deviceId=${deviceId}`, { headers });
  return c.env.DEVICE_HUB.get(c.env.DEVICE_HUB.idFromName(deviceId)).fetch(fwd);
}

/**
 * After master keys were revoked or rotated: closes the master live sockets of every non-revoked device
 * (`keyIds` = only sockets opened with those keys; omitted = all). Runs in the background, never throws.
 */
export function closeMasterLiveSockets(env: Env, waitUntil: (p: Promise<unknown>) => void, keyIds?: string[]): void {
  waitUntil(
    (async () => {
      const ids = (await env.DB.prepare("SELECT id FROM devices WHERE revoked_at IS NULL").all<{ id: string }>()).results.map((r) => r.id);
      await Promise.all(
        ids.map(async (id) => {
          try {
            await env.DEVICE_HUB.get(env.DEVICE_HUB.idFromName(id)).closeMasterSockets(keyIds);
          } catch (e) {
            console.error("live: closeMasterSockets failed", id, e instanceof Error ? e.message : e);
          }
        }),
      );
    })().catch((e) => console.error("live: close master sockets failed", e instanceof Error ? e.message : e)),
  );
}
