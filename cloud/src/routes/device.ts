// Device-facing routes: WebSocket hand-off to DeviceHub, event uploads, sealed blob uploads (API.md 2-3).
import { saveAndPushAlerts } from "../alerts";
import { verifyUploadToken } from "../auth/upload-token";
import { type IngestEvent, ingestEvents } from "../ingest";
import { HttpError, errorResponse, json, parseJsonBytes, readBytes } from "../lib/http";
import { normTs } from "../lib/time";
import { ULID_RE } from "../lib/ulid";
import type { Ctx } from "../router";
import { BLOB_KEY_RE } from "./master";
import { validateEvent } from "../generated/validators";

export const MAX_BLOB_BYTES = 2 * 1024 * 1024;
const MAX_BATCH_BYTES = 5 * 1024 * 1024;
const MAX_EVENTS = 500;

interface DeviceRow {
  id: string;
  hostname: string;
  timezone: string | null;
  revoked_at: string | null;
}

/** Bearer upload token -> active device, else 401/403. */
async function authDevice(c: Ctx): Promise<DeviceRow> {
  const secret = c.env.UPLOAD_TOKEN_SECRET;
  if (!secret) throw new HttpError(503, "misconfigured", "upload tokens are not configured");
  const auth = c.request.headers.get("authorization") ?? "";
  const m = /^Bearer (\S+)$/.exec(auth);
  const deviceId = m ? await verifyUploadToken(secret, m[1]!) : null;
  if (!deviceId) throw new HttpError(401, "unauthorized", "missing, invalid or expired upload token");
  const row = await c.env.DB.prepare("SELECT id, hostname, timezone, revoked_at FROM devices WHERE id = ?").bind(deviceId).first<DeviceRow>();
  if (!row) throw new HttpError(401, "unauthorized", "unknown device");
  if (row.revoked_at) throw new HttpError(403, "revoked", "device revoked");
  return row;
}

/** GET /v1/device/ws?deviceId=<ULID> -> DeviceHub (auth happens inside the socket). */
export async function deviceWs(c: Ctx): Promise<Response> {
  if (c.request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return errorResponse(426, "upgrade_required", "expected a WebSocket upgrade");
  }
  const deviceId = c.url.searchParams.get("deviceId") ?? "";
  if (!ULID_RE.test(deviceId)) throw new HttpError(400, "invalid_query", "deviceId must be a ULID");
  const row = await c.env.DB.prepare("SELECT revoked_at FROM devices WHERE id = ?").bind(deviceId).first<{ revoked_at: string | null }>();
  if (!row) throw new HttpError(404, "not_found", "unknown device");
  if (row.revoked_at) throw new HttpError(403, "revoked", "device revoked");
  const stub = c.env.DEVICE_HUB.get(c.env.DEVICE_HUB.idFromName(deviceId));
  return stub.fetch(c.request);
}

/**
 * POST /v1/device/events. The wrapper (deviceId/sentAt/events[1..500]) must be valid; each event is
 * validated on its own so one bad event cannot block the agent's outbox forever: invalid ones are
 * reported in `rejected` (extension of the contract) and the rest is stored.
 */
export async function postEvents(c: Ctx): Promise<Response> {
  const device = await authDevice(c);
  const batch = parseJsonBytes(await readBytes(c.request, MAX_BATCH_BYTES)) as Record<string, unknown> | null;
  if (
    !batch ||
    typeof batch !== "object" ||
    typeof batch.sentAt !== "string" ||
    !Array.isArray(batch.events) ||
    batch.events.length < 1 ||
    batch.events.length > MAX_EVENTS ||
    Object.keys(batch).some((k) => !["deviceId", "sentAt", "events"].includes(k))
  ) {
    throw new HttpError(400, "invalid_body", "body is not an EventBatch");
  }
  if (batch.deviceId !== device.id) throw new HttpError(403, "wrong_device", "batch deviceId does not match the upload token");

  const accepted: IngestEvent[] = [];
  const rejected: { id: string | null; error: string }[] = [];
  const ids = new Set<string>();
  for (const raw of batch.events as unknown[]) {
    const ev = raw as Partial<IngestEvent> | null;
    const id = ev && typeof ev.id === "string" ? ev.id : null;
    if (!validateEvent(raw)) {
      const e = validateEvent.errors?.[0];
      rejected.push({ id, error: `invalid_body${e ? `: ${e.instancePath} ${e.message ?? ""}`.trimEnd() : ""}` });
      continue;
    }
    const e = raw as IngestEvent;
    if (e.deviceId !== device.id) {
      rejected.push({ id, error: "wrong_device" });
      continue;
    }
    if (ids.has(e.id)) continue;
    ids.add(e.id);
    accepted.push({ ...e, ts: normTs(e.ts)! });
  }

  if (accepted.length > 0) {
    const drafts = await ingestEvents(c.env, device, accepted);
    await saveAndPushAlerts(c.env, drafts, (p) => c.exec.waitUntil(p));
  }
  return json(rejected.length ? { accepted: accepted.length, rejected } : { accepted: accepted.length });
}

/**
 * PUT /v1/device/blobs/<key>?reqId=<ULID>: answers a master blob request (API.md section 9). Sealed bytes, <= 2 MB,
 * key must be in the caller's prefix. The bytes are forwarded to the DeviceHub and never stored.
 */
export async function putBlob(c: Ctx): Promise<Response> {
  const device = await authDevice(c);
  const key = c.params.key ?? "";
  const m = BLOB_KEY_RE.exec(key);
  if (!m || m[1] !== device.id) throw new HttpError(403, "forbidden_key", `key must match screens/${device.id}/<yyyy-mm-dd>/<eventId>.bin`);
  const reqId = c.url.searchParams.get("reqId") ?? "";
  if (!ULID_RE.test(reqId)) throw new HttpError(400, "invalid_query", "reqId (ULID) is required");
  const bytes = await readBytes(c.request, MAX_BLOB_BYTES);
  if (bytes.length === 0) throw new HttpError(400, "invalid_body", "empty blob");
  const hub = c.env.DEVICE_HUB.get(c.env.DEVICE_HUB.idFromName(device.id));
  const ok = await hub.resolveBlob(reqId, key, bytes);
  if (!ok) throw new HttpError(410, "gone", "unknown or expired reqId");
  return new Response(null, { status: 200 });
}
