// Master endpoints (API.md sections 4 and 5).
import type { EnqueueResult, PolicyMeta } from "../device-hub";
import type { Env } from "../env";
import { verifyEnvelope } from "../envelope";
import { decodeCursor, cursorClause, paginate, parseLimit } from "../lib/cursor";
import { type SigAlg, keyIdOf, publicKeyLengthOk, secretEquals, sha256Hex } from "../lib/crypto";
import { b64urlDecode } from "../lib/encoding";
import { HttpError, json, noContent, notFound, parseJsonBytes, readBytes, validateOrThrow } from "../lib/http";
import { localDay, normTs, nowIso } from "../lib/time";
import { ULID_RE, ulid } from "../lib/ulid";
import { type Ctx, lookupMasterKey } from "../router";
import { validateMasterRegister, validatePushSubscribe } from "../generated/validators";

/** A device counts as online while its socket is open and it reported within this window. */
const ONLINE_FRESH_MS = 3 * 60_000;
export const BLOB_KEY_RE = /^screens\/([0-9A-HJKMNP-TV-Z]{26})\/(\d{4}-\d{2}-\d{2})\/([0-9A-HJKMNP-TV-Z]{26})\.bin$/;

interface DeviceRow {
  id: string;
  hostname: string;
  online: number;
  last_seen_at: string | null;
  state_json: string | null;
  policy_version: number | null;
  timezone: string | null;
  revoked_at: string | null;
}

const hub = (env: Env, deviceId: string) => env.DEVICE_HUB.get(env.DEVICE_HUB.idFromName(deviceId));

async function requireDevice(env: Env, id: string | undefined, allowRevoked = false): Promise<DeviceRow> {
  if (!id || !ULID_RE.test(id)) throw notFound("unknown device");
  const row = await env.DB.prepare(
    "SELECT id, hostname, online, last_seen_at, state_json, policy_version, timezone, revoked_at FROM devices WHERE id = ?",
  ).bind(id).first<DeviceRow>();
  if (!row || (row.revoked_at && !allowRevoked)) throw notFound("unknown device");
  return row;
}

function qTs(c: Ctx, name: string): string | null {
  const v = c.url.searchParams.get(name);
  if (v === null || v === "") return null;
  const n = normTs(v);
  if (!n) throw new HttpError(400, "invalid_query", `${name} must be an RFC 3339 timestamp`);
  return n;
}

function qSid(c: Ctx): string | null {
  const v = c.url.searchParams.get("user");
  if (v === null || v === "") return null;
  if (!/^S-1-5-21(-[0-9]+){3,4}$/.test(v)) throw new HttpError(400, "invalid_query", "user must be a SID");
  return v;
}

/** Builds `WHERE` + params from optional conditions. */
function where(conds: Array<[string, unknown[]] | null>): { sql: string; params: unknown[] } {
  const parts: string[] = [];
  const params: unknown[] = [];
  for (const c of conds) {
    if (!c || !c[0]) continue;
    parts.push(c[0]);
    params.push(...c[1]);
  }
  return { sql: parts.length ? "WHERE " + parts.join(" AND ") : "", params };
}

function timeRange(c: Ctx, col = "ts"): Array<[string, unknown[]] | null> {
  const from = qTs(c, "from");
  const to = qTs(c, "to");
  return [from ? [`${col} >= ?`, [from]] : null, to ? [`${col} < ?`, [to]] : null];
}

function cursorCond(c: Ctx, tsCol = "ts", idCol = "id"): [string, unknown[]] | null {
  const cc = cursorClause(decodeCursor(c.url.searchParams.get("cursor")), tsCol, idCol);
  return cc.sql ? [cc.sql, cc.params] : null;
}

// ------------------------------------------------------------------ registration

interface RegisterBody {
  bootstrapSecret: string;
  keys: { keyId: string; alg: SigAlg; publicKey: string; role: "sign" | "read" }[];
  sealPubKey: string;
}

/** POST /v1/master/register (no X-MC-Auth; guarded by ADMIN_BOOTSTRAP_SECRET). */
export async function register(c: Ctx): Promise<Response> {
  const env = c.env;
  const body = validateOrThrow<RegisterBody>(validateMasterRegister, parseJsonBytes(await readBytes(c.request, 32 * 1024)), "register request");
  const secret = env.ADMIN_BOOTSTRAP_SECRET;
  if (!secret || !(await secretEquals(body.bootstrapSecret, secret))) {
    throw new HttpError(403, "forbidden", "bootstrap secret rejected");
  }
  // Recovery code is single use (API.md section 13B): only the sha256 of the used secret is kept.
  const secretHash = await sha256Hex(secret);
  const used = await env.DB.prepare("SELECT v FROM config WHERE k = 'bootstrap_used'").first<{ v: string }>();
  if (used?.v === secretHash) throw new HttpError(403, "recovery_code_used", "this recovery code was already used; generate a new one (deploy-cloud.ps1 -RotateBootstrap)");
  const ids = new Set<string>();
  for (const k of body.keys) {
    const raw = b64urlDecode(k.publicKey);
    if (!raw || !publicKeyLengthOk(k.alg, raw)) throw new HttpError(400, "invalid_body", `publicKey of ${k.keyId} has the wrong size for ${k.alg}`);
    if ((await keyIdOf(raw)) !== k.keyId) throw new HttpError(400, "invalid_body", `keyId ${k.keyId} does not match sha256(publicKey)`);
    if (ids.has(k.keyId)) throw new HttpError(400, "invalid_body", "duplicate keyId");
    ids.add(k.keyId);
  }
  if (!body.keys.some((k) => k.role === "sign")) throw new HttpError(400, "invalid_body", "at least one sign key is required");
  const seal = b64urlDecode(body.sealPubKey);
  if (!seal || seal.length !== 32) throw new HttpError(400, "invalid_body", "sealPubKey must be a raw 32-byte X25519 key");

  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare("UPDATE master_keys SET revoked_at = ? WHERE revoked_at IS NULL").bind(now),
    ...body.keys.map((k) =>
      env.DB.prepare("INSERT OR REPLACE INTO master_keys (key_id, alg, public_key, role, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL)")
        .bind(k.keyId, k.alg, k.publicKey, k.role, now),
    ),
    env.DB.prepare("INSERT OR REPLACE INTO config (k, v, updated_at) VALUES ('master_seal_pub_key', ?, ?)").bind(body.sealPubKey, now),
    env.DB.prepare("INSERT OR REPLACE INTO config (k, v, updated_at) VALUES ('bootstrap_used', ?, ?)").bind(secretHash, now),
  ]);
  return json({ keys: body.keys.map((k) => ({ keyId: k.keyId, role: k.role })) }, 201);
}

// ------------------------------------------------------------------ devices

export async function listDevices(c: Ctx): Promise<Response> {
  const db = c.env.DB;
  const [devices, users] = await Promise.all([
    db.prepare("SELECT id, hostname, online, last_seen_at, state_json, policy_version FROM devices WHERE revoked_at IS NULL ORDER BY enrolled_at")
      .all<DeviceRow>(),
    db.prepare(
      `SELECT u.device_id, u.user_sid, u.name, u.is_admin, u.managed, u.label FROM managed_users u
       JOIN devices d ON d.id = u.device_id WHERE d.revoked_at IS NULL ORDER BY u.name`,
    ).all<{ device_id: string; user_sid: string; name: string; is_admin: number; managed: number; label: string | null }>(),
  ]);
  const now = Date.now();
  const items = devices.results.map((d) => ({
    deviceId: d.id,
    hostname: d.hostname,
    online: d.online === 1 && d.last_seen_at !== null && now - Date.parse(d.last_seen_at) < ONLINE_FRESH_MS,
    lastSeen: d.last_seen_at,
    state: d.state_json ? JSON.parse(d.state_json) : null,
    users: users.results
      .filter((u) => u.device_id === d.id)
      .map((u) => ({ sid: u.user_sid, name: u.name, isAdmin: u.is_admin === 1, managed: u.managed === 1, label: u.label })),
    policyVersion: d.policy_version,
  }));
  return json({ items });
}

export async function revokeDevice(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id);
  await c.env.DB.prepare("UPDATE devices SET revoked_at = ?, online = 0 WHERE id = ?").bind(nowIso(), d.id).run();
  await hub(c.env, d.id).revoke(d.id);
  return noContent();
}

export async function getSeq(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id, true);
  return json(await hub(c.env, d.id).getSeq());
}

// ------------------------------------------------------------------ policy & commands

export async function getPolicy(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id, true);
  const row = await c.env.DB.prepare("SELECT version, seq, signed_blob FROM policies WHERE device_id = ? ORDER BY seq DESC LIMIT 1")
    .bind(d.id)
    .first<{ version: number; seq: number; signed_blob: string }>();
  if (!row) throw notFound("no policy");
  return json({ version: row.version, seq: row.seq, envelope: JSON.parse(row.signed_blob) });
}

function enqueueError(r: Exclude<EnqueueResult, { ok: true }>): HttpError {
  if (r.code === "replayed") return new HttpError(409, "replayed", `seq must be greater than ${r.lastSeq}`, { lastSeq: r.lastSeq });
  if (r.code === "duplicate") return new HttpError(409, "duplicate", "commandId already queued");
  return notFound("unknown device");
}

interface PolicyBody {
  version: number;
  timezone: string;
  users: Record<string, { label: string }>;
  retentionDays: { events: number; web: number; screenshots: number };
}

export async function putPolicy(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id);
  const v = await verifyEnvelope<PolicyBody>(c.json(), "policy", d.id, (id) => lookupMasterKey(c.env, id));
  const p = v.signed.body;
  const meta: PolicyMeta = {
    version: p.version,
    timezone: p.timezone,
    retentionDays: p.retentionDays,
    users: Object.fromEntries(Object.entries(p.users).map(([sid, u]) => [sid, u.label])),
  };
  const r = await hub(c.env, d.id).enqueue({
    deviceId: d.id,
    kind: "policy",
    seq: v.signed.seq,
    envelopeJson: JSON.stringify(v.envelope),
    keyId: v.envelope.keyId,
    issuedAt: v.issuedAt,
    expiresAt: v.expiresAt,
    policy: meta,
  });
  if (!r.ok) throw enqueueError(r);
  return json({ version: p.version, seq: v.signed.seq }, 202);
}

export async function postCommand(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id);
  const v = await verifyEnvelope<{ commandId: string; type: string; userSid?: string }>(c.json(), "command", d.id, (id) =>
    lookupMasterKey(c.env, id),
  );
  const cmd = v.signed.body;
  const r = await hub(c.env, d.id).enqueue({
    deviceId: d.id,
    kind: "command",
    seq: v.signed.seq,
    envelopeJson: JSON.stringify(v.envelope),
    keyId: v.envelope.keyId,
    issuedAt: v.issuedAt,
    expiresAt: v.expiresAt,
    command: { commandId: cmd.commandId, type: cmd.type, userSid: cmd.userSid ?? null },
  });
  if (!r.ok) throw enqueueError(r);
  return json({ commandId: cmd.commandId, delivered: r.delivered }, 202);
}

export async function getCommand(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id, true);
  const row = await c.env.DB.prepare("SELECT status, ack_error, expires_at FROM commands WHERE id = ? AND device_id = ?")
    .bind(c.params.commandId, d.id)
    .first<{ status: string; ack_error: string | null; expires_at: string }>();
  if (!row) throw notFound("unknown command");
  const status = row.status === "queued" && row.expires_at <= nowIso() ? "expired" : row.status;
  return json(row.ack_error ? { status, error: row.ack_error } : { status });
}

// ------------------------------------------------------------------ history

const TYPE_ITEM_RE = /^[a-z_]+(\.[a-z_]+|\.\*)?$/;
const MAX_TYPE_ITEMS = 20;

/**
 * Parses an event-type filter (API.md section 5, `type` / `exclude`): comma list of exact types and/or
 * `prefix.*` entries. Returns null for an absent/empty value; throws 400 on a malformed entry.
 */
export function parseTypeFilter(raw: string | null, name: string): { exact: string[]; prefixes: string[] } | null {
  if (raw === null) return null;
  const items = raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  if (items.length === 0) return null;
  if (items.length > MAX_TYPE_ITEMS) throw new HttpError(400, "invalid_query", `${name}: at most ${MAX_TYPE_ITEMS} entries`);
  const exact: string[] = [];
  const prefixes: string[] = [];
  for (const it of items) {
    if (!TYPE_ITEM_RE.test(it)) throw new HttpError(400, "invalid_query", `${name} entries must be event types or prefix.*`);
    if (it.endsWith(".*")) prefixes.push(it.slice(0, -1)); // keeps the trailing dot: "web."
    else exact.push(it);
  }
  return { exact: [...new Set(exact)], prefixes: [...new Set(prefixes)] };
}

/** SQL condition matching a parsed type filter (`negate` for `exclude`). Prefixes contain only [a-z_.]. */
export function typeFilterSql(f: { exact: string[]; prefixes: string[] }, negate: boolean, col = "type"): [string, unknown[]] {
  const parts: string[] = [];
  const params: unknown[] = [];
  if (f.exact.length) {
    parts.push(`${col} IN (${f.exact.map(() => "?").join(", ")})`);
    params.push(...f.exact);
  }
  for (const p of f.prefixes) {
    // `_` is a LIKE wildcard; escape it so e.g. `request.*` can never match more than its literal prefix.
    parts.push(`${col} LIKE ? ESCAPE '\\'`);
    params.push(p.replace(/_/g, "\\_") + "%");
  }
  const any = `(${parts.join(" OR ")})`;
  return [negate ? `NOT ${any}` : any, params];
}

export async function listEvents(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id, true);
  const limit = parseLimit(c.url.searchParams.get("limit"), 50, 200);
  const include = parseTypeFilter(c.url.searchParams.get("type"), "type");
  const exclude = parseTypeFilter(c.url.searchParams.get("exclude"), "exclude");
  const sid = qSid(c);
  const w = where([
    ["device_id = ?", [d.id]],
    sid ? ["user_sid = ?", [sid]] : null,
    include ? typeFilterSql(include, false) : null,
    exclude ? typeFilterSql(exclude, true) : null,
    ...timeRange(c),
    cursorCond(c),
  ]);
  const rows = (
    await c.env.DB.prepare(
      `SELECT id, device_id, user_sid, ts, mono_ms, type, data_json FROM events ${w.sql} ORDER BY ts DESC, id DESC LIMIT ?`,
    ).bind(...w.params, limit + 1).all<{ id: string; device_id: string; user_sid: string | null; ts: string; mono_ms: number; type: string; data_json: string }>()
  ).results;
  const page = paginate(rows, limit, (r) => ({ ts: r.ts, id: r.id }));
  return json({
    items: page.items.map((r) => ({
      id: r.id,
      deviceId: r.device_id,
      ...(r.user_sid ? { userSid: r.user_sid } : {}),
      ts: r.ts,
      monoMs: r.mono_ms,
      type: r.type,
      data: JSON.parse(r.data_json),
    })),
    next: page.next,
  });
}

export async function listWeb(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id, true);
  const limit = parseLimit(c.url.searchParams.get("limit"), 50, 200);
  const kind = c.url.searchParams.get("kind");
  if (kind && !["visit", "search", "blocked"].includes(kind)) throw new HttpError(400, "invalid_query", "kind must be visit|search|blocked");
  const q = c.url.searchParams.get("q");
  if (q && q.length > 200) throw new HttpError(400, "invalid_query", "q too long");
  const like = q ? "%" + q.replace(/[\\%_]/g, (m) => "\\" + m) + "%" : null;
  const sid = qSid(c);
  const w = where([
    ["device_id = ?", [d.id]],
    sid ? ["user_sid = ?", [sid]] : null,
    kind ? ["kind = ?", [kind]] : null,
    like ? ["(url LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\')", [like, like, like]] : null,
    ...timeRange(c),
    cursorCond(c),
  ]);
  const rows = (
    await c.env.DB.prepare(
      `SELECT id, ts, kind, url, host, title, duration_sec, category FROM web_visits ${w.sql} ORDER BY ts DESC, id DESC LIMIT ?`,
    ).bind(...w.params, limit + 1).all<{ id: string; ts: string; kind: string; url: string | null; host: string | null; title: string | null; duration_sec: number | null; category: string | null }>()
  ).results;
  const page = paginate(rows, limit, (r) => ({ ts: r.ts, id: r.id }));
  return json({
    items: page.items.map((r) => webItem(r)),
    next: page.next,
  });
}

/** web_visits row -> API item. Search rows store the query in `title` and the engine in `category`/`host`. */
export function webItem(r: { ts: string; kind: string; url: string | null; host: string | null; title: string | null; duration_sec: number | null; category: string | null }) {
  const search = r.kind === "search";
  return {
    ts: r.ts,
    kind: r.kind,
    url: r.url,
    host: r.host,
    title: r.title,
    durationSec: r.duration_sec,
    category: r.category,
    query: search ? r.title : null,
    engine: search ? r.category : null,
  };
}

export async function getUsage(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id, true);
  let day = c.url.searchParams.get("day");
  if (day && !/^\d{4}-\d{2}-\d{2}$/.test(day)) throw new HttpError(400, "invalid_query", "day must be YYYY-MM-DD");
  day ||= localDay(Date.now(), d.timezone);
  const sid = qSid(c);
  const w = where([["device_id = ?", [d.id]], ["day = ?", [day]], sid ? ["user_sid = ?", [sid]] : null]);
  const rows = (
    await c.env.DB.prepare(
      `SELECT exe, MAX(grp) AS grp, SUM(active_sec) AS active_sec FROM usage_daily ${w.sql} GROUP BY exe ORDER BY active_sec DESC`,
    ).bind(...w.params).all<{ exe: string; grp: string; active_sec: number }>()
  ).results;
  return json({
    totalSec: rows.reduce((s, r) => s + r.active_sec, 0),
    apps: rows.map((r) => ({ exe: r.exe, group: r.grp || null, activeSec: r.active_sec })),
  });
}

export async function listScreenshots(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id, true);
  const limit = parseLimit(c.url.searchParams.get("limit"), 50, 200);
  const sid = qSid(c);
  const w = where([["device_id = ?", [d.id]], sid ? ["user_sid = ?", [sid]] : null, ...timeRange(c), cursorCond(c)]);
  const rows = (
    await c.env.DB.prepare(
      `SELECT id, ts, blob_key, width, height, foreground_exe FROM screenshots ${w.sql} ORDER BY ts DESC, id DESC LIMIT ?`,
    ).bind(...w.params, limit + 1).all<{ id: string; ts: string; blob_key: string; width: number; height: number; foreground_exe: string | null }>()
  ).results;
  const page = paginate(rows, limit, (r) => ({ ts: r.ts, id: r.id }));
  return json({
    items: page.items.map((r) => ({
      eventId: r.id,
      ts: r.ts,
      blobKey: r.blob_key,
      width: r.width,
      height: r.height,
      foregroundExe: r.foreground_exe,
    })),
    next: page.next,
  });
}

/** GET /v1/master/blobs/<key>: relayed on demand from the device through its DeviceHub (API.md section 9). */
export async function getBlob(c: Ctx): Promise<Response> {
  const key = c.params.key ?? "";
  const m = BLOB_KEY_RE.exec(key);
  if (!m) throw notFound("unknown blob");
  const r = await hub(c.env, m[1]!).requestBlob(key);
  if (r.status === "ok") {
    return new Response(r.bytes, {
      headers: { "content-type": "application/octet-stream", "content-length": String(r.bytes.length), "cache-control": "no-store" },
    });
  }
  if (r.status === "offline") throw new HttpError(409, "device_offline", "device is offline");
  if (r.status === "timeout") throw new HttpError(504, "device_timeout", "device did not respond");
  throw notFound("screenshot no longer on the device");
}

// ------------------------------------------------------------------ alerts & push

export async function listAlerts(c: Ctx): Promise<Response> {
  const limit = parseLimit(c.url.searchParams.get("limit"), 50, 200);
  const unacked = c.url.searchParams.get("unacked");
  if (unacked !== null && unacked !== "" && unacked !== "0" && unacked !== "1") {
    throw new HttpError(400, "invalid_query", "unacked must be 0 or 1");
  }
  const deviceId = c.url.searchParams.get("deviceId");
  if (deviceId && !ULID_RE.test(deviceId)) throw new HttpError(400, "invalid_query", "deviceId must be a ULID");
  const w = where([
    unacked === "1" ? ["acked_at IS NULL", []] : null,
    deviceId ? ["device_id = ?", [deviceId]] : null,
    cursorCond(c),
  ]);
  const rows = (
    await c.env.DB.prepare(
      `SELECT id, device_id, user_sid, ts, type, severity, data_json, acked_at FROM alerts ${w.sql} ORDER BY ts DESC, id DESC LIMIT ?`,
    ).bind(...w.params, limit + 1).all<{ id: string; device_id: string; user_sid: string | null; ts: string; type: string; severity: string; data_json: string; acked_at: string | null }>()
  ).results;
  const page = paginate(rows, limit, (r) => ({ ts: r.ts, id: r.id }));
  return json({
    items: page.items.map((r) => ({
      id: r.id,
      deviceId: r.device_id,
      userSid: r.user_sid,
      ts: r.ts,
      type: r.type,
      severity: r.severity,
      ackedAt: r.acked_at,
      data: JSON.parse(r.data_json),
    })),
    next: page.next,
  });
}

export async function ackAlert(c: Ctx): Promise<Response> {
  const id = c.params.id ?? "";
  if (!ULID_RE.test(id)) throw notFound("unknown alert");
  const r = await c.env.DB.prepare("UPDATE alerts SET acked_at = COALESCE(acked_at, ?) WHERE id = ?").bind(nowIso(), id).run();
  if (r.meta.changes === 0) throw notFound("unknown alert");
  return noContent();
}

export async function pushSubscribe(c: Ctx): Promise<Response> {
  const body = validateOrThrow<{ fcmToken: string }>(validatePushSubscribe, c.json(), "push subscribe request");
  const now = nowIso();
  await c.env.DB.prepare(
    `INSERT INTO push_subscriptions (id, fcm_token, master_key_id, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(fcm_token) DO UPDATE SET master_key_id = excluded.master_key_id, last_seen_at = excluded.last_seen_at`,
  ).bind(ulid(), body.fcmToken, c.master?.key_id ?? null, now, now).run();
  return noContent();
}


/** GET /v1/master/devices/:id/apps?user=<sid>: latest app inventory of one user (API.md section 11); 404 when none yet. */
export async function getApps(c: Ctx): Promise<Response> {
  const d = await requireDevice(c.env, c.params.id, true);
  const sid = qSid(c);
  if (!sid) throw new HttpError(400, "invalid_query", "user (SID) is required");
  const row = await c.env.DB.prepare("SELECT generated_at, apps_json FROM app_inventory WHERE device_id = ? AND user_sid = ?")
    .bind(d.id, sid).first<{ generated_at: string; apps_json: string }>();
  if (!row) throw notFound("no inventory yet");
  return json({ generatedAt: row.generated_at, apps: JSON.parse(row.apps_json) });
}
