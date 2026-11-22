// QR pairing initiated by the device (API.md section 10).
//
// Rate limit (10 starts / IP / hour): fixed window per UTC hour in the D1 table `claim_rate`
// (atomic upsert ... RETURNING); old buckets are purged by the hourly cron.
import { type SigAlg, keyIdOf, publicKeyLengthOk, randomBytes, randomCrockford, normalizePairingCode, sha256Hex, verifySignature } from "../lib/crypto";
import { b64urlDecode, b64urlEncode, utf8 } from "../lib/encoding";
import { HttpError, json, noContent, notFound, parseJsonBytes, readBytes, validateOrThrow } from "../lib/http";
import { nowIso, parseAuthTs } from "../lib/time";
import { ulid } from "../lib/ulid";
import type { Ctx } from "../router";
import { validateEnrollStartRequest, validateMasterRegisterWithClaim } from "../generated/validators";
import { type EnrollDeviceFields, insertDevice, loadMasterInfo } from "./enroll";

export const CLAIM_TTL_MS = 15 * 60_000;
export const CLAIM_RATE_LIMIT = 10;
export const POLL_SKEW_MS = 300_000;

interface ClaimRow {
  claim_id: string;
  code: string;
  device_pub_key: string;
  hostname: string;
  os_version: string | null;
  agent_version: string | null;
  local_users_json: string;
  expires_at: string;
  status: "pending" | "approved" | "rejected" | "expired";
  device_id: string | null;
}

const CLAIM_COLS = "claim_id, code, device_pub_key, hostname, os_version, agent_version, local_users_json, expires_at, status, device_id";
const CLAIM_ID_RE = /^[A-Za-z0-9_-]{22}$/;

/** First 12 hex chars of sha256(raw device public key). */
async function fingerprint(pubKeyB64: string): Promise<string> {
  return (await sha256Hex(b64urlDecode(pubKeyB64) ?? new Uint8Array(0))).slice(0, 12);
}

/** Effective status: a pending claim past its expiry is expired. */
export function effectiveStatus(row: Pick<ClaimRow, "status" | "expires_at">, now: number): ClaimRow["status"] {
  return row.status === "pending" && Date.parse(row.expires_at) <= now ? "expired" : row.status;
}

/** Fixed-window rate limit (CLAIM_RATE_LIMIT / key / UTC hour) on the `claim_rate` table. */
async function checkClaimRate(env: Ctx["env"], key: string, nowS: string): Promise<void> {
  const rate = await env.DB.prepare(
    "INSERT INTO claim_rate (ip, bucket, n) VALUES (?, ?, 1) ON CONFLICT (ip, bucket) DO UPDATE SET n = n + 1 RETURNING n",
  ).bind(key, nowS.slice(0, 13)).first<{ n: number }>();
  if ((rate?.n ?? 1) > CLAIM_RATE_LIMIT) throw new HttpError(429, "rate_limited", "too many pairing requests from this address");
}

/** POST /v1/enroll/start */
export async function enrollStart(c: Ctx): Promise<Response> {
  const env = c.env;
  const body = validateOrThrow<EnrollDeviceFields>(validateEnrollStartRequest, parseJsonBytes(await readBytes(c.request, 64 * 1024)), "enroll start request");
  const pub = b64urlDecode(body.devicePubKey);
  if (!pub || pub.length !== 32) throw new HttpError(400, "invalid_body", "devicePubKey must be a raw 32-byte Ed25519 key");
  if (new Set(body.localUsers.map((u) => u.sid)).size !== body.localUsers.length) {
    throw new HttpError(400, "invalid_body", "duplicate SID in localUsers");
  }

  const now = Date.now();
  const nowS = nowIso(now);
  const ip = c.request.headers.get("cf-connecting-ip") ?? "unknown";
  await checkClaimRate(env, ip, nowS);

  const claimId = b64urlEncode(randomBytes(16));
  const code = randomCrockford(8);
  const expiresAt = nowIso(now + CLAIM_TTL_MS);
  await env.DB.prepare(
    `INSERT INTO claims (claim_id, code, device_pub_key, hostname, os_version, agent_version, local_users_json, created_at, expires_at, status, created_ip)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
  ).bind(claimId, code, body.devicePubKey, body.hostname, body.osVersion, body.agentVersion, JSON.stringify(body.localUsers), nowS, expiresAt, ip).run();
  return json({ claimId, code, expiresAt }, 201);
}

/** GET /v1/enroll/claim/:claimId?ts=&sig= (device poll, Ed25519 over "poll|claimId|ts") */
export async function pollClaim(c: Ctx): Promise<Response> {
  const claimId = c.params.claimId!;
  const ts = c.url.searchParams.get("ts") ?? "";
  const sig = c.url.searchParams.get("sig") ?? "";
  const now = Date.now();
  const tsMs = parseAuthTs(ts);
  if (!CLAIM_ID_RE.test(claimId) || !Number.isFinite(tsMs) || Math.abs(now - tsMs) > POLL_SKEW_MS) {
    throw new HttpError(401, "stale_request", "poll timestamp missing or outside ±300 s");
  }
  const row = await c.env.DB.prepare(`SELECT ${CLAIM_COLS} FROM claims WHERE claim_id = ?`).bind(claimId).first<ClaimRow>();
  if (!row) throw notFound("claim not found");
  const pub = b64urlDecode(row.device_pub_key);
  const sigBytes = b64urlDecode(sig);
  if (!pub || !sigBytes || !(await verifySignature("ed25519", pub, sigBytes, utf8(`poll|${claimId}|${ts}`)))) {
    throw new HttpError(401, "bad_signature", "poll signature invalid");
  }
  const status = effectiveStatus(row, now);
  if (status === "expired" || status === "rejected") throw new HttpError(410, status, `claim ${status}`);
  if (status === "pending") return json({ status: "pending" }, 202);
  const master = await loadMasterInfo(c.env);
  return json({ status: "approved", deviceId: row.device_id, serverTime: nowIso(now), ...master });
}

async function claimView(row: ClaimRow, now: number, withId: boolean) {
  const status = effectiveStatus(row, now);
  if (status !== "pending") throw new HttpError(410, status === "approved" ? "already_approved" : status, `claim ${status}`);
  return {
    ...(withId ? { claimId: row.claim_id } : {}),
    hostname: row.hostname,
    osVersion: row.os_version ?? "",
    localUsers: JSON.parse(row.local_users_json) as unknown,
    fp: await fingerprint(row.device_pub_key),
    expiresAt: row.expires_at,
  };
}

/** GET /v1/master/claims/:claimId */
export async function getClaim(c: Ctx): Promise<Response> {
  const row = await c.env.DB.prepare(`SELECT ${CLAIM_COLS} FROM claims WHERE claim_id = ?`).bind(c.params.claimId!).first<ClaimRow>();
  if (!row) throw notFound("claim not found");
  return json(await claimView(row, Date.now(), false));
}

/** GET /v1/master/claims/by-code/:code */
export async function getClaimByCode(c: Ctx): Promise<Response> {
  const code = normalizePairingCode(c.params.code!);
  if (!code) throw notFound("claim not found");
  const row = await c.env.DB.prepare(`SELECT ${CLAIM_COLS} FROM claims WHERE code = ? ORDER BY created_at DESC LIMIT 1`).bind(code).first<ClaimRow>();
  if (!row) throw notFound("claim not found");
  return json(await claimView(row, Date.now(), true));
}

/** POST /v1/master/claims/:claimId/approve - sign-role key only (biometric on the phone). */
export async function approveClaim(c: Ctx): Promise<Response> {
  if (c.master?.role !== "sign") throw new HttpError(403, "sign_key_required", "approving a claim requires a sign-role key");
  const env = c.env;
  const claimId = c.params.claimId!;
  const row = await env.DB.prepare(`SELECT ${CLAIM_COLS} FROM claims WHERE claim_id = ?`).bind(claimId).first<ClaimRow>();
  if (!row) throw notFound("claim not found");
  const now = Date.now();
  const status = effectiveStatus(row, now);
  if (status !== "pending") throw new HttpError(410, status === "approved" ? "already_approved" : status, `claim ${status}`);
  await loadMasterInfo(env); // 409 if no master / sign key

  const nowS = nowIso(now);
  const deviceId = ulid(now);
  // Atomic single use: only one concurrent approval wins the pending -> approved transition.
  const won = await env.DB.prepare(
    "UPDATE claims SET status = 'approved', device_id = ?, approved_by = ? WHERE claim_id = ? AND status = 'pending' AND expires_at > ? RETURNING claim_id",
  ).bind(deviceId, c.master.key_id, claimId, nowS).first<{ claim_id: string }>();
  if (!won) throw new HttpError(410, "already_approved", "claim already used or expired");
  try {
    await insertDevice(
      env,
      deviceId,
      {
        devicePubKey: row.device_pub_key,
        hostname: row.hostname,
        osVersion: row.os_version ?? "",
        agentVersion: row.agent_version ?? "",
        localUsers: JSON.parse(row.local_users_json) as EnrollDeviceFields["localUsers"],
      },
      nowS,
    );
  } catch (e) {
    await env.DB.prepare("UPDATE claims SET status = 'pending', device_id = NULL, approved_by = NULL WHERE claim_id = ?").bind(claimId).run();
    throw e;
  }
  return json({ deviceId }, 201);
}

/** POST /v1/master/claims/:claimId/reject */
export async function rejectClaim(c: Ctx): Promise<Response> {
  const r = await c.env.DB.prepare(
    "UPDATE claims SET status = 'rejected' WHERE claim_id = ? AND status = 'pending' AND expires_at > ? RETURNING claim_id",
  ).bind(c.params.claimId!, nowIso()).first();
  if (!r) {
    const exists = await c.env.DB.prepare("SELECT 1 AS x FROM claims WHERE claim_id = ?").bind(c.params.claimId!).first();
    throw exists ? new HttpError(410, "not_pending", "claim is no longer pending") : notFound("claim not found");
  }
  return noContent();
}

interface RegisterWithClaimBody {
  claimId: string;
  keys: { keyId: string; alg: SigAlg; publicKey: string; role: "sign" | "read" }[];
  sealPubKey: string;
  sig: string;
}

const noActiveMaster = async (env: Ctx["env"]) =>
  (await env.DB.prepare("SELECT 1 AS x FROM master_keys WHERE revoked_at IS NULL LIMIT 1").first()) === null;

/**
 * POST /v1/master/register-with-claim (API.md section 12; no X-MC-Auth, trust on first use).
 * One D1 batch (a transaction): the claim UPDATE only matches while the claim is pending, unexpired and no
 * active master key exists; every later statement is guarded by "this claim now carries my deviceId", so
 * two racing phones cannot both win and nothing else is written when the first statement matches no row.
 */
export async function registerWithClaim(c: Ctx): Promise<Response> {
  const env = c.env;
  const body = validateOrThrow<RegisterWithClaimBody>(validateMasterRegisterWithClaim, parseJsonBytes(await readBytes(c.request, 32 * 1024)), "register-with-claim request");
  const ids = new Set<string>();
  let signKey: RegisterWithClaimBody["keys"][number] | undefined;
  for (const k of body.keys) {
    const raw = b64urlDecode(k.publicKey);
    if (!raw || !publicKeyLengthOk(k.alg, raw)) throw new HttpError(400, "invalid_body", `publicKey of ${k.keyId} has the wrong size for ${k.alg}`);
    if ((await keyIdOf(raw)) !== k.keyId) throw new HttpError(400, "invalid_body", `keyId ${k.keyId} does not match sha256(publicKey)`);
    if (ids.has(k.keyId)) throw new HttpError(400, "invalid_body", "duplicate keyId");
    ids.add(k.keyId);
    if (k.role === "sign" && !signKey) signKey = k;
  }
  if (!signKey) throw new HttpError(400, "invalid_body", "at least one sign key is required");
  const seal = b64urlDecode(body.sealPubKey);
  if (!seal || seal.length !== 32) throw new HttpError(400, "invalid_body", "sealPubKey must be a raw 32-byte X25519 key");
  const sigBytes = b64urlDecode(body.sig);
  if (!sigBytes || !(await verifySignature(signKey.alg, b64urlDecode(signKey.publicKey)!, sigBytes, utf8("register|" + body.claimId)))) {
    throw new HttpError(400, "bad_signature", "sig does not verify with the sign key over register|claimId");
  }

  const now = Date.now();
  const nowS = nowIso(now);
  await checkClaimRate(env, "reg|" + (c.request.headers.get("cf-connecting-ip") ?? "unknown"), nowS);

  const masterExists = () => new HttpError(409, "master_exists", "a master is already registered on this server");
  const claimGone = (row: ClaimRow) => {
    const st = effectiveStatus(row, Date.now());
    return new HttpError(410, st === "approved" ? "already_approved" : st, `claim ${st}`);
  };
  const loadClaim = () => env.DB.prepare(`SELECT ${CLAIM_COLS} FROM claims WHERE claim_id = ?`).bind(body.claimId).first<ClaimRow>();

  const row = await loadClaim();
  if (!row) throw notFound("claim not found");
  if (!(await noActiveMaster(env))) throw masterExists();
  if (effectiveStatus(row, now) !== "pending") throw claimGone(row);

  const deviceId = ulid(now);
  const mine = "EXISTS (SELECT 1 FROM claims WHERE claim_id = ? AND device_id = ?)";
  const users = JSON.parse(row.local_users_json) as EnrollDeviceFields["localUsers"];
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE claims SET status = 'approved', device_id = ?, approved_by = ?
       WHERE claim_id = ? AND status = 'pending' AND expires_at > ?
         AND NOT EXISTS (SELECT 1 FROM master_keys WHERE revoked_at IS NULL)`,
    ).bind(deviceId, signKey.keyId, body.claimId, nowS),
    ...body.keys.map((k) =>
      env.DB.prepare(
        `INSERT OR REPLACE INTO master_keys (key_id, alg, public_key, role, created_at, revoked_at)
         SELECT ?, ?, ?, ?, ?, NULL WHERE ${mine}`,
      ).bind(k.keyId, k.alg, k.publicKey, k.role, nowS, body.claimId, deviceId),
    ),
    env.DB.prepare(`INSERT OR REPLACE INTO config (k, v, updated_at) SELECT 'master_seal_pub_key', ?, ? WHERE ${mine}`)
      .bind(body.sealPubKey, nowS, body.claimId, deviceId),
    env.DB.prepare(
      `INSERT INTO devices (id, hostname, os_version, agent_version, device_pub_key, enrolled_at, last_seen_at)
       SELECT ?, ?, ?, ?, ?, ?, ? WHERE ${mine}`,
    ).bind(deviceId, row.hostname, row.os_version ?? "", row.agent_version ?? "", row.device_pub_key, nowS, nowS, body.claimId, deviceId),
    ...users.map((u) =>
      env.DB.prepare(
        `INSERT INTO managed_users (device_id, user_sid, name, is_admin, managed, updated_at)
         SELECT ?, ?, ?, ?, 0, ? WHERE ${mine}`,
      ).bind(deviceId, u.sid, u.name, u.isAdmin ? 1 : 0, nowS, body.claimId, deviceId),
    ),
  ]);
  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    if (!(await noActiveMaster(env))) throw masterExists();
    const again = await loadClaim();
    throw again ? claimGone(again) : notFound("claim not found");
  }
  return json({ deviceId, keys: body.keys.map((k) => ({ keyId: k.keyId, role: k.role })) }, 201);
}
