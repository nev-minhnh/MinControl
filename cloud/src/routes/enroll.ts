// POST /v1/enroll (API.md section 1) and pairing-code issuance.
import type { Env } from "../env";
import { normalizePairingCode, randomCrockford } from "../lib/crypto";
import { b64urlDecode } from "../lib/encoding";
import { HttpError, json, parseJsonBytes, readBytes, validateOrThrow } from "../lib/http";
import { nowIso } from "../lib/time";
import { ulid } from "../lib/ulid";
import type { Ctx } from "../router";
import { validateEnrollRequest } from "../generated/validators";

export const PAIRING_TTL_MS = 15 * 60_000;
export const PAIRING_MAX_FAILED = 5;

interface EnrollBody {
  code: string;
  devicePubKey: string;
  hostname: string;
  osVersion: string;
  agentVersion: string;
  localUsers: { sid: string; name: string; isAdmin: boolean }[];
}

/** POST /v1/master/pairing-codes */
export async function createPairingCode(c: Ctx): Promise<Response> {
  const now = Date.now();
  const code = randomCrockford(8);
  const expiresAt = nowIso(now + PAIRING_TTL_MS);
  await c.env.DB.prepare("INSERT INTO pairing_codes (code, created_at, expires_at) VALUES (?, ?, ?)").bind(code, nowIso(now), expiresAt).run();
  return json({ code, expiresAt }, 201);
}

/**
 * A wrong code cannot be attributed to one pairing code, so every failed attempt counts against all
 * codes that are currently open; a code is dead after PAIRING_MAX_FAILED failures. With at most a few
 * open codes and 32^8 possibilities this caps an online guessing attack at 5 tries per code.
 */
async function recordFailedAttempt(env: Env, now: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE pairing_codes SET failed_attempts = failed_attempts + 1 WHERE used_at IS NULL AND expires_at > ? AND failed_attempts < ?",
  ).bind(now, PAIRING_MAX_FAILED).run();
}

export async function enroll(c: Ctx): Promise<Response> {
  const env = c.env;
  const body = validateOrThrow<EnrollBody>(validateEnrollRequest, parseJsonBytes(await readBytes(c.request, 64 * 1024)), "enroll request");
  const pub = b64urlDecode(body.devicePubKey);
  if (!pub || pub.length !== 32) throw new HttpError(400, "invalid_body", "devicePubKey must be a raw 32-byte Ed25519 key");
  const sids = new Set(body.localUsers.map((u) => u.sid));
  if (sids.size !== body.localUsers.length) throw new HttpError(400, "invalid_body", "duplicate SID in localUsers");

  const now = Date.now();
  const nowS = nowIso(now);
  const code = normalizePairingCode(body.code);
  if (!code) {
    await recordFailedAttempt(env, nowS);
    throw new HttpError(403, "invalid_code", "pairing code is invalid, expired or already used");
  }

  const [keys, seal] = await Promise.all([
    env.DB.prepare("SELECT key_id, alg, public_key FROM master_keys WHERE role = 'sign' AND revoked_at IS NULL ORDER BY created_at")
      .all<{ key_id: string; alg: string; public_key: string }>(),
    env.DB.prepare("SELECT v FROM config WHERE k = 'master_seal_pub_key'").first<{ v: string }>(),
  ]);
  if (keys.results.length === 0 || !seal) {
    throw new HttpError(409, "no_master", "no master is registered");
  }

  // Atomic single-use claim.
  const claimed = await env.DB.prepare(
    `UPDATE pairing_codes SET used_at = ? WHERE code = ? AND used_at IS NULL AND expires_at > ? AND failed_attempts < ? RETURNING code`,
  ).bind(nowS, code, nowS, PAIRING_MAX_FAILED).first<{ code: string }>();
  if (!claimed) {
    await recordFailedAttempt(env, nowS);
    throw new HttpError(403, "invalid_code", "pairing code is invalid, expired or already used");
  }

  const deviceId = ulid(now);
  const stmts = [
    env.DB.prepare(
      `INSERT INTO devices (id, hostname, os_version, agent_version, device_pub_key, enrolled_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(deviceId, body.hostname, body.osVersion, body.agentVersion, body.devicePubKey, nowS, nowS),
    ...body.localUsers.map((u) =>
      env.DB.prepare(
        "INSERT INTO managed_users (device_id, user_sid, name, is_admin, managed, updated_at) VALUES (?, ?, ?, ?, 0, ?)",
      ).bind(deviceId, u.sid, u.name, u.isAdmin ? 1 : 0, nowS),
    ),
    env.DB.prepare("UPDATE pairing_codes SET device_id = ? WHERE code = ?").bind(deviceId, code),
  ];
  await env.DB.batch(stmts);

  return json(
    {
      deviceId,
      serverTime: nowS,
      masterKeys: keys.results.map((k) => ({ keyId: k.key_id, alg: k.alg, publicKey: k.public_key })),
      masterSealPubKey: seal.v,
    },
    201,
  );
}
