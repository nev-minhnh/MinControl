// Changing the parent's phone (API.md section 13A).
//
// Pending-keys design: the new phone's keys live ONLY in the `transfers` row (new_keys_json,
// new_seal_pub_key) until /complete; `master_keys` is untouched before that, so a claimed but unconfirmed
// transfer cannot authenticate anything. /complete activates them in one D1 batch.
import type { DeviceHub } from "../device-hub";
import { verifyEnvelope } from "../envelope";
import { type SigAlg, keyIdOf, publicKeyLengthOk, randomBytes, sha256Hex, verifySignature } from "../lib/crypto";
import { b64urlDecode, b64urlEncode, utf8 } from "../lib/encoding";
import { HttpError, json, notFound, parseJsonBytes, readBytes, validateOrThrow } from "../lib/http";
import { nowIso } from "../lib/time";
import { ULID_RE, ulid } from "../lib/ulid";
import { type Ctx, lookupMasterKey } from "../router";
import { validateTransferClaim, validateTransferComplete } from "../generated/validators";
import { checkClaimRate } from "./claims";

export const TRANSFER_TTL_MS = 10 * 60_000;
/** master_keys envelopes are valid for 30 days (+1 day slack). */
const MAX_ENVELOPE_LIFETIME_MS = 31 * 86_400_000;

interface Key {
  keyId: string;
  alg: SigAlg;
  publicKey: string;
  role: "sign" | "read";
}

interface TransferRow {
  id: string;
  created_by_key: string;
  status: "pending" | "claimed" | "done" | "expired";
  expires_at: string;
  new_keys_json: string | null;
  new_seal_pub_key: string | null;
  transport_pub_key: string | null;
  sealed_seal_key: string | null;
}

const COLS = "id, created_by_key, status, expires_at, new_keys_json, new_seal_pub_key, transport_pub_key, sealed_seal_key";
const hub = (env: Ctx["env"], deviceId: string) => env.DEVICE_HUB.get(env.DEVICE_HUB.idFromName(deviceId)) as DurableObjectStub<DeviceHub>;

const effective = (r: TransferRow, now: number): TransferRow["status"] =>
  (r.status === "pending" || r.status === "claimed") && Date.parse(r.expires_at) <= now ? "expired" : r.status;

async function loadTransfer(c: Ctx, id: string | undefined): Promise<TransferRow> {
  if (!id || !ULID_RE.test(id)) throw notFound("unknown transfer");
  const row = await c.env.DB.prepare(`SELECT ${COLS} FROM transfers WHERE id = ?`).bind(id).first<TransferRow>();
  if (!row) throw notFound("unknown transfer");
  return row;
}

const requireSign = (c: Ctx) => {
  if (c.master?.role !== "sign") throw new HttpError(403, "sign_key_required", "this request requires a sign-role key");
  return c.master;
};

/** POST /v1/master/transfers (sign key) -> 201 {transferId, token, expiresAt} */
export async function createTransfer(c: Ctx): Promise<Response> {
  const master = requireSign(c);
  const now = Date.now();
  const nowS = nowIso(now);
  const id = ulid(now);
  const token = b64urlEncode(randomBytes(32));
  const expiresAt = nowIso(now + TRANSFER_TTL_MS);
  await c.env.DB.batch([
    // Only one transfer can be in flight: older unfinished ones are expired.
    c.env.DB.prepare("UPDATE transfers SET status = 'expired' WHERE status IN ('pending', 'claimed')"),
    c.env.DB.prepare(
      "INSERT INTO transfers (id, token_hash, created_by_key, status, expires_at, created_at) VALUES (?, ?, ?, 'pending', ?, ?)",
    ).bind(id, await sha256Hex(token), master.key_id, expiresAt, nowS),
  ]);
  return json({ transferId: id, token, expiresAt }, 201);
}

/** GET /v1/master/transfers/:id - old keys while pending/claimed, the NEW keys once done. */
export async function getTransfer(c: Ctx): Promise<Response> {
  const row = await loadTransfer(c, c.params.id);
  const status = effective(row, Date.now());
  if (status === "done") {
    const keys = JSON.parse(row.new_keys_json ?? "[]") as Key[];
    if (!keys.some((k) => k.keyId === c.master!.key_id)) throw new HttpError(403, "forbidden", "transfer result is only for the new phone");
    return json({ status: "done", sealedSealKey: row.sealed_seal_key });
  }
  if (status === "expired") return json({ status: "expired" });
  if (status === "claimed") {
    const keys = JSON.parse(row.new_keys_json ?? "[]") as Key[];
    const sign = keys.find((k) => k.role === "sign");
    return json({
      status: "claimed",
      newKeys: keys,
      sealPubKey: row.new_seal_pub_key,
      transportPubKey: row.transport_pub_key,
      fp: sign ? sign.keyId.slice(0, 12) : "", // first 12 hex of sha256(new sign public key) = keyId prefix
      expiresAt: row.expires_at,
    });
  }
  return json({ status: "pending", expiresAt: row.expires_at });
}

interface ClaimBody {
  token: string;
  keys: Key[];
  sealPubKey: string;
  transportPubKey: string;
  sig: string;
}

/** POST /v1/master/transfers/claim (no auth; single-use token, sig by the new sign key over "transfer|"+token). */
export async function claimTransfer(c: Ctx): Promise<Response> {
  const env = c.env;
  const body = validateOrThrow<ClaimBody>(validateTransferClaim, parseJsonBytes(await readBytes(c.request, 32 * 1024)), "transfer claim");
  const now = Date.now();
  const nowS = nowIso(now);
  await checkClaimRate(env, "xfer|" + (c.request.headers.get("cf-connecting-ip") ?? "unknown"), nowS);

  const row = await env.DB.prepare(`SELECT ${COLS} FROM transfers WHERE token_hash = ?`).bind(await sha256Hex(body.token)).first<TransferRow>();
  if (!row) throw new HttpError(404, "invalid_token", "unknown transfer token");
  const st = effective(row, now);
  if (st === "expired") throw new HttpError(410, "expired", "transfer expired");
  if (st !== "pending") throw new HttpError(410, "token_used", "transfer token already used");

  const ids = new Set<string>();
  let sign: Key | undefined;
  let hasRead = false;
  for (const k of body.keys) {
    const raw = b64urlDecode(k.publicKey);
    if (!raw || !publicKeyLengthOk(k.alg, raw)) throw new HttpError(400, "invalid_body", `publicKey of ${k.keyId} has the wrong size for ${k.alg}`);
    if ((await keyIdOf(raw)) !== k.keyId) throw new HttpError(400, "invalid_body", `keyId ${k.keyId} does not match sha256(publicKey)`);
    if (ids.has(k.keyId)) throw new HttpError(400, "invalid_body", "duplicate keyId");
    ids.add(k.keyId);
    if (k.role === "sign") sign ??= k;
    else hasRead = true;
  }
  if (!sign || !hasRead) throw new HttpError(400, "invalid_body", "a sign key and a read key are required");
  for (const f of [body.sealPubKey, body.transportPubKey]) {
    const raw = b64urlDecode(f);
    if (!raw || raw.length !== 32) throw new HttpError(400, "invalid_body", "sealPubKey/transportPubKey must be raw 32-byte X25519 keys");
  }
  const sig = b64urlDecode(body.sig);
  if (!sig || !(await verifySignature(sign.alg, b64urlDecode(sign.publicKey)!, sig, utf8("transfer|" + body.token)))) {
    throw new HttpError(400, "bad_signature", "sig does not verify with the new sign key over transfer|token");
  }
  // New keyIds must never have been used (a revoked old key must not be resurrected).
  for (const id of ids) {
    if (await env.DB.prepare("SELECT 1 AS x FROM master_keys WHERE key_id = ?").bind(id).first()) {
      throw new HttpError(409, "key_exists", "a key with this keyId is already known to the server");
    }
  }

  // Atomic single use; the new phone then has a further TTL to be confirmed on the old phone.
  const won = await env.DB.prepare(
    `UPDATE transfers SET status = 'claimed', new_keys_json = ?, new_seal_pub_key = ?, transport_pub_key = ?, expires_at = ?
     WHERE id = ? AND status = 'pending' AND expires_at > ? RETURNING id`,
  ).bind(JSON.stringify(body.keys), body.sealPubKey, body.transportPubKey, nowIso(now + TRANSFER_TTL_MS), row.id, nowS).first<{ id: string }>();
  if (!won) throw new HttpError(410, "token_used", "transfer token already used or expired");
  return json({ transferId: row.id, status: "pending" }, 202);
}

interface CompleteBody {
  envelopes: Record<string, unknown>;
  sealedSealKey: string;
}

interface MasterKeysBody {
  keys: Key[];
  sealPubKey: string;
}

/** POST /v1/master/transfers/:id/complete (old sign key) */
export async function completeTransfer(c: Ctx): Promise<Response> {
  requireSign(c);
  const env = c.env;
  const t = await loadTransfer(c, c.params.id);
  const now = Date.now();
  const st = effective(t, now);
  if (st === "expired") throw new HttpError(410, "expired", "transfer expired");
  if (st !== "claimed") throw new HttpError(409, "not_claimed", `transfer is ${st}`);
  const body = validateOrThrow<CompleteBody>(validateTransferComplete, c.json(), "transfer complete");

  const newKeys = JSON.parse(t.new_keys_json ?? "[]") as Key[];
  const newSign = newKeys.filter((k) => k.role === "sign");

  const devices = (await env.DB.prepare("SELECT id FROM devices WHERE revoked_at IS NULL").all<{ id: string }>()).results.map((r) => r.id);
  const missing = devices.filter((d) => !(d in body.envelopes));
  if (missing.length) throw new HttpError(400, "missing_device_envelope", "an envelope is required for every non-revoked device", { deviceIds: missing });
  const extra = Object.keys(body.envelopes).filter((d) => !devices.includes(d));
  if (extra.length) throw new HttpError(400, "unknown_device_envelope", "envelope for an unknown or revoked device", { deviceIds: extra });

  const queued: { deviceId: string; seq: number; envelopeJson: string; keyId: string; issuedAt: string; expiresAt: string }[] = [];
  for (const deviceId of devices) {
    const v = await verifyEnvelope<MasterKeysBody>(body.envelopes[deviceId], "master_keys", deviceId, (id) => lookupMasterKey(env, id), now);
    const b = v.signed.body;
    const same =
      b.sealPubKey === t.new_seal_pub_key &&
      b.keys.length === newSign.length &&
      newSign.every((k) => b.keys.some((x) => x.keyId === k.keyId && x.alg === k.alg && x.publicKey === k.publicKey && x.role === "sign"));
    if (!same) throw new HttpError(400, "wrong_keys", `master_keys body of ${deviceId} does not match the claimed new keys`);
    if (Date.parse(v.expiresAt) - Date.parse(v.issuedAt) > MAX_ENVELOPE_LIFETIME_MS) {
      throw new HttpError(400, "invalid_body", "master_keys envelope lifetime must be at most 30 days");
    }
    queued.push({ deviceId, seq: v.signed.seq, envelopeJson: JSON.stringify(v.envelope), keyId: v.envelope.keyId, issuedAt: v.issuedAt, expiresAt: v.expiresAt });
  }
  // Early seq check per device (the DO re-checks atomically when it queues).
  for (const q of queued) {
    const last = (await hub(env, q.deviceId).getSeq()).masterKeys;
    if (q.seq <= last) throw new HttpError(409, "replayed", `master_keys seq of ${q.deviceId} must be greater than ${last}`, { deviceId: q.deviceId, lastSeq: last });
  }

  // ONE atomic batch. The first statement only matches a claimed, unexpired transfer and stamps a random nonce;
  // every later statement is guarded by that nonce, so a racing second /complete changes nothing.
  const nonce = b64urlEncode(randomBytes(16));
  const nowS = nowIso(now);
  const guard = "EXISTS (SELECT 1 FROM transfers WHERE id = ? AND complete_nonce = ?)";
  const stmts = [
    env.DB.prepare(
      `UPDATE transfers SET status = 'done', sealed_seal_key = ?, complete_nonce = ?, completed_at = ?
       WHERE id = ? AND status = 'claimed' AND expires_at > ?`,
    ).bind(body.sealedSealKey, nonce, nowS, t.id, nowS),
    env.DB.prepare(`UPDATE master_keys SET revoked_at = ? WHERE revoked_at IS NULL AND ${guard}`).bind(nowS, t.id, nonce),
    ...newKeys.map((k) =>
      env.DB.prepare(`INSERT INTO master_keys (key_id, alg, public_key, role, created_at, revoked_at) SELECT ?, ?, ?, ?, ?, NULL WHERE ${guard}`)
        .bind(k.keyId, k.alg, k.publicKey, k.role, nowS, t.id, nonce),
    ),
    env.DB.prepare(`INSERT OR REPLACE INTO config (k, v, updated_at) SELECT 'master_seal_pub_key', ?, ? WHERE ${guard}`)
      .bind(t.new_seal_pub_key, nowS, t.id, nonce),
    ...queued.map((q) =>
      env.DB.prepare(`INSERT INTO transfer_devices (transfer_id, device_id, seq, status, updated_at) SELECT ?, ?, ?, 'queued', ? WHERE ${guard}`)
        .bind(t.id, q.deviceId, q.seq, nowS, t.id, nonce),
    ),
  ];
  const results = await env.DB.batch(stmts);
  if ((results[0]?.meta?.changes ?? 0) !== 1) throw new HttpError(409, "not_claimed", "transfer is no longer claimable");

  // Queue to every DeviceHub (delivered before policy/commands). The keys are already switched, so a failure
  // here can only be a device revoked in between; log and carry on.
  const outcomes = await Promise.all(
    queued.map(async (q) => {
      try {
        const r = await hub(env, q.deviceId).enqueue({
          deviceId: q.deviceId,
          kind: "master_keys",
          seq: q.seq,
          envelopeJson: q.envelopeJson,
          keyId: q.keyId,
          issuedAt: q.issuedAt,
          expiresAt: q.expiresAt,
          masterKeys: { transferId: t.id },
        });
        return { deviceId: q.deviceId, queued: r.ok, delivered: r.ok && r.delivered };
      } catch (e) {
        console.error("transfer: enqueue failed", q.deviceId, e instanceof Error ? e.message : e);
        return { deviceId: q.deviceId, queued: false, delivered: false };
      }
    }),
  );
  return json({ status: "done", devices: outcomes });
}
