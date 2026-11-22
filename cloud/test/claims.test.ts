import { describe, expect, it } from "vitest";
import { requestSigningString } from "../src/auth/master";
import { runCron } from "../src/cron";
import worker, { type Env } from "../src/index";
import { keyIdOf, sha256Hex } from "../src/lib/crypto";
import { b64urlEncode, utf8 } from "../src/lib/encoding";

// ---- minimal in-memory D1 fake: only the statements used by the claims flow -----------------------------------
type Row = Record<string, any>;
function fakeDb() {
  const t = { claims: new Map<string, Row>(), rate: new Map<string, number>(), devices: new Map<string, Row>(), users: [] as Row[], keys: [] as Row[], deleted: [] as string[] };
  const exec = (sql: string, a: any[]): { first?: Row | null; all?: Row[] } => {
    if (sql.startsWith("INSERT INTO claim_rate")) {
      const k = `${a[0]}|${a[1]}`;
      t.rate.set(k, (t.rate.get(k) ?? 0) + 1);
      return { first: { n: t.rate.get(k) } };
    }
    if (sql.startsWith("INSERT INTO claims")) {
      t.claims.set(a[0], { claim_id: a[0], code: a[1], device_pub_key: a[2], hostname: a[3], os_version: a[4], agent_version: a[5], local_users_json: a[6], created_at: a[7], expires_at: a[8], status: "pending", device_id: null, approved_by: null });
      return {};
    }
    if (sql.includes("FROM claims WHERE claim_id")) return { first: t.claims.get(a[0]) ?? null };
    if (sql.includes("FROM claims WHERE code")) return { first: [...t.claims.values()].find((c) => c.code === a[0]) ?? null };
    if (sql.startsWith("UPDATE claims SET status = 'approved'")) {
      const c = t.claims.get(a[2]);
      if (!c || c.status !== "pending" || !(c.expires_at > a[3])) return { first: null };
      Object.assign(c, { status: "approved", device_id: a[0], approved_by: a[1] });
      return { first: { claim_id: c.claim_id } };
    }
    if (sql.startsWith("UPDATE claims SET status = 'rejected'")) {
      const c = t.claims.get(a[0]);
      if (!c || c.status !== "pending" || !(c.expires_at > a[1])) return { first: null };
      c.status = "rejected";
      return { first: { claim_id: c.claim_id } };
    }
    if (sql.startsWith("SELECT 1 AS x FROM claims")) return { first: t.claims.has(a[0]) ? { x: 1 } : null };
    if (sql.includes("FROM master_keys WHERE role = 'sign'")) return { all: t.keys.filter((k) => k.role === "sign") };
    if (sql.includes("FROM master_keys WHERE key_id")) return { first: t.keys.find((k) => k.key_id === a[0]) ?? null };
    if (sql.includes("FROM config")) return { first: { v: "SEAL" } };
    if (sql.startsWith("INSERT INTO devices")) { t.devices.set(a[0], { id: a[0], hostname: a[1], device_pub_key: a[4] }); return {}; }
    if (sql.startsWith("INSERT INTO managed_users")) { t.users.push({ device_id: a[0], user_sid: a[1], name: a[2] }); return {}; }
    if (sql.startsWith("DELETE FROM")) { t.deleted.push(sql); return {}; }
    if (sql.startsWith("SELECT id, hostname, timezone")) return { all: [] };
    return {};
  };
  const stmt = (sql: string, a: any[] = []) => ({
    bind: (...b: any[]) => stmt(sql, b),
    first: async () => exec(sql, a).first ?? null,
    all: async () => ({ results: exec(sql, a).all ?? [] }),
    run: async () => (exec(sql, a), {}),
    _run: () => exec(sql, a),
  });
  const db = { prepare: (s: string) => stmt(s), batch: async (l: any[]) => l.map((s) => s._run()) };
  return { db: db as unknown as D1Database, t };
}

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const ED = { name: "Ed25519" };
async function keypair() {
  const kp = (await crypto.subtle.generateKey(ED, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  const sign = async (s: string) => b64urlEncode(new Uint8Array(await crypto.subtle.sign(ED, kp.privateKey, utf8(s))));
  return { raw, pub: b64urlEncode(raw), sign, keyId: await keyIdOf(raw) };
}

async function setup() {
  const { db, t } = fakeDb();
  const sign = await keypair();
  const read = await keypair();
  t.keys.push({ key_id: sign.keyId, alg: "ed25519", public_key: sign.pub, role: "sign" });
  t.keys.push({ key_id: read.keyId, alg: "ed25519", public_key: read.pub, role: "read" });
  const env = { DB: db } as unknown as Env;
  const call = (method: string, path: string, init: RequestInit = {}) =>
    worker.fetch(new Request(`https://example.test${path}`, { method, ...init }), env, ctx);
  const master = async (k: typeof sign, method: string, path: string, ts = String(Math.floor(Date.now() / 1000))) => {
    const sig = await k.sign(await requestSigningString(method, path, ts, new Uint8Array(0)));
    return call(method, path, { headers: { "x-mc-auth": `v1;${k.keyId};${ts};${sig}` } });
  };
  const device = await keypair();
  const start = await call("POST", "/v1/enroll/start", {
    headers: { "cf-connecting-ip": "1.2.3.4" },
    body: JSON.stringify({ devicePubKey: device.pub, hostname: "PC-BIN", osVersion: "10.0", agentVersion: "0.1.0", localUsers: [{ sid: "S-1-5-21-1-2-3-1001", name: "Bin", isAdmin: false }] }),
  });
  const claim = (await start.json()) as { claimId: string; code: string; expiresAt: string };
  const poll = async (k = device, ts = String(Math.floor(Date.now() / 1000)), sigFor = k) => {
    const sig = await sigFor.sign(`poll|${claim.claimId}|${ts}`);
    return call("GET", `/v1/enroll/claim/${claim.claimId}?ts=${ts}&sig=${sig}`);
  };
  return { env, t, call, master, sign, read, device, claim, start, poll };
}

describe("enroll start + claims", () => {
  it("start returns claimId (16 B), 8-char Crockford code, 15 min expiry", async () => {
    const s = await setup();
    expect(s.start.status).toBe(201);
    expect(s.claim.claimId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(s.claim.code).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/);
    expect(Date.parse(s.claim.expiresAt) - Date.now()).toBeGreaterThan(14 * 60_000);
  });

  it("rate limits the 11th start per IP per hour", async () => {
    const s = await setup(); // 1 used
    const body = (await s.t.claims.get(s.claim.claimId)) as Row;
    const req = () =>
      s.call("POST", "/v1/enroll/start", {
        headers: { "cf-connecting-ip": "1.2.3.4" },
        body: JSON.stringify({ devicePubKey: body.device_pub_key, hostname: "H", osVersion: "1", agentVersion: "1", localUsers: [] }),
      });
    for (let i = 0; i < 9; i++) expect((await req()).status).toBe(201);
    expect((await req()).status).toBe(429);
  });

  it("poll: pending 202; bad signature, other key and stale ts -> 401", async () => {
    const s = await setup();
    expect((await s.poll()).status).toBe(202);
    expect((await s.poll(s.device, undefined, await keypair())).status).toBe(401);
    expect(((await (await s.poll(s.device, undefined, await keypair())).json()) as any).error).toBe("bad_signature");
    const stale = String(Math.floor(Date.now() / 1000) - 400);
    const res = await s.poll(s.device, stale);
    expect(res.status).toBe(401);
    expect(((await res.json()) as any).error).toBe("stale_request");
  });

  it("approve requires a sign-role key (read key -> 403), then creates the device once", async () => {
    const s = await setup();
    const path = `/v1/master/claims/${s.claim.claimId}/approve`;
    expect((await s.master(s.read, "POST", path)).status).toBe(403);
    expect(s.t.devices.size).toBe(0);

    const ok = await s.master(s.sign, "POST", path);
    expect(ok.status).toBe(201);
    const { deviceId } = (await ok.json()) as { deviceId: string };
    expect(s.t.devices.get(deviceId)?.hostname).toBe("PC-BIN");
    expect(s.t.users).toHaveLength(1);
    expect(s.t.claims.get(s.claim.claimId)?.approved_by).toBe(s.sign.keyId);

    // single use
    expect((await s.master(s.sign, "POST", path)).status).toBe(410);
    expect(s.t.devices.size).toBe(1);

    // device now gets the enrolment response
    const polled = await s.poll();
    expect(polled.status).toBe(200);
    expect(await polled.json()).toMatchObject({ status: "approved", deviceId, masterSealPubKey: "SEAL", masterKeys: [{ keyId: s.sign.keyId }] });
  });

  it("expired claim -> 410 expired for device poll, master view and approve", async () => {
    const s = await setup();
    s.t.claims.get(s.claim.claimId)!.expires_at = new Date(Date.now() - 1000).toISOString();
    const res = await s.poll();
    expect(res.status).toBe(410);
    expect(((await res.json()) as any).error).toBe("expired");
    expect((await s.master(s.read, "GET", `/v1/master/claims/${s.claim.claimId}`)).status).toBe(410);
    expect((await s.master(s.sign, "POST", `/v1/master/claims/${s.claim.claimId}/approve`)).status).toBe(410);
    expect(s.t.devices.size).toBe(0);
  });

  it("reject -> 204, device sees 410 rejected, approve afterwards fails", async () => {
    const s = await setup();
    expect((await s.master(s.read, "POST", `/v1/master/claims/${s.claim.claimId}/reject`)).status).toBe(204);
    const res = await s.poll();
    expect(res.status).toBe(410);
    expect(((await res.json()) as any).error).toBe("rejected");
    expect((await s.master(s.sign, "POST", `/v1/master/claims/${s.claim.claimId}/approve`)).status).toBe(410);
  });

  it("GET claim and by-code return hostname, localUsers and the 12-hex fingerprint", async () => {
    const s = await setup();
    const fp = (await sha256Hex(s.device.raw)).slice(0, 12);
    const a = (await (await s.master(s.read, "GET", `/v1/master/claims/${s.claim.claimId}`)).json()) as any;
    expect(a).toMatchObject({ hostname: "PC-BIN", fp, localUsers: [{ name: "Bin" }] });
    const dashed = `${s.claim.code.slice(0, 4)}-${s.claim.code.slice(4)}`;
    const b = (await (await s.master(s.read, "GET", `/v1/master/claims/by-code/${dashed}`)).json()) as any;
    expect(b).toMatchObject({ claimId: s.claim.claimId, fp });
  });

  it("cron purges claims older than a day", async () => {
    const s = await setup();
    await runCron(s.env, ctx, Date.now() + 2 * 86_400_000);
    expect(s.t.deleted.some((q) => q.includes("FROM claims"))).toBe(true);
  });
});
