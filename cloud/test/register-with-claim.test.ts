import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";
import { keyIdOf } from "../src/lib/crypto";
import { b64urlEncode, utf8 } from "../src/lib/encoding";

// In-memory D1 fake covering the statements of enroll/start and register-with-claim.
type Row = Record<string, any>;
function fakeDb() {
  const t = { claims: new Map<string, Row>(), rate: new Map<string, number>(), devices: new Map<string, Row>(), users: [] as Row[], keys: new Map<string, Row>(), config: new Map<string, string>() };
  const active = () => [...t.keys.values()].some((k) => !k.revoked_at);
  const exec = (sql: string, a: any[]): { first?: Row | null; changes?: number } => {
    if (sql.startsWith("INSERT INTO claim_rate")) {
      const k = `${a[0]}|${a[1]}`;
      t.rate.set(k, (t.rate.get(k) ?? 0) + 1);
      return { first: { n: t.rate.get(k) } };
    }
    if (sql.startsWith("INSERT INTO claims")) {
      t.claims.set(a[0], { claim_id: a[0], code: a[1], device_pub_key: a[2], hostname: a[3], os_version: a[4], agent_version: a[5], local_users_json: a[6], expires_at: a[8], status: "pending", device_id: null, approved_by: null });
      return {};
    }
    if (sql.startsWith("SELECT") && sql.includes("FROM claims WHERE claim_id")) return { first: t.claims.get(a[0]) ?? null };
    if (sql.includes("FROM master_keys WHERE revoked_at IS NULL LIMIT 1")) return { first: active() ? { x: 1 } : null };
    if (sql.startsWith("UPDATE claims SET status = 'approved'")) {
      const c = t.claims.get(a[2]);
      if (!c || c.status !== "pending" || !(c.expires_at > a[3]) || active()) return { changes: 0 };
      Object.assign(c, { status: "approved", device_id: a[0], approved_by: a[1] });
      return { changes: 1 };
    }
    const mine = (claimId: string, deviceId: string) => t.claims.get(claimId)?.device_id === deviceId;
    if (sql.startsWith("INSERT OR REPLACE INTO master_keys")) {
      if (!mine(a[5], a[6])) return { changes: 0 };
      t.keys.set(a[0], { key_id: a[0], alg: a[1], public_key: a[2], role: a[3], revoked_at: null });
      return { changes: 1 };
    }
    if (sql.startsWith("INSERT OR REPLACE INTO config")) {
      if (!mine(a[2], a[3])) return { changes: 0 };
      t.config.set("master_seal_pub_key", a[0]);
      return { changes: 1 };
    }
    if (sql.startsWith("INSERT INTO devices")) {
      if (!mine(a[7], a[8])) return { changes: 0 };
      t.devices.set(a[0], { id: a[0], hostname: a[1] });
      return { changes: 1 };
    }
    if (sql.startsWith("INSERT INTO managed_users")) {
      if (!mine(a[5], a[6])) return { changes: 0 };
      t.users.push({ device_id: a[0], user_sid: a[1] });
      return { changes: 1 };
    }
    return {};
  };
  const stmt = (sql: string, a: any[] = []) => ({
    bind: (...b: any[]) => stmt(sql, b),
    first: async () => exec(sql, a).first ?? null,
    all: async () => ({ results: [] }),
    run: async () => ({ meta: { changes: exec(sql, a).changes ?? 0 } }),
    _run: () => ({ meta: { changes: exec(sql, a).changes ?? 0 } }),
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
  return { pub: b64urlEncode(raw), sign, keyId: await keyIdOf(raw) };
}

async function setup() {
  const { db, t } = fakeDb();
  const env = { DB: db } as unknown as Env;
  const call = (path: string, body: unknown, ip = "9.9.9.9") =>
    worker.fetch(new Request(`https://example.test${path}`, { method: "POST", headers: { "cf-connecting-ip": ip }, body: JSON.stringify(body) }), env, ctx);
  const device = await keypair();
  const start = await call("/v1/enroll/start", { devicePubKey: device.pub, hostname: "PC-BIN", osVersion: "10", agentVersion: "1", localUsers: [{ sid: "S-1-5-21-1-2-3-1001", name: "Bin", isAdmin: false }] }, "1.1.1.1");
  const claim = (await start.json()) as { claimId: string };
  const body = async (claimId = claim.claimId, signWith?: Awaited<ReturnType<typeof keypair>>) => {
    const sign = await keypair();
    const read = await keypair();
    return {
      claimId,
      keys: [
        { keyId: sign.keyId, alg: "ed25519", publicKey: sign.pub, role: "sign" },
        { keyId: read.keyId, alg: "ed25519", publicKey: read.pub, role: "read" },
      ],
      sealPubKey: b64urlEncode(crypto.getRandomValues(new Uint8Array(32))),
      sig: await (signWith ?? sign).sign("register|" + claimId),
    };
  };
  return { t, call, claim, body };
}

const PATH = "/v1/master/register-with-claim";

describe("POST /v1/master/register-with-claim", () => {
  it("success: registers keys + seal key and approves the claim, creating the device", async () => {
    const s = await setup();
    const b = await s.body();
    const res = await s.call(PATH, b);
    expect(res.status).toBe(201);
    const out = (await res.json()) as { deviceId: string; keys: { keyId: string; role: string }[] };
    expect(out.deviceId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(out.keys).toEqual(b.keys.map((k) => ({ keyId: k.keyId, role: k.role })));
    expect(s.t.keys.size).toBe(2);
    expect(s.t.config.get("master_seal_pub_key")).toBe(b.sealPubKey);
    expect(s.t.devices.has(out.deviceId)).toBe(true);
    expect(s.t.users).toHaveLength(1);
    expect(s.t.claims.get(s.claim.claimId)).toMatchObject({ status: "approved", device_id: out.deviceId });
  });

  it("master_exists: 409 when a master is already registered", async () => {
    const s = await setup();
    const other = await keypair();
    s.t.keys.set(other.keyId, { key_id: other.keyId, role: "sign", revoked_at: null });
    const res = await s.call(PATH, await s.body());
    expect(res.status).toBe(409);
    expect(((await res.json()) as any).error).toBe("master_exists");
    expect(s.t.claims.get(s.claim.claimId)!.status).toBe("pending");
  });

  it("expired claim: 410 and nothing registered", async () => {
    const s = await setup();
    s.t.claims.get(s.claim.claimId)!.expires_at = new Date(Date.now() - 1000).toISOString();
    const res = await s.call(PATH, await s.body());
    expect(res.status).toBe(410);
    expect(((await res.json()) as any).error).toBe("expired");
    expect(s.t.keys.size).toBe(0);
  });

  it("rejected claim: 410", async () => {
    const s = await setup();
    s.t.claims.get(s.claim.claimId)!.status = "rejected";
    expect((await s.call(PATH, await s.body())).status).toBe(410);
  });

  it("bad signature (other key / other claim id) and bad body: 400", async () => {
    const s = await setup();
    expect((await s.call(PATH, await s.body(s.claim.claimId, await keypair()))).status).toBe(400);
    const b = await s.body();
    expect((await s.call(PATH, { ...b, claimId: "A".repeat(22) })).status).toBe(400);
    expect((await s.call(PATH, { ...b, extra: 1 })).status).toBe(400);
    expect((await s.call(PATH, { ...b, keys: [b.keys[1]] })).status).toBe(400); // no sign key
    expect(s.t.keys.size).toBe(0);
  });

  it("race: the second registration after the first gets 409; concurrent calls have exactly one winner", async () => {
    const s = await setup();
    expect((await s.call(PATH, await s.body())).status).toBe(201);
    expect((await s.call(PATH, await s.body())).status).toBe(409);

    const r = await setup();
    const [x, y] = await Promise.all([r.call(PATH, await r.body()), r.call(PATH, await r.body())]);
    expect([x.status, y.status].sort()).toEqual([201, 409]);
    expect(r.t.keys.size).toBe(2);
    expect(r.t.devices.size).toBe(1);
  });

  it("rate limits like enroll/start: 11th call per IP per hour is 429", async () => {
    const s = await setup();
    s.t.claims.get(s.claim.claimId)!.status = "rejected";
    const b = await s.body();
    for (let i = 0; i < 10; i++) expect((await s.call(PATH, b)).status).toBe(410);
    expect((await s.call(PATH, b)).status).toBe(429);
  });
});
