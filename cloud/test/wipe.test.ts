// API.md section 18: deregister, delete-with-data, last-device cleanup, era wipe, reset.
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";
import { wipePreviousEra } from "../src/wipe";
import { resetAll, revokeDevice } from "../src/routes/master";
import { b64urlEncode, utf8 } from "../src/lib/encoding";

const A = "01JABCDEFGHJKMNPQRSTVWXYZ0";
const B = "01JABCDEFGHJKMNPQRSTVWXYZ1";
const ED = { name: "Ed25519" };

function setup() {
  const sql = new DatabaseSync(":memory:");
  for (const f of readdirSync("migrations").sort()) sql.exec(readFileSync(join("migrations", f), "utf8"));
  const stmt = (q: string, args: unknown[] = []) => ({
    bind: (...a: unknown[]) => stmt(q, a),
    first: async () => (sql.prepare(q).get(...(args as never[])) as unknown) ?? null,
    all: async () => ({ results: sql.prepare(q).all(...(args as never[])) as unknown[] }),
    run: async () => ({ meta: { changes: Number(sql.prepare(q).run(...(args as never[])).changes) } }),
    _run: () => ({ meta: { changes: Number(sql.prepare(q).run(...(args as never[])).changes) } }),
  });
  const db = { prepare: (q: string) => stmt(q), batch: async (l: ReturnType<typeof stmt>[]) => l.map((s) => s._run()) } as unknown as D1Database;
  const purged: string[] = [];
  const env = {
    DB: db,
    DEVICE_HUB: {
      idFromName: (n: string) => n,
      get: (id: string) => ({ purge: async () => void purged.push(id), revoke: async () => {}, closeMasterSockets: async () => 0 }),
    },
  } as unknown as Env;
  return { sql, env, purged };
}

async function seedDevice(sql: DatabaseSync, id: string) {
  const kp = (await crypto.subtle.generateKey(ED, true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = b64urlEncode(new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer));
  sql.exec(`INSERT INTO devices (id, hostname, device_pub_key, enrolled_at) VALUES ('${id}','PC','${pub}','x')`);
  sql.exec(`INSERT INTO managed_users (device_id,user_sid,name,updated_at) VALUES ('${id}','S-1-5-21-1-2-3-1001','a','x')`);
  sql.exec(`INSERT INTO events (id,device_id,ts,mono_ms,type,data_json,received_at) VALUES ('e${id}','${id}','t',1,'x','{}','t')`);
  sql.exec(`INSERT INTO alerts (id,device_id,ts,type,severity,data_json) VALUES ('a${id}','${id}','t','x','info','{}')`);
  sql.exec(`INSERT INTO usage_daily (device_id,user_sid,day,exe,active_sec) VALUES ('${id}','s','d','e',1)`);
  sql.exec(`INSERT INTO app_inventory (device_id,user_sid,generated_at,apps_json) VALUES ('${id}','s','g','[]')`);
  return async (ts: string) => b64urlEncode(new Uint8Array(await crypto.subtle.sign(ED, kp.privateKey, utf8(`deregister|${id}|${ts}`))));
}
function master(sql: DatabaseSync) {
  sql.exec(`INSERT OR REPLACE INTO master_keys (key_id,alg,public_key,role,created_at) VALUES ('k1','ed25519','p','sign','x')`);
  sql.exec(`INSERT OR REPLACE INTO config (k,v,updated_at) VALUES ('master_seal_pub_key','s','x'),('settings','{"notifyLogon":true}','x'),('usage:2026-11-23','5','x')`);
  sql.exec(`INSERT OR REPLACE INTO push_subscriptions (id,fcm_token,created_at) VALUES ('p','t','x')`);
}
const count = (sql: DatabaseSync, t: string) => (sql.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get() as { n: number }).n;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const post = (env: Env, body: unknown) =>
  worker.fetch(new Request("https://x/v1/device/deregister", { method: "POST", body: JSON.stringify(body) }), env, ctx);

describe("deregister", () => {
  it("deletes the device and all data; last device resets the master; idempotent", async () => {
    const { sql, env, purged } = setup();
    const sign = await seedDevice(sql, A);
    master(sql);
    const ts = String(Math.floor(Date.now() / 1000));
    const r = await post(env, { deviceId: A, ts, sig: await sign(ts) });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ deleted: true });
    for (const t of ["devices", "events", "alerts", "usage_daily", "app_inventory", "managed_users"]) expect(count(sql, t)).toBe(0);
    expect(purged).toEqual([A]);
    expect(count(sql, "master_keys WHERE revoked_at IS NULL")).toBe(0);
    expect(count(sql, "push_subscriptions")).toBe(0);
    expect(count(sql, "config WHERE k = 'master_seal_pub_key'")).toBe(0);
    expect(await (await post(env, { deviceId: A, ts, sig: await sign(ts) })).json()).toEqual({ deleted: false });
  });
  it("keeps the master while another device remains; rejects bad signature and stale ts", async () => {
    const { sql, env } = setup();
    const sign = await seedDevice(sql, A);
    await seedDevice(sql, B);
    master(sql);
    const ts = String(Math.floor(Date.now() / 1000));
    expect((await post(env, { deviceId: A, ts, sig: "A".repeat(86) })).status).toBe(401);
    const old = String(Math.floor(Date.now() / 1000) - 1000);
    expect((await post(env, { deviceId: A, ts: old, sig: await sign(old) })).status).toBe(401);
    expect((await post(env, { deviceId: A, ts, sig: await sign(ts) })).status).toBe(200);
    expect(count(sql, "devices")).toBe(1);
    expect(count(sql, "master_keys WHERE revoked_at IS NULL")).toBe(1);
    expect(count(sql, "push_subscriptions")).toBe(1);
  });
});

describe("wipe", () => {
  it("wipePreviousEra keeps the new device, meter rows and the master seal key", async () => {
    const { sql, env } = setup();
    await seedDevice(sql, A);
    await seedDevice(sql, B);
    master(sql);
    await wipePreviousEra(env, B);
    expect(count(sql, "devices")).toBe(1);
    expect(count(sql, `devices WHERE id = '${B}'`)).toBe(1);
    expect(count(sql, "alerts")).toBe(1);
    expect(count(sql, "push_subscriptions")).toBe(0);
    expect(count(sql, "config WHERE k = 'settings'")).toBe(0);
    expect(count(sql, "config WHERE k LIKE 'usage:%' OR k = 'master_seal_pub_key'")).toBe(2);
  });
  it("master DELETE device removes data; reset needs a sign key and wipes everything", async () => {
    const { sql, env } = setup();
    await seedDevice(sql, A);
    master(sql);
    const c = (role: string, params: Record<string, string> = {}) => ({ env, exec: ctx, params, master: { role } }) as never;
    await expect(resetAll(c("read"))).rejects.toMatchObject({ status: 403 });
    expect((await revokeDevice(c("sign", { id: A }))).status).toBe(204);
    expect(count(sql, "devices")).toBe(0);
    expect(count(sql, "master_keys WHERE revoked_at IS NULL")).toBe(0);
    await seedDevice(sql, B);
    master(sql);
    expect((await resetAll(c("sign"))).status).toBe(200);
    expect(count(sql, "devices") + count(sql, "master_keys") + count(sql, "events") + count(sql, "push_subscriptions")).toBe(0);
    expect(count(sql, "config")).toBe(1);
  });
});
