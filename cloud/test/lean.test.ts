// API.md section 16: lean ingest, domains route, settings + session pushes, free-tier meter.
import { DatabaseSync } from "node:sqlite";
import { generateKeyPair } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { intakeEvents, notifySessions } from "../src/ingest";
import { FREE_ROWS_WRITTEN_LIMIT, meteredEnv, readUsage } from "../src/meter";
import * as m from "../src/routes/master";
import type { Ctx } from "../src/router";
import type { Env } from "../src/env";
import { ALERT_TYPES, type Settings, loadSettings } from "../src/settings";

const DEV = "01JABCDEFGHJKMNPQRSTVWXYZ0";
const SID = "S-1-5-21-1-2-3-1001";

function makeDb() {
  const sql = new DatabaseSync(":memory:");
  const dir = join(process.cwd(), "migrations");
  for (const f of readdirSync(dir).sort()) sql.exec(readFileSync(join(dir, f), "utf8"));
  const stmt = (q: string, args: unknown[] = []) => ({
    bind: (...a: unknown[]) => stmt(q, a),
    first: async () => (sql.prepare(q).get(...(args as never[])) as unknown) ?? null,
    all: async () => {
      const st = sql.prepare(q);
      if (/RETURNING/i.test(q)) return { results: st.all(...(args as never[])) as unknown[], meta: { rows_written: 1 } };
      if (/^\s*SELECT/i.test(q)) return { results: st.all(...(args as never[])) as unknown[], meta: { rows_written: 0 } };
      return { results: [], meta: { rows_written: Number(st.run(...(args as never[])).changes) } };
    },
    run: async () => ({ meta: { rows_written: Number(sql.prepare(q).run(...(args as never[])).changes) } }),
    _run: () => ({ meta: { rows_written: Number(sql.prepare(q).run(...(args as never[])).changes) } }),
  });
  const db = {
    prepare: (q: string) => stmt(q),
    batch: async (l: ReturnType<typeof stmt>[]) => l.map((s) => s._run()),
  };
  sql.exec(`INSERT INTO devices (id, hostname, device_pub_key, enrolled_at, timezone) VALUES ('${DEV}', 'PC-CON', 'k', '2026-11-01T00:00:00Z', 'Asia/Ho_Chi_Minh')`);
  sql.exec(`INSERT INTO managed_users (device_id, user_sid, name, is_admin, managed, label, updated_at) VALUES ('${DEV}', '${SID}', 'con', 0, 1, 'Bi', 'x')`);
  return { db: db as unknown as D1Database, sql };
}

const dev = { id: DEV, hostname: "PC-CON", timezone: "Asia/Ho_Chi_Minh" };
let n = 0;
const ev = (type: string, data: Record<string, unknown>, ts = new Date().toISOString()) => ({
  id: `E${String(++n).padStart(25, "0")}`,
  deviceId: DEV,
  userSid: SID,
  ts,
  monoMs: 1,
  type,
  data,
});
const ctx = (env: Env, params: Record<string, string>, query = "", body: unknown = undefined): Ctx =>
  ({ env, params, url: new URL(`https://x/?${query}`), json: () => body }) as unknown as Ctx;

afterEach(() => vi.unstubAllGlobals());

async function stubFcm(db: D1Database): Promise<{ env: Env; sent: Record<string, string>[] }> {
  await db.prepare("INSERT INTO push_subscriptions (id, fcm_token, created_at) VALUES ('s1','tok','x')").run();
  const pem = await new Promise<string>((res, rej) =>
    generateKeyPair("rsa", { modulusLength: 2048 }, (e, _p, k) => (e ? rej(e) : res(k.export({ type: "pkcs8", format: "pem" }) as string))),
  );
  const sent: Record<string, string>[] = [];
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    if (String(url).includes("oauth")) return Response.json({ access_token: "a", expires_in: 3600 });
    sent.push(JSON.parse(String(init?.body)).message.data);
    return Response.json({});
  });
  return { env: { DB: db, FCM_SERVICE_ACCOUNT_JSON: JSON.stringify({ project_id: "p", client_email: "e@x", private_key: pem }) } as Env, sent };
}

describe("lean ingest", () => {
  it("skips events rows for net.domain/usage.tick but keeps aggregates with first/last seen", async () => {
    const { db, sql } = makeDb();
    const env = { DB: db } as Env;
    const t1 = "2026-11-22T08:40:00.000Z";
    const t2 = "2026-11-22T08:46:00.000Z";
    await intakeEvents(
      env,
      dev,
      [
        ev("net.domain", { host: "x.test", exe: "a.exe", windowStart: t1, connections: 2, allowed: true }, t1),
        ev("usage.tick", { minuteStart: t1, activeSec: 50, exe: "a.exe" }, t1),
        ev("web.visit", { browser: "chrome", url: "https://x.test/", title: "t", durationSec: 1 }, t1),
      ],
      () => {},
    );
    await intakeEvents(env, dev, [ev("net.domain", { host: "x.test", exe: "a.exe", windowStart: t2, connections: 3, allowed: true }, t2)], () => {});
    const types = (sql.prepare("SELECT type FROM events").all() as { type: string }[]).map((r) => r.type);
    expect(types).toEqual(["web.visit"]);
    expect(sql.prepare("SELECT SUM(active_sec) s FROM usage_daily").get()).toEqual({ s: 50 });
    expect(sql.prepare("SELECT connections, first_seen, last_seen FROM domains_daily").get()).toEqual({ connections: 5, first_seen: t1, last_seen: t2 });
  });

  it("migration 0005 purges old rows and drops the unused indexes", () => {
    const sql = new DatabaseSync(":memory:");
    const dir = join(process.cwd(), "migrations");
    const files = readdirSync(dir).sort();
    for (const f of files.filter((f) => f < "0005")) sql.exec(readFileSync(join(dir, f), "utf8"));
    sql.exec(`INSERT INTO devices (id, hostname, device_pub_key, enrolled_at) VALUES ('D', 'h', 'k', 'x')`);
    sql.exec(`INSERT INTO events (id, device_id, ts, mono_ms, type, data_json, received_at) VALUES ('1','D','t',1,'net.domain','{}','t'),('2','D','t',1,'web.visit','{}','t')`);
    sql.exec(readFileSync(join(dir, files.find((f) => f.startsWith("0005"))!), "utf8"));
    expect(sql.prepare("SELECT id FROM events").all()).toEqual([{ id: "2" }]);
    const idx = (sql.prepare("SELECT name FROM sqlite_master WHERE type='index'").all() as { name: string }[]).map((r) => r.name);
    expect(idx).not.toContain("idx_events_device_type_ts");
    expect(idx).toContain("idx_events_device_ts");
  });
});

describe("domains, settings and usage routes", () => {
  it("groups domains by host", async () => {
    const { db } = makeDb();
    const env = { DB: db } as Env;
    const day = "2026-11-22";
    const ins = (host: string, exe: string, allowed: number, c: number, f: string, l: string) =>
      db
        .prepare("INSERT INTO domains_daily (device_id, user_sid, day, host, exe, allowed, connections, bytes_out, bytes_in, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
        .bind(DEV, SID, day, host, exe, allowed, c, 1, 2, f, l)
        .run();
    await ins("a.test", "chrome.exe", 1, 5, "2026-11-22T01:00:00.000Z", "2026-11-22T02:00:00.000Z");
    await ins("a.test", "edge.exe", 0, 2, "2026-11-22T00:30:00.000Z", "2026-11-22T03:00:00.000Z");
    await ins("b.test", "", 1, 9, "2026-11-22T05:00:00.000Z", "2026-11-22T05:00:00.000Z");
    const r = await m.listDomains(ctx(env, { id: DEV }, `day=${day}&user=${SID}`));
    expect(await r.json()).toEqual({
      items: [
        { host: "b.test", apps: [], connections: 9, bytesOut: 1, bytesIn: 2, blocked: false, firstSeen: "2026-11-22T05:00:00.000Z", lastSeen: "2026-11-22T05:00:00.000Z" },
        { host: "a.test", apps: ["chrome.exe", "edge.exe"], connections: 7, bytesOut: 2, bytesIn: 4, blocked: true, firstSeen: "2026-11-22T00:30:00.000Z", lastSeen: "2026-11-22T03:00:00.000Z" },
      ],
    });
    expect(await (await m.listDomains(ctx(env, { id: DEV }, "day=2026-01-01"))).json()).toEqual({ items: [] });
    await expect(m.listDomains(ctx(env, { id: DEV }, "day=bad"))).rejects.toMatchObject({ status: 400 });
  });

  it("settings defaults: only tamper on; merge on PUT; validation", async () => {
    const { db } = makeDb();
    const env = { DB: db } as Env;
    const got = (await (await m.getSettings(ctx(env, {}))).json()) as Settings;
    expect(got.notifyLogon).toBe(false);
    expect(Object.keys(got.alerts).sort()).toEqual([...ALERT_TYPES].sort());
    for (const [t, v] of Object.entries(got.alerts)) expect(v).toEqual({ enabled: t === "tamper", minIntervalMin: 0 });
    // legacy flag maps onto session.logon
    await m.putSettings(ctx(env, {}, "", { notifyLogon: true }));
    let s2 = (await (await m.getSettings(ctx(env, {}))).json()) as Settings;
    expect(s2.notifyLogon).toBe(true);
    expect(s2.alerts["session.logon"].enabled).toBe(true);
    // partial alerts merge
    await m.putSettings(ctx(env, {}, "", { alerts: { "quota.exhausted": { enabled: true, minIntervalMin: 30 }, tamper: { minIntervalMin: 5 } } }));
    s2 = (await (await m.getSettings(ctx(env, {}))).json()) as Settings;
    expect(s2.alerts["quota.exhausted"]).toEqual({ enabled: true, minIntervalMin: 30 });
    expect(s2.alerts.tamper).toEqual({ enabled: true, minIntervalMin: 5 });
    expect(s2.alerts["session.logon"].enabled).toBe(true);
    await expect(m.putSettings(ctx(env, {}, "", { notifyLogoff: "yes" }))).rejects.toMatchObject({ status: 400 });
    await expect(m.putSettings(ctx(env, {}, "", { alerts: { bogus: { enabled: true } } }))).rejects.toMatchObject({ status: 400 });
    await expect(m.putSettings(ctx(env, {}, "", { alerts: { tamper: { enabled: "x" } } }))).rejects.toMatchObject({ status: 400 });
    await expect(m.putSettings(ctx(env, {}, "", { alerts: { tamper: { minIntervalMin: -1 } } }))).rejects.toMatchObject({ status: 400 });
    await expect(m.putSettings(ctx(env, {}, "", { alerts: { tamper: { minIntervalMin: 1.5 } } }))).rejects.toMatchObject({ status: 400 });
  });

  it("reads legacy stored settings", async () => {
    const { db } = makeDb();
    await db.prepare("INSERT INTO config (k, v, updated_at) VALUES ('settings', ?, 'x')").bind(JSON.stringify({ notifyLogoff: true })).run();
    const s = await loadSettings(db);
    expect(s.alerts["session.logoff"].enabled).toBe(true);
    expect(s.alerts.tamper.enabled).toBe(true);
  });
});

describe("alert settings in the engine", () => {
  async function setup(alerts: object | null) {
    const { db } = makeDb();
    if (alerts) await db.prepare("INSERT INTO config (k, v, updated_at) VALUES ('settings', ?, 'x')").bind(JSON.stringify({ alerts })).run();
    const { env, sent } = await stubFcm(db);
    const dev = { id: DEV, hostname: "PC-CON", timezone: "Asia/Ho_Chi_Minh" };
    const run = async (events: ReturnType<typeof ev>[]) => {
      await intakeEvents(env, dev, events, () => undefined);
      return db.prepare("SELECT type FROM alerts ORDER BY ts, id").all<{ type: string }>().then((r) => r.results.map((x) => x.type));
    };
    return { db, env, sent, run };
  }
  const T0 = Date.now() - 3600_000;
  const at = (min: number) => new Date(T0 + min * 60_000).toISOString();

  it("only tamper by default", async () => {
    const { run } = await setup(null);
    const types = await run([ev("quota.exhausted", { scope: "total", remainingMin: 0 }, at(0)), ev("tamper.clock_jump", {}, at(1)), ev("request.exe_approval", { exe: "a.exe", path: "C:\a.exe", pid: 1 }, at(2)), ev("web.blocked", { host: "a.test", source: "proxy", reason: "category" }, at(3))]);
    expect(types).toEqual(["tamper.clock_jump"]);
  });

  it("enabled types raise alerts, minIntervalMin limits per type", async () => {
    const { run } = await setup({ "quota.exhausted": { enabled: true, minIntervalMin: 10 }, "request.exe_approval": { enabled: true, minIntervalMin: 0 } });
    expect(await run([ev("quota.exhausted", { scope: "total", remainingMin: 0 }, at(0)), ev("quota.exhausted", { scope: "total", remainingMin: 0 }, at(5)), ev("request.exe_approval", { exe: "a.exe", path: "C:\a.exe", pid: 1 }, at(5)), ev("request.exe_approval", { exe: "b.exe", path: "C:\b.exe", pid: 1 }, at(6))])).toEqual([
      "quota.exhausted",
      "request.exe_approval",
      "request.exe_approval",
    ]);
    // later batch: inside the window of the stored alert at(0) -> dropped; after it -> raised
    expect(await run([ev("quota.exhausted", { scope: "total", remainingMin: 0 }, at(8))])).toHaveLength(3);
    expect(await run([ev("quota.exhausted", { scope: "total", remainingMin: 0 }, at(11))])).toHaveLength(4);
  });

  it("tamper.* share one settings key and interval", async () => {
    const { run } = await setup({ tamper: { enabled: true, minIntervalMin: 30 } });
    expect(await run([ev("tamper.clock_jump", {}, at(0)), ev("tamper.agent_killed", {}, at(1))])).toEqual(["tamper.clock_jump"]);
  });

  it("burst alert only when blocked.burst is enabled", async () => {
    const off = await setup(null);
    expect(await off.run([ev("web.blocked", { host: "a", source: "proxy", reason: "category" }, at(0)), ev("web.blocked", { host: "b", source: "proxy", reason: "category" }, at(1)), ev("web.blocked", { host: "c", source: "proxy", reason: "category" }, at(2))])).toEqual([]);
    const on = await setup({ "blocked.burst": { enabled: true, minIntervalMin: 0 } });
    expect(await on.run([ev("web.blocked", { host: "a", source: "proxy", reason: "category" }, at(0)), ev("web.blocked", { host: "b", source: "proxy", reason: "category" }, at(1)), ev("web.blocked", { host: "c", source: "proxy", reason: "category" }, at(2))])).toEqual(["blocked.burst"]);
  });
});

describe("session pushes", () => {
  async function run(settings: object | null, events: ReturnType<typeof ev>[]) {
    const { db } = makeDb();
    if (settings) await db.prepare("INSERT INTO config (k, v, updated_at) VALUES ('settings', ?, 'x')").bind(JSON.stringify(settings)).run();
    const { env, sent } = await stubFcm(db);
    await notifySessions(env, dev, events as never);
    return sent;
  }

  it("pushes Vietnamese logon/logoff notices when enabled", async () => {
    const t = new Date(Date.now() - 60_000).toISOString();
    const sent = await run({ notifyLogon: true, notifyLogoff: true }, [ev("session.logon", {}, t), ev("session.logoff", {}, t)]);
    expect(sent).toHaveLength(2);
    expect(sent[0]).toMatchObject({ type: "notice", severity: "info", title: "Bi vừa đăng nhập PC-CON", deviceId: DEV, userSid: SID });
    expect(sent[0]!.body).toMatch(/^Lúc \d\d:\d\d \d\d\/\d\d/);
    expect(sent[1]!.title).toBe("Bi đã đăng xuất PC-CON");
  });

  it("session notices honour alerts map and minIntervalMin", async () => {
    const t = (sec: number) => new Date(Date.now() - 60_000 + sec * 1000).toISOString();
    const settings = { alerts: { "session.logon": { enabled: true, minIntervalMin: 10 }, "session.logoff": { enabled: false, minIntervalMin: 0 } } };
    const { db } = makeDb();
    await db.prepare("INSERT INTO config (k, v, updated_at) VALUES ('settings', ?, 'x')").bind(JSON.stringify(settings)).run();
    const { env, sent } = await stubFcm(db);
    await notifySessions(env, dev, [ev("session.logon", {}, t(0)), ev("session.logoff", {}, t(1))] as never);
    expect(sent).toHaveLength(1);
    await notifySessions(env, dev, [ev("session.logon", {}, t(30))] as never); // within 10 min of the previous one
    expect(sent).toHaveLength(1);
  });

  it("stays silent when disabled", async () => {
    const t = new Date().toISOString();
    expect(await run(null, [ev("session.logon", {}, t)])).toHaveLength(0);
    expect(await run({ notifyLogon: true }, [ev("session.logoff", {}, t)])).toHaveLength(0);
  });
});

describe("free-tier meter", () => {
  it("sums rows_written per UTC day and pushes 70 % and 90 % once each", async () => {
    const { db } = makeDb();
    const { env: base, sent } = await stubFcm(db);
    const pending: Promise<unknown>[] = [];
    const env = meteredEnv(base, (p) => pending.push(p));
    const settle = async () => {
      while (pending.length) await pending.shift();
    };
    const add = (k: string) => env.DB.prepare("INSERT INTO config (k, v, updated_at) VALUES (?, '1', 'x')").bind(k).run();

    await add("a");
    await env.DB.batch([env.DB.prepare("INSERT INTO config (k, v, updated_at) VALUES ('b','1','x')"), env.DB.prepare("INSERT INTO config (k, v, updated_at) VALUES ('c','1','x')")]);
    await settle();
    const u = await readUsage(db);
    expect(u.rowsWritten).toBeGreaterThanOrEqual(3);
    expect(u.limit).toBe(100000);

    const seed = (v: number) => db.prepare("UPDATE config SET v = ? WHERE k = ?").bind(String(v), `usage:${u.day}`).run();
    await seed(FREE_ROWS_WRITTEN_LIMIT * 0.7 - 5);
    for (let i = 0; i < 10; i++) await add(`p${i}`);
    await settle();
    expect(sent.map((s) => s.title)).toEqual([expect.stringContaining("(70 %)")]);
    expect(sent[0]).toMatchObject({ type: "notice", severity: "warn" });
    for (let i = 0; i < 5; i++) await add(`q${i}`);
    await settle();
    expect(sent).toHaveLength(1); // once per day
    await seed(FREE_ROWS_WRITTEN_LIMIT * 0.9 - 2);
    for (let i = 0; i < 4; i++) await add(`r${i}`);
    await settle();
    expect(sent).toHaveLength(2);
    expect(sent[1]!.title).toContain("(90 %)");
    const usage = (await (await m.getMeterUsage(ctx(base, {}))).json()) as { percent: number };
    expect(usage.percent).toBeGreaterThanOrEqual(90);
  });
});
