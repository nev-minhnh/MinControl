// API.md section 15: live events over the device socket, master live sockets (fan-out, read-only, idle close).
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DeviceHub, MASTER_IDLE_MS, MASTER_KEY_HEADER, MASTER_TAG } from "../src/device-hub";
import worker, { type Env } from "../src/index";
import { keyIdOf, sha256Hex } from "../src/lib/crypto";
import { b64urlEncode, utf8 } from "../src/lib/encoding";
import { ulid } from "../src/lib/ulid";
import { validateWsDeviceMessage } from "../src/generated/validators";

// ------------------------------------------------------------------ fakes
function sqliteD1() {
  const sql = new DatabaseSync(":memory:");
  const dir = join(process.cwd(), "migrations");
  for (const f of readdirSync(dir).sort()) sql.exec(readFileSync(join(dir, f), "utf8"));
  let queries = 0;
  const stmt = (q: string, args: unknown[] = []) => ({
    bind: (...a: unknown[]) => stmt(q, a),
    first: async () => (queries++, (sql.prepare(q).get(...(args as never[])) as unknown) ?? null),
    all: async () => (queries++, { results: sql.prepare(q).all(...(args as never[])) as unknown[] }),
    run: async () => (queries++, { meta: { changes: Number(sql.prepare(q).run(...(args as never[])).changes) } }),
    _run: () => ({ meta: { changes: Number(sql.prepare(q).run(...(args as never[])).changes) } }),
  });
  const db = {
    prepare: (q: string) => stmt(q),
    batch: async (list: ReturnType<typeof stmt>[]) => {
      queries++;
      sql.exec("BEGIN");
      try {
        const out = list.map((s) => s._run());
        sql.exec("COMMIT");
        return out;
      } catch (e) {
        sql.exec("ROLLBACK");
        throw e;
      }
    },
  };
  return { db: db as unknown as D1Database, sql, queries: () => queries };
}

/** DO SqlStorage on node:sqlite. */
function fakeSqlStorage() {
  const sql = new DatabaseSync(":memory:");
  return {
    exec(q: string, ...binds: unknown[]) {
      if (binds.length === 0 && /;\s*\S/.test(q.trim().replace(/;\s*$/, ""))) {
        sql.exec(q);
        return { toArray: () => [] };
      }
      const st = sql.prepare(q);
      const rows = /^\s*SELECT/i.test(q) ? (st.all(...(binds as never[])) as unknown[]) : (st.run(...(binds as never[])), []);
      return { toArray: () => rows };
    },
  };
}

class FakeWS {
  sent: string[] = [];
  readyState = 1;
  closed: { code: number; reason: string } | null = null;
  tags: string[] = [];
  autoTs: Date | null = null;
  private att: unknown = null;
  send(s: string) {
    if (this.readyState !== 1) throw new Error("closed");
    this.sent.push(s);
  }
  close(code: number, reason: string) {
    if (this.readyState !== 1) throw new Error("closed");
    this.readyState = 3;
    this.closed = { code, reason };
  }
  serializeAttachment(a: unknown) {
    this.att = structuredClone(a);
  }
  deserializeAttachment() {
    return this.att === null ? null : structuredClone(this.att);
  }
  frames() {
    return this.sent.map((s) => JSON.parse(s) as Record<string, any>);
  }
}

function fakeCtx() {
  const sockets: FakeWS[] = [];
  const waits: Promise<unknown>[] = [];
  let alarm: number | null = null;
  const ctx = {
    storage: { sql: fakeSqlStorage(), setAlarm: async (t: number) => void (alarm = t) },
    acceptWebSocket: (ws: FakeWS, tags: string[] = []) => {
      ws.tags = tags;
      sockets.push(ws);
    },
    getWebSockets: (tag?: string) => sockets.filter((w) => w.readyState === 1 && (tag === undefined || w.tags.includes(tag))),
    setWebSocketAutoResponse() {},
    getWebSocketAutoResponseTimestamp: (ws: FakeWS) => ws.autoTs,
    waitUntil: (p: Promise<unknown>) => void waits.push(p),
  };
  return { ctx, sockets, waits, alarm: () => alarm };
}

// Runtime globals the hub uses that Node lacks (WebSocketPair, 101 responses).
const RealResponse = globalThis.Response;
const g = globalThis as Record<string, unknown>;
beforeAll(() => {
  g.WebSocketPair = class {
    0 = new FakeWS();
    1 = new FakeWS();
  };
  g.WebSocketRequestResponsePair = class {
    constructor(
      public request: string,
      public response: string,
    ) {}
  };
  class TestResponse extends RealResponse {
    declare webSocket: WebSocket | null;
    constructor(body?: BodyInit | null, init?: ResponseInit & { webSocket?: unknown }) {
      const is101 = init?.status === 101;
      super(body, is101 ? { ...init, status: 200 } : init);
      Object.defineProperty(this, "webSocket", { value: init?.webSocket ?? null });
      if (is101) Object.defineProperty(this, "status", { value: 101 });
    }
  }
  g.Response = TestResponse;
});
afterAll(() => {
  g.Response = RealResponse;
});

const ED = { name: "Ed25519" };
async function keypair() {
  const kp = (await crypto.subtle.generateKey(ED, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  const sign = async (s: string | Uint8Array) =>
    b64urlEncode(new Uint8Array(await crypto.subtle.sign(ED, kp.privateKey, typeof s === "string" ? utf8(s) : s)));
  return { pub: b64urlEncode(raw), sign, keyId: await keyIdOf(raw) };
}

const SID = "S-1-5-21-1111111111-2222222222-3333333333-1001";

async function setupHub() {
  const d1 = sqliteD1();
  const dev = await keypair();
  const deviceId = ulid();
  const now = new Date().toISOString();
  d1.sql.prepare("INSERT INTO devices (id, hostname, device_pub_key, enrolled_at, timezone) VALUES (?, 'KID-PC', ?, ?, 'Asia/Ho_Chi_Minh')").run(deviceId, dev.pub, now);
  d1.sql.prepare("INSERT INTO managed_users (device_id, user_sid, name, is_admin, managed, updated_at) VALUES (?, ?, 'Bin', 0, 1, ?)").run(deviceId, SID, now);
  const env = { DB: d1.db, UPLOAD_TOKEN_SECRET: "upload-secret-for-tests-0123456789" } as unknown as Env;
  const f = fakeCtx();
  const hub = new DeviceHub(f.ctx as unknown as DurableObjectState, env);

  const connectDevice = async () => {
    const res = await hub.fetch(new Request(`https://x/v1/device/ws?deviceId=${deviceId}`, { headers: { upgrade: "websocket" } }));
    expect(res.status).toBe(101);
    const ws = f.sockets[f.sockets.length - 1]!;
    const { nonce } = ws.frames()[0]!;
    const ts = Math.floor(Date.now() / 1000);
    const sig = await dev.sign(`${nonce}|${deviceId}|${ts}`);
    await hub.webSocketMessage(ws as unknown as WebSocket, JSON.stringify({ t: "auth", deviceId, ts, sig }));
    expect(ws.frames().at(-1)!.t).toBe("ready");
    return ws;
  };
  const connectMaster = async (keyId = "k".repeat(16)) => {
    const res = await hub.fetch(
      new Request(`https://device-hub/v1/master/live?deviceId=${deviceId}`, { headers: { upgrade: "websocket", [MASTER_KEY_HEADER]: keyId } }),
    );
    expect(res.status).toBe(101);
    return f.sockets[f.sockets.length - 1]!;
  };
  const send = (ws: FakeWS, frame: unknown) => hub.webSocketMessage(ws as unknown as WebSocket, JSON.stringify(frame));
  const ev = (type: string, data: Record<string, unknown>, over: Record<string, unknown> = {}) => ({
    id: ulid(),
    deviceId,
    userSid: SID,
    ts: new Date().toISOString(),
    monoMs: 1,
    type,
    data,
    ...over,
  });
  return { d1, hub, f, deviceId, connectDevice, connectMaster, send, ev };
}

// ------------------------------------------------------------------ device events frame
describe("device events frame (API.md 15)", () => {
  it("schema accepts events frames of 1..50 and rejects empty/oversized ones", () => {
    expect(validateWsDeviceMessage({ t: "events", events: [{}] })).toBe(true);
    expect(validateWsDeviceMessage({ t: "events", events: [] })).toBe(false);
    expect(validateWsDeviceMessage({ t: "events", events: Array(51).fill({}) })).toBe(false);
    expect(validateWsDeviceMessage({ t: "events", events: [{}], extra: 1 })).toBe(false);
  });

  it("ingests into D1 with one batch, acks, is idempotent on id, and raises alerts", async () => {
    const s = await setupHub();
    const ws = await s.connectDevice();
    const visit = s.ev("web.visit", { url: "https://www.youtube.com/watch?v=abc", title: "YT", browser: "msedge", durationSec: 60 });
    const tamper = s.ev("tamper.state_tampered", { detail: "policy.json signature check failed" }, { userSid: undefined });
    delete (tamper as Record<string, unknown>).userSid;

    const before = s.d1.queries();
    await s.send(ws, { t: "events", events: [visit, tamper] });
    // hostname/timezone come from the cached attachment: existing-id SELECT + insert batch + rule context + alert batch
    expect(s.d1.queries() - before).toBeLessThanOrEqual(4);
    const ack = ws.frames().at(-1)!;
    expect(ack).toEqual({ t: "events_ack", ids: [visit.id, tamper.id], rejected: [] });
    expect(s.d1.sql.prepare("SELECT COUNT(*) AS n FROM events WHERE device_id = ?").get(s.deviceId)).toEqual({ n: 2 });
    expect(s.d1.sql.prepare("SELECT host FROM web_visits WHERE id = ?").get(visit.id)).toEqual({ host: "www.youtube.com" });
    expect(s.d1.sql.prepare("SELECT type FROM alerts WHERE device_id = ?").all(s.deviceId)).toEqual([{ type: "tamper.state_tampered" }]);

    // resend: acked again, nothing duplicated, no second alert
    await s.send(ws, { t: "events", events: [visit, tamper] });
    expect(ws.frames().at(-1)).toEqual({ t: "events_ack", ids: [visit.id, tamper.id], rejected: [] });
    expect(s.d1.sql.prepare("SELECT COUNT(*) AS n FROM events").get()).toEqual({ n: 2 });
    expect(s.d1.sql.prepare("SELECT COUNT(*) AS n FROM alerts").get()).toEqual({ n: 1 });
  });

  it("rejects bad events individually and stores the rest", async () => {
    const s = await setupHub();
    const ws = await s.connectDevice();
    const good = s.ev("web.visit", { url: "https://a.example/", title: "A", browser: "msedge", durationSec: 5 });
    const badSchema = { ...s.ev("web.visit", {}), type: "nope.unknown" };
    const otherDevice = s.ev("web.visit", { url: "https://b.example/", title: "B", browser: "msedge", durationSec: 5 }, { deviceId: ulid() });
    const tooBig = s.ev("web.visit", { url: "https://c.example/", title: "x".repeat(70 * 1024), browser: "msedge", durationSec: 5 });
    // frame stays under the 64 KB cap except for tooBig: send it in its own frame below
    await s.send(ws, { t: "events", events: [good, badSchema, otherDevice, good] });
    const ack = ws.frames().at(-1)!;
    expect(ack.ids).toEqual([good.id]);
    expect(ack.rejected).toEqual([
      { id: badSchema.id, error: expect.stringMatching(/^invalid_body/) },
      { id: otherDevice.id, error: "wrong_device" },
    ]);
    expect(s.d1.sql.prepare("SELECT id FROM events").all()).toEqual([{ id: good.id }]);
    // > 64 KB frame is refused by the frame cap (device must use HTTP for it)
    await s.send(ws, { t: "events", events: [tooBig] });
    expect(ws.closed?.code).toBe(4400);
  });

  it("on a D1 failure only schema rejections are acked (rest stays in the outbox)", async () => {
    const s = await setupHub();
    const ws = await s.connectDevice();
    const good = s.ev("web.visit", { url: "https://a.example/", title: "A", browser: "msedge", durationSec: 5 });
    const realBatch = (s.d1.db as unknown as { batch: unknown }).batch;
    (s.d1.db as unknown as { batch: unknown }).batch = async () => {
      throw new Error("D1 down");
    };
    await s.send(ws, { t: "events", events: [good, { id: "x" }] });
    (s.d1.db as unknown as { batch: unknown }).batch = realBatch;
    expect(ws.frames().at(-1)).toEqual({ t: "events_ack", ids: [], rejected: [{ id: "x", error: expect.stringMatching(/^invalid_body/) }] });
  });
});

// ------------------------------------------------------------------ master sockets
describe("master live sockets (API.md 15)", () => {
  it("are tagged, get online on connect, then state / accepted events / online changes", async () => {
    const s = await setupHub();
    const m = await s.connectMaster();
    expect(m.tags).toEqual([MASTER_TAG]);
    expect(m.frames()).toEqual([{ t: "online", deviceId: s.deviceId, online: false }]);

    const dev = await s.connectDevice();
    expect(m.frames().at(-1)).toEqual({ t: "online", deviceId: s.deviceId, online: true });

    const state = { ts: new Date().toISOString(), agentVersion: "0.2.0", policyVersion: 7, users: [{ sid: SID }] };
    await s.send(dev, { t: "state", state });
    expect(m.frames().at(-1)).toEqual({ t: "state", deviceId: s.deviceId, state });

    const good = s.ev("web.visit", { url: "https://a.example/", title: "A", browser: "msedge", durationSec: 5 });
    await s.send(dev, { t: "events", events: [good, { id: "bad" }] });
    const pushed = m.frames().at(-1)!;
    expect(pushed.t).toBe("events");
    expect(pushed.deviceId).toBe(s.deviceId);
    expect(pushed.events.map((e: { id: string }) => e.id)).toEqual([good.id]);

    // a second master gets the same fan-out; device socket never gets master frames
    const m2 = await s.connectMaster();
    expect(m2.frames()).toEqual([{ t: "online", deviceId: s.deviceId, online: true }]);
    expect(dev.frames().some((f) => f.t === "events" || f.t === "online")).toBe(false);

    dev.readyState = 3;
    await s.hub.webSocketClose(dev as unknown as WebSocket, 1006, "", false);
    expect(m.frames().at(-1)).toEqual({ t: "online", deviceId: s.deviceId, online: false });
    expect(m2.frames().at(-1)).toEqual({ t: "online", deviceId: s.deviceId, online: false });
    expect(s.d1.sql.prepare("SELECT online FROM devices WHERE id = ?").get(s.deviceId)).toEqual({ online: 0 });
  });

  it("are read-only: only ping is answered, everything else ignored; closing one does not mark the device offline", async () => {
    const s = await setupHub();
    const dev = await s.connectDevice();
    const m = await s.connectMaster();
    const n = m.sent.length;
    await s.send(m, { t: "events", events: [s.ev("web.visit", { url: "https://x/", title: "x", browser: "msedge", durationSec: 1 })] });
    await s.send(m, { t: "state", state: {} });
    await s.hub.webSocketMessage(m as unknown as WebSocket, "not json");
    expect(m.sent.length).toBe(n);
    expect(m.closed).toBeNull();
    expect(s.d1.sql.prepare("SELECT COUNT(*) AS n FROM events").get()).toEqual({ n: 0 });
    await s.send(m, { t: "ping", x: 1 });
    expect(m.frames().at(-1)).toEqual({ t: "pong" });

    m.readyState = 3;
    await s.hub.webSocketClose(m as unknown as WebSocket, 1000, "", true);
    expect(s.d1.sql.prepare("SELECT online FROM devices WHERE id = ?").get(s.deviceId)).toEqual({ online: 1 });
    expect(dev.closed).toBeNull();
  });

  it("idle sockets (no ping for 10 min) are closed by the alarm; pinging ones and the device stay", async () => {
    const s = await setupHub();
    const dev = await s.connectDevice();
    const idle = await s.connectMaster();
    const live = await s.connectMaster();
    const auto = await s.connectMaster();
    const old = Date.now() - MASTER_IDLE_MS - 1000;
    for (const w of [idle, live, auto]) {
      const att = w.deserializeAttachment() as { connectedAt: number; lastPingMs: number };
      w.serializeAttachment({ ...att, connectedAt: old, lastPingMs: old });
    }
    await s.send(live, { t: "ping", n: 1 }); // seen by webSocketMessage
    auto.autoTs = new Date(); // answered by the auto-response while hibernating
    await s.hub.alarm();
    expect(idle.closed?.code).toBe(4408);
    expect(live.closed).toBeNull();
    expect(auto.closed).toBeNull();
    expect(dev.closed).toBeNull();
    // next alarm is due no later than when the newest master would go idle
    expect(s.f.alarm()!).toBeLessThanOrEqual(Date.now() + MASTER_IDLE_MS + 1000);
  });

  it("closeMasterSockets closes masters (optionally by key) but not the device; revoke closes everything", async () => {
    const s = await setupHub();
    const dev = await s.connectDevice();
    const a = await s.connectMaster("a".repeat(16));
    const b = await s.connectMaster("b".repeat(16));
    expect(await s.hub.closeMasterSockets(["a".repeat(16)])).toBe(1);
    expect(a.closed?.code).toBe(4401);
    expect(b.closed).toBeNull();
    expect(await s.hub.closeMasterSockets()).toBe(1);
    expect(b.closed?.code).toBe(4401);
    expect(dev.closed).toBeNull();
    const c = await s.connectMaster();
    await s.hub.revoke(s.deviceId);
    expect(c.closed?.code).toBe(4403);
    expect(dev.closed?.code).toBe(4403);
  });

  it("refuses a master hand-off without a key id", async () => {
    const s = await setupHub();
    const res = await s.hub.fetch(new Request(`https://device-hub/v1/master/live?deviceId=${s.deviceId}`, { headers: { upgrade: "websocket" } }));
    expect(res.status).toBe(401);
  });
});

// ------------------------------------------------------------------ Worker route
describe("GET /v1/master/live (Worker)", () => {
  async function setupRoute() {
    const d1 = sqliteD1();
    const read = await keypair();
    const revoked = await keypair();
    const now = new Date().toISOString();
    d1.sql.prepare("INSERT INTO master_keys VALUES (?, 'ed25519', ?, 'read', ?, NULL)").run(read.keyId, read.pub, now);
    d1.sql.prepare("INSERT INTO master_keys VALUES (?, 'ed25519', ?, 'read', ?, ?)").run(revoked.keyId, revoked.pub, now, now);
    const deviceId = ulid();
    d1.sql.prepare("INSERT INTO devices (id, hostname, device_pub_key, enrolled_at) VALUES (?, 'PC', 'x', ?)").run(deviceId, now);
    const forwarded: Request[] = [];
    const ns = {
      idFromName: (n: string) => n,
      get: () => ({ fetch: async (r: Request) => (forwarded.push(r), new RealResponse("hub")) }),
    };
    const env = { DB: d1.db, DEVICE_HUB: ns } as unknown as Env;
    const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
    const call = async (path: string, key?: Awaited<ReturnType<typeof keypair>>, headers: Record<string, string> = { upgrade: "websocket" }) => {
      const h = { ...headers };
      if (key) {
        const ts = String(Math.floor(Date.now() / 1000));
        h["x-mc-auth"] = `v1;${key.keyId};${ts};${await key.sign(`GET\n${path}\n${ts}\n${await sha256Hex(utf8(""))}`)}`;
      }
      return worker.fetch(new Request(`https://example.test${path}`, { headers: h }), env, ctx);
    };
    return { d1, read, revoked, deviceId, forwarded, call };
  }

  it("verifies X-MC-Auth and forwards to the device's hub with the key id", async () => {
    const s = await setupRoute();
    const res = await s.call(`/v1/master/live?deviceId=${s.deviceId}`, s.read);
    expect(await res.text()).toBe("hub");
    expect(s.forwarded).toHaveLength(1);
    const f = s.forwarded[0]!;
    expect(new URL(f.url).pathname).toBe("/v1/master/live");
    expect(f.headers.get("upgrade")).toBe("websocket");
    expect(f.headers.get(MASTER_KEY_HEADER)).toBe(s.read.keyId);
  });

  it("auth failures: no header, revoked key, tampered path -> 401 and nothing forwarded", async () => {
    const s = await setupRoute();
    expect((await s.call(`/v1/master/live?deviceId=${s.deviceId}`)).status).toBe(401);
    expect((await s.call(`/v1/master/live?deviceId=${s.deviceId}`, s.revoked)).status).toBe(401);
    const signedFor = await s.call(`/v1/master/live?deviceId=${s.deviceId}`, s.read);
    expect(signedFor.status).toBe(200);
    // signature for another deviceId must not work
    const ts = String(Math.floor(Date.now() / 1000));
    const other = ulid();
    const sig = await s.read.sign(`GET\n/v1/master/live?deviceId=${other}\n${ts}\n${await sha256Hex(utf8(""))}`);
    const r = await s.call(`/v1/master/live?deviceId=${s.deviceId}`, undefined, { upgrade: "websocket", "x-mc-auth": `v1;${s.read.keyId};${ts};${sig}` });
    expect(r.status).toBe(401);
    expect(s.forwarded).toHaveLength(1);
  });

  it("requires an upgrade and a known, non-revoked device", async () => {
    const s = await setupRoute();
    expect((await s.call(`/v1/master/live?deviceId=${s.deviceId}`, s.read, {})).status).toBe(426);
    expect((await s.call(`/v1/master/live?deviceId=${ulid()}`, s.read)).status).toBe(404);
    expect((await s.call(`/v1/master/live?deviceId=nope`, s.read)).status).toBe(400);
    s.d1.sql.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?").run(new Date().toISOString(), s.deviceId);
    expect((await s.call(`/v1/master/live?deviceId=${s.deviceId}`, s.read)).status).toBe(404);
    expect(s.forwarded).toHaveLength(0);
  });
});
