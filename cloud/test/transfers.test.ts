import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";
import { keyIdOf, sha256Hex } from "../src/lib/crypto";
import { b64urlEncode, utf8 } from "../src/lib/encoding";
import { ulid } from "../src/lib/ulid";

// Real SQLite (node:sqlite) behind a minimal D1 facade, running the actual migrations.
function sqliteD1() {
  const sql = new DatabaseSync(":memory:");
  const dir = join(process.cwd(), "migrations");
  for (const f of readdirSync(dir).sort()) sql.exec(readFileSync(join(dir, f), "utf8"));
  const stmt = (q: string, args: unknown[] = []) => ({
    bind: (...a: unknown[]) => stmt(q, a),
    first: async () => (sql.prepare(q).get(...(args as never[])) as unknown) ?? null,
    all: async () => ({ results: sql.prepare(q).all(...(args as never[])) as unknown[] }),
    run: async () => ({ meta: { changes: Number(sql.prepare(q).run(...(args as never[])).changes) } }),
  });
  const db = {
    prepare: (q: string) => stmt(q),
    batch: async (list: ReturnType<typeof stmt>[]) => {
      sql.exec("BEGIN");
      try {
        const out = [];
        for (const s of list) out.push(await s.run());
        sql.exec("COMMIT");
        return out;
      } catch (e) {
        sql.exec("ROLLBACK");
        throw e;
      }
    },
  };
  return { db: db as unknown as D1Database, sql };
}

const ED = { name: "Ed25519" };
type Kp = Awaited<ReturnType<typeof keypair>>;
async function keypair() {
  const kp = (await crypto.subtle.generateKey(ED, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  const sign = async (s: string | Uint8Array) =>
    b64urlEncode(new Uint8Array(await crypto.subtle.sign(ED, kp.privateKey, typeof s === "string" ? utf8(s) : s)));
  return { pub: b64urlEncode(raw), sign, keyId: await keyIdOf(raw) };
}
const rand32 = () => b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

function fakeHubs() {
  const last = new Map<string, number>();
  const enq: { deviceId: string; kind: string; seq: number; transferId?: string }[] = [];
  const ns = {
    idFromName: (n: string) => n,
    get: (id: string) => ({
      getSeq: async () => ({ policy: 0, command: 0, masterKeys: last.get(id) ?? 0 }),
      enqueue: async (i: { kind: string; seq: number; masterKeys?: { transferId: string } }) => {
        last.set(id, i.seq);
        enq.push({ deviceId: id, kind: i.kind, seq: i.seq, transferId: i.masterKeys?.transferId });
        return { ok: true, delivered: false };
      },
    }),
  };
  return { ns, enq };
}

async function setup() {
  const { db, sql } = sqliteD1();
  const hubs = fakeHubs();
  const env = { DB: db, DEVICE_HUB: hubs.ns, ADMIN_BOOTSTRAP_SECRET: "s3cret-bootstrap" } as unknown as Env;
  const now = new Date().toISOString();
  const oldSign = await keypair();
  const oldRead = await keypair();
  for (const [k, role] of [[oldSign, "sign"], [oldRead, "read"]] as const) {
    sql.prepare("INSERT INTO master_keys VALUES (?, 'ed25519', ?, ?, ?, NULL)").run(k.keyId, k.pub, role, now);
  }
  sql.prepare("INSERT INTO config VALUES ('master_seal_pub_key', ?, ?)").run(rand32(), now);
  const devs = [ulid(Date.now()), ulid(Date.now() + 1)];
  for (const id of devs) sql.prepare("INSERT INTO devices (id, hostname, device_pub_key, enrolled_at) VALUES (?, 'PC', 'x', ?)").run(id, now);
  const revokedDev = ulid(Date.now() + 2);
  sql.prepare("INSERT INTO devices (id, hostname, device_pub_key, enrolled_at, revoked_at) VALUES (?, 'PC', 'x', ?, ?)").run(revokedDev, now, now);

  const call = async (method: string, path: string, body?: unknown, auth?: Kp, ip = "7.7.7.7") => {
    const raw = body === undefined ? "" : JSON.stringify(body);
    const headers: Record<string, string> = { "cf-connecting-ip": ip };
    if (auth) {
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = await auth.sign(`${method}\n${path}\n${ts}\n${await sha256Hex(utf8(raw))}`);
      headers["x-mc-auth"] = `v1;${auth.keyId};${ts};${sig}`;
    }
    return worker.fetch(new Request(`https://example.test${path}`, { method, headers, body: raw === "" ? undefined : raw }), env, ctx);
  };

  const newSign = await keypair();
  const newRead = await keypair();
  const newSeal = rand32();
  const newKeys = [
    { keyId: newSign.keyId, alg: "ed25519", publicKey: newSign.pub, role: "sign" },
    { keyId: newRead.keyId, alg: "ed25519", publicKey: newRead.pub, role: "read" },
  ];
  const create = async () => (await (await call("POST", "/v1/master/transfers", undefined, oldSign)).json()) as { transferId: string; token: string };
  const claimBody = async (token: string, over: Record<string, unknown> = {}) => ({
    token, keys: newKeys, sealPubKey: newSeal, transportPubKey: rand32(), sig: await newSign.sign("transfer|" + token), ...over,
  });
  const envelope = async (deviceId: string, seq: number, body: unknown, signer: Kp = oldSign) => {
    const payload = {
      deviceId, kind: "master_keys", seq, issuedAt: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(), body,
    };
    const bytes = utf8(JSON.stringify(payload));
    return { v: 1, alg: "ed25519", keyId: signer.keyId, payload: b64urlEncode(bytes), sig: await signer.sign(bytes) };
  };
  const goodBody = { keys: [{ keyId: newSign.keyId, alg: "ed25519", publicKey: newSign.pub, role: "sign" }], sealPubKey: newSeal };
  const allEnvelopes = async (body: unknown = goodBody, signer: Kp = oldSign) =>
    Object.fromEntries(await Promise.all(devs.map(async (d) => [d, await envelope(d, 1, body, signer)])));
  return { sql, call, hubs, oldSign, oldRead, newSign, newRead, newSeal, devs, create, claimBody, envelope, goodBody, allEnvelopes };
}

describe("phone transfer (API.md section 13A)", () => {
  it("happy path: create, claim, poll, complete, new keys active, old revoked, envelopes queued", async () => {
    const s = await setup();
    expect((await s.call("POST", "/v1/master/transfers", undefined, s.oldRead)).status).toBe(403); // sign key only
    const { transferId, token } = await s.create();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);

    let poll = await s.call("GET", `/v1/master/transfers/${transferId}`, undefined, s.oldRead);
    expect(await poll.json()).toMatchObject({ status: "pending" });

    const claim = await s.call("POST", "/v1/master/transfers/claim", await s.claimBody(token));
    expect(claim.status).toBe(202);
    expect(await claim.json()).toEqual({ transferId, status: "pending" });
    // pending keys are not active yet
    expect(s.sql.prepare("SELECT COUNT(*) AS n FROM master_keys WHERE key_id = ?").get(s.newSign.keyId)).toEqual({ n: 0 });
    expect((await s.call("GET", `/v1/master/transfers/${transferId}`, undefined, s.newRead)).status).toBe(401);

    poll = await s.call("GET", `/v1/master/transfers/${transferId}`, undefined, s.oldSign);
    const claimed = (await poll.json()) as any;
    expect(claimed.status).toBe("claimed");
    expect(claimed.fp).toBe(s.newSign.keyId.slice(0, 12));
    expect(claimed.newKeys).toHaveLength(2);
    expect(claimed.transportPubKey).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const sealed = rand32();
    const done = await s.call("POST", `/v1/master/transfers/${transferId}/complete`, { envelopes: await s.allEnvelopes(), sealedSealKey: sealed }, s.oldSign);
    expect(done.status).toBe(200);

    const active = (s.sql.prepare("SELECT key_id FROM master_keys WHERE revoked_at IS NULL").all() as any[]).map((r) => r.key_id).sort();
    expect(active).toEqual([s.newSign.keyId, s.newRead.keyId].sort());
    expect(s.sql.prepare("SELECT v FROM config WHERE k = 'master_seal_pub_key'").get()).toEqual({ v: s.newSeal });
    expect(s.hubs.enq.map((e) => e.deviceId).sort()).toEqual([...s.devs].sort());
    expect(s.hubs.enq.every((e) => e.kind === "master_keys" && e.seq === 1 && e.transferId === transferId)).toBe(true);
    expect(s.sql.prepare("SELECT COUNT(*) AS n FROM transfer_devices WHERE transfer_id = ? AND status = 'queued'").get(transferId)).toEqual({ n: 2 });

    // new phone polls with its NEW read key; old keys are revoked
    const fin = await s.call("GET", `/v1/master/transfers/${transferId}`, undefined, s.newRead);
    expect(await fin.json()).toEqual({ status: "done", sealedSealKey: sealed });
    expect((await s.call("GET", `/v1/master/transfers/${transferId}`, undefined, s.oldRead)).status).toBe(401);
    // completing twice is refused
    const again = await s.call("POST", `/v1/master/transfers/${transferId}/complete`, { envelopes: await s.allEnvelopes(s.goodBody, s.newSign), sealedSealKey: sealed }, s.newSign);
    expect(again.status).toBe(409);
  });

  it("token is single use; bad token / bad sig rejected", async () => {
    const s = await setup();
    const { token } = await s.create();
    const bad = await s.claimBody(token, { sig: await s.newRead.sign("transfer|" + token) });
    expect((await s.call("POST", "/v1/master/transfers/claim", bad)).status).toBe(400);
    expect((await s.call("POST", "/v1/master/transfers/claim", await s.claimBody(rand32()))).status).toBe(404);
    expect((await s.call("POST", "/v1/master/transfers/claim", await s.claimBody(token))).status).toBe(202);
    const again = await s.call("POST", "/v1/master/transfers/claim", await s.claimBody(token));
    expect(again.status).toBe(410);
    expect(((await again.json()) as any).error).toBe("token_used");
  });

  it("claim is rate limited per IP", async () => {
    const s = await setup();
    let last = 0;
    for (let i = 0; i < 11; i++) last = (await s.call("POST", "/v1/master/transfers/claim", await s.claimBody(rand32()), undefined, "5.5.5.5")).status;
    expect(last).toBe(429);
  });

  it("complete rejects wrong envelopes", async () => {
    const s = await setup();
    const { transferId, token } = await s.create();
    await s.call("POST", "/v1/master/transfers/claim", await s.claimBody(token));
    const path = `/v1/master/transfers/${transferId}/complete`;
    const sealed = rand32();
    const other = await keypair();
    const wrongKeys = await s.allEnvelopes({ keys: [{ keyId: other.keyId, alg: "ed25519", publicKey: other.pub, role: "sign" }], sealPubKey: s.newSeal });
    let r = await s.call("POST", path, { envelopes: wrongKeys, sealedSealKey: sealed }, s.oldSign);
    expect(r.status).toBe(400);
    expect(((await r.json()) as any).error).toBe("wrong_keys");
    r = await s.call("POST", path, { envelopes: await s.allEnvelopes({ ...s.goodBody, sealPubKey: rand32() }), sealedSealKey: sealed }, s.oldSign);
    expect(((await r.json()) as any).error).toBe("wrong_keys");
    r = await s.call("POST", path, { envelopes: await s.allEnvelopes(s.goodBody, other), sealedSealKey: sealed }, s.oldSign); // unknown signer
    expect(r.status).toBe(403);
    r = await s.call("POST", path, { envelopes: await s.allEnvelopes(s.goodBody, s.oldRead), sealedSealKey: sealed }, s.oldSign); // read key
    expect(r.status).toBe(403);
    const swapped = await s.allEnvelopes(); // envelope addressed to another device
    [swapped[s.devs[0]!], swapped[s.devs[1]!]] = [swapped[s.devs[1]!]!, swapped[s.devs[0]!]!];
    r = await s.call("POST", path, { envelopes: swapped, sealedSealKey: sealed }, s.oldSign);
    expect(((await r.json()) as any).error).toBe("wrong_device");
    // nothing changed
    expect(s.sql.prepare("SELECT COUNT(*) AS n FROM master_keys WHERE revoked_at IS NULL").get()).toEqual({ n: 2 });
    expect(s.hubs.enq).toHaveLength(0);
  });

  it("complete requires an envelope for every non-revoked device (and none for others)", async () => {
    const s = await setup();
    const { transferId, token } = await s.create();
    await s.call("POST", "/v1/master/transfers/claim", await s.claimBody(token));
    const path = `/v1/master/transfers/${transferId}/complete`;
    const all = await s.allEnvelopes();
    let r = await s.call("POST", path, { envelopes: { [s.devs[0]!]: all[s.devs[0]!] }, sealedSealKey: rand32() }, s.oldSign);
    expect(r.status).toBe(400);
    const j = (await r.json()) as any;
    expect(j.error).toBe("missing_device_envelope");
    expect(j.details.deviceIds).toEqual([s.devs[1]]);
    r = await s.call("POST", path, { envelopes: { ...all, [ulid(Date.now() + 9)]: all[s.devs[0]!] }, sealedSealKey: rand32() }, s.oldSign);
    expect(((await r.json()) as any).error).toBe("unknown_device_envelope");
    expect(s.sql.prepare("SELECT status FROM transfers WHERE id = ?").get(transferId)).toEqual({ status: "claimed" });
  });

  it("complete before claim is refused", async () => {
    const s = await setup();
    const { transferId } = await s.create();
    const r = await s.call("POST", `/v1/master/transfers/${transferId}/complete`, { envelopes: await s.allEnvelopes(), sealedSealKey: rand32() }, s.oldSign);
    expect(r.status).toBe(409);
  });
});

describe("recovery code (API.md section 13B)", () => {
  it("a bootstrap secret works once, then 403 recovery_code_used", async () => {
    const s = await setup();
    const reg = async (secret: string) => {
      const sign = await keypair();
      const read = await keypair();
      return s.call("POST", "/v1/master/register", {
        bootstrapSecret: secret,
        keys: [
          { keyId: sign.keyId, alg: "ed25519", publicKey: sign.pub, role: "sign" },
          { keyId: read.keyId, alg: "ed25519", publicKey: read.pub, role: "read" },
        ],
        sealPubKey: rand32(),
      });
    };
    expect((await reg("wrong")).status).toBe(403);
    expect((await reg("s3cret-bootstrap")).status).toBe(201);
    const again = await reg("s3cret-bootstrap");
    expect(again.status).toBe(403);
    expect(((await again.json()) as any).error).toBe("recovery_code_used");
    expect(s.sql.prepare("SELECT v FROM config WHERE k = 'bootstrap_used'").get()).toEqual({ v: await sha256Hex("s3cret-bootstrap") });
  });
});
