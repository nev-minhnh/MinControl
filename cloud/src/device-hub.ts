// DeviceHub: one SQLite-backed Durable Object per device (idFromName(deviceId)).
// Holds the device WebSocket (hibernation API), the signed policy/command queue with per-kind seq,
// presence and upload-token refresh. D1 mirrors (policies, commands, devices.online/state) are written
// from here so the Worker can serve master reads without waking the DO.
import { DurableObject } from "cloudflare:workers";
import { issueUploadToken } from "./auth/upload-token";
import { type BlobResult, BlobRelay } from "./blob-relay";
import type { Env } from "./env";
import { randomBytes, verifySignatureB64 } from "./lib/crypto";
import { b64urlEncode, utf8 } from "./lib/encoding";
import { nowIso, parseAuthTs } from "./lib/time";
import { validateWsDeviceMessage } from "./generated/validators";

/** Close codes sent to the device. */
export const CLOSE_AUTH_FAILED = 4401;
export const CLOSE_REVOKED = 4403;
export const CLOSE_REPLACED = 4000;
export const CLOSE_BAD_FRAME = 4400;

const AUTH_TIMEOUT_MS = 30_000;
const AUTH_SKEW_MS = 300_000;
/** Refresh the upload token this long before it expires. */
const TOKEN_REFRESH_LEAD_MS = 10 * 60_000;
const MAX_FRAME_BYTES = 64 * 1024;

interface Attachment {
  deviceId: string;
  nonce: string;
  authed: boolean;
  connectedAt: number;
  tokenExpMs: number;
}

export interface PolicyMeta {
  version: number;
  timezone: string;
  retentionDays: { events: number; web: number; screenshots: number };
  /** managed users of this policy: SID -> label */
  users: Record<string, string>;
}

export interface EnqueueInput {
  deviceId: string;
  kind: "policy" | "command";
  seq: number;
  envelopeJson: string;
  keyId: string;
  issuedAt: string;
  expiresAt: string;
  policy?: PolicyMeta;
  command?: { commandId: string; type: string; userSid: string | null };
}

export type EnqueueResult =
  | { ok: true; delivered: boolean }
  | { ok: false; code: "replayed" | "duplicate" | "revoked"; lastSeq: number };

type Msg =
  | { t: "auth"; deviceId: string; ts: number; sig: string } // ts = unix seconds
  | { t: "ack"; ack: { commandId: string; status: "applied" | "rejected" | "failed"; at: string; error?: string; detail?: string } }
  | { t: "policy_applied"; version: number; seq: number }
  | { t: "policy_rejected"; seq: number; error: string }
  | { t: "state"; state: { agentVersion: string; policyVersion?: number | null } & Record<string, unknown> }
  | { t: "blob_missing"; reqId: string }
  | { t: "ping" }
  | { t: "pong" };

export class DeviceHub extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  /** Pending master blob requests (in memory only, API.md section 9). */
  private readonly blobs = new BlobRelay();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS policy (
        id INTEGER PRIMARY KEY CHECK (id = 1), seq INTEGER NOT NULL, version INTEGER NOT NULL,
        envelope TEXT NOT NULL, expires_ms INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS queue (
        seq INTEGER PRIMARY KEY, command_id TEXT NOT NULL UNIQUE, envelope TEXT NOT NULL,
        expires_ms INTEGER NOT NULL, status TEXT NOT NULL);
    `);
    // Pings are answered without waking the object (device pings every 30 s).
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"t":"ping"}', '{"t":"pong"}'));
  }

  // ---------------------------------------------------------------- meta helpers
  private meta(k: string): string | null {
    const row = this.sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = ?", k).toArray()[0];
    return row ? row.v : null;
  }
  private setMeta(k: string, v: string | number): void {
    this.sql.exec("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, String(v));
  }
  private metaNum(k: string): number {
    return Number(this.meta(k) ?? 0);
  }
  private bindDevice(deviceId: string): void {
    const cur = this.meta("deviceId");
    if (cur === null) this.setMeta("deviceId", deviceId);
    else if (cur !== deviceId) throw new Error("DeviceHub bound to a different device");
  }
  private get revoked(): boolean {
    return this.meta("revoked") === "1";
  }

  private authedSockets(): WebSocket[] {
    return this.ctx.getWebSockets().filter((ws) => (ws.deserializeAttachment() as Attachment | null)?.authed);
  }

  // ---------------------------------------------------------------- RPC (called by the Worker)
  async getSeq(): Promise<{ policy: number; command: number }> {
    return { policy: this.metaNum("lastPolicySeq"), command: this.metaNum("lastCommandSeq") };
  }

  async enqueue(input: EnqueueInput): Promise<EnqueueResult> {
    this.bindDevice(input.deviceId);
    const now = Date.now();
    const expiresMs = Date.parse(input.expiresAt);
    const createdAt = nowIso(now);
    if (this.revoked) return { ok: false, code: "revoked", lastSeq: 0 };

    // Synchronous check-and-insert (no await in between) keeps seq strictly increasing under concurrency.
    if (input.kind === "policy") {
      const last = this.metaNum("lastPolicySeq");
      if (input.seq <= last) return { ok: false, code: "replayed", lastSeq: last };
      const p = input.policy!;
      this.sql.exec(
        "INSERT OR REPLACE INTO policy (id, seq, version, envelope, expires_ms) VALUES (1, ?, ?, ?, ?)",
        input.seq, p.version, input.envelopeJson, expiresMs,
      );
      this.setMeta("lastPolicySeq", input.seq);

      const db = this.env.DB;
      const stmts = [
        db.prepare(
          `INSERT OR REPLACE INTO policies (device_id, seq, version, signed_blob, key_id, issued_at, expires_at, created_at, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued')`,
        ).bind(input.deviceId, input.seq, p.version, input.envelopeJson, input.keyId, input.issuedAt, input.expiresAt, createdAt),
        db.prepare("UPDATE devices SET policy_version = ?, timezone = ?, retention_json = ? WHERE id = ?")
          .bind(p.version, p.timezone, JSON.stringify(p.retentionDays), input.deviceId),
        db.prepare("UPDATE managed_users SET managed = 0, label = NULL, updated_at = ? WHERE device_id = ?").bind(createdAt, input.deviceId),
      ];
      for (const [sid, label] of Object.entries(p.users)) {
        stmts.push(
          db.prepare(
            `INSERT INTO managed_users (device_id, user_sid, name, is_admin, managed, label, updated_at) VALUES (?, ?, ?, 0, 1, ?, ?)
             ON CONFLICT(device_id, user_sid) DO UPDATE SET managed = 1, label = excluded.label, updated_at = excluded.updated_at`,
          ).bind(input.deviceId, sid, label, label, createdAt),
        );
      }
      await db.batch(stmts);
      const delivered = this.sendToDevice(input.envelopeJson);
      if (delivered) await this.markPolicyDelivered(input.seq);
      return { ok: true, delivered };
    }

    const c = input.command!;
    const last = this.metaNum("lastCommandSeq");
    if (input.seq <= last) return { ok: false, code: "replayed", lastSeq: last };
    if (this.sql.exec("SELECT 1 FROM queue WHERE command_id = ?", c.commandId).toArray().length > 0) {
      return { ok: false, code: "duplicate", lastSeq: last };
    }
    this.sql.exec(
      "INSERT INTO queue (seq, command_id, envelope, expires_ms, status) VALUES (?, ?, ?, ?, 'queued')",
      input.seq, c.commandId, input.envelopeJson, expiresMs,
    );
    this.setMeta("lastCommandSeq", input.seq);
    await this.env.DB.prepare(
      `INSERT OR IGNORE INTO commands (id, device_id, user_sid, type, signed_blob, seq, created_at, expires_at, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued')`,
    ).bind(c.commandId, input.deviceId, c.userSid, c.type, input.envelopeJson, input.seq, createdAt, input.expiresAt).run();

    const delivered = this.sendToDevice(input.envelopeJson);
    if (delivered) await this.markCommandDelivered(input.seq, c.commandId);
    this.scheduleAlarm();
    return { ok: true, delivered };
  }

  /** Master blob request: asks the device for a sealed screenshot and waits (25 s) for its upload. */
  async requestBlob(key: string): Promise<BlobResult> {
    const ws = this.authedSockets()[0];
    if (!ws) return { status: "offline" };
    return this.blobs.request(key, (frame) => this.sendRaw(ws, frame));
  }

  /** Device upload (PUT ?reqId=) forwarded by the Worker. False = unknown/expired reqId. */
  async resolveBlob(reqId: string, key: string, bytes: Uint8Array): Promise<boolean> {
    return this.blobs.resolveBytes(reqId, key, bytes);
  }

  async revoke(deviceId: string): Promise<void> {
    this.bindDevice(deviceId);
    this.setMeta("revoked", "1");
    this.blobs.failAll("offline");
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.close(CLOSE_REVOKED, "revoked");
      } catch {
        /* already closed */
      }
    }
  }

  // ---------------------------------------------------------------- WebSocket
  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return Response.json({ error: "upgrade_required", message: "expected a WebSocket upgrade" }, { status: 426 });
    }
    const deviceId = new URL(request.url).searchParams.get("deviceId") ?? "";
    try {
      this.bindDevice(deviceId);
    } catch {
      return Response.json({ error: "wrong_device", message: "device mismatch" }, { status: 400 });
    }
    if (this.revoked) return Response.json({ error: "revoked", message: "device revoked" }, { status: 403 });

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    this.ctx.acceptWebSocket(server);
    const nonce = b64urlEncode(randomBytes(32));
    const att: Attachment = { deviceId, nonce, authed: false, connectedAt: Date.now(), tokenExpMs: 0 };
    server.serializeAttachment(att);
    server.send(JSON.stringify({ t: "challenge", nonce }));
    this.scheduleAlarm();
    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const att = ws.deserializeAttachment() as Attachment | null;
    if (!att) return this.closeWs(ws, CLOSE_BAD_FRAME, "no session");
    if (typeof message !== "string" || message.length > MAX_FRAME_BYTES) {
      return this.closeWs(ws, att.authed ? CLOSE_BAD_FRAME : CLOSE_AUTH_FAILED, "bad frame");
    }
    let msg: unknown;
    try {
      msg = JSON.parse(message);
    } catch {
      return this.closeWs(ws, att.authed ? CLOSE_BAD_FRAME : CLOSE_AUTH_FAILED, "bad json");
    }
    const valid = validateWsDeviceMessage(msg);
    const m = msg as Msg;
    if (!att.authed) {
      if (!valid || m.t !== "auth") {
        if (valid && m.t === "ping") return ws.send('{"t":"pong"}');
        return this.closeWs(ws, CLOSE_AUTH_FAILED, "auth required");
      }
      return this.handleAuth(ws, att, m);
    }
    if (!valid) {
      console.warn("DeviceHub: invalid frame", JSON.stringify(validateWsDeviceMessage.errors?.[0] ?? null));
      return;
    }
    switch (m.t) {
      case "ping":
        ws.send('{"t":"pong"}');
        return;
      case "pong":
      case "auth":
        return;
      case "ack":
        return this.handleAck(m.ack);
      case "policy_applied":
        return this.handlePolicyResult(m.seq, "applied", null, m.version);
      case "policy_rejected":
        return this.handlePolicyResult(m.seq, "rejected", m.error, null);
      case "blob_missing":
        this.blobs.resolveMissing(m.reqId);
        return;
      case "state":
        await this.env.DB.prepare(
          "UPDATE devices SET state_json = ?, last_seen_at = ?, online = 1, agent_version = ? WHERE id = ?",
        ).bind(JSON.stringify(m.state), nowIso(), m.state.agentVersion, att.deviceId).run();
        return;
    }
  }

  override async webSocketClose(ws: WebSocket, code: number, _reason: string, _wasClean: boolean): Promise<void> {
    this.closeWs(ws, code === 1005 || code === 1006 ? 1000 : code, "closed");
    await this.updatePresence(ws);
  }

  override async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    await this.updatePresence(ws);
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    const secret = this.env.UPLOAD_TOKEN_SECRET;
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (!att) continue;
      if (!att.authed) {
        if (now - att.connectedAt >= AUTH_TIMEOUT_MS) this.closeWs(ws, CLOSE_AUTH_FAILED, "auth timeout");
        continue;
      }
      if (secret && att.tokenExpMs - now <= TOKEN_REFRESH_LEAD_MS) {
        const tok = await issueUploadToken(secret, att.deviceId, now);
        att.tokenExpMs = tok.expMs;
        ws.serializeAttachment(att);
        this.sendRaw(ws, JSON.stringify({ t: "token", uploadToken: tok.token, uploadTokenExpiresAt: tok.expiresAt }));
      }
    }
    await this.expireCommands(now);
    this.scheduleAlarm();
  }

  // ---------------------------------------------------------------- internals
  private async handleAuth(ws: WebSocket, att: Attachment, m: Extract<Msg, { t: "auth" }>): Promise<void> {
    const now = Date.now();
    const tsText = String(m.ts); // decimal string, as signed by the device
    const tsMs = parseAuthTs(tsText);
    if (m.deviceId !== att.deviceId || !Number.isFinite(tsMs) || Math.abs(now - tsMs) > AUTH_SKEW_MS) {
      return this.closeWs(ws, CLOSE_AUTH_FAILED, "auth failed");
    }
    const row = await this.env.DB.prepare("SELECT device_pub_key, revoked_at FROM devices WHERE id = ?")
      .bind(att.deviceId)
      .first<{ device_pub_key: string; revoked_at: string | null }>();
    if (!row || row.revoked_at || this.revoked) {
      if (row?.revoked_at) this.setMeta("revoked", "1");
      return this.closeWs(ws, row?.revoked_at ? CLOSE_REVOKED : CLOSE_AUTH_FAILED, "auth failed");
    }
    const signed = utf8(`${att.nonce}|${att.deviceId}|${tsText}`);
    if (!(await verifySignatureB64("ed25519", row.device_pub_key, m.sig, signed))) {
      return this.closeWs(ws, CLOSE_AUTH_FAILED, "auth failed");
    }
    const secret = this.env.UPLOAD_TOKEN_SECRET;
    if (!secret) {
      console.error("DeviceHub: UPLOAD_TOKEN_SECRET is not set");
      return this.closeWs(ws, 1011, "server misconfigured");
    }
    // One live connection per device: the newest wins.
    for (const other of this.authedSockets()) {
      if (other !== ws) this.closeWs(other, CLOSE_REPLACED, "replaced by a newer connection");
    }
    const tok = await issueUploadToken(secret, att.deviceId, now);
    att.authed = true;
    att.tokenExpMs = tok.expMs;
    ws.serializeAttachment(att);
    ws.send(JSON.stringify({ t: "ready", serverTime: nowIso(now), uploadToken: tok.token, uploadTokenExpiresAt: tok.expiresAt }));
    await this.env.DB.prepare("UPDATE devices SET online = 1, last_seen_at = ? WHERE id = ?").bind(nowIso(now), att.deviceId).run();
    await this.deliverPending(ws, now);
    this.scheduleAlarm();
  }

  /** Pending policy first, then queued (and delivered-but-unacked) commands in seq order. */
  private async deliverPending(ws: WebSocket, now: number): Promise<void> {
    const handled = this.metaNum("policyHandledSeq");
    const p = this.sql.exec<{ seq: number; envelope: string; expires_ms: number }>(
      "SELECT seq, envelope, expires_ms FROM policy WHERE id = 1",
    ).toArray()[0];
    if (p && p.seq > handled && p.expires_ms > now) {
      if (this.sendEnvelope(ws, p.envelope)) await this.markPolicyDelivered(p.seq);
    }
    await this.expireCommands(now);
    const rows = this.sql.exec<{ seq: number; command_id: string; envelope: string; status: string }>(
      "SELECT seq, command_id, envelope, status FROM queue WHERE status IN ('queued', 'delivered') ORDER BY seq",
    ).toArray();
    for (const r of rows) {
      if (!this.sendEnvelope(ws, r.envelope)) break;
      if (r.status === "queued") await this.markCommandDelivered(r.seq, r.command_id);
    }
  }

  /** Sends a stored envelope to the live authenticated connection, if any. */
  private sendToDevice(envelopeJson: string): boolean {
    const ws = this.authedSockets()[0];
    return ws ? this.sendEnvelope(ws, envelopeJson) : false;
  }

  private sendEnvelope(ws: WebSocket, envelopeJson: string): boolean {
    return this.sendRaw(ws, `{"t":"envelope","envelope":${envelopeJson}}`);
  }

  private sendRaw(ws: WebSocket, frame: string): boolean {
    try {
      ws.send(frame);
      return true;
    } catch {
      return false;
    }
  }

  private async markPolicyDelivered(seq: number): Promise<void> {
    const id = this.meta("deviceId");
    await this.env.DB.prepare("UPDATE policies SET status = 'delivered' WHERE device_id = ? AND seq = ? AND status = 'queued'")
      .bind(id, seq)
      .run();
  }

  private async markCommandDelivered(seq: number, commandId: string): Promise<void> {
    this.sql.exec("UPDATE queue SET status = 'delivered' WHERE seq = ? AND status = 'queued'", seq);
    await this.env.DB.prepare("UPDATE commands SET status = 'delivered' WHERE id = ? AND status = 'queued'").bind(commandId).run();
  }

  private async handleAck(ack: Extract<Msg, { t: "ack" }>["ack"]): Promise<void> {
    const row = this.sql.exec<{ seq: number; status: string }>("SELECT seq, status FROM queue WHERE command_id = ?", ack.commandId).toArray()[0];
    if (!row) return;
    // A redelivered command the device had already applied comes back as "replayed": keep the
    // earlier outcome instead of overwriting it with a rejection.
    if (ack.status === "rejected" && ack.error === "replayed" && row.status !== "queued") {
      this.sql.exec("UPDATE queue SET status = 'done' WHERE seq = ?", row.seq);
      return;
    }
    this.sql.exec("UPDATE queue SET status = 'done' WHERE seq = ?", row.seq);
    await this.env.DB.prepare(
      "UPDATE commands SET status = ?, ack_at = ?, ack_error = ?, ack_detail = ? WHERE id = ? AND status IN ('queued', 'delivered', 'expired')",
    ).bind(ack.status, nowIso(), ack.error ?? null, ack.detail ?? null, ack.commandId).run();
    this.sql.exec("DELETE FROM queue WHERE status IN ('done', 'expired') AND seq < ?", row.seq - 100);
  }

  private async handlePolicyResult(seq: number, status: "applied" | "rejected", error: string | null, version: number | null): Promise<void> {
    if (seq > this.metaNum("lastPolicySeq")) return; // unknown seq
    if (seq > this.metaNum("policyHandledSeq")) this.setMeta("policyHandledSeq", seq);
    const id = this.meta("deviceId");
    const db = this.env.DB;
    const stmts = [db.prepare("UPDATE policies SET status = ?, error = ? WHERE device_id = ? AND seq = ?").bind(status, error, id, seq)];
    if (version !== null) stmts.push(db.prepare("UPDATE devices SET applied_policy_version = ? WHERE id = ?").bind(version, id));
    await db.batch(stmts);
  }

  private async expireCommands(now: number): Promise<void> {
    const expired = this.sql.exec<{ command_id: string }>(
      "SELECT command_id FROM queue WHERE status = 'queued' AND expires_ms <= ?", now,
    ).toArray();
    if (expired.length === 0) return;
    this.sql.exec("UPDATE queue SET status = 'expired' WHERE status = 'queued' AND expires_ms <= ?", now);
    const db = this.env.DB;
    await db.batch(
      expired.map((r) => db.prepare("UPDATE commands SET status = 'expired' WHERE id = ? AND status = 'queued'").bind(r.command_id)),
    );
  }

  private async updatePresence(closing: WebSocket): Promise<void> {
    const att = closing.deserializeAttachment() as Attachment | null;
    if (!att?.authed) return;
    const stillOnline = this.authedSockets().some((ws) => ws !== closing && ws.readyState === WebSocket.OPEN);
    if (!stillOnline) {
      this.blobs.failAll("offline");
      await this.env.DB.prepare("UPDATE devices SET online = 0, last_seen_at = ? WHERE id = ?").bind(nowIso(), att.deviceId).run();
    }
  }

  private closeWs(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.close(code, reason);
    } catch {
      /* already closed */
    }
  }

  /** Next wake-up: auth timeouts of pending sockets, token refresh, next queued command expiry. */
  private scheduleAlarm(): void {
    let next = Infinity;
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (!att) continue;
      next = Math.min(next, att.authed ? att.tokenExpMs - TOKEN_REFRESH_LEAD_MS : att.connectedAt + AUTH_TIMEOUT_MS);
    }
    const q = this.sql.exec<{ m: number | null }>("SELECT MIN(expires_ms) AS m FROM queue WHERE status = 'queued'").toArray()[0];
    if (q?.m != null) next = Math.min(next, q.m);
    if (Number.isFinite(next)) void this.ctx.storage.setAlarm(Math.max(next, Date.now() + 1000));
  }
}
