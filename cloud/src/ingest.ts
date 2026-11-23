// Event batch ingestion: generic `events` plus denormalised tables, idempotent on event id.
// D1 allows at most 100 bound parameters per statement, so rows are written as chunked multi-row inserts
// inside one atomic batch (keeps the query count low on the Workers free plan).
import { type AlertDraft, BURST_TYPES, BURST_WINDOW_MS, type RuleContext, alertForEvent, burstAlert, burstDetails, detectBurst, saveAndPushAlerts } from "./alerts";
import type { Env } from "./env";
import { localDay, normTs, nowIso } from "./lib/time";
import { validateEvent } from "./generated/validators";

/** `diag.report` events may carry up to 256 KB of data (API.md section 14); every other type stays small. */
export const MAX_DIAG_BYTES = 256 * 1024;
export const MAX_EVENT_BYTES = 64 * 1024;

export interface IngestEvent {
  id: string;
  deviceId: string;
  userSid?: string;
  ts: string; // normalised
  monoMs: number;
  type: string;
  data: Record<string, unknown>;
}

type Row = unknown[];

export interface Rows {
  events: Row[];
  web: Row[];
  screenshots: Row[];
  usage: Row[];
  domains: Row[];
}

const MAX_PARAMS = 100;

const s = (v: unknown): string | null => (typeof v === "string" ? v : null);
const n = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export function hostOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

/** Builds all row values for new (not yet stored) events. Pure; aggregates usage/domains per key. */
export function buildRows(events: IngestEvent[], deviceId: string, timezone: string | null, receivedAt: string): Rows {
  const rows: Rows = { events: [], web: [], screenshots: [], usage: [], domains: [] };
  const usage = new Map<string, Row>();
  const domains = new Map<string, Row>();
  for (const e of events) {
    const d = e.data;
    const sid = e.userSid ?? null;
    rows.events.push([e.id, deviceId, sid, e.ts, e.monoMs, e.type, JSON.stringify(d), receivedAt]);
    switch (e.type) {
      case "web.visit": {
        const url = s(d.url);
        rows.web.push([e.id, deviceId, sid, e.ts, "visit", url, hostOf(url), s(d.title), n(d.durationSec), null, s(d.transition)]);
        break;
      }
      case "web.search":
        rows.web.push([e.id, deviceId, sid, e.ts, "search", null, s(d.engine), s(d.query), null, s(d.engine), null]);
        break;
      case "web.blocked": {
        const url = s(d.url);
        rows.web.push([e.id, deviceId, sid, e.ts, "blocked", url, s(d.host) ?? hostOf(url), null, null, s(d.category) ?? s(d.reason), null]);
        break;
      }
      case "screenshot.taken": {
        const key = s(d.blobKey);
        // Only index blobs inside the caller's own prefix (the GET route enforces the key shape too).
        if (key && key.startsWith(`screens/${deviceId}/`)) {
          rows.screenshots.push([e.id, deviceId, sid, e.ts, key, n(d.width), n(d.height), s(d.reason), s(d.commandId), s(d.foregroundExe)]);
        }
        break;
      }
      case "usage.tick": {
        if (!sid) break;
        const minuteMs = Date.parse(s(d.minuteStart) ?? e.ts);
        const day = localDay(Number.isFinite(minuteMs) ? minuteMs : Date.parse(e.ts), timezone);
        const exe = (s(d.exe) ?? "").toLowerCase();
        const k = `${sid}\u0000${day}\u0000${exe}`;
        const cur = usage.get(k);
        const sec = n(d.activeSec) ?? 0;
        if (cur) {
          cur[5] = (cur[5] as number) + sec;
          if (s(d.group)) cur[4] = s(d.group);
        } else {
          const row: Row = [deviceId, sid, day, exe, s(d.group) ?? "", sec];
          usage.set(k, row);
          rows.usage.push(row);
        }
        break;
      }
      case "net.domain": {
        if (!sid) break;
        const winMs = Date.parse(s(d.windowStart) ?? e.ts);
        const day = localDay(Number.isFinite(winMs) ? winMs : Date.parse(e.ts), timezone);
        const host = (s(d.host) ?? "").toLowerCase();
        const exe = (s(d.exe) ?? "").toLowerCase();
        const allowed = d.allowed === false ? 0 : 1;
        const k = `${sid}\u0000${day}\u0000${host}\u0000${exe}\u0000${allowed}`;
        const cur = domains.get(k);
        if (cur) {
          cur[6] = (cur[6] as number) + (n(d.connections) ?? 0);
          cur[7] = (cur[7] as number) + (n(d.bytesOut) ?? 0);
          cur[8] = (cur[8] as number) + (n(d.bytesIn) ?? 0);
        } else {
          const row: Row = [deviceId, sid, day, host, exe, allowed, n(d.connections) ?? 0, n(d.bytesOut) ?? 0, n(d.bytesIn) ?? 0];
          domains.set(k, row);
          rows.domains.push(row);
        }
        break;
      }
    }
  }
  return rows;
}

/** Chunked multi-row INSERT statements (≤ 100 parameters each). */
export function chunkedInsert(db: D1Database, head: string, cols: number, rows: Row[], tail = ""): D1PreparedStatement[] {
  const per = Math.max(1, Math.floor(MAX_PARAMS / cols));
  const tuple = "(" + Array(cols).fill("?").join(", ") + ")";
  const out: D1PreparedStatement[] = [];
  for (let i = 0; i < rows.length; i += per) {
    const chunk = rows.slice(i, i + per);
    out.push(db.prepare(`${head} VALUES ${chunk.map(() => tuple).join(", ")} ${tail}`).bind(...chunk.flat()));
  }
  return out;
}

async function existingIds(db: D1Database, ids: string[]): Promise<Set<string>> {
  const found = new Set<string>();
  for (let i = 0; i < ids.length; i += MAX_PARAMS) {
    const chunk = ids.slice(i, i + MAX_PARAMS);
    const r = await db.prepare(`SELECT id FROM events WHERE id IN (${chunk.map(() => "?").join(",")})`).bind(...chunk).all<{ id: string }>();
    for (const row of r.results) found.add(row.id);
  }
  return found;
}

export interface DeviceInfo {
  id: string;
  hostname: string;
  timezone: string | null;
}

/**
 * Stores the events that are not stored yet and returns alert drafts for them. Retried batches are
 * no-ops (aggregates are only incremented for new ids). Two concurrent copies of the same batch could
 * double-count usage; the agent uploads sequentially, so this is accepted.
 */
export async function ingestEvents(env: Env, device: DeviceInfo, events: IngestEvent[]): Promise<AlertDraft[]> {
  const db = env.DB;
  const seen = await existingIds(db, events.map((e) => e.id));
  const fresh = events.filter((e) => !seen.has(e.id));
  if (fresh.length === 0) return [];
  const rows = buildRows(fresh, device.id, device.timezone, nowIso());
  const stmts = [
    ...chunkedInsert(db, "INSERT OR IGNORE INTO events (id, device_id, user_sid, ts, mono_ms, type, data_json, received_at)", 8, rows.events),
    ...chunkedInsert(
      db,
      "INSERT OR IGNORE INTO web_visits (id, device_id, user_sid, ts, kind, url, host, title, duration_sec, category, transition)",
      11,
      rows.web,
    ),
    ...chunkedInsert(
      db,
      "INSERT OR IGNORE INTO screenshots (id, device_id, user_sid, ts, blob_key, width, height, reason, command_id, foreground_exe)",
      10,
      rows.screenshots,
    ),
    ...chunkedInsert(
      db,
      "INSERT INTO usage_daily (device_id, user_sid, day, exe, grp, active_sec)",
      6,
      rows.usage,
      "ON CONFLICT(device_id, user_sid, day, exe) DO UPDATE SET active_sec = active_sec + excluded.active_sec, grp = CASE WHEN excluded.grp <> '' THEN excluded.grp ELSE grp END",
    ),
    ...chunkedInsert(
      db,
      "INSERT INTO domains_daily (device_id, user_sid, day, host, exe, allowed, connections, bytes_out, bytes_in)",
      9,
      rows.domains,
      "ON CONFLICT(device_id, user_sid, day, host, exe, allowed) DO UPDATE SET connections = connections + excluded.connections, bytes_out = bytes_out + excluded.bytes_out, bytes_in = bytes_in + excluded.bytes_in",
    ),
  ];
  await db.batch(stmts);
  return evaluateAlerts(env, device, fresh);
}

function safeJson(s: string): Record<string, unknown> {
  try {
    const v: unknown = JSON.parse(s);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

async function ruleContext(env: Env, device: DeviceInfo): Promise<RuleContext> {
  const users = (
    await env.DB.prepare("SELECT user_sid, name, label FROM managed_users WHERE device_id = ?")
      .bind(device.id)
      .all<{ user_sid: string; name: string; label: string | null }>()
  ).results;
  const names = new Map(users.map((u) => [u.user_sid, u.label || u.name]));
  return { hostname: device.hostname, userName: (sid) => (sid ? (names.get(sid) ?? sid) : "Máy") };
}

async function evaluateAlerts(env: Env, device: DeviceInfo, fresh: IngestEvent[]): Promise<AlertDraft[]> {
  const needsSingle = fresh.some((e) => e.type === "quota.exhausted" || e.type === "request.exe_approval" || e.type.startsWith("tamper."));
  const blockedUsers = new Map<string, number>(); // sid -> earliest new blocked ts (ms)
  for (const e of fresh) {
    if (BURST_TYPES.has(e.type) && e.userSid) {
      const t = Date.parse(e.ts);
      blockedUsers.set(e.userSid, Math.min(blockedUsers.get(e.userSid) ?? Infinity, t));
    }
  }
  if (!needsSingle && blockedUsers.size === 0) return [];
  const ctx = await ruleContext(env, device);
  const drafts: AlertDraft[] = [];
  for (const e of fresh) {
    const a = alertForEvent({ ...e, deviceId: device.id }, ctx);
    if (a) drafts.push(a);
  }
  for (const [sid, earliest] of blockedUsers) {
    const last = await env.DB.prepare(
      "SELECT MAX(ts) AS ts FROM alerts WHERE device_id = ? AND user_sid = ? AND type = 'blocked.burst'",
    ).bind(device.id, sid).first<{ ts: string | null }>();
    const lowerMs = Math.max(earliest - BURST_WINDOW_MS, last?.ts ? Date.parse(last.ts) : -Infinity);
    const recent = (
      await env.DB.prepare(
        `SELECT id, ts, type, data_json FROM events WHERE device_id = ? AND user_sid = ? AND type IN ('web.blocked', 'process.blocked') AND ts > ?
         ORDER BY ts, id LIMIT 1000`,
      ).bind(device.id, sid, new Date(Math.max(lowerMs, 0)).toISOString()).all<{ id: string; ts: string; type: string; data_json: string }>()
    ).results;
    const idx = detectBurst(recent.map((r) => Date.parse(r.ts)));
    if (idx >= 0) {
      const trigger = recent[idx]!;
      const tMs = Date.parse(trigger.ts);
      const inBurst = recent.filter((r) => {
        const t = Date.parse(r.ts);
        return t <= tMs && tMs - t <= BURST_WINDOW_MS;
      });
      const details = burstDetails(inBurst.map((r) => ({ type: r.type, data: safeJson(r.data_json) })));
      drafts.push(burstAlert(device.id, sid, trigger.id, trigger.ts, inBurst.length, ctx, details));
    }
  }
  return drafts;
}

export interface RejectedEvent {
  id: string | null;
  error: string;
}

export interface ScreenResult {
  accepted: IngestEvent[];
  rejected: RejectedEvent[];
}

/**
 * Validates every event on its own (schema, device id, data size cap) so one bad event cannot block the
 * agent's outbox forever. Duplicate ids inside one batch are dropped silently. Pure.
 */
export function screenEvents(raw: readonly unknown[], deviceId: string): ScreenResult {
  const accepted: IngestEvent[] = [];
  const rejected: RejectedEvent[] = [];
  const ids = new Set<string>();
  for (const r of raw) {
    const ev = r as Partial<IngestEvent> | null;
    const id = ev && typeof ev === "object" && typeof ev.id === "string" ? ev.id : null;
    if (!validateEvent(r)) {
      const e = validateEvent.errors?.[0];
      rejected.push({ id, error: `invalid_body${e ? `: ${e.instancePath} ${e.message ?? ""}`.trimEnd() : ""}` });
      continue;
    }
    const e = r as IngestEvent;
    if (e.deviceId !== deviceId) {
      rejected.push({ id, error: "wrong_device" });
      continue;
    }
    const size = new TextEncoder().encode(JSON.stringify(e.data)).length;
    if (size > (e.type === "diag.report" ? MAX_DIAG_BYTES : MAX_EVENT_BYTES)) {
      rejected.push({ id, error: "too_large" });
      continue;
    }
    if (ids.has(e.id)) continue;
    ids.add(e.id);
    accepted.push({ ...e, ts: normTs(e.ts)! });
  }
  return { accepted, rejected };
}

/**
 * The single event intake used by HTTP `POST /v1/device/events` and the DeviceHub `events` frame (API.md 3, 15):
 * screen -> store (idempotent on id, one D1 batch) -> `onStored` (ack / live fan-out) -> alerts + FCM.
 * Throws when D1 fails; nothing is acknowledged then and the device retries.
 */
export async function intakeEvents(
  env: Env,
  device: DeviceInfo,
  raw: readonly unknown[],
  waitUntil: (p: Promise<unknown>) => void,
  onStored?: (r: ScreenResult) => void,
): Promise<ScreenResult> {
  const r = screenEvents(raw, device.id);
  const drafts = r.accepted.length > 0 ? await ingestEvents(env, device, r.accepted) : [];
  onStored?.(r);
  await saveAndPushAlerts(env, drafts, waitUntil);
  return r;
}
