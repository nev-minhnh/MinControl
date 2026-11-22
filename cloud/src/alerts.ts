// Alert rules (API.md section 6) and persistence. Rule functions are pure so they can be unit tested.
import type { Env } from "./env";
import { sendAlertPushes } from "./fcm";
import { nowIso } from "./lib/time";
import { ulid } from "./lib/ulid";

export type Severity = "info" | "warn" | "critical";

export interface AlertDraft {
  type: string;
  severity: Severity;
  deviceId: string;
  userSid: string | null;
  ts: string;
  eventId: string | null;
  title: string;
  body: string;
  /** merged into the stored `data` (API.md section 8: event data for single-event alerts, burst/offline details) */
  extra?: Record<string, unknown>;
}

/** Details of a blocked burst (API.md section 8): distinct hosts / exes and the shared web category. */
export interface BurstDetails {
  hosts?: string[];
  exes?: string[];
  category?: string;
}

export interface AlertRow {
  id: string;
  deviceId: string;
  userSid: string | null;
  ts: string;
  type: string;
  severity: Severity;
  title: string;
  body: string;
}

export interface RuleEvent {
  id: string;
  deviceId: string;
  userSid?: string | null;
  ts: string;
  type: string;
  data: Record<string, unknown>;
}

export interface RuleContext {
  hostname: string;
  /** display name for a SID (label, Windows name, or the SID) */
  userName: (sid: string | null | undefined) => string;
}

export const BURST_THRESHOLD = 3;
export const BURST_WINDOW_MS = 10 * 60_000;
export const OFFLINE_AFTER_MS = 2 * 3600_000;
export const BURST_TYPES = new Set(["web.blocked", "process.blocked"]);

const TAMPER_TEXT: Record<string, string> = {
  "tamper.agent_killed": "Tiến trình giám sát đã bị tắt",
  "tamper.service_stopped": "Dịch vụ MinControl đã bị dừng",
  "tamper.wfp_filter_missing": "Bộ lọc mạng đã bị gỡ",
  "tamper.proxy_bypass_attempt": "Có dấu hiệu cố vượt qua bộ lọc web",
  "tamper.timezone_changed": "Múi giờ máy đã bị thay đổi",
  "tamper.clock_jump": "Đồng hồ hệ thống đã bị chỉnh",
  "tamper.managed_user_is_admin": "Tài khoản được quản lý đang có quyền quản trị",
  "tamper.extension_missing": "Tiện ích trình duyệt đã bị gỡ hoặc tắt",
  "tamper.offline_gap": "Máy đã ngắt giám sát một khoảng thời gian",
  "tamper.state_tampered": "Dữ liệu chính sách trên máy đã bị sửa",
};

/** Max distinct hosts / exes listed in a burst alert. */
export const BURST_DETAIL_MAX = 10;

const str = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : null);

/**
 * Single-event rules: quota.exhausted, request.exe_approval, tamper.*.
 * The alert's `data` = the event's `data` plus {title, body, eventId} (API.md section 8).
 */
export function alertForEvent(ev: RuleEvent, ctx: RuleContext): AlertDraft | null {
  const base = { deviceId: ev.deviceId, userSid: ev.userSid ?? null, ts: ev.ts, eventId: ev.id, type: ev.type };
  const who = ctx.userName(ev.userSid);
  if (ev.type === "quota.exhausted") {
    const scope = str(ev.data.scope) ?? "total";
    const what = scope.startsWith("group:") ? `thời gian nhóm "${scope.slice(6)}"` : "thời gian dùng máy hôm nay";
    return { ...base, severity: "info", title: "Đã hết giờ", body: `${who} trên ${ctx.hostname} đã dùng hết ${what}.`, extra: { ...ev.data } };
  }
  if (ev.type === "request.exe_approval") {
    const exe = str(ev.data.exe) ?? "một ứng dụng";
    return {
      ...base,
      severity: "warn",
      title: "Yêu cầu cho phép ứng dụng",
      body: `${who} trên ${ctx.hostname} muốn chạy ${exe}.`,
      extra: { ...ev.data }, // exe, path, pid, sha256, publisher, signed, sizeBytes as sent by the device
    };
  }
  if (ev.type.startsWith("tamper.")) {
    const what = TAMPER_TEXT[ev.type] ?? "Phát hiện hành vi can thiệp";
    const userPart = ev.userSid ? ` (${who})` : "";
    return {
      ...base,
      severity: "critical",
      title: "Cảnh báo can thiệp",
      body: `${ctx.hostname}${userPart}: ${what}.`,
      extra: { ...ev.data },
    };
  }
  return null;
}

/**
 * Burst rule: ≥ BURST_THRESHOLD blocked events of one user within BURST_WINDOW_MS -> one alert.
 * `times` = ascending ms timestamps of blocked events that happened after the user's previous burst
 * alert (so events already covered by an alert never count again). Returns the index of the event that
 * completes the first burst, or -1.
 */
export function detectBurst(times: readonly number[], threshold = BURST_THRESHOLD, windowMs = BURST_WINDOW_MS): number {
  for (let i = threshold - 1; i < times.length; i++) {
    if (times[i]! - times[i - threshold + 1]! <= windowMs) return i;
  }
  return -1;
}

/**
 * Summarises the blocked events of one burst: distinct `web.blocked` hosts, distinct `process.blocked`
 * exes (first BURST_DETAIL_MAX each, in order) and `category` when every web block carries the same one.
 */
export function burstDetails(events: ReadonlyArray<{ type: string; data: Record<string, unknown> }>): BurstDetails {
  const hosts: string[] = [];
  const exes: string[] = [];
  const cats = new Set<string | null>();
  for (const e of events) {
    if (e.type === "web.blocked") {
      const h = str(e.data.host);
      if (h && !hosts.includes(h) && hosts.length < BURST_DETAIL_MAX) hosts.push(h);
      cats.add(str(e.data.category));
    } else if (e.type === "process.blocked") {
      const x = str(e.data.exe);
      if (x && !exes.includes(x) && exes.length < BURST_DETAIL_MAX) exes.push(x);
    }
  }
  const out: BurstDetails = {};
  if (hosts.length) out.hosts = hosts;
  if (exes.length) out.exes = exes;
  const [onlyCat] = cats;
  if (cats.size === 1 && onlyCat) out.category = onlyCat;
  return out;
}

export function burstAlert(
  deviceId: string,
  userSid: string,
  triggerEventId: string,
  ts: string,
  count: number,
  ctx: RuleContext,
  details: BurstDetails = {},
): AlertDraft {
  return {
    type: "blocked.burst",
    severity: "warn",
    deviceId,
    userSid,
    ts,
    eventId: triggerEventId,
    title: "Truy cập bị chặn liên tục",
    body: `${ctx.userName(userSid)} trên ${ctx.hostname} đã bị chặn ${count} lần trong 10 phút.`,
    extra: { count, ...details },
  };
}

/** Offline rule: true when the device has been silent > 2 h and no alert was raised for this period. */
export function isOfflineAlertDue(lastSeenMs: number, lastAlertMs: number | null, now: number): boolean {
  return now - lastSeenMs > OFFLINE_AFTER_MS && (lastAlertMs === null || lastAlertMs < lastSeenMs);
}

export function offlineAlert(deviceId: string, hostname: string, lastSeen: string, now: number): AlertDraft {
  return {
    type: "device.offline",
    severity: "warn",
    deviceId,
    userSid: null,
    ts: nowIso(now),
    eventId: null,
    title: "Máy mất kết nối",
    body: `${hostname} đã ngoại tuyến hơn 2 giờ.`,
    extra: { lastSeen },
  };
}

/** Inserts alerts (idempotent on event id) and pushes the newly created ones. */
export async function saveAndPushAlerts(env: Env, drafts: AlertDraft[], waitUntil: (p: Promise<unknown>) => void): Promise<AlertRow[]> {
  if (drafts.length === 0) return [];
  const rows = drafts.map((d) => ({ id: ulid(Date.parse(d.ts) || Date.now()), d }));
  const results = await env.DB.batch(
    rows.map(({ id, d }) =>
      env.DB.prepare(
        `INSERT OR IGNORE INTO alerts (id, device_id, user_sid, ts, type, severity, event_id, data_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(id, d.deviceId, d.userSid, d.ts, d.type, d.severity, d.eventId, JSON.stringify({ ...d.extra, title: d.title, body: d.body, eventId: d.eventId })),
    ),
  );
  const created: AlertRow[] = [];
  rows.forEach(({ id, d }, i) => {
    if ((results[i]?.meta.changes ?? 0) > 0) {
      created.push({ id, deviceId: d.deviceId, userSid: d.userSid, ts: d.ts, type: d.type, severity: d.severity, title: d.title, body: d.body });
    }
  });
  if (created.length > 0) waitUntil(sendAlertPushes(env, created).catch((e) => console.error("push failed", e)));
  return created;
}
