// Hourly cron: retention purge (per policy retentionDays, screenshot metadata rows), command expiry,
// offline-device alerts (> 2 h, one alert per offline period), stale pairing codes.
import { isOfflineAlertDue, offlineAlert, saveAndPushAlerts } from "./alerts";
import type { Env } from "./env";
import { DAY_MS, localDay, nowIso } from "./lib/time";

export interface Retention {
  events: number;
  web: number;
  screenshots: number;
}

/** Used until the first policy arrives. */
export const DEFAULT_RETENTION: Retention = { events: 90, web: 90, screenshots: 30 };

export function parseRetention(json: string | null): Retention {
  if (!json) return DEFAULT_RETENTION;
  try {
    const r = JSON.parse(json) as Partial<Retention>;
    const ok = (v: unknown, d: number) => (typeof v === "number" && v >= 1 ? v : d);
    return { events: ok(r.events, DEFAULT_RETENTION.events), web: ok(r.web, DEFAULT_RETENTION.web), screenshots: ok(r.screenshots, DEFAULT_RETENTION.screenshots) };
  } catch {
    return DEFAULT_RETENTION;
  }
}

interface DeviceRow {
  id: string;
  hostname: string;
  timezone: string | null;
  retention_json: string | null;
  last_seen_at: string | null;
  enrolled_at: string;
  offline_alerted_at: string | null;
  revoked_at: string | null;
}

export async function runCron(env: Env, ctx: ExecutionContext, now: number = Date.now()): Promise<void> {
  const db = env.DB;
  const nowS = nowIso(now);
  await db.batch([
    db.prepare("UPDATE commands SET status = 'expired' WHERE status = 'queued' AND expires_at <= ?").bind(nowS),
    db.prepare("DELETE FROM pairing_codes WHERE expires_at < ?").bind(nowIso(now - DAY_MS)),
  ]);

  const devices = (
    await db.prepare(
      "SELECT id, hostname, timezone, retention_json, last_seen_at, enrolled_at, offline_alerted_at, revoked_at FROM devices",
    ).all<DeviceRow>()
  ).results;

  const offline = [];
  for (const d of devices) {
    try {
      await purgeDevice(env, d, now);
    } catch (e) {
      console.error("retention purge failed", d.id, e);
    }
    if (d.revoked_at) continue;
    const lastSeen = d.last_seen_at ?? d.enrolled_at;
    if (isOfflineAlertDue(Date.parse(lastSeen), d.offline_alerted_at ? Date.parse(d.offline_alerted_at) : null, now)) {
      offline.push(offlineAlert(d.id, d.hostname, lastSeen, now));
      await db.prepare("UPDATE devices SET offline_alerted_at = ?, online = 0 WHERE id = ?").bind(nowS, d.id).run();
    }
  }
  await saveAndPushAlerts(env, offline, (p) => ctx.waitUntil(p));
}

async function purgeDevice(env: Env, d: DeviceRow, now: number): Promise<void> {
  const db = env.DB;
  const r = parseRetention(d.retention_json);
  const evCut = nowIso(now - r.events * DAY_MS);
  const evDay = localDay(now - r.events * DAY_MS, d.timezone);
  const webCut = nowIso(now - r.web * DAY_MS);
  const shotCut = nowIso(now - r.screenshots * DAY_MS);
  await db.batch([
    db.prepare("DELETE FROM events WHERE device_id = ? AND ts < ?").bind(d.id, evCut),
    db.prepare("DELETE FROM alerts WHERE device_id = ? AND ts < ?").bind(d.id, evCut),
    db.prepare("DELETE FROM usage_daily WHERE device_id = ? AND day < ?").bind(d.id, evDay),
    db.prepare("DELETE FROM domains_daily WHERE device_id = ? AND day < ?").bind(d.id, evDay),
    db.prepare("DELETE FROM commands WHERE device_id = ? AND created_at < ? AND status <> 'queued'").bind(d.id, evCut),
    db.prepare(
      "DELETE FROM policies WHERE device_id = ? AND created_at < ? AND seq < (SELECT MAX(seq) FROM policies WHERE device_id = ?)",
    ).bind(d.id, evCut, d.id),
    db.prepare("DELETE FROM web_visits WHERE device_id = ? AND ts < ?").bind(d.id, webCut),
    db.prepare("DELETE FROM screenshots WHERE device_id = ? AND ts < ?").bind(d.id, shotCut),
  ]);
}
