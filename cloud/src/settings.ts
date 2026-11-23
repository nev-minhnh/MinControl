// Account-wide master settings (API.md sections 16 and 19), stored as one JSON row in `config`.
export const ALERT_TYPES = [
  "tamper",
  "request.exe_approval",
  "quota.exhausted",
  "quota.warning",
  "blocked.burst",
  "web.blocked",
  "process.blocked",
  "device.offline",
  "session.logon",
  "session.logoff",
] as const;
export type AlertType = (typeof ALERT_TYPES)[number];

export interface AlertSetting {
  enabled: boolean;
  /** at most one alert per (device, user, type) in this many minutes; 0 = no limit */
  minIntervalMin: number;
}
export type AlertSettings = Record<AlertType, AlertSetting>;

export const MAX_INTERVAL_MIN = 7 * 24 * 60;

export interface Settings {
  /** mirrors alerts["session.logon"].enabled / ["session.logoff"].enabled (API.md section 16 compatibility) */
  notifyLogon: boolean;
  notifyLogoff: boolean;
  alerts: AlertSettings;
}

export const SETTINGS_KEY = "settings";

export function defaultAlerts(): AlertSettings {
  return Object.fromEntries(ALERT_TYPES.map((t) => [t, { enabled: t === "tamper", minIntervalMin: 0 }])) as AlertSettings;
}

export const DEFAULT_SETTINGS: Settings = { notifyLogon: false, notifyLogoff: false, alerts: defaultAlerts() };

/** Maps a concrete alert/event type to its settings key (`tamper.*` -> `tamper`); null when it has none. */
export function alertSettingKey(type: string): AlertType | null {
  if (type.startsWith("tamper.")) return "tamper";
  return (ALERT_TYPES as readonly string[]).includes(type) && type !== "tamper" ? (type as AlertType) : null;
}

function clampInterval(v: unknown, fallback: number): number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_INTERVAL_MIN ? v : fallback;
}

/** Tolerant normalisation of stored JSON (legacy rows only have notifyLogon / notifyLogoff). */
export function normalizeSettings(v: Partial<Settings> | null | undefined): Settings {
  const alerts = defaultAlerts();
  const stored = (v?.alerts ?? {}) as Partial<Record<string, Partial<AlertSetting>>>;
  for (const t of ALERT_TYPES) {
    const s = stored[t];
    if (s && typeof s === "object") {
      alerts[t] = { enabled: typeof s.enabled === "boolean" ? s.enabled : alerts[t].enabled, minIntervalMin: clampInterval(s.minIntervalMin, 0) };
    }
  }
  // legacy flags apply when the new map has no entry for the session types
  if (!stored["session.logon"] && v?.notifyLogon === true) alerts["session.logon"].enabled = true;
  if (!stored["session.logoff"] && v?.notifyLogoff === true) alerts["session.logoff"].enabled = true;
  return { notifyLogon: alerts["session.logon"].enabled, notifyLogoff: alerts["session.logoff"].enabled, alerts };
}

export async function loadSettings(db: D1Database): Promise<Settings> {
  const row = await db.prepare("SELECT v FROM config WHERE k = ?").bind(SETTINGS_KEY).first<{ v: string }>();
  if (!row) return normalizeSettings(null);
  try {
    return normalizeSettings(JSON.parse(row.v) as Partial<Settings>);
  } catch {
    return normalizeSettings(null);
  }
}

export async function saveSettings(db: D1Database, s: Settings, now: string): Promise<void> {
  await db
    .prepare("INSERT OR REPLACE INTO config (k, v, updated_at) VALUES (?, ?, ?)")
    .bind(SETTINGS_KEY, JSON.stringify(s), now)
    .run();
}
