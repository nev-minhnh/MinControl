// Account-wide master settings (API.md section 16), stored as one JSON row in `config`.
export interface Settings {
  notifyLogon: boolean;
  notifyLogoff: boolean;
}

export const SETTINGS_KEY = "settings";
export const DEFAULT_SETTINGS: Settings = { notifyLogon: false, notifyLogoff: false };

export async function loadSettings(db: D1Database): Promise<Settings> {
  const row = await db.prepare("SELECT v FROM config WHERE k = ?").bind(SETTINGS_KEY).first<{ v: string }>();
  if (!row) return { ...DEFAULT_SETTINGS };
  try {
    const v = JSON.parse(row.v) as Partial<Settings>;
    return { notifyLogon: v.notifyLogon === true, notifyLogoff: v.notifyLogoff === true };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveSettings(db: D1Database, s: Settings, now: string): Promise<void> {
  await db
    .prepare("INSERT OR REPLACE INTO config (k, v, updated_at) VALUES (?, ?, ?)")
    .bind(SETTINGS_KEY, JSON.stringify(s), now)
    .run();
}
