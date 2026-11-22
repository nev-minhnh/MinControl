// Time helpers. Stored times are Date.toISOString() so that lexical order equals time order.

export const nowIso = (now: number = Date.now()): string => new Date(now).toISOString();

/** Parses an RFC 3339 timestamp; returns ms or NaN. */
export const parseTs = (s: string): number => Date.parse(s);

/** Normalises an RFC 3339 timestamp to `YYYY-MM-DDTHH:MM:SS.sssZ`; null if unparsable. */
export function normTs(s: string): string | null {
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/**
 * Auth timestamps (X-MC-Auth, WS auth) may be unix seconds or RFC 3339; returns ms or NaN.
 * The signed string always uses the value verbatim.
 */
export function parseAuthTs(ts: string): number {
  if (/^\d{9,11}$/.test(ts)) return Number(ts) * 1000;
  if (/^\d{12,14}$/.test(ts)) return Number(ts);
  return /^\d{4}-\d{2}-\d{2}T/.test(ts) ? Date.parse(ts) : NaN;
}

const dayFormatters = new Map<string, Intl.DateTimeFormat>();

/** YYYY-MM-DD of `ms` in an IANA timezone (falls back to UTC on unknown zones). */
export function localDay(ms: number, timeZone: string | null | undefined): string {
  const tz = timeZone || "UTC";
  let f = dayFormatters.get(tz);
  if (!f) {
    try {
      f = new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" });
    } catch {
      f = new Intl.DateTimeFormat("en-CA", { timeZone: "UTC", year: "numeric", month: "2-digit", day: "2-digit" });
    }
    dayFormatters.set(tz, f);
  }
  return f.format(new Date(ms));
}

export const DAY_MS = 86_400_000;
