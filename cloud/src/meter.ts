// Free-tier meter (API.md section 16): every D1 statement the Worker / DeviceHub / cron runs goes through
// `meteredEnv`, which sums `meta.rows_written` and stores it per UTC day in `config` (`usage:<yyyy-mm-dd>`).
import type { Env } from "./env";
import { sendNoticePushes } from "./fcm";
import { nowIso } from "./lib/time";

export const FREE_ROWS_WRITTEN_LIMIT = 100_000;
export const METER_THRESHOLDS = [70, 90] as const;
export const usageKey = (day: string) => `usage:${day}`;

const WRITE_RE = /^\s*(INSERT|UPDATE|DELETE|REPLACE)\b/i;
const rowsOf = (meta: unknown): number => {
  const v = (meta as { rows_written?: unknown } | undefined)?.rows_written;
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0;
};

class MeteredStatement {
  constructor(
    readonly raw: D1PreparedStatement,
    private readonly sql: string,
    private readonly record: (rows: number) => void,
  ) {}
  bind(...values: unknown[]): MeteredStatement {
    return new MeteredStatement(this.raw.bind(...values), this.sql, this.record);
  }
  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const r = await this.raw.run<T>();
    this.record(rowsOf(r.meta));
    return r;
  }
  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const r = await this.raw.all<T>();
    this.record(rowsOf(r.meta));
    return r;
  }
  async first<T = unknown>(colName?: string): Promise<T | null> {
    const r = colName === undefined ? await this.raw.first<T>() : await this.raw.first<T>(colName);
    // `first()` exposes no meta; a write with RETURNING that found a row wrote at least one row.
    if (r !== null && WRITE_RE.test(this.sql)) this.record(1);
    return r;
  }
}

export function meterDb(db: D1Database, record: (rows: number) => void): D1Database {
  const wrapper = {
    prepare: (sql: string) => new MeteredStatement(db.prepare(sql), sql, record),
    async batch<T = unknown>(stmts: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      const raws = stmts.map((s) => (s instanceof MeteredStatement ? s.raw : s));
      const results = await db.batch<T>(raws);
      record(results.reduce((sum, r) => sum + rowsOf(r.meta), 0));
      return results;
    },
    exec: (q: string) => db.exec(q),
  };
  return wrapper as unknown as D1Database;
}

const metered = new WeakSet<object>();

/**
 * Returns `env` with `DB` replaced by a metering wrapper. Counted rows are flushed to `config` right after the
 * statement that produced them (one extra upserted row per flush, itself counted in the next flush) through
 * `waitUntil`. Idempotent.
 */
export function meteredEnv(env: Env, waitUntil: (p: Promise<unknown>) => void): Env {
  if (metered.has(env.DB)) return env;
  const raw = env.DB;
  let pending = 0;
  let carry = 0; // rows written by the meter's own upserts, billed with the next flush
  let flushing: Promise<void> | null = null;
  const out: Env = { ...env, DB: undefined as unknown as D1Database };
  const flushOnce = async (): Promise<void> => {
    const delta = pending + carry;
    pending = 0;
    carry = 0;
    const now = nowIso();
    const r = await raw
      .prepare(
        `INSERT INTO config (k, v, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(k) DO UPDATE SET v = CAST(CAST(v AS INTEGER) + ? AS TEXT), updated_at = excluded.updated_at RETURNING v`,
      )
      .bind(usageKey(now.slice(0, 10)), String(delta), now, delta)
      .all<{ v: string }>();
    carry += rowsOf(r.meta) || 1;
    const total = Number(r.results[0]?.v ?? delta);
    const notices = METER_THRESHOLDS.filter((p) => {
      const t = (FREE_ROWS_WRITTEN_LIMIT * p) / 100;
      return total - delta < t && total >= t;
    }).map((p) => ({
      severity: "warn" as const,
      title: `Sắp chạm hạn mức miễn phí của Cloudflare hôm nay (${p} %)`,
      body: `Đã ghi ${total.toLocaleString("en-US")} / ${FREE_ROWS_WRITTEN_LIMIT.toLocaleString("en-US")} dòng D1 trong ngày (UTC).`,
    }));
    if (notices.length > 0) await sendNoticePushes(out, notices);
  };
  const schedule = () => {
    if (flushing) return;
    const p: Promise<void> = (async () => {
      try {
        while (pending > 0) await flushOnce();
      } catch (e) {
        console.error("meter flush failed", e);
      }
    })().finally(() => {
      flushing = null;
      if (pending > 0) schedule();
    });
    flushing = p;
    waitUntil(p);
  };
  out.DB = meterDb(raw, (rows) => {
    if (rows <= 0) return;
    pending += rows;
    schedule();
  });
  metered.add(out.DB);
  return out;
}

export interface UsageReport {
  day: string;
  rowsWritten: number;
  limit: number;
  percent: number;
}

export async function readUsage(db: D1Database, now: number = Date.now()): Promise<UsageReport> {
  const day = nowIso(now).slice(0, 10);
  const row = await db.prepare("SELECT v FROM config WHERE k = ?").bind(usageKey(day)).first<{ v: string }>();
  const rowsWritten = Number(row?.v ?? 0) || 0;
  return { day, rowsWritten, limit: FREE_ROWS_WRITTEN_LIMIT, percent: Math.round((rowsWritten / FREE_ROWS_WRITTEN_LIMIT) * 1000) / 10 };
}
