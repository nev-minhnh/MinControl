// Opaque pagination cursor = base64url(JSON [ts, id]) of the last item returned (newest-first lists).
import { b64urlDecode, b64urlEncode, fromUtf8, utf8 } from "./encoding";
import { HttpError } from "./http";

export interface CursorPos {
  ts: string;
  id: string;
}

export function encodeCursor(pos: CursorPos): string {
  return b64urlEncode(utf8(JSON.stringify([pos.ts, pos.id])));
}

export function decodeCursor(cursor: string | null | undefined): CursorPos | null {
  if (!cursor) return null;
  const bytes = b64urlDecode(cursor);
  let parsed: unknown;
  try {
    parsed = bytes ? JSON.parse(fromUtf8(bytes)) : null;
  } catch {
    parsed = null;
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 2 ||
    typeof parsed[0] !== "string" ||
    typeof parsed[1] !== "string" ||
    parsed[0].length > 40 ||
    parsed[1].length > 64
  ) {
    throw new HttpError(400, "invalid_cursor", "cursor is malformed");
  }
  return { ts: parsed[0], id: parsed[1] };
}

/**
 * SQL fragment for "strictly older than the cursor" in an `ORDER BY ts DESC, id DESC` listing.
 * Returns an empty clause when there is no cursor.
 */
export function cursorClause(pos: CursorPos | null, tsCol = "ts", idCol = "id"): { sql: string; params: string[] } {
  if (!pos) return { sql: "", params: [] };
  return { sql: `(${tsCol} < ? OR (${tsCol} = ? AND ${idCol} < ?))`, params: [pos.ts, pos.ts, pos.id] };
}

/** Splits `limit + 1` fetched rows into the page and the next cursor. */
export function paginate<T>(rows: T[], limit: number, pos: (row: T) => CursorPos): { items: T[]; next: string | null } {
  if (rows.length <= limit) return { items: rows, next: null };
  const items = rows.slice(0, limit);
  return { items, next: encodeCursor(pos(items[items.length - 1]!)) };
}

export function parseLimit(raw: string | null, def: number, max: number): number {
  if (raw === null || raw === "") return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new HttpError(400, "invalid_query", "limit must be a positive integer");
  return Math.min(n, max);
}
