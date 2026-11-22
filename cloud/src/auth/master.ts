// Master request authentication (API.md section 4): `X-MC-Auth: v1;<keyId>;<ts>;<sig>`,
// sig over UTF-8 `METHOD \n pathWithQuery \n ts \n hex(sha256(body))`, |now - ts| <= 300 s.
import { type SigAlg, sha256Hex, verifySignatureB64 } from "../lib/crypto";
import { utf8 } from "../lib/encoding";
import { HttpError } from "../lib/http";
import { parseAuthTs } from "../lib/time";

export const AUTH_SKEW_MS = 300_000;

export interface MasterKeyRow {
  key_id: string;
  alg: SigAlg;
  public_key: string;
  role: "sign" | "read";
}

export interface ParsedAuthHeader {
  keyId: string;
  ts: string;
  sig: string;
}

export function parseAuthHeader(header: string | null): ParsedAuthHeader | null {
  if (!header) return null;
  const parts = header.split(";");
  if (parts.length !== 4 || parts[0] !== "v1") return null;
  const [, keyId, ts, sig] = parts as [string, string, string, string];
  if (!/^[0-9a-f]{16}$/.test(keyId) || !/^[A-Za-z0-9_-]{86}$/.test(sig) || ts.length === 0 || ts.length > 40) return null;
  return { keyId, ts, sig };
}

export async function requestSigningString(method: string, pathWithQuery: string, ts: string, body: Uint8Array): Promise<string> {
  return `${method.toUpperCase()}\n${pathWithQuery}\n${ts}\n${await sha256Hex(body)}`;
}

/**
 * Verifies the X-MC-Auth header. `lookupKey` returns the active (non-revoked) key or null.
 * Throws 401 on any failure; returns the key on success.
 */
export async function verifyMasterRequest(
  request: Request,
  body: Uint8Array,
  lookupKey: (keyId: string) => Promise<MasterKeyRow | null>,
  now: number = Date.now(),
): Promise<MasterKeyRow> {
  const parsed = parseAuthHeader(request.headers.get("x-mc-auth"));
  if (!parsed) throw new HttpError(401, "unauthorized", "missing or malformed X-MC-Auth");
  const tsMs = parseAuthTs(parsed.ts);
  if (!Number.isFinite(tsMs) || Math.abs(now - tsMs) > AUTH_SKEW_MS) {
    throw new HttpError(401, "stale_request", "X-MC-Auth timestamp outside ±300 s");
  }
  const key = await lookupKey(parsed.keyId);
  if (!key) throw new HttpError(401, "unknown_key", "unknown or revoked master key");
  const url = new URL(request.url);
  const signing = await requestSigningString(request.method, url.pathname + url.search, parsed.ts, body);
  if (!(await verifySignatureB64(key.alg, key.public_key, parsed.sig, utf8(signing)))) {
    throw new HttpError(401, "bad_signature", "X-MC-Auth signature invalid");
  }
  return key;
}
