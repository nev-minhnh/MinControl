// WebCrypto helpers: signature verification (Ed25519, ES256 P1363), hashing, HMAC, random codes.
import { b64urlDecode, b64urlEncode, bytesEqual, hex, utf8 } from "./encoding";

export type SigAlg = "ed25519" | "es256";

/** Copies into a fresh ArrayBuffer-backed view (WebCrypto typings reject SharedArrayBuffer views). */
const buf = (b: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(b);

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf(bytes)));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  return hex(await sha256(data));
}

/** keyId = first 16 hex chars of SHA-256 of the raw public key (protocol/README.md rule 5). */
export async function keyIdOf(rawPublicKey: Uint8Array): Promise<string> {
  return (await sha256Hex(rawPublicKey)).slice(0, 16);
}

/** Expected raw public key length per algorithm (Ed25519 32 B, P-256 uncompressed SEC1 65 B). */
export function publicKeyLengthOk(alg: SigAlg, raw: Uint8Array): boolean {
  return alg === "ed25519" ? raw.length === 32 : raw.length === 65 && raw[0] === 0x04;
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function importVerifyKey(alg: SigAlg, raw: Uint8Array): Promise<CryptoKey> {
  const cacheKey = alg + ":" + b64urlEncode(raw);
  let p = keyCache.get(cacheKey);
  if (!p) {
    const algo = alg === "ed25519" ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: "P-256" };
    p = crypto.subtle.importKey("raw", buf(raw), algo, false, ["verify"]);
    p.catch(() => keyCache.delete(cacheKey));
    if (keyCache.size > 256) keyCache.clear();
    keyCache.set(cacheKey, p);
  }
  return p;
}

/**
 * Verifies a 64-byte signature. ES256 signatures are IEEE P1363 (r||s), which is the WebCrypto format.
 * Returns false (never throws) on malformed keys or signatures.
 */
export async function verifySignature(
  alg: SigAlg,
  rawPublicKey: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  if (signature.length !== 64 || !publicKeyLengthOk(alg, rawPublicKey)) return false;
  try {
    const key = await importVerifyKey(alg, rawPublicKey);
    const algo = alg === "ed25519" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };
    return await crypto.subtle.verify(algo, key, buf(signature), buf(data));
  } catch {
    return false;
  }
}

/** Same as verifySignature but with b64url-encoded key and signature. */
export async function verifySignatureB64(alg: SigAlg, publicKeyB64: string, sigB64: string, data: Uint8Array): Promise<boolean> {
  const key = b64urlDecode(publicKeyB64);
  const sig = b64urlDecode(sigB64);
  if (!key || !sig) return false;
  return verifySignature(alg, key, sig, data);
}

const hmacCache = new Map<string, Promise<CryptoKey>>();

function hmacKey(secret: string): Promise<CryptoKey> {
  let p = hmacCache.get(secret);
  if (!p) {
    p = crypto.subtle.importKey("raw", buf(utf8(secret)), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    hmacCache.set(secret, p);
  }
  return p;
}

export async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), buf(utf8(data))));
}

/** Constant-time string equality via SHA-256 of both sides (hides length too). */
export async function secretEquals(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  return bytesEqual(ha, hb);
}

export const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Crypto-random Crockford base32 string (32 symbols -> `byte & 31` is unbiased). */
export function randomCrockford(length: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let s = "";
  for (const b of bytes) s += CROCKFORD[b & 31];
  return s;
}

/**
 * Normalises a user-typed pairing code: dashes/spaces dropped, upper case, Crockford aliases
 * (I/L -> 1, O -> 0). Returns null if anything outside the alphabet remains.
 */
export function normalizePairingCode(input: string): string | null {
  const s = input
    .replace(/[\s-]/g, "")
    .toUpperCase()
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
  return /^[0-9A-HJKMNP-TV-Z]{8}$/.test(s) ? s : null;
}

export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
