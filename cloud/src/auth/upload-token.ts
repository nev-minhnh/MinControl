// Device upload tokens: `<deviceId>.<expUnixSec>.<b64url HMAC-SHA256(secret, "mc-upload-v1|deviceId|exp")>`.
import { hmacSha256 } from "../lib/crypto";
import { b64urlDecode, b64urlEncode, bytesEqual } from "../lib/encoding";
import { ULID_RE } from "../lib/ulid";

export const UPLOAD_TOKEN_TTL_SEC = 3600;

const signingInput = (deviceId: string, exp: number) => `mc-upload-v1|${deviceId}|${exp}`;

export async function issueUploadToken(
  secret: string,
  deviceId: string,
  now: number = Date.now(),
): Promise<{ token: string; expiresAt: string; expMs: number }> {
  const exp = Math.floor(now / 1000) + UPLOAD_TOKEN_TTL_SEC;
  const mac = await hmacSha256(secret, signingInput(deviceId, exp));
  return { token: `${deviceId}.${exp}.${b64urlEncode(mac)}`, expiresAt: new Date(exp * 1000).toISOString(), expMs: exp * 1000 };
}

/** Returns the deviceId the token is bound to, or null if malformed, forged or expired. */
export async function verifyUploadToken(secret: string, token: string, now: number = Date.now()): Promise<string | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [deviceId, expStr, macStr] = parts as [string, string, string];
  if (!ULID_RE.test(deviceId) || !/^\d{1,12}$/.test(expStr)) return null;
  const exp = Number(expStr);
  if (exp * 1000 <= now) return null;
  const mac = b64urlDecode(macStr);
  if (!mac) return null;
  const expected = await hmacSha256(secret, signingInput(deviceId, exp));
  return bytesEqual(mac, expected) ? deviceId : null;
}
