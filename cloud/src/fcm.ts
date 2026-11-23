// FCM HTTP v1 push (data-only). OAuth2 access token from a service-account JWT (RS256 via WebCrypto),
// cached per isolate until 5 min before expiry.
import type { AlertRow } from "./alerts";
import type { Env } from "./env";
import { b64urlEncode, utf8 } from "./lib/encoding";
import { nowIso } from "./lib/time";

interface ServiceAccount {
  project_id: string;
  client_email: string;
  private_key: string;
  token_uri?: string;
}

const SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";

let cached: { email: string; token: string; expMs: number } | null = null;

export function parseServiceAccount(raw: string | undefined): ServiceAccount | null {
  if (!raw) return null;
  try {
    const sa = JSON.parse(raw) as Partial<ServiceAccount>;
    if (typeof sa.project_id === "string" && typeof sa.client_email === "string" && typeof sa.private_key === "string") {
      return sa as ServiceAccount;
    }
  } catch {
    /* fallthrough */
  }
  console.error("FCM_SERVICE_ACCOUNT_JSON is not a valid service-account JSON");
  return null;
}

function pemToPkcs8(pem: string): Uint8Array<ArrayBuffer> {
  const b64 = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\\n|\s/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Builds the signed RS256 JWT assertion for the OAuth2 JWT-bearer grant. */
export async function buildJwtAssertion(sa: ServiceAccount, now: number = Date.now()): Promise<string> {
  const iat = Math.floor(now / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claims = { iss: sa.client_email, scope: SCOPE, aud: sa.token_uri ?? DEFAULT_TOKEN_URI, iat, exp: iat + 3600 };
  const input = `${b64urlEncode(utf8(JSON.stringify(header)))}.${b64urlEncode(utf8(JSON.stringify(claims)))}`;
  const key = await crypto.subtle.importKey("pkcs8", pemToPkcs8(sa.private_key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new Uint8Array(utf8(input)));
  return `${input}.${b64urlEncode(sig)}`;
}

async function accessToken(sa: ServiceAccount): Promise<string> {
  const now = Date.now();
  if (cached && cached.email === sa.client_email && cached.expMs - 300_000 > now) return cached.token;
  const assertion = await buildJwtAssertion(sa, now);
  const res = await fetch(sa.token_uri ?? DEFAULT_TOKEN_URI, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }),
  });
  if (!res.ok) throw new Error(`FCM OAuth token request failed: ${res.status}`);
  const body = (await res.json()) as { access_token: string; expires_in: number };
  cached = { email: sa.client_email, token: body.access_token, expMs: now + body.expires_in * 1000 };
  return body.access_token;
}

/** FCM data payload (all values must be strings). */
export function alertPushData(a: AlertRow): Record<string, string> {
  return {
    type: "alert",
    alertId: a.id,
    deviceId: a.deviceId,
    userSid: a.userSid ?? "",
    severity: a.severity,
    title: a.title,
    body: a.body,
  };
}

/** Sends each data payload to every subscribed token; drops tokens FCM reports as unregistered. Returns the delivered item indexes. */
async function pushAll(env: Env, items: Record<string, string>[]): Promise<{ delivered: Set<number>; dead: Set<string> }> {
  const delivered = new Set<number>();
  const dead = new Set<string>();
  const sa = parseServiceAccount(env.FCM_SERVICE_ACCOUNT_JSON);
  if (!sa || items.length === 0) return { delivered, dead };
  const subs = (await env.DB.prepare("SELECT id, fcm_token FROM push_subscriptions").all<{ id: string; fcm_token: string }>()).results;
  if (subs.length === 0) return { delivered, dead };
  const token = await accessToken(sa);
  const url = `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(sa.project_id)}/messages:send`;
  for (const [i, data] of items.entries()) {
    for (const s of subs) {
      if (dead.has(s.id)) continue;
      const res = await fetch(url, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ message: { token: s.fcm_token, data, android: { priority: "high" } } }),
      });
      if (res.ok) {
        delivered.add(i);
      } else if (res.status === 404 || res.status === 400) {
        const text = await res.text();
        if (res.status === 404 || text.includes("UNREGISTERED") || text.includes("registration token")) dead.add(s.id);
      } else if (res.status === 401) {
        cached = null;
        console.error("FCM rejected the access token");
        break;
      } else {
        console.error(`FCM send failed: ${res.status}`);
      }
    }
  }
  return { delivered, dead };
}

const deadTokenStmts = (env: Env, dead: Set<string>) => [...dead].map((id) => env.DB.prepare("DELETE FROM push_subscriptions WHERE id = ?").bind(id));

/** Sends every alert to every subscribed token; drops tokens FCM reports as unregistered. */
export async function sendAlertPushes(env: Env, alerts: AlertRow[]): Promise<void> {
  const { delivered, dead } = await pushAll(env, alerts.map(alertPushData));
  const stmts = [
    ...deadTokenStmts(env, dead),
    ...[...delivered].map((i) => env.DB.prepare("UPDATE alerts SET pushed_at = ? WHERE id = ?").bind(nowIso(), alerts[i]!.id)),
  ];
  if (stmts.length > 0) await env.DB.batch(stmts);
}

/** Notice push without an alert row (session notifications, free-tier meter). `type:"notice"` data message. */
export interface NoticePush {
  deviceId?: string;
  userSid?: string | null;
  severity?: "info" | "warn" | "critical";
  title: string;
  body: string;
}

export async function sendNoticePushes(env: Env, notices: NoticePush[]): Promise<void> {
  const data = notices.map((n) => ({
    type: "notice",
    severity: n.severity ?? "info",
    title: n.title,
    body: n.body,
    ...(n.deviceId ? { deviceId: n.deviceId } : {}),
    ...(n.userSid ? { userSid: n.userSid } : {}),
  }));
  const { dead } = await pushAll(env, data);
  const stmts = deadTokenStmts(env, dead);
  if (stmts.length > 0) await env.DB.batch(stmts);
}
