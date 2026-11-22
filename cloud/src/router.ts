// Minimal method + regex router with per-route auth.
import { type MasterKeyRow, verifyMasterRequest } from "./auth/master";
import type { Env } from "./env";
import { HttpError, errorResponse, parseJsonBytes, readBytes } from "./lib/http";

export interface Ctx {
  env: Env;
  exec: ExecutionContext;
  request: Request;
  url: URL;
  params: Record<string, string>;
  /** raw body (master routes only; device/enroll routes read their own body) */
  body: Uint8Array;
  master: MasterKeyRow | null;
  json<T = unknown>(): T;
}

export type Handler = (c: Ctx) => Promise<Response>;
export type AuthMode = "none" | "master";

interface Route {
  method: string;
  re: RegExp;
  keys: string[];
  auth: AuthMode;
  handler: Handler;
}

/** Master request bodies: a policy envelope may carry up to 1 MiB of base64url payload. */
export const MAX_MASTER_BODY = 1_500_000;

export async function lookupMasterKey(env: Env, keyId: string): Promise<MasterKeyRow | null> {
  return env.DB.prepare("SELECT key_id, alg, public_key, role FROM master_keys WHERE key_id = ? AND revoked_at IS NULL")
    .bind(keyId)
    .first<MasterKeyRow>();
}

export class Router {
  private readonly routes: Route[] = [];

  /** `path` uses `:name` for one segment and `*name` (last) for the rest of the path. */
  add(method: string, path: string, auth: AuthMode, handler: Handler): this {
    const keys: string[] = [];
    const re = new RegExp(
      "^" +
        path.replace(/[:*]([a-zA-Z]+)/g, (m, k: string) => {
          keys.push(k);
          return m.startsWith("*") ? "(.+)" : "([^/]+)";
        }) +
        "/?$",
    );
    this.routes.push({ method, re, keys, auth, handler });
    return this;
  }

  async handle(request: Request, env: Env, exec: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    let pathMatched = false;
    for (const r of this.routes) {
      const m = r.re.exec(url.pathname);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== request.method) continue;
      const params: Record<string, string> = {};
      try {
        r.keys.forEach((k, i) => {
          params[k] = decodeURIComponent(m[i + 1]!);
        });
        let body: Uint8Array = new Uint8Array(0);
        let master: MasterKeyRow | null = null;
        if (r.auth === "master") {
          body = await readBytes(request, MAX_MASTER_BODY);
          master = await verifyMasterRequest(request, body, (id) => lookupMasterKey(env, id));
        }
        const ctx: Ctx = {
          env,
          exec,
          request,
          url,
          params,
          body,
          master,
          json: <T>() => parseJsonBytes(body) as T,
        };
        return await r.handler(ctx);
      } catch (e) {
        if (e instanceof HttpError) return errorResponse(e.status, e.code, e.message, e.details);
        if (e instanceof URIError) return errorResponse(400, "invalid_path", "malformed percent-encoding");
        console.error("unhandled error", request.method, url.pathname, e instanceof Error ? e.stack : e);
        return errorResponse(500, "internal", "internal error");
      }
    }
    return pathMatched ? errorResponse(405, "method_not_allowed") : errorResponse(404, "not_found");
  }
}
