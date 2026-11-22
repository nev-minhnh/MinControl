import { DeviceHub } from "./device-hub";

export { DeviceHub };

export interface Env {
  DB: D1Database;
  BLOBS: R2Bucket;
  DEVICE_HUB: DurableObjectNamespace<DeviceHub>;
  ADMIN_BOOTSTRAP_SECRET?: string;
  FCM_SERVICE_ACCOUNT_JSON?: string;
}

interface Route {
  method: string;
  name: string;
  pattern: RegExp;
}

// Routes from SPEC section 9 "API sketch".
const SKETCH: ReadonlyArray<readonly [string, string]> = [
  ["POST", "/v1/enroll"],
  ["GET", "/v1/device/ws"],
  ["POST", "/v1/device/events"],
  ["PUT", "/v1/device/blobs/:key"],
  ["GET", "/v1/master/devices"],
  ["GET", "/v1/master/devices/:id/state"],
  ["GET", "/v1/master/devices/:id/events"],
  ["GET", "/v1/master/devices/:id/web"],
  ["PUT", "/v1/master/devices/:id/policy"],
  ["POST", "/v1/master/devices/:id/commands"],
  ["POST", "/v1/master/pairing-codes"],
  ["POST", "/v1/master/push/subscribe"],
];

const ROUTES: Route[] = SKETCH.map(([method, path]) => ({
  method,
  name: path,
  pattern: new RegExp("^" + path.replace(/:[a-z]+/g, "[^/]+") + "/?$"),
}));

export default {
  async fetch(request: Request, _env: Env, _ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (request.method === "GET" && pathname === "/health") {
      return Response.json({ ok: true });
    }
    const route = ROUTES.find((r) => r.method === request.method && r.pattern.test(pathname));
    if (route) {
      return Response.json({ error: "not_implemented", route: `${route.method} ${route.name}` }, { status: 501 });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  },

  async scheduled(_controller: ScheduledController, _env: Env, _ctx: ExecutionContext): Promise<void> {
    // M1: retention purge, daily summary push, offline-device alert.
  },
} satisfies ExportedHandler<Env>;
