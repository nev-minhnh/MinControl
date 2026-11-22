import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";

/** One instance per device (SQLite-backed). M0 stub: WebSocket, command queue and presence come in M1. */
export class DeviceHub extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  override async fetch(_request: Request): Promise<Response> {
    return Response.json({ error: "not_implemented", route: "DeviceHub" }, { status: 501 });
  }
}
