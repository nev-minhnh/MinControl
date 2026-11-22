import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";

const env = {} as Env;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const call = (method: string, path: string, init: RequestInit = {}) =>
  worker.fetch(new Request(`https://example.test${path}`, { method, ...init }), env, ctx);

describe("router", () => {
  it("GET /health -> 200 ok", async () => {
    const res = await call("GET", "/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("unknown path -> 404 with error shape", async () => {
    const res = await call("GET", "/nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found", message: expect.any(String) });
  });

  it("known path, wrong method -> 405", async () => {
    expect((await call("GET", "/v1/enroll")).status).toBe(405);
  });

  it("master route without X-MC-Auth -> 401", async () => {
    const res = await call("GET", "/v1/master/devices");
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "unauthorized" });
  });

  it("master route with stale timestamp -> 401 stale_request", async () => {
    const sig = "A".repeat(86);
    const res = await call("GET", "/v1/master/devices", { headers: { "x-mc-auth": `v1;0123456789abcdef;1000000000;${sig}` } });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "stale_request" });
  });

  it("enroll with malformed JSON -> 400", async () => {
    const res = await call("POST", "/v1/enroll", { body: "{nope" });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_json" });
  });

  it("enroll with schema-invalid body -> 400 invalid_body", async () => {
    const res = await call("POST", "/v1/enroll", { body: JSON.stringify({ code: "K7Q2-9XMB" }) });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_body" });
  });

  it("device ws without upgrade -> 426", async () => {
    expect((await call("GET", "/v1/device/ws?deviceId=01JDQ3Z8K4M2N6P8R0S2T4V6W8")).status).toBe(426);
  });

  it("device events without upload token secret -> 503", async () => {
    expect((await call("POST", "/v1/device/events", { body: "{}" })).status).toBe(503);
  });

  it("device inventory without upload token secret -> 503", async () => {
    expect((await call("PUT", "/v1/device/inventory", { body: "{}" })).status).toBe(503);
  });

  it("master apps route without X-MC-Auth -> 401", async () => {
    expect((await call("GET", "/v1/master/devices/01JDQ3Z8K4M2N6P8R0S2T4V6W8/apps?user=S-1-5-21-1-2-3-1001")).status).toBe(401);
  });

  it("device inventory route rejects GET -> 405", async () => {
    expect((await call("GET", "/v1/device/inventory")).status).toBe(405);
  });
});
