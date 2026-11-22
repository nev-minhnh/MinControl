import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";

const env = {} as Env;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const call = (method: string, path: string) =>
  worker.fetch(new Request(`https://example.test${path}`, { method }), env, ctx);

describe("router", () => {
  it("GET /health -> 200 ok", async () => {
    const res = await call("GET", "/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });
  it("sketched route -> 501", async () => {
    const res = await call("GET", "/v1/master/devices/01ARZ3NDEKTSV4RRFFQ69G5FAV/state");
    expect(res.status).toBe(501);
    expect(await res.json()).toMatchObject({ error: "not_implemented" });
  });
  it("unknown -> 404", async () => {
    expect((await call("GET", "/nope")).status).toBe(404);
  });
});
