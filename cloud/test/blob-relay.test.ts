import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BLOB_TIMEOUT_MS, BlobRelay } from "../src/blob-relay";
import { validateWsDeviceMessage } from "../src/generated/validators";

const KEY = "screens/01ARZ3NDEKTSV4RRFFQ69G5FAV/2026-11-22/01ARZ3NDEKTSV4RRFFQ69G5FAW.bin";

function setup() {
  const relay = new BlobRelay();
  const frames: string[] = [];
  const send = (f: string) => (frames.push(f), true);
  const reqIdOf = () => (JSON.parse(frames[frames.length - 1]!) as { reqId: string }).reqId;
  return { relay, frames, send, reqIdOf };
}

describe("BlobRelay", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("sends blob_request with a ULID reqId and keeps it pending", () => {
    const { relay, frames, send } = setup();
    void relay.request(KEY, send);
    const f = JSON.parse(frames[0]!);
    expect(f).toMatchObject({ t: "blob_request", key: KEY });
    expect(f.reqId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(relay.size).toBe(1);
  });

  it("device upload resolves with the bytes, once", async () => {
    const { relay, send, reqIdOf } = setup();
    const p = relay.request(KEY, send);
    const bytes = new Uint8Array([1, 2, 3]);
    expect(relay.resolveBytes(reqIdOf(), KEY, bytes)).toBe(true);
    expect(await p).toEqual({ status: "ok", bytes });
    expect(relay.size).toBe(0);
    expect(relay.resolveBytes(reqIdOf(), KEY, bytes)).toBe(false); // already consumed -> 410
  });

  it("unknown reqId or wrong key -> false (410)", () => {
    const { relay, send, reqIdOf } = setup();
    void relay.request(KEY, send);
    expect(relay.resolveBytes("01ARZ3NDEKTSV4RRFFQ69G5FAX", KEY, new Uint8Array(1))).toBe(false);
    expect(relay.resolveBytes(reqIdOf(), KEY.replace("2026-11-22", "2026-11-21"), new Uint8Array(1))).toBe(false);
    expect(relay.size).toBe(1);
  });

  it("blob_missing resolves as missing", async () => {
    const { relay, send, reqIdOf } = setup();
    const p = relay.request(KEY, send);
    expect(relay.resolveMissing(reqIdOf())).toBe(true);
    expect(await p).toEqual({ status: "missing" });
  });

  it("times out after 25 s and then rejects a late upload", async () => {
    const { relay, send, reqIdOf } = setup();
    const p = relay.request(KEY, send);
    const id = reqIdOf();
    vi.advanceTimersByTime(BLOB_TIMEOUT_MS - 1);
    expect(relay.size).toBe(1);
    vi.advanceTimersByTime(1);
    expect(await p).toEqual({ status: "timeout" });
    expect(relay.size).toBe(0);
    expect(relay.resolveBytes(id, KEY, new Uint8Array(1))).toBe(false);
  });

  it("no authenticated socket -> offline, nothing left pending", async () => {
    const relay = new BlobRelay();
    expect(await relay.request(KEY, () => false)).toEqual({ status: "offline" });
    expect(await relay.request(KEY, () => { throw new Error("closed"); })).toEqual({ status: "offline" });
    expect(relay.size).toBe(0);
  });

  it("failAll (socket closed) resolves every waiter as offline", async () => {
    const { relay, send } = setup();
    const a = relay.request(KEY, send);
    const b = relay.request(KEY, send);
    relay.failAll("offline");
    expect(await a).toEqual({ status: "offline" });
    expect(await b).toEqual({ status: "offline" });
    expect(relay.size).toBe(0);
  });
});

describe("WS frame blob_missing", () => {
  it("is accepted with a ULID reqId and rejected otherwise", () => {
    expect(validateWsDeviceMessage({ t: "blob_missing", reqId: "01ARZ3NDEKTSV4RRFFQ69G5FAX" })).toBe(true);
    expect(validateWsDeviceMessage({ t: "blob_missing" })).toBe(false);
    expect(validateWsDeviceMessage({ t: "blob_missing", reqId: "x" })).toBe(false);
  });
});
