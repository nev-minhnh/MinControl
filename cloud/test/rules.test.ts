import { describe, expect, it } from "vitest";
import { alertForEvent, burstAlert, detectBurst, isOfflineAlertDue, type RuleContext } from "../src/alerts";
import { parseRetention, DEFAULT_RETENTION } from "../src/cron";
import { cursorClause, decodeCursor, encodeCursor, paginate, parseLimit } from "../src/lib/cursor";
import { buildRows, hostOf } from "../src/ingest";
import { localDay } from "../src/lib/time";

const DEV = "01JDQ3Z8K4M2N6P8R0S2T4V6W8";
const SID = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const ctx: RuleContext = { hostname: "PC-TEST", userName: (sid) => (sid === SID ? "Bé" : (sid ?? "Máy")) };
const ev = (type: string, data: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => ({
  id: "01JDQ50000000000000000BK0C",
  deviceId: DEV,
  userSid: SID,
  ts: "2026-11-22T08:41:00.000Z",
  monoMs: 1,
  type,
  data,
  ...extra,
});

describe("cursor", () => {
  it("round-trips and is opaque base64url", () => {
    const c = encodeCursor({ ts: "2026-11-22T08:41:00.000Z", id: "01JDQ50000000000000000BK0C" });
    expect(c).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeCursor(c)).toEqual({ ts: "2026-11-22T08:41:00.000Z", id: "01JDQ50000000000000000BK0C" });
    expect(decodeCursor(null)).toBeNull();
  });
  it("rejects garbage", () => {
    expect(() => decodeCursor("!!")).toThrow();
    expect(() => decodeCursor("e30")).toThrow(); // "{}"
  });
  it("builds the keyset clause and pages", () => {
    expect(cursorClause(null).sql).toBe("");
    expect(cursorClause({ ts: "t", id: "i" }).params).toEqual(["t", "t", "i"]);
    const rows = [1, 2, 3].map((n) => ({ ts: `t${n}`, id: `i${n}` }));
    const page = paginate(rows, 2, (r) => r);
    expect(page.items).toHaveLength(2);
    expect(decodeCursor(page.next)).toEqual({ ts: "t2", id: "i2" });
    expect(paginate(rows, 3, (r) => r).next).toBeNull();
  });
  it("clamps limit", () => {
    expect(parseLimit(null, 50, 200)).toBe(50);
    expect(parseLimit("999", 50, 200)).toBe(200);
    expect(() => parseLimit("0", 50, 200)).toThrow();
  });
});

describe("alert rules", () => {
  it("raises single-event alerts in Vietnamese", () => {
    const q = alertForEvent(ev("quota.exhausted", { scope: "total", remainingMin: 0 }), ctx)!;
    expect(q).toMatchObject({ type: "quota.exhausted", severity: "info", userSid: SID });
    expect(q.body).toContain("Bé");
    expect(q.body).toContain("PC-TEST");
    expect(alertForEvent(ev("request.exe_approval", { exe: "game.exe", path: "C:\\g.exe", pid: 1 }), ctx)!.severity).toBe("warn");
    const t = alertForEvent(ev("tamper.clock_jump", { jumpSec: 3600 }, { userSid: undefined }), ctx)!;
    expect(t).toMatchObject({ severity: "critical", title: "Cảnh báo can thiệp", userSid: null });
    expect(alertForEvent(ev("web.visit", { url: "https://x", browser: "chrome" }), ctx)).toBeNull();
    expect(alertForEvent(ev("quota.warning", { scope: "total", remainingMin: 5 }), ctx)).toBeNull();
  });

  it("detects ≥3 blocked within 10 minutes", () => {
    const m = 60_000;
    expect(detectBurst([0, 5 * m])).toBe(-1);
    expect(detectBurst([0, 5 * m, 10 * m])).toBe(2);
    expect(detectBurst([0, 5 * m, 10 * m + 1])).toBe(-1);
    expect(detectBurst([0, 20 * m, 21 * m, 22 * m])).toBe(3);
    const a = burstAlert(DEV, SID, "x", "2026-11-22T08:41:00.000Z", 3, ctx);
    expect(a).toMatchObject({ type: "blocked.burst", severity: "warn" });
    expect(a.body).toContain("3 lần");
  });

  it("offline alert once per offline period", () => {
    const h = 3600_000;
    expect(isOfflineAlertDue(0, null, 2 * h + 1)).toBe(true);
    expect(isOfflineAlertDue(0, null, 2 * h)).toBe(false);
    expect(isOfflineAlertDue(0, 3 * h, 4 * h)).toBe(false); // already alerted for this period
    expect(isOfflineAlertDue(5 * h, 3 * h, 8 * h)).toBe(true); // came back, went offline again
  });
});

describe("ingest rows", () => {
  it("denormalises web, screenshots and aggregates usage/domains", () => {
    const rows = buildRows(
      [
        ev("web.visit", { url: "https://Example.com/a", browser: "msedge", title: "A", durationSec: 30 }, { id: "A1" }),
        ev("web.search", { engine: "google", query: "mèo" }, { id: "A2" }),
        ev("web.blocked", { host: "bad.test", source: "proxy", reason: "category", category: "adult" }, { id: "A3" }),
        ev("usage.tick", { minuteStart: "2026-11-22T08:40:00Z", activeSec: 50, exe: "Minecraft.exe", group: "games" }, { id: "A4" }),
        ev("usage.tick", { minuteStart: "2026-11-22T08:41:00Z", activeSec: 60, exe: "minecraft.exe" }, { id: "A5" }),
        ev("net.domain", { host: "x.test", exe: "a.exe", windowStart: "2026-11-22T08:40:00Z", connections: 2, allowed: true }, { id: "A6" }),
        ev("net.domain", { host: "x.test", exe: "a.exe", windowStart: "2026-11-22T08:45:00Z", connections: 3, bytesIn: 10, allowed: true }, { id: "A7" }),
        ev("screenshot.taken", { blobKey: `screens/${DEV}/2026-11-22/A8.bin`, width: 1, height: 1, reason: "interval" }, { id: "A8" }),
        ev("screenshot.taken", { blobKey: "screens/OTHER/2026-11-22/A9.bin", width: 1, height: 1, reason: "interval" }, { id: "A9" }),
      ],
      DEV,
      "Asia/Ho_Chi_Minh",
      "2026-11-22T09:00:00.000Z",
    );
    expect(rows.events).toHaveLength(9);
    expect(rows.web.map((r) => r[4])).toEqual(["visit", "search", "blocked"]);
    expect(rows.web[0]![6]).toBe("example.com");
    expect(rows.usage).toEqual([[DEV, SID, "2026-11-22", "minecraft.exe", "games", 110]]);
    expect(rows.domains).toHaveLength(1);
    expect(rows.domains[0]!.slice(6)).toEqual([5, 0, 10]);
    expect(rows.screenshots).toHaveLength(1);
  });

  it("buckets usage by local day", () => {
    expect(localDay(Date.parse("2026-11-22T18:30:00Z"), "Asia/Ho_Chi_Minh")).toBe("2026-11-23");
    expect(localDay(Date.parse("2026-11-22T18:30:00Z"), null)).toBe("2026-11-22");
    expect(hostOf("not a url")).toBeNull();
  });

  it("parses retention with defaults", () => {
    expect(parseRetention(null)).toEqual(DEFAULT_RETENTION);
    expect(parseRetention('{"events":30,"web":7,"screenshots":3}')).toEqual({ events: 30, web: 7, screenshots: 3 });
  });
});
