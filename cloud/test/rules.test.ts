import { describe, expect, it } from "vitest";
import { alertForEvent, burstAlert, burstDetails, detectBurst, isOfflineAlertDue, type RuleContext } from "../src/alerts";
import { parseTypeFilter, typeFilterSql, webItem } from "../src/routes/master";
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

  it("alert data = event data (exe approval carries the file identity)", () => {
    const data = {
      exe: "game.exe", path: "C:\\Users\\bin\\Downloads\\game.exe", pid: 7, sha256: "b".repeat(64),
      publisher: "Game Studio", signed: true, sizeBytes: 1234,
    };
    const a = alertForEvent(ev("request.exe_approval", data), ctx)!;
    expect(a).toMatchObject({ type: "request.exe_approval", severity: "warn", userSid: SID, eventId: "01JDQ50000000000000000BK0C" });
    expect(a.extra).toEqual(data);
    const q = alertForEvent(ev("quota.exhausted", { scope: "group:games", remainingMin: 0 }), ctx)!;
    expect(q.extra).toEqual({ scope: "group:games", remainingMin: 0 });
    expect(q.body).toContain("games");
  });

  it("tamper.state_tampered is critical and keeps detail", () => {
    const a = alertForEvent(ev("tamper.state_tampered", { detail: "policy.json signature check failed" }, { userSid: undefined }), ctx)!;
    expect(a).toMatchObject({ type: "tamper.state_tampered", severity: "critical", userSid: null });
    expect(a.extra).toEqual({ detail: "policy.json signature check failed" });
    expect(a.body).toContain("chính sách");
  });

  it("summarises a burst (hosts, exes, shared category)", () => {
    const web = (host: string, category?: string) => ({ type: "web.blocked", data: { host, source: "proxy", reason: "category", ...(category ? { category } : {}) } });
    const proc = (exe: string) => ({ type: "process.blocked", data: { exe, path: `C:\\${exe}`, pid: 1 } });
    expect(burstDetails([web("a.test", "adult"), web("b.test", "adult"), web("a.test", "adult")])).toEqual({ hosts: ["a.test", "b.test"], category: "adult" });
    expect(burstDetails([web("a.test", "adult"), web("b.test", "games"), proc("x.exe")])).toEqual({ hosts: ["a.test", "b.test"], exes: ["x.exe"] });
    expect(burstDetails([web("a.test", "adult"), web("b.test")])).toEqual({ hosts: ["a.test", "b.test"] });
    expect(burstDetails([proc("x.exe"), proc("y.exe"), proc("x.exe")])).toEqual({ exes: ["x.exe", "y.exe"] });
    expect(burstDetails(Array.from({ length: 15 }, (_, i) => web(`h${i}.test`))).hosts).toHaveLength(10);
    const a = burstAlert(DEV, SID, "x", "2026-11-22T08:41:00.000Z", 3, ctx, { hosts: ["a.test"], category: "adult" });
    expect(a.extra).toEqual({ count: 3, hosts: ["a.test"], category: "adult" });
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

describe("master query helpers", () => {
  it("parses multi-type / prefix filters", () => {
    expect(parseTypeFilter(null, "type")).toBeNull();
    expect(parseTypeFilter(" , ", "type")).toBeNull();
    expect(parseTypeFilter("web.*,process.blocked,web.*", "type")).toEqual({ exact: ["process.blocked"], prefixes: ["web."] });
    expect(() => parseTypeFilter("web.visit;drop", "type")).toThrow();
    expect(() => parseTypeFilter("WEB.visit", "type")).toThrow();
    expect(() => parseTypeFilter(Array(21).fill("web.visit").join(","), "type")).toThrow();
  });

  it("builds include / exclude SQL", () => {
    const f = parseTypeFilter("usage.tick,web.*,tamper.*", "type")!;
    expect(typeFilterSql(f, false)).toEqual([
      "(type IN (?) OR type LIKE ? ESCAPE '\\' OR type LIKE ? ESCAPE '\\')",
      ["usage.tick", "web.%", "tamper.%"],
    ]);
    const x = typeFilterSql(parseTypeFilter("request.*", "exclude")!, true);
    expect(x[0]).toBe("NOT (type LIKE ? ESCAPE '\\')");
    expect(x[1]).toEqual(["request.%"]);
    expect(typeFilterSql(parseTypeFilter("usage_x.*", "type")!, false)[1]).toEqual(["usage\\_x.%"]);
  });

  it("maps web rows with query/engine for searches", () => {
    const base = { ts: "t", url: null, host: "google", title: "mèo", duration_sec: null, category: "google" };
    expect(webItem({ ...base, kind: "search" })).toMatchObject({ kind: "search", query: "mèo", engine: "google" });
    expect(webItem({ ...base, kind: "visit", title: "Page", category: null })).toMatchObject({ query: null, engine: null, title: "Page" });
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
