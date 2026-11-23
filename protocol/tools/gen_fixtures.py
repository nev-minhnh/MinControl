"""Regenerate protocol/fixtures. Run: python protocol/tools/gen_fixtures.py"""
import copy
import json
import pathlib
import shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent / "fixtures"
DEV = "01JDQ3Z8K4M2N6P8R0S2T4V6W8"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def week(weekday, weekend):
    return {d: (weekend if d in ("sat", "sun") else weekday) for d in DAYS}


POLICY = {
    "version": 7,
    "timezone": "Asia/Ho_Chi_Minh",
    "users": {
        SID: {
            "label": "Bin",
            "screenTime": {
                "dailyQuotaMin": week(120, 180),
                "allowedWindows": week(["15:00-21:00"], ["08:00-21:30"]),
                "warnAtMin": [5, 1],
                "graceSec": 60,
                "countIdle": False,
                "idleThresholdSec": 300,
            },
            "appGroups": {
                "games": {
                    "label": "Game",
                    "match": [{"publisher": "Mojang*"}, {"exe": "Minecraft*.exe"}],
                    "dailyQuotaMin": week(60, 90),
                }
            },
            "appRules": [
                {"action": "block", "match": {"exe": "firefox*.exe"}},
                {"action": "block", "match": {"pathUnderUserWritable": True}, "except": [{"sha256": "a" * 64}]},
            ],
            "newExecutable": "ask",
            "web": {
                "mode": "blocklist",
                "blockedCategories": ["adult", "gambling", "proxy-vpn"],
                "categorySchedules": {"games": week(["15:00-17:00"], [])},
                "blockDomains": ["*.example-bad.com"],
                "allowDomains": ["*.edu.vn", "olm.vn"],
                "safeSearch": True,
                "youtube": "strict",
                "allowedBrowsers": ["msedge.exe", "chrome.exe"],
                "netExemptApps": [],
            },
            "monitoring": {
                "foregroundTitles": True, "browserHistory": True, "domainLog": True,
                "downloads": True, "usb": True,
                "screenshots": {"intervalMin": 5, "onlyWhenActive": True, "maxWidth": 1280, "jpegQuality": 60},
            },
        }
    },
    "retentionDays": {"events": 180, "web": 180, "screenshots": 30},
}
EMPTY_POLICY = {"version": 1, "timezone": "Asia/Ho_Chi_Minh", "users": {},
                "retentionDays": {"events": 180, "web": 180, "screenshots": 30}}


def mutate(base, fn):
    p = copy.deepcopy(base)
    fn(p)
    return p


def user(p):
    return p["users"][SID]


LOCK = {"commandId": "01JDQ40000000000000000V0CK", "type": "lock_now", "userSid": SID, "until": "2026-11-23T00:00:00Z"}
REFRESH = {"commandId": "01JDQ4000000000000000REFRS", "type": "refresh"}
DIAGNOSE = {"commandId": "01JDQ4000000000000000D1AG0", "type": "diagnose"}
DIAG = {"id": "01JDQ5000000000000000D1AGR", "deviceId": DEV, "ts": "2026-11-23T08:00:00Z", "monoMs": 99,
        "type": "diag.report",
        "data": {"commandId": DIAGNOSE["commandId"],
                 "sections": {"service": {"version": "0.3.0", "uptimeSec": 1234}, "policy": {"version": 7, "seq": 42, "storedOk": True}}}}
VISIT = {"id": "01JDQ50000000000000000V1ST", "deviceId": DEV, "userSid": SID, "ts": "2026-11-22T08:44:00Z",
         "monoMs": 3600000, "type": "web.visit",
         "data": {"url": "https://www.youtube.com/watch?v=abc", "title": "Huong dan xay nha Minecraft",
                  "browser": "msedge", "durationSec": 360}}
GAP = {"id": "01JDQ5000000000000000000GP", "deviceId": DEV, "ts": "2026-11-22T08:44:00Z", "monoMs": 12,
       "type": "tamper.offline_gap", "data": {"gapSec": 7200}}
BLOCKED = {"id": "01JDQ50000000000000000BK0C", "deviceId": DEV, "userSid": SID, "ts": "2026-11-22T08:41:00Z",
           "monoMs": 3400000, "type": "process.blocked",
           "data": {"exe": "FirefoxPortable.exe", "path": "E:\\FirefoxPortable\\FirefoxPortable.exe", "pid": 4242,
                    "signed": False, "rule": "allowedBrowsers"}}
STATE_TAMPERED = {"id": "01JDQ5000000000000000STTMP", "deviceId": DEV, "ts": "2026-11-22T08:46:00Z", "monoMs": 15,
                  "type": "tamper.state_tampered", "data": {"detail": "policy.json signature check failed"}}
DOH_BLOCKED = {"id": "01JDQ5000000000000000000DH", "deviceId": DEV, "userSid": SID, "ts": "2026-11-22T08:42:00Z",
               "monoMs": 3500000, "type": "web.blocked",
               "data": {"host": "dns.google", "source": "proxy", "reason": "doh", "exe": "chrome.exe"}}
STATE = {"ts": "2026-11-22T08:50:00Z", "agentVersion": "0.2.0", "policyVersion": 7,
         "users": [{"sid": SID, "loggedOn": True, "active": True, "locked": False, "lockedUntil": None,
                    "remainingMin": 72, "usedMin": 48, "groups": {"games": {"usedMin": 23, "remainingMin": 37}},
                    "foregroundExe": "Minecraft.exe", "foregroundTitle": "Minecraft 1.21",
                    "foregroundStartedAt": "2026-11-22T08:31:00Z"}]}
STATE_LOCKED = {"ts": "2026-11-22T08:50:00Z", "agentVersion": "0.2.0", "policyVersion": None,
                "users": [{"sid": SID, "loggedOn": False, "active": False, "locked": True,
                           "lockedUntil": "2026-11-23T00:00:00Z", "remainingMin": None, "usedMin": None,
                           "foregroundExe": None, "foregroundTitle": None, "foregroundStartedAt": None}]}
SIG = "A" * 86
ENV = {"v": 1, "alg": "ed25519", "keyId": "3f9ac21d77e0b14a", "payload": "eyJkZXZpY2VJZCI6IjAxIn0", "sig": SIG}


def body(kind, seq, b, exp="2026-11-22T09:50:00Z"):
    return {"deviceId": DEV, "kind": kind, "seq": seq, "issuedAt": "2026-11-22T08:50:00Z", "expiresAt": exp, "body": b}


MK_KEY = {"keyId": "3f9a1c2b4d5e6f70", "alg": "ed25519", "publicKey": "A" * 43, "role": "sign"}
MASTER_KEYS = {"keys": [MK_KEY], "sealPubKey": "B" * 43}

INV = {"deviceId": DEV, "generatedAt": "2026-11-22T08:45:00Z", "users": {SID: {"apps": [
    {"id": "a" * 64, "name": "Minecraft Launcher", "kind": "win32", "publisher": "Mojang", "version": "2.3.1",
     "installDir": r"C:\Program Files (x86)\Minecraft Launcher", "exe": "MinecraftLauncher.exe",
     "exePath": r"C:\Program Files (x86)\Minecraft Launcher\MinecraftLauncher.exe",
     "lastUsed": "2026-11-22T07:30:00Z", "minutes7d": 310, "category": "game"},
    {"id": "b" * 64, "name": "game.exe", "kind": "seen", "exe": "game.exe", "minutes7d": 12},
]}}}

FIXTURES = {
    "policy": {
        "valid": {
            "basic": POLICY,
            "no-managed-users": EMPTY_POLICY,
            "net-exempt-app-with-path": mutate(POLICY, lambda p: user(p)["web"].update(
                netExemptApps=[{"exe": "Zoom.exe", "path": r"%ProgramFiles%\Zoom\bin\Zoom.exe"}])),
            "blocking-v2": mutate(POLICY, lambda p: (user(p).update(
                appMode="allowlist", keywords={"words": ["cờ bạc", "sex"], "matchSearches": True, "matchTitles": True},
                appRules=[{"action": "allow", "match": {"exe": "chrome.exe"}}]),
                user(p)["web"].update(blockedServices=["tiktok", "roblox"], allowedServices=["youtube"]))),
            "allowlist-via-allowed-service": mutate(POLICY, lambda p: (user(p).update(appMode="allowlist", appRules=[]),
                user(p)["web"].update(allowedServices=["steam"]))),
            "no-use-day-and-any-time-day": mutate(POLICY, lambda p: user(p)["screenTime"]["allowedWindows"].update(
                sun=[], sat=["00:00-24:00"])),
        },
        "invalid": {
            "builtin-admin-group-sid": mutate(EMPTY_POLICY, lambda p: p["users"].update({"S-1-5-32-544": user(POLICY)})),
            "unknown-field": mutate(EMPTY_POLICY, lambda p: p.update(debug=True)),
            "missing-weekday": mutate(POLICY, lambda p: user(p)["screenTime"]["dailyQuotaMin"].pop("sun")),
            "browser-not-supported": mutate(POLICY, lambda p: user(p)["web"].update(allowedBrowsers=["firefox.exe"])),
            "domain-uppercase": mutate(POLICY, lambda p: user(p)["web"].update(blockDomains=["Example.COM"])),
            "service-id-uppercase": mutate(POLICY, lambda p: user(p)["web"].update(blockedServices=["TikTok"])),
            "service-id-duplicate": mutate(POLICY, lambda p: user(p)["web"].update(blockedServices=["tiktok", "tiktok"])),
            "app-mode-unknown": mutate(POLICY, lambda p: user(p).update(appMode="denylist")),
            "keywords-word-too-long": mutate(POLICY, lambda p: user(p).update(
                keywords={"words": ["x" * 65], "matchSearches": True, "matchTitles": True})),
            "keywords-empty-word": mutate(POLICY, lambda p: user(p).update(
                keywords={"words": [""], "matchSearches": True, "matchTitles": True})),
            "keywords-too-many": mutate(POLICY, lambda p: user(p).update(
                keywords={"words": [f"w{i}" for i in range(501)], "matchSearches": True, "matchTitles": True})),
            "net-exempt-app-without-path": mutate(POLICY, lambda p: user(p)["web"].update(netExemptApps=[{"exe": "Zoom.exe"}])),
        },
        # schema-valid but must be rejected by the semantic validator in each agent's policy engine
        "semantic-invalid": {
            "window-crosses-midnight": mutate(POLICY, lambda p: user(p)["screenTime"]["allowedWindows"].update(mon=["21:00-06:00"])),
            "overlapping-windows": mutate(POLICY, lambda p: user(p)["screenTime"]["allowedWindows"].update(mon=["15:00-18:00", "17:00-21:00"])),
            "category-both-blocked-and-scheduled": mutate(POLICY, lambda p: user(p)["web"].update(blockedCategories=["games"])),
            # warnAtMin entry >= that day's quota (quota > 0): mon quota 3 min, warn at 5
            "warn-at-not-below-quota": mutate(POLICY, lambda p: user(p)["screenTime"]["dailyQuotaMin"].update(mon=3)),
            "domain-in-block-and-allow": mutate(POLICY, lambda p: user(p)["web"].update(blockDomains=["*.example-bad.com", "olm.vn"])),
            "allowlist-empty-allow-domains": mutate(POLICY, lambda p: user(p)["web"].update(mode="allowlist", allowDomains=[])),
            "overlapping-category-schedule-windows": mutate(POLICY, lambda p: user(p)["web"]["categorySchedules"]["games"].update(
                mon=["15:00-17:00", "16:00-18:00"])),
            "service-both-blocked-and-allowed": mutate(POLICY, lambda p: user(p)["web"].update(
                blockedServices=["tiktok", "youtube"], allowedServices=["youtube"])),
            "allowlist-app-mode-without-allow-rule-or-service": mutate(POLICY, lambda p: (user(p).update(appMode="allowlist"),
                user(p)["web"].update(allowedServices=[]))),
            "unknown-timezone": mutate(POLICY, lambda p: p.update(timezone="Mars/Olympus")),
        },
    },
    "command": {
        "valid": {
            "lock-until": LOCK,
            "add-time-group": {"commandId": "01JDQ4000000000000000ADD15", "type": "add_time", "userSid": SID, "minutes": 15, "group": "games"},
            "refresh": REFRESH,
            "diagnose": DIAGNOSE,
        },
        "invalid": {
            "add-time-zero": {"commandId": "01JDQ4000000000000000ADD00", "type": "add_time", "userSid": SID, "minutes": 0},
            "lock-missing-sid": {"commandId": LOCK["commandId"], "type": "lock_now"},
            "extra-field": dict(REFRESH, userSid=SID),
            "unknown-type": {"commandId": REFRESH["commandId"], "type": "format_disk"},
            "bad-ulid": dict(REFRESH, commandId="not-a-ulid"),
        },
    },
    "command-ack": {
        "valid": {
            "applied": {"commandId": LOCK["commandId"], "status": "applied", "at": "2026-11-22T08:51:00Z"},
            "rejected-replay": {"commandId": LOCK["commandId"], "status": "rejected", "at": "2026-11-22T08:51:00Z", "error": "replayed"},
        },
        "invalid": {
            "rejected-without-error": {"commandId": LOCK["commandId"], "status": "rejected", "at": "2026-11-22T08:51:00Z"},
            "applied-with-error": {"commandId": LOCK["commandId"], "status": "applied", "at": "2026-11-22T08:51:00Z", "error": "internal"},
        },
    },
    "event": {
        "valid": {"web-visit": VISIT, "tamper-offline-gap-no-user": GAP, "process-blocked": BLOCKED,
                  "tamper-state-tampered": STATE_TAMPERED, "diag-report": DIAG, "web-blocked-doh": DOH_BLOCKED,
                  "web-blocked-keyword": mutate(DOH_BLOCKED, lambda e: e.update(id="01JDQ500000000000000000KWD", data={
                      "host": "www.google.com", "source": "extension", "reason": "keyword", "keyword": "cờ bạc"})),
                  "web-blocked-keyword-full": mutate(DOH_BLOCKED, lambda e: e.update(id="01JDQ500000000000000KWDFUL", data={
                      "host": "www.google.com", "url": "https://www.google.com/search?q=c%E1%BB%9D+b%E1%BA%A1c", "source": "extension",
                      "reason": "keyword", "keyword": "cờ bạc", "action": "closed_tab", "title": "cờ bạc online - Google Search",
                      "query": "cờ bạc online", "engine": "google", "exe": "chrome.exe", "count": 3, "rule": "Từ khóa: cờ bạc"})),
                  "process-blocked-killed": mutate(BLOCKED, lambda e: e.update(id="01JDQ500000000000000000PKL", data=dict(
                      e["data"], action="killed", count=2, title="Roblox", rule="Dịch vụ: Roblox"))),
                  "web-blocked-service": mutate(DOH_BLOCKED, lambda e: e.update(id="01JDQ500000000000000000SVC", data={
                      "host": "www.tiktok.com", "source": "proxy", "reason": "service", "service": "tiktok"})),
                  "process-blocked-service": mutate(BLOCKED, lambda e: e.update(id="01JDQ500000000000000000PSV", data=dict(
                      e["data"], exe="RobloxPlayerBeta.exe", service="roblox", rule="service:roblox"))),
                  "web-blocked-port": mutate(DOH_BLOCKED, lambda e: e.update(id="01JDQ500000000000000000PRT", data={
                      "host": "203.0.113.7", "source": "proxy", "reason": "port", "exe": "game.exe"}))},
        "invalid": {
            "web-blocked-bad-action": mutate(DOH_BLOCKED, lambda e: e["data"].update(action="killed")),
            "web-blocked-count-zero": mutate(DOH_BLOCKED, lambda e: e["data"].update(count=0)),
            "process-blocked-bad-action": mutate(BLOCKED, lambda e: e["data"].update(action="closed_tab")),
            "web-blocked-service-bad-id": mutate(DOH_BLOCKED, lambda e: e["data"].update(reason="service", service="TikTok")),
            "web-blocked-keyword-too-long": mutate(DOH_BLOCKED, lambda e: e["data"].update(reason="keyword", keyword="x" * 65)),
            "web-visit-missing-userSid": mutate(VISIT, lambda e: e.pop("userSid")),
            "web-visit-wrong-data": mutate(VISIT, lambda e: e.update(data=BLOCKED["data"])),
            "local-time-not-utc": mutate(GAP, lambda e: e.update(ts="2026-11-22T15:44:00+07:00")),
            "diag-report-without-commandId": mutate(DIAG, lambda e: e["data"].pop("commandId")),
            "unknown-type": mutate(GAP, lambda e: e.update(type="tamper.something_new")),
            "web-blocked-unknown-reason": mutate(DOH_BLOCKED, lambda e: e["data"].update(reason="firewall")),
        },
    },
    "device-state": {
        "valid": {"active-user": STATE, "locked-no-policy": STATE_LOCKED,
                  "minimal": {"ts": "2026-11-22T08:50:00Z", "agentVersion": "0.2.0", "users": []}},
        "invalid": {
            "missing-ts": mutate(STATE, lambda s: s.pop("ts")),
            "unknown-field": mutate(STATE, lambda s: s.update(debug=True)),
            "unknown-user-field": mutate(STATE, lambda s: s["users"][0].update(screenOn=True)),
            "foreground-started-local-time": mutate(STATE, lambda s: s["users"][0].update(foregroundStartedAt="2026-11-22T15:31:00+07:00")),
            "builtin-group-sid": mutate(STATE, lambda s: s["users"][0].update(sid="S-1-5-32-544")),
        },
    },
    "event-batch": {
        "valid": {"two-events": {"deviceId": DEV, "sentAt": "2026-11-22T08:45:00Z", "events": [VISIT, GAP]}},
        "invalid": {
            "empty": {"deviceId": DEV, "sentAt": "2026-11-22T08:45:00Z", "events": []},
            "contains-invalid-event": {"deviceId": DEV, "sentAt": "2026-11-22T08:45:00Z", "events": [mutate(VISIT, lambda e: e.pop("userSid"))]},
        },
    },
    "inventory": {
        "valid": {
            "two-apps": INV,
            "empty-user": {"deviceId": DEV, "generatedAt": "2026-11-22T08:45:00Z", "users": {SID: {"apps": []}}},
        },
        "invalid": {
            "bad-kind": mutate(INV, lambda i: i["users"][SID]["apps"][0].update(kind="msi")),
            "bad-sha256-id": mutate(INV, lambda i: i["users"][SID]["apps"][0].update(id="NOTHEX")),
            "unknown-field": mutate(INV, lambda i: i["users"][SID]["apps"][0].update(icon="x")),
            "missing-name": mutate(INV, lambda i: i["users"][SID]["apps"][0].pop("name")),
        },
    },
    "signed-envelope": {
        "valid": {"ed25519": ENV, "es256": dict(ENV, alg="es256")},
        "invalid": {
            "padded-sig": dict(ENV, sig=SIG + "=="),
            "alg-none": dict(ENV, alg="none"),
            "short-keyid": dict(ENV, keyId="3f9a"),
        },
    },
    "signed-body": {
        "valid": {
            "command": body("command", 42, LOCK),
            "policy": body("policy", 7, POLICY, exp="2027-11-22T08:50:00Z"),
            "master-keys": body("master_keys", 3, MASTER_KEYS, exp="2026-12-22T08:50:00Z"),
        },
        "invalid": {
            "kind-mismatch": body("policy", 8, LOCK),
            "seq-zero": body("command", 0, REFRESH),
            "master-keys-role-read": body("master_keys", 4, dict(MASTER_KEYS, keys=[dict(MK_KEY, role="read")])),
            "master-keys-missing-seal-key": body("master_keys", 4, {"keys": [MK_KEY]}),
            "invalid-inner-command": body("command", 43, {"commandId": REFRESH["commandId"], "type": "format_disk"}),
        },
    },
}


def main():
    if ROOT.exists():
        shutil.rmtree(ROOT)
    n = 0
    for stem, groups in FIXTURES.items():
        for group, items in groups.items():
            d = ROOT / stem / group
            d.mkdir(parents=True, exist_ok=True)
            for name, obj in items.items():
                (d / f"{name}.json").write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                n += 1
    print(f"wrote {n} fixtures to {ROOT}")


if __name__ == "__main__":
    main()
