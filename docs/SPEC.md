# MinControl — Specification (Phase 1: Windows)

Status: draft v0.1 · 2026-11-22 · owner: Minh

MinControl is a self-built parental-control system. Phase 1 controls and monitors
**Windows 11 Pro** PCs from a **master app on Minh's Android phone**, with an
all-Cloudflare backend. Android and iPad agents come in later phases; nothing in
Phase 1 may assume Windows-only concepts in the protocol or cloud layer.

---

## 1. Goals and non-goals

### Goals (Phase 1)
1. Screen time: daily quota, allowed time windows, per-category limits, warnings, forced logoff.
2. App control: block apps, limit app groups, approve/deny new executables.
3. Web filtering for the managed user: domain/category rules, SafeSearch, YouTube Restricted,
   block bypass (VPN, DoH, QUIC, portable browsers, InPrivate).
4. Full monitoring log: sessions, foreground apps + window titles, processes, full browser URL
   history + titles + search terms, domains contacted by every app, installs, downloads, USB,
   screenshots, tamper events.
5. Remote control from the phone: lock, add time, pause limits, screenshot, edit policy.
6. Alerts pushed to the phone.

### Non-goals (Phase 1)
- Keylogging and chat-content capture (deliberately excluded).
- TLS interception (MITM). Full URLs come from the browser extension only.
- Android / iPad agents (protocol must be ready for them, implementation is later).
- Kernel drivers. Everything is user-mode + WFP + OS policy.

---

## 2. Core invariants (must hold for every feature)

| # | Invariant |
|---|---|
| I1 | **Per-user scope.** Every enforcement and every log record is keyed by the Windows **SID** of a *managed* user. Processes, sessions, network flows and registry writes of any other SID are never touched. |
| I2 | **Admins are never affected.** A SID that is a member of local Administrators can never be managed. If a managed SID becomes admin, enforcement for it **stops** (an admin can undo anything) and a critical `tamper.managed_user_is_admin` alert is raised once per day until fixed (decided by Minh 2026-11-22). |
| I3 | **Offline enforcement.** The device holds the full signed policy locally and enforces it with no network. Cloud is for sync, commands and logs only. |
| I4 | **Fail closed for the managed user.** If the agent stack is broken, the managed user loses internet (persistent WFP filters) and the session is logged off after a grace period. The admin user is unaffected. |
| I5 | **Commands and policies are signed by the master key.** The device verifies the Ed25519 signature against master public keys pinned at enrolment. A compromised Cloudflare account cannot command a device. |
| I6 | **Timezone-proof schedules.** Schedules are evaluated in the policy's fixed IANA timezone (default `Asia/Ho_Chi_Minh`), not the system timezone. Usage time is counted with a monotonic clock. |
| I7 | **No secrets readable by the managed user.** All state lives in `%ProgramData%\MinControl` with ACL `SYSTEM:F, Administrators:F`, nothing for Users. Device private key is DPAPI(machine)-protected. |

---

## 3. Components and repo layout

Repo root `D:\Coding_Project\MinControl\` holds one folder per branch (git worktrees).
Inside a branch folder:

```
protocol/            JSON Schemas — single source of truth for messages, policy, events
windows/             .NET 10 solution MinControl.sln
  src/MinControl.Core/        policy model, policy engine (pure, unit-tested), crypto, protocol types
  src/MinControl.Service/     Windows Service (LocalSystem): orchestration, cloud link, enforcement
  src/MinControl.Session/     per-session helper (runs as SYSTEM inside the user's session): UI overlay,
                              foreground tracking, screenshots
  src/MinControl.NetGuard/    WFP filter management + local filtering proxy
  src/MinControl.NativeHost/  Chrome/Edge native-messaging host (bridges extension -> Service)
  src/MinControl.Setup/       installer/enrolment CLI (run as admin)
  tests/                      xUnit; Core must reach high coverage (time math!)
extension/           Chromium MV3 extension (Edge + Chrome), TypeScript
cloud/               Cloudflare Worker (TypeScript), Durable Objects, D1 migrations, wrangler.toml
android-master/      Master app: Kotlin + Jetpack Compose, portrait only (design: docs/design/master-app)
docs/                specs, ADRs, runbooks
```

Shared types: C# and TS types are generated from `protocol/*.schema.json` (or hand-kept with a
contract test that validates sample messages against the schemas on both sides).

---

## 4. Identity, enrolment, security

### Keys
- **Master key**: generated in the **Android Keystore** (StrongBox when available), non-exportable,
  `setUserAuthenticationRequired` → every signature needs **BiometricPrompt**. Algorithm: Ed25519 if the
  device Keystore supports it, else ECDSA P-256 (the envelope carries `alg`; devices verify both).
  Optional second master key (backup phone / offline paper key) — devices accept any pinned master key.
- **Master encryption key**: X25519 keypair for sealing screenshots. Private part stays on phone
  (exportable backup encrypted with a passphrase, so a lost phone does not lose old screenshots).
- **Device key**: Ed25519, generated by `MinControl.Setup` at install, DPAPI-machine protected.

### Enrolment flow
1. Admin opens the master app → "Add device" → Worker creates a one-time **pairing code** (8 chars, 15 min TTL)
   bound to the account. The app shows the code + master public keys fingerprint.
2. On the PC, admin runs `MinControl.Setup.exe enroll <code>` (elevated). Setup generates the device
   key, calls `POST /v1/enroll {code, devicePubKey, hostname, osVersion, localUsers[]}`.
3. Worker returns `{deviceId, masterPubKeys[], masterSealPubKey, cloudUrl}`. Setup pins the master keys.
4. In the master app the admin picks which local users are **managed** (admins are greyed out, I2). This
   becomes policy v1, signed by the master key, pushed to the device.

### Device ↔ cloud auth
- WebSocket `GET /v1/device/ws` → server sends nonce → device answers `sign(deviceKey, nonce||deviceId||ts)`.
- HTTPS uploads carry a short-lived token issued over the authenticated WS.

### Master ↔ cloud auth
- The master app registers its public key at first run (bootstrap with a one-time admin secret set as a
  Worker secret). `/v1/master/*` requests carry a signed request header (key id, timestamp, body hash);
  reads use a separate non-biometric Keystore key so browsing history does not prompt every time.
- Cloudflare Access is optional (only for a future read-only web dashboard).
- Any state-changing request (policy, command) carries a master signature that the **device** verifies (I5).

### Replay protection
Every signed envelope: `{v, deviceId, seq, issuedAt, expiresAt, body}`; device rejects `seq <= lastSeq`
and expired envelopes.

---

## 5. Policy model (desired state)

One policy document per device, versioned, signed. Abbreviated example:

```jsonc
{
  "version": 7,
  "timezone": "Asia/Ho_Chi_Minh",
  "users": {
    "S-1-5-21-...-1001": {
      "label": "Bin",
      "screenTime": {
        "dailyQuotaMin": { "mon-fri": 120, "sat-sun": 180 },
        "allowedWindows": { "mon-fri": ["15:00-21:00"], "sat-sun": ["08:00-21:30"] },
        "warnAtMin": [5, 1],
        "graceSec": 60,
        "countIdle": false, "idleThresholdSec": 300
      },
      "appGroups": {
        "games": { "match": [{ "publisher": "Valve*" }, { "exe": "Minecraft*.exe" }], "dailyQuotaMin": 60 }
      },
      "appRules": [
        { "action": "block", "match": { "exe": "firefox.exe" } },
        { "action": "block", "match": { "pathUnderUserWritable": true }, "except": [{ "sha256": "..." }] }
      ],
      "newExecutable": "ask",            // allow | block | ask (block + alert with approve button)
      "web": {
        "mode": "blocklist",             // blocklist | allowlist
        "blockedCategories": ["adult", "gambling", "proxy-vpn"],
        "blockDomains": ["*.example-bad.com"],
        "allowDomains": ["*.edu.vn"],
        "safeSearch": true, "youtube": "strict",   // off | moderate | strict
        "allowedBrowsers": ["msedge.exe", "chrome.exe"],
        "netExemptApps": [{ "exe": "SomeGame.exe", "sha256": "..." }]
      },
      "monitoring": {
        "foregroundTitles": true, "browserHistory": true, "domainLog": true,
        "downloads": true, "usb": true,
        "screenshots": { "intervalMin": 5, "onlyWhenActive": true, "maxWidth": 1280, "jpegQuality": 60 }
      }
    }
  },
  "retentionDays": { "events": 180, "web": 180, "screenshots": 30 }
}
```

Temporary overrides (from commands) are **not** policy edits; they are signed `override` records with
an expiry (e.g. `+30 min today`, `pause limits until 18:00`, `lock until 07:00`).

---

### Screen-time semantics (decided by Minh 2026-11-22)
- A weekday with an **empty `allowedWindows` list means no screen time that day** (fail closed).
- Conflicting overrides (`lock_now` vs `pause_limits`/`unlock`): **the most recent command wins**.
- `remainingMin` shown to the child and in the master app = **min(quota left, minutes until the current
  allowed window ends)**.

## 6. Commands (master → device, signed)

| Command | Effect |
|---|---|
| `lock_now {userSid?, until?}` | Show lock overlay, logoff after `graceSec`; blocks new logons until `until` |
| `unlock {userSid}` | Clears a `lock_now` |
| `add_time {userSid, minutes, scope: today}` | Extends today's quota |
| `pause_limits {userSid, until}` | Suspends screen-time limits (filters stay on) |
| `screenshot {userSid?}` | Immediate sealed screenshot |
| `message {userSid, text}` | Shows a message to the child |
| `approve_exe {sha256, decision}` | Answer to a `new_executable` request |
| `kill_process {pid}` / `logoff {userSid}` | Direct actions |
| `refresh` | Re-sync policy, flush logs |

Device acknowledges every command with `{commandId, status, error?}`. Offline devices receive queued
commands on reconnect unless expired.

---

## 7. Events (device → cloud)

Common envelope: `{id (ULID), deviceId, userSid?, ts (UTC), monoMs, type, data}`. Batched (≤ 500 or 60 s).

| Type | Data |
|---|---|
| `session.logon/logoff/lock/unlock` | sessionId |
| `usage.tick` (aggregated per minute) | foreground exe, window title, group, active/idle |
| `process.start/stop/blocked` | exe, path, sha256, publisher, pid, parent |
| `web.visit` (extension) | url, title, tabId, durationSec, transition |
| `web.search` (extension) | engine, query |
| `web.blocked` | url/host, rule, source (proxy/extension) |
| `net.domain` (proxy) | host, exe, bytes, allowed |
| `install.detected` | product, version, scope (machine/user/appx) |
| `download.completed` | url, file name, size, sha256 |
| `usb.attached/detached` | vendor, product, volume label |
| `screenshot.taken` | blobKey (sealed), width, height |
| `quota.warning / quota.exhausted` | remaining |
| `request.exe_approval` | exe info |
| `tamper.*` | `agent_killed`, `service_stopped`, `wfp_filter_missing`, `proxy_bypass_attempt`, `timezone_changed`, `clock_jump`, `managed_user_is_admin`, `extension_missing`, `offline_gap` |

Alert-worthy events (`quota.exhausted`, `*.blocked` bursts, `request.*`, `tamper.*`) trigger an FCM push.

---

## 8. Windows agent design

### 8.1 Processes
- **MinControl.Service** — LocalSystem, auto-start, recovery = restart (0 s, 0 s, 0 s), registered for
  Safe Mode (`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\{Minimal,Network}\MinControl`).
- **MinControl.Session** — started by the Service in each managed user's session via
  `CreateProcessAsUser` with a **duplicated SYSTEM token whose SessionId is set** to that session, on
  `WinSta0\Default`. The child cannot kill it (access denied). Service restarts it within 2 s if it
  exits; absence > 30 s → `tamper.agent_killed` + logoff (I4).
- IPC Service ↔ Session/NativeHost: named pipes with explicit DACL (SYSTEM only for Session; NativeHost
  pipe allows the managed SID but only for the narrow `web.*` message set, authenticated by checking
  the client PID's token SID).

### 8.2 Sessions and screen time
- Subscribe to `SERVICE_CONTROL_SESSIONCHANGE` (logon, logoff, lock, unlock, console connect/disconnect).
- Usage counts only while the managed session is the **active console session, unlocked**, and (if
  `countIdle=false`) user input within `idleThresholdSec` (idle reported by Session via `GetLastInputInfo`).
- Accounting is a pure function in Core: `(policy, overrides, usageLedger, now) → state {allowed, remainingMin, reason, nextChange}`. Unit-test DST-less tz, midnight rollover, overlapping windows, overrides.
- Ledger persisted every 30 s to local SQLite; uses monotonic deltas, wall clock only to bucket by local day in the policy tz.
- On exhaustion: warn at configured minutes → full-screen overlay (topmost, covers all monitors) with
  countdown → `WTSLogoffSession`. Logon outside allowance → overlay "not allowed now" → logoff after 30 s.

### 8.3 App control
- Process start/stop via ETW `Microsoft-Windows-Kernel-Process` (real-time session in Service).
- For each start: resolve token SID; ignore unless managed (I1). Evaluate `appRules`/groups; block =
  `TerminateProcess` immediately + `process.blocked` event + toast via Session.
- **Kernel-enforced layer** for known installed apps: deny-Execute ACE for the managed SID on the exe
  (machine-wide install paths only; user-owned files could have their DACL changed by the user).
- `pathUnderUserWritable` = exe under the user's profile, `%TEMP%`, removable drives → policy `newExecutable`.
- Hash cache (path+size+mtime → sha256, Authenticode publisher).

### 8.4 Network guard (per-user, no driver)
- **WFP**, own provider + sublayer, **persistent** filters (survive service crash/reboot, I4):
  - `ALE_AUTH_CONNECT_V4/V6` + `ALE_AUTH_RECV_ACCEPT` scoped by `FWPM_CONDITION_ALE_USER_ID` = managed SID:
    - permit (high weight): remote = loopback (proxy) ; app-id ∈ `netExemptApps`
    - block (low weight): everything else, TCP and UDP (kills QUIC, DoT, direct DoH, VPN clients)
  - System-service traffic (DNS client, Windows Update, Defender) runs as other SIDs → untouched.
  - Watchdog re-checks filters every 60 s → `tamper.wfp_filter_missing` and re-adds.
- **Filtering proxy** inside Service on `127.0.0.1:<port>` (HTTP + CONNECT):
  - Identify caller: TCP table lookup (source port → PID → token SID).
  - Decide on host: allow/block lists, categories (offline category list, refreshed from cloud), schedule.
  - SafeSearch/YouTube: rewrite CONNECT target IP to `forcesafesearch.google.com`, `strict.bing.com`,
    `restrict.youtube.com` / `restrictmoderate.youtube.com` (no TLS interception).
  - Block → for HTTPS, refuse CONNECT (browser shows error; extension shows the friendly page).
  - Emit `net.domain` aggregated per (exe, host, 5 min).
- **Proxy settings for the managed user** written into `HKU\<SID>` (load `NTUSER.DAT` via `RegLoadKey`
  if not logged on): WinINET proxy + lock policy, and Chrome/Edge `ProxyMode=fixed_servers`. Apps that
  ignore the proxy simply have no network (by design).

### 8.5 Browsers
- Policies in `HKU\<SID>\Software\Policies\{Microsoft\Edge, Google\Chrome}` (not writable by the user):
  `ExtensionInstallForcelist`, `InPrivateModeAvailability=1` / `IncognitoModeAvailability=1`,
  `DeveloperToolsAvailability=2`, `BrowserGuestModeEnabled=0`, `BrowserAddPersonEnabled=0`,
  `DnsOverHttpsMode=off`, `ForceGoogleSafeSearch=1`, `ForceYouTubeRestrict=2`, `ProxyMode/ProxyServer`.
- **Gotcha:** on non-domain-joined Windows, Chrome/Edge only force-install extensions **from their
  stores**. ⇒ publish the extension **unlisted** on Chrome Web Store and Edge Add-ons.
- Extension (MV3): `tabs`, `webNavigation`, `history`, `downloads`, `nativeMessaging`, `storage`,
  `declarativeNetRequest` (blocking pages). Sends `web.visit/search/blocked/download` to NativeHost.
  Heartbeat every 60 s; missing heartbeat while browser runs → `tamper.extension_missing` + block that browser.
- All browsers other than `allowedBrowsers` are blocked by app rules.

### 8.6 Other monitors
- Installs: watch `Uninstall` keys (HKLM, HKLM\WOW6432Node, HKU\<SID>) + AppX package events.
- USB: device-arrival notifications in Service.
- Screenshots: Session captures (DXGI Desktop Duplication, fallback GDI), resize, JPEG, **seal with
  master X25519 public key** (libsodium sealed box) → upload to R2 via Worker.
- Foreground: Session uses `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` + title polling 5 s.

### 8.7 Local storage
`%ProgramData%\MinControl\` (ACL I7): `state.db` (SQLite: policy, overrides, ledger, outbox, hash
cache), `device.key` (DPAPI machine), logs. Outbox retries with exponential backoff; capped at 500 MB
(drop oldest `usage.tick` first, never `tamper.*`).

### 8.8 Tamper resistance checklist
Child is Standard user · BIOS/UEFI password + boot order locked · BitLocker on · Safe Mode registered ·
persistent WFP · Session runs as SYSTEM · service DACL denies stop for non-admins (default) · installer
refuses to manage admin SIDs · clock/timezone change detection · offline gap reported on reconnect.

---

## 9. Cloud (Cloudflare)

- **Worker** `api.<domain>` (initially `*.workers.dev`): routing, auth, validation.
- **Durable Object `DeviceHub`** (one per device, SQLite-backed): holds the device WebSocket
  (hibernation API), command queue, presence, last state snapshot (time left, current app).
- **D1** tables: `devices`, `managed_users`, `policies (device_id, version, signed_blob)`, `commands`,
  `events` (generic), `web_visits`, `usage_daily`, `domains_daily`, `screenshots`, `alerts`,
  `push_subscriptions`, `pairing_codes`. Indexes on `(device_id, user_sid, ts)`.
- **R2** bucket `mincontrol-blobs`: sealed screenshots, daily backups.
- **Cron** (hourly/daily): retention purge, daily summary push, offline-device alert.
- **FCM** (HTTP v1, Firebase project used only for messaging) from the Worker to the master app.
- Verify current free-tier limits (Workers requests, DO, D1 rows written/day, R2) before M1 and size
  batching accordingly; budget fallback = Workers Paid plan.

### API sketch
```
POST /v1/enroll                     (pairing code)
GET  /v1/device/ws                  (device, WebSocket → DeviceHub)
POST /v1/device/events              (device token, batch)
PUT  /v1/device/blobs/:key          (device token, sealed screenshot)
GET  /v1/master/devices             (master signature)
GET  /v1/master/devices/:id/state
GET  /v1/master/devices/:id/events?type=&user=&from=&to=&q=
GET  /v1/master/devices/:id/web?user=&from=&to=&q=
PUT  /v1/master/devices/:id/policy  (signed)
POST /v1/master/devices/:id/commands (signed)
POST /v1/master/pairing-codes
POST /v1/master/push/subscribe
```

---

## 10. Master app (Android, Kotlin + Compose, portrait only)

Design mock-ups: `docs/design/master-app/project/*.dc.html` (9 screens, Vietnamese UI).
Biometric confirmation for every signed action (lock, policy apply, approvals). Extras: home-screen
widget (time left), Quick Settings tile ("lock all").

Screens: **Overview** (each child: online, current app, time left, quick buttons lock / +15 / +30 /
+60) · **Timeline** (today: sessions, apps, web) · **Web history** (search, filter by domain/date,
blocked attempts) · **Apps** (usage per app/group, new-exe approvals) · **Screenshots** (decrypted on
phone) · **Policy editor** (forms, diff before signing) · **Alerts** · **Devices** (enrol, revoke).
FCM push, Room cache for offline views.

---

## 11. Milestones

| M | Deliverable | Done when |
|---|---|---|
| M0 | Repo skeleton, `protocol/` schemas, CI (build + tests) | schemas validated by contract tests |
| M1 | Cloud: enrol, DeviceHub WS, commands, events → D1; master app: Keystore key + biometric, devices, quick commands, FCM | fake device script can enrol, receive `add_time`, upload events |
| M2 | Windows Service core: enrol CLI, policy store + signature check, sessions, quota/schedule, overlay, logoff, commands | in a Hyper-V VM the managed user is logged off on time; admin unaffected |
| M3 | App control + monitors (ETW, foreground, installs, USB, downloads) | blocked app dies < 1 s; timeline visible in master app |
| M4 | NetGuard: persistent WFP + proxy + SafeSearch + domain log | managed user: VPN/DoH/QUIC/portable browser all fail; admin browses normally |
| M5 | Extension (unlisted in both stores) + browser policies + full history | URLs + searches visible in master app; InPrivate disabled |
| M6 | Sealed screenshots, alerts + FCM push, retention cron | screenshot round-trip decrypts only on phone |
| M7 | MSI installer (WiX), hardening, tamper test pass, real-PC rollout | tamper checklist §8.8 passes in VM, then on the kids' PCs |

**Test environment:** Hyper-V VM (Windows 11 Pro) with one admin + one standard user. Never test
enforcement on the kids' real PCs before M7.

---

## 12. Open questions
1. Kids' Windows accounts: Microsoft account or local? How many PCs / managed users?
2. ~~Domain~~ — decided: no custom domain; use `*.workers.dev` / `*.pages.dev`. All URLs are config, so a
   domain can be added later (only if workers.dev gets blocked). Cloudflare account: created.
3. Category list source for web filtering (open lists, e.g. UT1 blacklists / OISD) — licence check.
4. Child-facing features: "request more time" button? Visible tray icon showing time left?
5. ~~Repo visibility~~ — decided: **public**. Consequence: security must never rely on obscurity;
   no secrets, URLs of a real deployment, account IDs or SIDs in the repo (use `.dev.vars` / local config).
