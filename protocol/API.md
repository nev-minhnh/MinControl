# MinControl wire API (v1) — contract between cloud, device agents and master app

Bodies are JSON (UTF-8) unless noted. All payload types named here are defined in the
`*.schema.json` files of this folder. Errors: HTTP 4xx/5xx with `{"error":"<code>","message":"..."}`.
Base64url = RFC 4648 §5, no padding. Times = RFC 3339 UTC with `Z`.

## 1. Device enrolment (HTTP, unauthenticated, pairing code is the secret)

`POST /v1/enroll`
```json
{ "code": "K7Q29XMB", "devicePubKey": "<b64url raw Ed25519 32 B>", "hostname": "PC-BIN",
  "osVersion": "10.0.26100", "agentVersion": "0.1.0",
  "localUsers": [ { "sid": "S-1-5-21-…-1001", "name": "Bin", "isAdmin": false } ] }
```
→ `201`
```json
{ "deviceId": "<ULID>", "serverTime": "…Z",
  "masterKeys": [ { "keyId": "3f9a…", "alg": "ed25519|es256", "publicKey": "<b64url>" } ],
  "masterSealPubKey": "<b64url X25519 32 B>" }
```
Pairing code: 8 chars Crockford base32 (display as `XXXX-XXXX`, dash ignored), single use, TTL 15 min,
max 5 failed attempts per code. `masterKeys` = keys with role `sign` only. Device pins them.

## 2. Device WebSocket `GET /v1/device/ws?deviceId=<ULID>` (routed to Durable Object `DeviceHub`)

Messages are JSON objects with a `t` field.

| Dir | Message | Notes |
|---|---|---|
| S→D | `{"t":"challenge","nonce":"<b64url 32 B>"}` | first frame |
| D→S | `{"t":"auth","deviceId","ts","sig"}` | `ts` = unix seconds as a JSON **integer**; `sig` = b64url Ed25519(deviceKey, UTF-8 `nonce + "\|" + deviceId + "\|" + ts`) with `ts` as its decimal string |
| S→D | `{"t":"ready","serverTime","uploadToken","uploadTokenExpiresAt"}` | or close code `4401` on bad auth |
| S→D | `{"t":"envelope","envelope":SignedEnvelope}` | pending policy first, then queued commands in seq order |
| D→S | `{"t":"ack","ack":CommandAck}` | for every command envelope |
| D→S | `{"t":"policy_applied","version":7,"seq":12}` or `{"t":"policy_rejected","seq":12,"error":"<code>"}` | `error` ∈ the `command-ack.schema.json` `error` enum |
| D→S | `{"t":"state","state":DeviceState}` | every 60 s and on change |
| S→D | `{"t":"token","uploadToken","uploadTokenExpiresAt"}` | refresh before expiry (token TTL 1 h) |
| both | `{"t":"ping"}` / `{"t":"pong"}` | device pings every 30 s |

`DeviceState` (schema: `device-state.schema.json`):
```json
{ "ts": "…Z", "agentVersion": "0.1.0", "policyVersion": 7,
  "users": [ { "sid": "S-1-5-21-…-1001", "loggedOn": true, "active": true, "locked": false,
               "lockedUntil": null, "remainingMin": 72, "usedMin": 48,
               "groups": { "games": { "usedMin": 23, "remainingMin": 37 } },
               "foregroundExe": "Minecraft.exe", "foregroundTitle": "Minecraft 1.21",
               "foregroundStartedAt": "…Z" } ] }
```
Required: `ts`, `agentVersion`, `users[].sid`; `lockedUntil`, `remainingMin`, `usedMin`, `foreground*` may be
`null`. `foregroundStartedAt` (optional) = when the current foreground app got focus (RFC 3339 UTC).

## 3. Device uploads (HTTP, `Authorization: Bearer <uploadToken>`)
- `POST /v1/device/events` body = `EventBatch` → `200 {"accepted": n}` (idempotent on event `id`).
- `PUT /v1/device/blobs/<key>` body = raw sealed bytes (`application/octet-stream`, ≤ 2 MB) → `201`.
  `<key>` = `screens/<deviceId>/<yyyy-mm-dd>/<eventId>.bin`; must start with the caller's device prefix.

## 4. Master authentication
- Two master keys in the Android Keystore: role `sign` (biometric-gated; signs policy/command envelopes)
  and role `read` (no biometric; signs API requests).
- Every `/v1/master/*` request carries
  `X-MC-Auth: v1;<keyId>;<ts>;<sig>` where `<ts>` = unix seconds as a decimal string (the same string is
  used in the signed text) and `sig` = b64url signature by a registered master key over UTF-8
  `METHOD + "\n" + pathWithQuery + "\n" + ts + "\n" + hex(sha256(body))` (empty body → sha256 of empty).
  Reject if `|now - ts| > 300 s` or key unknown/revoked.
- `POST /v1/master/register` (no X-MC-Auth) body
  `{"bootstrapSecret","keys":[{"keyId","alg","publicKey","role":"sign|read"}],"sealPubKey"}`.
  Allowed only when the secret equals Worker secret `ADMIN_BOOTSTRAP_SECRET`. Re-registering replaces keys
  (used when the phone is replaced) and pushes nothing to devices — devices keep their pinned sign keys until
  re-enrolled.
- ES256 signatures are IEEE P1363 (r‖s, 64 B). `keyId` per protocol/README.md.

## 5. Master endpoints (all require X-MC-Auth)
| Method & path | Body / query | Response |
|---|---|---|
| `POST /v1/master/pairing-codes` | – | `{"code","expiresAt"}` |
| `GET /v1/master/devices` | – | `{"items":[{"deviceId","hostname","online","lastSeen","state":DeviceState\|null,"users":[{"sid","name","isAdmin","managed","label"}],"policyVersion"}]}` |
| `DELETE /v1/master/devices/:id` | – | `204` (revoke; closes WS, rejects future auth) |
| `GET /v1/master/devices/:id/seq` | – | `{"policy":<last seq>,"command":<last seq>}` |
| `GET /v1/master/devices/:id/policy` | – | `{"version","seq","envelope":SignedEnvelope}` or `404` |
| `PUT /v1/master/devices/:id/policy` | SignedEnvelope (kind policy) | `202 {"version","seq"}`; server checks signature with a registered sign key, seq > last |
| `POST /v1/master/devices/:id/commands` | SignedEnvelope (kind command) | `202 {"commandId","delivered":bool}` |
| `GET /v1/master/devices/:id/commands/:commandId` | – | `{"status":"queued\|delivered\|applied\|rejected\|failed\|expired","error"?}` |
| `GET /v1/master/devices/:id/events` | `type,exclude,user,from,to,cursor,limit≤200` | `{"items":[Event],"next":cursor\|null}` newest first. `type` = comma list of event types and/or `prefix.*` (`type=web.*,process.blocked`); `exclude` = same syntax, removes matches (default none) |
| `GET /v1/master/devices/:id/web` | `user,from,to,q,kind(visit\|search\|blocked),cursor,limit` | `{"items":[{"ts","kind","url","host","title","durationSec","category","query","engine"}],"next"}`; `query`/`engine` set for `kind=search` (null otherwise) |
| `GET /v1/master/devices/:id/usage` | `user,day=YYYY-MM-DD` | `{"totalSec","apps":[{"exe","group","activeSec"}]}` |
| `GET /v1/master/devices/:id/screenshots` | `user,from,to,cursor` | `{"items":[{"eventId","ts","blobKey","width","height","foregroundExe"}],"next"}` |
| `GET /v1/master/blobs/<key>` | – | sealed bytes |
| `GET /v1/master/alerts` | `unacked=1,deviceId,cursor,limit` | `{"items":[{"id","deviceId","userSid","ts","type","severity":"info\|warn\|critical","ackedAt":ts\|null,"data"}],"next"}` (see §8 Alerts for `data`) |
| `POST /v1/master/alerts/:id/ack` | – | `204` |
| `POST /v1/master/push/subscribe` | `{"fcmToken"}` | `204` |

## 6. Push (FCM HTTP v1, data-only message)
`{"type":"alert","alertId","deviceId","userSid","severity","title","body"}` — title/body in Vietnamese,
rendered by the app. Alert-worthy events: `quota.exhausted`, `request.exe_approval`, `tamper.*`,
≥3 `web.blocked` or `process.blocked` for one user within 10 min (one alert), device offline > 2 h.

## 7. Screenshot sealing
libsodium `crypto_box_seal` (X25519 + XSalsa20-Poly1305) with `masterSealPubKey`; plaintext = JPEG bytes.
Only the phone holds the private key.

## 8. Clarifications decided at integration (binding)
- **`ts`** in `X-MC-Auth` and in the WS `auth` frame = unix **seconds**, decimal integer; the signed text uses
  that decimal string. WS frame: `"ts": <integer>`.
- **Event batch response**: `200 {"accepted":n,"rejected":[{"id","error"}]}` (`rejected` only when non-empty).
  Devices drop rejected events from the outbox (log locally) and never retry them.
- **Register response**: `201 {"keys":[{"keyId","role"}]}`; wrong secret → `403 forbidden`.
- **Error codes** for `PUT policy` / `POST commands`: 400 `invalid_body|wrong_device|expired`,
  403 `unknown_key|bad_signature`, 409 `replayed` (with `details.lastSeq`) | `duplicate`, 404 unknown/revoked device.
- **Expiry**: policy envelopes `expiresAt` = issuedAt + 365 days; command envelopes ≤ 24 h
  (lock_now: max(issuedAt + 24 h, until + 1 h)). Expired queued envelopes are never delivered.
- **WS**: auth timeout 30 s; close codes 4401 auth failed, 4403 revoked, 4000 replaced by a newer connection,
  4400 bad frame. Unacked commands are re-sent on reconnect (devices must treat a replay of an already
  applied commandId as `applied`, idempotently).
- **Alerts** `type` = the event type or `blocked.burst` / `device.offline`; severity quota → info,
  exe approval / burst / offline → warn, tamper → critical. `data` = the triggering event's `data` **plus**
  `{title, body, eventId}` (so `request.exe_approval` carries `exe`, `path`, `sha256`, `publisher`, `signed`,
  `sizeBytes`; the user is the item's `userSid`). `blocked.burst` data = `{title, body, eventId, count,
  hosts?:[..], exes?:[..], category?}` (`eventId` = the event completing the burst; `hosts` from `web.blocked`,
  `exes` from `process.blocked`, `category` when all web blocks share one). `device.offline` data =
  `{title, body, eventId:null, lastSeen}`. `ackedAt` is a top-level item field (not inside `data`).
- **Event ownership on Windows**: `usage.tick`, `quota.*` and interval screenshots are emitted by the
  Service enforcer (win-session); on-demand screenshots by the command dispatcher (win-core).

## 9. Screenshot storage on the device (decided by Minh 2026-11-22 — replaces R2 storage)
Screenshots are **not stored in the cloud**. R2 is optional and unused by default.
- **Device**: every capture (interval or command) is sealed (§7) and written to
  `%ProgramData%\MinControl\screens\<yyyy-mm-dd>\<eventId>.bin` (ACL I7), then `screenshot.taken` is emitted with
  `blobKey = screens/<deviceId>/<yyyy-mm-dd>/<eventId>.bin` (unchanged format). The device deletes files older than
  `retentionDays.screenshots` (daily) and caps the folder at 2 GB (oldest first).
- **On-demand relay**: `GET /v1/master/blobs/<key>` → Worker → the device's `DeviceHub`.
  - Device offline → `409 {"error":"device_offline"}`.
  - Online → DO sends WS `{"t":"blob_request","reqId":"<ULID>","key":"<blobKey>"}` and holds the master request
    (timeout 25 s → `504 {"error":"device_timeout"}`).
  - Device answers by `PUT /v1/device/blobs/<key>?reqId=<reqId>` (Bearer upload token, ≤ 2 MB, prefix check as §3);
    the Worker forwards the bytes to the DO, which completes the waiting master request with
    `200 application/octet-stream` and **does not persist** them. Unknown/expired reqId → `410`.
  - File missing on device → device sends WS `{"t":"blob_missing","reqId"}` → master gets `404 {"error":"not_found"}`.
- `PUT /v1/device/blobs/<key>` **without** `reqId` is no longer used (→ `400`).
- Cloud retention cron no longer touches R2; screenshot metadata rows in D1 follow `retentionDays.screenshots`.
- Master app: `409 device_offline` → "Máy đang tắt — mở lại khi máy online"; `504` → "Máy không phản hồi, thử lại".

## 10. QR pairing initiated by the device (decided by Minh 2026-11-22; preferred over typed codes)
The child's PC shows a QR; the parent scans and approves on the phone; nothing is typed and no secret is
embedded in the installer. `/v1/enroll` with a pairing code (§1) stays for CLI/silent installs.
1. Device `POST /v1/enroll/start` (unauthenticated) body
   `{devicePubKey, hostname, osVersion, agentVersion, localUsers:[{sid,name,isAdmin}]}` →
   `201 {"claimId":"<b64url 16 B>","code":"<8 Crockford>","expiresAt"}` (TTL 15 min; rate-limit 10/h per IP).
2. QR payload: `mincontrol://pair?v=1&c=<claimId>&f=<fp>` where `fp` = first 12 hex chars of sha256(raw devicePubKey).
   Both screens show `fp` as `XXXX-XXXX-XXXX` so the parent can compare; the fallback `code` is shown small.
3. Device polls `GET /v1/enroll/claim/<claimId>?ts=<unix s>&sig=<b64url Ed25519(deviceKey, "poll|"+claimId+"|"+ts)>`
   every 2 s (±300 s) → `202 {"status":"pending"}` | `200 {"status":"approved", deviceId, serverTime, masterKeys,
   masterSealPubKey}` (same shape as §1 response) | `410 {"error":"expired"|"rejected"}`.
4. Master (X-MC-Auth): `GET /v1/master/claims/<claimId>` → `{hostname, osVersion, localUsers, fp, expiresAt}`;
   `GET /v1/master/claims/by-code/<code>` → same + `claimId` (manual fallback);
   `POST /v1/master/claims/<claimId>/approve` → `201 {"deviceId"}` — **must be authenticated with a `sign`-role key**
   (biometric on the phone); `POST /v1/master/claims/<claimId>/reject` → `204`. A claim is single use.
5. After approval the app continues with the existing "choose managed users → policy v1" flow.

## 11. App inventory from the PC (decided by Minh 2026-11-22)
The master app builds app groups / app rules by picking from the apps that really exist on the child's PC.
- **Device → cloud** `PUT /v1/device/inventory` (Bearer upload token, JSON ≤ 512 KB, schema
  `protocol/inventory.schema.json`): `{ "deviceId", "generatedAt", "users": { "<sid>": { "apps": [App] } } }` for every
  managed SID. `App` = `{ "id": "<stable sha256 hex of kind|key>", "name", "kind": "win32"|"appx"|"seen",
  "publisher"?, "version"?, "installDir"?, "exe"?, "exePath"?, "lastUsed"? (RFC3339 Z), "minutes7d"? (int),
  "category"? ("game"|"browser"|"social"|"video"|"study"|"system"|"other") }`.
  Sources: Uninstall keys (HKLM, WOW6432Node, HKU\<sid>) — skip SystemComponent/updates; the user's Start-menu
  shortcuts (resolve .lnk → exe); AppX packages of the user; plus every exe the user actually ran in the last 7 days
  (`kind:"seen"`, from the process/usage data) with `minutes7d`. Merge by exe path; publisher from Authenticode when
  known. `category` = best-effort hint from a built-in publisher/name list (Valve, Riot, Epic, Mojang, Roblox,
  miHoYo/HoYoverse, Garena, VNG… → game; Zalo, Discord, Messenger, Telegram → social; …).
  Sent at service start, every 6 h, after `install.detected`, and when a `refresh` command is applied.
- **Cloud** stores the latest inventory per (device, sid) (replace, not append).
- **Master** `GET /v1/master/devices/:id/apps?user=<sid>` → `{ "generatedAt", "apps": [App] }` (404 if none yet).
- **Mapping to policy** (app side): win32 with `installDir` → `AppMatch {"path": "<installDir>\*"}` (covers launcher +
  game exes and survives updates); otherwise `{"exe": "<exe>"}` plus `"publisher"` when known; appx →
  `{"path": "<installDir>\*"}`. The picker shows name, publisher, "đã dùng N phút/7 ngày", category chip, search,
  sorted by minutes7d then name; "Gợi ý: nhóm Game" pre-selects category=game.

## 12. One QR for everything (decided by Minh 2026-11-23; supersedes the separate setup QR for normal use)
The parent only ever scans the QR shown by `MinControl-Setup.exe` / `MinControl.Connect` on the child's PC.
- **QR v2**: `mincontrol://pair?v=2&u=<urlencoded server URL>&c=<claimId>&f=<fp>`. Phones accept v1 (no `u`) too.
- **Phone not set up yet** (no master keys on the phone): it creates its keys (sign + read, seal key) as in §4, then
  `POST /v1/master/register-with-claim` (no X-MC-Auth) body
  `{"claimId","keys":[{keyId,alg,publicKey,role}],"sealPubKey","sig":"<b64url signature by the new sign key over UTF-8 \"register|\"+claimId>"}`.
  Allowed **only when no master is registered yet on this server** (trust on first use) and the claim is pending and not
  expired; otherwise `409 {"error":"master_exists"}` / `410 expired`. On success it atomically registers the master
  and approves the claim exactly like §10 approve → `201 {"deviceId","keys":[{keyId,role}]}`. The phone then continues
  with the normal "choose managed users → sign policy v1" step.
- **Phone already set up**: unchanged §10 flow (approve with the sign key).
- **`master_exists` on a new phone** → the app explains "Máy chủ đã có điện thoại quản lý. Dùng điện thoại cũ để
  quét, hoặc chọn Đổi điện thoại." The "Đổi điện thoại" path is the existing `/v1/master/register` with the bootstrap
  secret (setup-qr / manual), now hidden under "Đổi điện thoại / khôi phục".
- Re-pairing a PC whose pinned master keys are stale: Setup/Connect "Ghép nối lại" creates a new claim; the approval
  response (§10) carries the current master keys and the device re-pins them.

## 13. Changing the parent's phone (decided by Minh 2026-11-23)
**A. Transfer (old phone available) — QR generated on the current phone, nothing pre-made.**
1. Old phone: Cài đặt → "Chuyển sang điện thoại mới" → biometric → `POST /v1/master/transfers` (X-MC-Auth with the
   **sign** key) → `201 {"transferId","token","expiresAt"}` (token = b64url 32 B, single use, 10 min). Old phone shows
   QR `mincontrol://transfer?v=1&u=<urlencoded server URL>&t=<token>` and polls `GET /v1/master/transfers/<id>`.
2. New phone (first-run "Quét mã" accepts this QR): creates keys (sign, read, seal) plus an ephemeral X25519 *transport*
   key → `POST /v1/master/transfers/claim` (no auth) `{token, keys:[…], sealPubKey, transportPubKey, sig}` where `sig` =
   new sign key over `"transfer|"+token` → `202 {"transferId","status":"pending"}`; keys stored as **pending**.
3. Old phone's poll returns `{"status":"claimed", newKeys, transportPubKey, fp}`; it shows the new phone's fingerprint
   (first 12 hex of sha256(new sign public key)) which the new phone also shows → parent confirms → biometric → old phone:
   a. signs one envelope per device (§4 SignedBody, new `kind: "master_keys"`, body
      `{"keys":[{keyId,alg,publicKey,role:"sign"}],"sealPubKey"}`, normal seq per kind, expiresAt +30 days) and
   b. seals the **old seal private key** to `transportPubKey` (crypto_box_seal) so old screenshots stay readable;
   `POST /v1/master/transfers/<id>/complete` (sign key) `{envelopes:{<deviceId>: SignedEnvelope}, sealedSealKey}`.
4. Server atomically: activates the new keys, revokes the old ones, queues each device's `master_keys` envelope
   (delivered like a policy, before queued commands), stores `sealedSealKey` for the new phone →
   new phone's `GET /v1/master/transfers/<id>` (now authorised with its own keys) returns `{status:"done", sealedSealKey}`;
   it imports the old seal private key (keeps it as an additional decryption key) — `sealPubKey` for NEW screenshots
   becomes the new phone's.
5. **Device**: a `master_keys` envelope verified with a currently pinned key **replaces** the pinned key set (and
   the seal public key) atomically; ack like a command (`applied`). An envelope signed by an unknown key → rejected.
**B. Lost phone — recovery code.** The pre-generated QR (`mincontrol://setup…`, bootstrap secret) is renamed
"Mã khôi phục": created once when the server is deployed, meant to be printed and kept. Using it (`/v1/master/register`) revokes old keys and marks that secret as used (the Worker stores a hash and refuses
the same secret again), so the parent needs a new recovery code afterwards (`scripts/deploy-cloud.ps1 -RotateBootstrap`
regenerates it and the QR). Every PC must then be re-paired ("Kết nối MinControl với điện thoại" → "Ghép nối lại"),
because devices cannot verify keys no old phone vouched for.

## 14. Remote diagnostics (decided 2026-11-23)
Command `diagnose` (signed like every command) → the device answers with ONE event `diag.report`
`{commandId, sections:{<name>:{...}}}` (≤ 256 KB) and acks `applied`. Sections (Windows): `service` (version, uptime,
hosted services state), `users` (managed SIDs, admin flags, sessions), `policy` (version, seq, stored ok),
`wfp` (provider/sublayer present, per-SID filter list with layer/action/weight/conditions, last apply result/error),
`proxy` (listening, port, active tunnels per sid/host, last decisions sample), `browser` (per SID: values of the
policies MinControl wrote: ProxyMode/ProxyServer, InPrivate, DoH, AllowDeletingBrowserHistory; history reader cursors),
`categories` (per list: file, bytes, entries, lastModified, lastError), `monitor` (ETW running or polling fallback,
rules count, last blocks), `logs` (last 200 warning/error lines). The master app shows it in "Chẩn đoán máy" and the
lead reads it from D1 (`events` type `diag.report`). No secrets (no keys, no tokens) may appear in a report.

## 15. Realtime (decided by Minh 2026-11-23)
Goal: while the parent has the app open and the PC is online, what the child does appears within ~1–3 s.
- **Device → cloud, live**: every event is ALSO sent immediately over the existing device WebSocket as
  `{"t":"events","events":[Event…]}` (≤ 50 per frame, ≤ 64 KB), right after it is written to the outbox. DeviceHub
  writes them to D1 exactly like `POST /v1/device/events` (same ingest code, idempotent on id), then answers
  `{"t":"events_ack","ids":[…]}`; the device deletes acked events from the outbox. The HTTP batch upload stays as the
  fallback (WS down, backlog after reconnect). Alert evaluation + FCM run on this path too (so pushes arrive in seconds).
- **State**: the device sends `state` immediately on foreground app change, lock/unlock, logon/logoff, quota threshold
  crossings (and still every 60 s). `net.domain` is aggregated per **1 minute** instead of 5, and the first connection to a
  new host in the current window is emitted at once.
- **Cloud → master, live**: `GET /v1/master/live?deviceId=<id>` upgrades to a WebSocket (auth: `X-MC-Auth` on the upgrade
  request, or `?auth=` with the same header value since browsers/OkHttp can set headers — use the header). DeviceHub
  keeps master sockets (hibernation API) and pushes `{"t":"state","deviceId","state"}`, `{"t":"events","deviceId",
  "events":[…]}` (already ingested ones) and `{"t":"online","deviceId","online":bool}`. Master sockets are read-only;
  ping/pong every 30 s; server closes idle master sockets after 10 min without pong.
- **App**: holds one live socket per device only while in the foreground (lifecycle-aware), merges pushed events into the
  visible lists and state instantly; polling (§ auto-refresh) stays as fallback with a slower interval (60 s) while the
  socket is healthy. In the background only FCM is used.

## 16. Lean storage + logon notifications + free-tier meter (decided by Minh 2026-11-23)
- **Ingest**: `net.domain` and `usage.tick` events are **not** inserted into `events` any more; they only update the
  aggregates `domains_daily` (new columns `first_seen`, `last_seen` RFC3339 Z; migration 0005) and `usage_daily`.
  They are still fanned out live to master sockets (§15) and still acked to the device. Existing rows of these two
  types in `events` are purged by the migration. `GET …/events?type=net.domain|usage.tick` returns an empty list.
- **New** `GET /v1/master/devices/:id/domains?user=<sid>&day=YYYY-MM-DD` (day in policy timezone, default today) →
  `{"items":[{"host","apps":[exe…],"connections","bytesOut","bytesIn","blocked":bool,"firstSeen","lastSeen"}]}`
  grouped by host (blocked = any blocked row for that host), sorted by connections desc, ≤ 2000 items.
- **Indexes**: keep only indexes used by real queries; every index costs one extra written row per insert.
- **Logon notifications**: `GET/PUT /v1/master/settings` → `{"notifyLogon":bool,"notifyLogoff":bool}` (account-wide,
  default false). When on, a `session.logon` / `session.logoff` event of a managed user produces an FCM push
  (severity info, title "CK vừa đăng nhập PC-NAME" / "… đã đăng xuất", body with local time) — no alert row.
- **Free-tier meter**: the Worker sums D1 `meta.rows_written` of its own statements per UTC day in `config`
  (`usage:<yyyy-mm-dd>` → rows; one extra row write per batch). `GET /v1/master/usage` →
  `{"day","rowsWritten","limit":100000,"percent"}`. Crossing 70 % and 90 % sends one FCM push each per day
  ("Sắp chạm hạn mức miễn phí của Cloudflare hôm nay (70 %)…").

## 17. Blocking model v2 (decided by Minh 2026-11-23)
Every kind of blocking supports two modes: **blocklist** (default allow, block what is listed) and **allowlist**
(default block, allow only what is listed).
- **Apps**: new `userPolicy.appMode: "blocklist"|"allowlist"` (default blocklist). In allowlist mode an exe runs only
  if an `allow` appRule (or an allowed service, below) matches — EXCEPT the always-allowed set: anything under
  %windir% (System32, SysWOW64, WinSxS, SystemApps, ImmersiveControlPanel…), MinControl's own folder, and
  Microsoft-signed exes under %ProgramFiles%\WindowsApps that are shell/system packages (Start, Search, Settings,
  ShellExperienceHost, TextInputHost, LockApp). `newExecutable` only applies in blocklist mode.
- **Web**: existing `web.mode` (blocklist|allowlist) unchanged.
- **Services** (one switch = app + domains): `web.blockedServices[]` / `web.allowedServices[]` with ids from the
  catalog `protocol/services.json` (`{"id","name","category","domains":[patterns],"apps":[AppMatch]}`; e.g. youtube,
  tiktok, facebook, instagram, messenger, zalo, discord, telegram, roblox, minecraft, steam, epicgames, netflix,
  spotify, twitch, garena, …). A blocked service blocks its apps AND domains; in allowlist mode an allowed service
  allows both. The catalog is versioned and shipped with the agent and the app (same file).
- **Keywords**: new `userPolicy.keywords: {"words":[string], "matchSearches":bool, "matchTitles":bool}`. Matching is
  case- and diacritics-insensitive on word boundaries (Vietnamese folded to ASCII). `matchSearches`: query of any
  search engine (Google, Bing, DuckDuckGo, Yandex, Yahoo, Cốc Cốc, YouTube search, Brave). `matchTitles`: browser tab
  titles (incl. YouTube video titles) and window titles of other apps. On a hit the agent closes the offending tab
  (browser) or window (other app) within ~1–2 s and emits `web.blocked` with `reason:"keyword"` and `keyword`.
- **Category data shipped**: the installer embeds a snapshot of all category lists (UT1 + MinControl's curated
  service domains) so categories work immediately; daily updates continue.
- **Events**: `web.blocked.reason` adds `"keyword"`, `"service"`; `web.blocked` data adds optional `keyword`,
  `service`; `process.blocked` data adds optional `service`. A `web.blocked` / `process.blocked` is emitted for
  EVERY attempt (rate limit: same host/exe at most once per 10 s), so the timeline always shows "Đã chặn".
