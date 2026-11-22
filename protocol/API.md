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
  (lock_now: until + 1 h). Expired queued envelopes are never delivered.
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
