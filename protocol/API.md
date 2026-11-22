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
| D→S | `{"t":"auth","deviceId","ts","sig"}` | `sig` = b64url Ed25519(deviceKey, UTF-8 `nonce + "\|" + deviceId + "\|" + ts`) |
| S→D | `{"t":"ready","serverTime","uploadToken","uploadTokenExpiresAt"}` | or close code `4401` on bad auth |
| S→D | `{"t":"envelope","envelope":SignedEnvelope}` | pending policy first, then queued commands in seq order |
| D→S | `{"t":"ack","ack":CommandAck}` | for every command envelope |
| D→S | `{"t":"policy_applied","version":7,"seq":12}` or `{"t":"policy_rejected","seq":12,"error":"<code>"}` | |
| D→S | `{"t":"state","state":DeviceState}` | every 60 s and on change |
| S→D | `{"t":"token","uploadToken","uploadTokenExpiresAt"}` | refresh before expiry (token TTL 1 h) |
| both | `{"t":"ping"}` / `{"t":"pong"}` | device pings every 30 s |

`DeviceState`:
```json
{ "ts": "…Z", "agentVersion": "0.1.0", "policyVersion": 7,
  "users": [ { "sid": "S-1-5-21-…-1001", "loggedOn": true, "active": true, "locked": false,
               "lockedUntil": null, "remainingMin": 72, "usedMin": 48,
               "groups": { "games": { "usedMin": 23, "remainingMin": 37 } },
               "foregroundExe": "Minecraft.exe", "foregroundTitle": "Minecraft 1.21" } ] }
```

## 3. Device uploads (HTTP, `Authorization: Bearer <uploadToken>`)
- `POST /v1/device/events` body = `EventBatch` → `200 {"accepted": n}` (idempotent on event `id`).
- `PUT /v1/device/blobs/<key>` body = raw sealed bytes (`application/octet-stream`, ≤ 2 MB) → `201`.
  `<key>` = `screens/<deviceId>/<yyyy-mm-dd>/<eventId>.bin`; must start with the caller's device prefix.

## 4. Master authentication
- Two master keys in the Android Keystore: role `sign` (biometric-gated; signs policy/command envelopes)
  and role `read` (no biometric; signs API requests).
- Every `/v1/master/*` request carries
  `X-MC-Auth: v1;<keyId>;<ts>;<sig>` where `sig` = b64url signature by a registered master key over UTF-8
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
| `GET /v1/master/devices/:id/events` | `type,user,from,to,cursor,limit≤200` | `{"items":[Event],"next":cursor\|null}` newest first |
| `GET /v1/master/devices/:id/web` | `user,from,to,q,kind(visit\|search\|blocked),cursor,limit` | `{"items":[{"ts","kind","url","host","title","durationSec","category"}],"next"}` |
| `GET /v1/master/devices/:id/usage` | `user,day=YYYY-MM-DD` | `{"totalSec","apps":[{"exe","group","activeSec"}]}` |
| `GET /v1/master/devices/:id/screenshots` | `user,from,to,cursor` | `{"items":[{"eventId","ts","blobKey","width","height","foregroundExe"}],"next"}` |
| `GET /v1/master/blobs/<key>` | – | sealed bytes |
| `GET /v1/master/alerts` | `cursor,limit` | `{"items":[{"id","deviceId","userSid","ts","type","severity":"info\|warn\|critical","data"}],"next"}` |
| `POST /v1/master/alerts/:id/ack` | – | `204` |
| `POST /v1/master/push/subscribe` | `{"fcmToken"}` | `204` |

## 6. Push (FCM HTTP v1, data-only message)
`{"type":"alert","alertId","deviceId","userSid","severity","title","body"}` — title/body in Vietnamese,
rendered by the app. Alert-worthy events: `quota.exhausted`, `request.exe_approval`, `tamper.*`,
≥3 `web.blocked` or `process.blocked` for one user within 10 min (one alert), device offline > 2 h.

## 7. Screenshot sealing
libsodium `crypto_box_seal` (X25519 + XSalsa20-Poly1305) with `masterSealPubKey`; plaintext = JPEG bytes.
Only the phone holds the private key.
