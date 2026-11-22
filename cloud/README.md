# MinControl cloud (Cloudflare Worker + Durable Object + D1)

Implements `protocol/API.md` v1. Nothing in this folder contains real ids, URLs or secrets.

## Layout
| Path | What |
|---|---|
| `src/index.ts` | Worker entry: route table + hourly cron |
| `src/router.ts` | method/regex router, `X-MC-Auth` enforcement, JSON error shape `{"error","message"}` |
| `src/device-hub.ts` | `DeviceHub` DO (SQLite, WebSocket hibernation): challenge/auth, policy/command queue with per-kind `seq`, acks, presence, upload-token refresh, revoke |
| `src/routes/enroll.ts` | pairing codes + `POST /v1/enroll` |
| `src/routes/master.ts` | `/v1/master/*` (register, devices, policy, commands, history, blobs, alerts, push) |
| `src/routes/device.ts` | `/v1/device/ws`, `/v1/device/events`, `/v1/device/blobs/<key>?reqId=` (answers a relay request) |
| `src/envelope.ts` | server-side verification of master-signed envelopes |
| `src/ingest.ts` | event batch → `events` + `web_visits`/`usage_daily`/`domains_daily`/`screenshots` |
| `src/alerts.ts`, `src/fcm.ts` | alert rules (API.md §6, Vietnamese texts) and FCM HTTP v1 push |
| `src/cron.ts` | retention purge (D1), command expiry, offline (> 2 h) alerts |
| `src/generated/validators.js` | **generated** ajv standalone validators (see below) |
| `schemas/` | cloud-local JSON schemas (enroll/register/push bodies, DeviceState, WS frames) |
| `migrations/0001_init.sql` | D1 schema |

### Schema validation
Workers forbid runtime code generation, so ajv cannot compile schemas inside the Worker. The schemas in
`../protocol` and `./schemas` are precompiled into `src/generated/validators.js`; after changing any schema run

```
npm run gen:validators
```

and commit the output.

## Secrets
| Name | Purpose |
|---|---|
| `ADMIN_BOOTSTRAP_SECRET` | allows `POST /v1/master/register` (unset = registration disabled). Long random string. |
| `UPLOAD_TOKEN_SECRET` | HMAC-SHA256 key for device upload tokens (required; ≥ 32 random bytes). |
| `FCM_SERVICE_ACCOUNT_JSON` | Firebase service-account JSON (one line) for FCM HTTP v1 pushes (unset = no pushes). |

Local dev: copy `.dev.vars.example` to `.dev.vars` (git-ignored) and fill in placeholders.

## Deploy (first time)
All commands from `cloud/` (set `npm_config_cache` to the repo's `tools/npm-cache` on this machine).
```
npm install
npx wrangler login
npx wrangler d1 create mincontrol                 # copy database_id into wrangler.toml locally (do not commit it)
npx wrangler d1 migrations apply mincontrol --remote
npx wrangler secret put ADMIN_BOOTSTRAP_SECRET
npx wrangler secret put UPLOAD_TOKEN_SECRET
npx wrangler secret put FCM_SERVICE_ACCOUNT_JSON  # paste the JSON on one line
npx wrangler deploy
```
Then register the master app once (`POST /v1/master/register` with the bootstrap secret) and consider
rotating `ADMIN_BOOTSTRAP_SECRET` afterwards (re-registering replaces all master keys).

The cron (`0 * * * *`) is configured in `wrangler.toml`. D1 statement counts are kept low (multi-row inserts,
one atomic batch per upload) but a busy family may still exceed free-tier D1 writes; budget fallback is
Workers Paid (SPEC §9).

## Commands
```
npm run typecheck
npm test               # unit tests (router, crypto/auth, cursor, alert rules, ingest) + protocol contract test
npm run gen:validators
npm run dev            # wrangler dev (local only)
```

## Behaviour notes (beyond API.md, see `docs/contract-requests/cloud.md`)
- Stored/returned timestamps are normalised to `YYYY-MM-DDTHH:MM:SS.sssZ`.
- WebSocket close codes: `4401` auth failed/timeout (30 s), `4403` revoked, `4000` replaced by a newer
  connection of the same device, `4400` bad frame. Upload tokens are refreshed 10 min before expiry.
- On (re)connect the hub sends the latest policy if the device has not yet applied/rejected it and it is
  not expired, then every queued or delivered-but-unacked command in `seq` order.
- `POST /v1/device/events` stores valid events and lists invalid ones in an extra `rejected` array.

## Screenshots (no R2)
Screenshots stay on the device (API.md section 9). `GET /v1/master/blobs/<key>` is relayed through the device's
`DeviceHub` (WS `blob_request`; device answers with `PUT /v1/device/blobs/<key>?reqId=` or WS `blob_missing`):
409 `device_offline`, 504 `device_timeout` after 25 s, 404 `not_found`. Bytes are never persisted in the cloud;
R2 is not needed and the `[[r2_buckets]]` block in `wrangler.toml` is commented out.
