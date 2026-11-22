# Contract requests from the cloud stream

Each item: what is missing/ambiguous in `protocol/API.md`, what the cloud does now (implemented choice).

1. **`ts` format in `X-MC-Auth` and WS `auth` is unspecified.** Cloud accepts unix seconds (10 digits),
   unix ms (13 digits) or RFC 3339; the value is used verbatim in the signed string. Proposal: fix it to
   unix seconds in API.md.
2. **Pairing code "max 5 failed attempts per code".** A wrong code cannot be attributed to a code, so every
   failed `POST /v1/enroll` increments `failed_attempts` of all open codes; a code with 5 failures is dead.
   Wrong code → `403 invalid_code`. If no master is registered → `409 no_master` (code is not consumed).
3. **`POST /v1/master/register` response** not specified → `201 {"keys":[{"keyId","role"}]}`. Keys are
   checked: size per alg, `keyId == first 16 hex of sha256(raw)`, at least one `sign` key; `sealPubKey`
   must be 32 bytes. Wrong secret → `403 forbidden`.
4. **`DeviceState` has no JSON schema.** Cloud validates with `cloud/schemas/device-state.schema.json`
   (fields of API.md §2; `lockedUntil`, `remainingMin`, `foregroundExe/Title` nullable; extra fields
   rejected). Proposal: move it into `protocol/` with fixtures (win-core produces it).
5. **Event batch with an invalid event.** Rejecting the whole batch would block the agent's outbox
   forever, so the cloud stores valid events and returns `200 {"accepted":n,"rejected":[{"id","error"}]}`
   (`rejected` only when non-empty). Wrapper invalid / deviceId ≠ token → 400 / 403. Proposal: document it.
6. **`GET .../web` for non-visit kinds.** `search`: `title` = query, `host` = engine, `category` = engine,
   `url` = null. `blocked`: `host`, `url`, `category` = data.category ?? data.reason.
7. **Alerts.** `type` = event type (`quota.exhausted`, `request.exe_approval`, `tamper.*`) or
   `blocked.burst` / `device.offline`. Severity: quota → info, exe approval / burst / offline → warn,
   tamper → critical. `data` = `{title, body, eventId, ackedAt, ...}` (+ `scope`, `exe`/`sha256`/`path`,
   `detail`, `count`, `lastSeen` per type). Burst: one alert when ≥ 3 blocked events of one user fall in a
   10-min window; events before the previous burst alert never count again.
8. **Error codes for `PUT policy` / `POST commands`.** 400 `invalid_body` | `wrong_device` | `expired`;
   403 `unknown_key` (not a registered **sign** key) | `bad_signature`; 409 `replayed`
   (`details.lastSeq`) | `duplicate` (commandId already queued); 404 unknown/revoked device.
9. **Policy `expiresAt`.** A queued policy is not (re)delivered after its `expiresAt` (the device would
   reject it anyway). The master app must give policies a long expiry (e.g. 30 days) — please state it.
10. **WS details not in API.md:** auth timeout 30 s; close codes `4401` auth failed, `4403` revoked,
    `4000` replaced (one live connection per device, newest wins), `4400` bad frame. Ping auto-response
    matches the exact text `{"t":"ping"}` (other spellings still work but wake the DO).
    Commands delivered but not acked are re-sent on reconnect; a later `rejected/replayed` ack for such a
    command does not overwrite its status.
11. **Timestamps returned** by the cloud are normalised to millisecond precision (`…00.000Z`).
12. **`GET .../usage`:** `user` optional (all users summed), `day` defaults to today in the policy timezone,
    `group` is null when the app has no group. **`GET .../events`:** `type` also accepts `prefix.*`
    (e.g. `tamper.*`). `limit` default 50, max 200 for all list endpoints.
13. **`GET /v1/master/devices`** omits revoked devices; `online` = socket open and seen in the last 3 min.
    Per-device history endpoints still work for revoked devices; writes return 404.
14. **Upload token** is opaque to the device (`<deviceId>.<exp>.<mac>`); 401 on missing/expired token,
    403 `revoked`. Blob key must match `screens/<ownDeviceId>/<yyyy-mm-dd>/<ULID>.bin` else 403.
