# MinControl protocol

JSON Schema (draft 2020-12) files in this folder are the **single source of truth** for every
message exchanged between the master app, the cloud and device agents. C#, TypeScript and Kotlin
types must follow them; each side runs a contract test that validates `fixtures/valid/*` (must pass)
and `fixtures/invalid/*` (must fail) against these schemas.

| File | What |
|---|---|
| `common.schema.json` | shared definitions (ids, SID, times, weekday maps) |
| `signed-envelope.schema.json` | wrapper for everything the master signs (`kind`: policy, command). Temporary overrides are created on the device by commands (`add_time`, `pause_limits`, `lock_now`) |
| `signed-body.schema.json` | the JSON inside `payload` of a signed envelope |
| `policy.schema.json` | desired-state policy for one device |
| `command.schema.json` | immediate commands (master → device) |
| `command-ack.schema.json` | device → cloud acknowledgement |
| `event.schema.json` / `event-batch.schema.json` | telemetry device → cloud |
| `device-state.schema.json` | live device status (WS `state` frame, API.md §2) |

## Signing rules (security-critical)

1. The signer serialises the **signed body** (`signed-body.schema.json`) to UTF-8 JSON **once**.
2. Those exact bytes are base64url-encoded (no padding) into `payload`.
3. `sig` = base64url(signature over the **raw payload bytes**, not over re-serialised JSON).
   So no canonical-JSON scheme is needed: verifiers never re-serialise before verifying.
4. `alg`: `ed25519` (preferred) or `es256` (ECDSA P-256, signature in IEEE P1363 r||s form, 64 bytes)
   for phones whose Keystore lacks Ed25519.
5. `keyId` = first 16 hex chars of SHA-256 of the raw public key (Ed25519: 32 bytes;
   P-256: uncompressed SEC1 point, 65 bytes).
6. Device checks, in order: `keyId` pinned → signature valid → `deviceId` is its own →
   `seq` > last accepted seq for that `kind` → `issuedAt - 5 min <= now < expiresAt`.
   Only then is `body` parsed and validated against the schema for `kind`.

## Fixtures
`fixtures/<schema-stem>/valid/*.json` must validate, `fixtures/<schema-stem>/invalid/*.json` must not
(e.g. `fixtures/policy/valid/basic.json` → `policy.schema.json`). Fixtures stay pure JSON; the
reason an invalid fixture must fail is its file name (`missing-userSid.json`).
`fixtures/policy/semantic-invalid/*` pass the schema but must be **rejected by each agent's policy
validator** (overlapping or midnight-crossing windows, warnAtMin ≥ that day's quota, a domain in both block and allow
lists, allowlist mode with no allowDomains, unknown IANA timezone, contradictory web rules). Regenerate all
fixtures with `python tools/gen_fixtures.py` — never hand-edit them.
Run `npm test` in this folder for the reference (ajv) check.

## Conventions
- Times: RFC 3339 UTC strings (`2026-11-22T08:50:00Z`). Local schedule times are `HH:MM` in the
  policy's IANA timezone.
- Ids: ULID (26 chars Crockford base32) for events/commands; `deviceId` is a ULID too.
- Unknown properties are **rejected** (`additionalProperties: false`) so typos fail loudly.
  Adding a field = schema change + fixture + version bump of the affected schema `$id`.
