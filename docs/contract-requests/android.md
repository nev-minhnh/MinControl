# Contract requests — android stream (`s-android`)

Workarounds used by the master app are noted per item; nothing in `protocol/` was edited.

1. **`X-MC-Auth` `<ts>` format** — resolved by lead: unix seconds, decimal string, same string in the signed text.
   The app does exactly that (`AuthHeader`, `MasterApi.build`). Please add one sentence to API.md §4.

2. **Alert `data` shape is undocumented (API.md §5 `/v1/master/alerts`).** The app needs, per alert type:
   - `request.exe_approval`: the event data (`exe`, `path`, `sha256`, `publisher`, `signed`, `sizeBytes`) — `sha256`
     and the alert's `userSid` are required to build the `approve_exe` command. Without `sha256` the Allow/Block
     buttons show an error.
   - burst alerts (`web.blocked` / `process.blocked` ≥3 in 10 min): `{ "count": n, "hosts": [..] or "exes": [..], "category"? }`.
   - device offline > 2 h: a `type` value (app assumes it contains `offline`, e.g. `device.offline`) and `{ "lastSeen" }`.
   - `tamper.*`: the event data (`detail`, `exe`, …).
   Proposal: `data` = the triggering event's `data` plus the burst fields above; document it in API.md §5/§6.

3. **Alerts list has no ack state / filters.** The app keeps ack state locally (Room) and only learns about acks made
   on this phone. Proposal: add `"ackedAt": ts|null` to each item and optional `unacked=1`, `deviceId=` query params.

4. **Web history `search` items**: `/web` items have `title`/`url`/`host` only. Proposal: add `query` and `engine`
   for `kind=search` (the app currently shows `title` as the query and guesses the engine from `host`).

5. **Events `type` filter accepts one exact type.** The timeline needs everything except `usage.tick`/`net.domain`
   noise; today it pages up to 5×200 events per day. Proposal: allow a comma list or a prefix (`type=web.*,process.blocked`).

6. **Policy envelope expiry** — resolved by lead: the app signs policies with `expiresAt = issuedAt + 365 d`, commands
   with 24 h (or `lock_now.until` + 1 h when later). Suggest documenting that the device checks `expiresAt` only on receipt.

7. **Register response**: app treats any 2xx as success and ignores the body (`{"ok":true}` is fine).

8. **Lock-all / multi-device commands**: every envelope needs its own Keystore signature, so "Khóa tất cả" shows one
   biometric prompt per managed user. If that is too annoying, a future `kind: "command-batch"` envelope (one signature,
   list of `{deviceId, seq, body}`) would fix it — not needed for M1.

9. **`DeviceState.users[].foregroundStartedAt`** (optional) would let the overview show "đang mở · 23 phút" as in the
   mock-up; today it only shows the window title.
