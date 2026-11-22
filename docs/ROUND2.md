# Round 2 — contract decisions and streams (binding)

Base: `main` after PR #1. Each stream works in its own worktree `D:\Coding_Project\MinControl\<branch>`
and edits only what it owns. Same rules as `docs/WORKSTREAMS.md` (no files outside the project, never run
enforcement code on this machine, no secrets, don't run test suites — the lead tests once after merge;
compile your own projects once at the end; commit on your branch; no push/merge).

## A. Protocol / API decisions (owned by stream `r2-cloud`, consumed by everyone)
1. **API.md §4** add: `<ts>` = unix seconds, decimal string, same string in the signed text. **§2** add: WS auth
   `"ts"` is an integer; `policy_rejected.error` uses the command-ack error enum.
2. **Alert item** in `GET /v1/master/alerts`: add `"ackedAt": ts|null`. Query params `unacked=1`, `deviceId=`.
   `data` = the triggering event's `data` **plus** `{title, body, eventId}`; burst alerts (`blocked.burst`) add
   `{count, hosts?:[..], exes?:[..], category?}`; `device.offline` adds `{lastSeen}`. `request.exe_approval`
   alerts therefore carry `sha256`, `exe`, `path`, `publisher`, `signed`, `sizeBytes`, and the item's `userSid`.
3. **`GET …/web`** items for `kind=search` add `"query"` and `"engine"`.
4. **`GET …/events`** `type` accepts a comma list and `prefix.*` entries (`type=web.*,process.blocked`), and
   `exclude=` with the same syntax (default none).
5. **DeviceState** becomes `protocol/device-state.schema.json` (+ fixtures valid/invalid via gen_fixtures.py), the
   API.md §2 shape plus optional `users[].foregroundStartedAt` (RFC3339 Z, when the current foreground app got focus).
   `ws` frames keep referencing it.
6. **event.schema.json**: add `tamper.state_tampered` (data `tamper`); `web.blocked.reason` enum adds `doh`, `port`.
7. **policy.schema.json**: `allowedWindows` description: empty list = no screen time that day (use `00:00-24:00` for
   any time). `netExemptApps` items require `path` (new `$defs/netExemptMatch` = appMatch + required path).
   `common.schema.json` `domainPattern` description: `example.com` = exact host; `*.example.com` = the apex and all
   subdomains.
8. **Semantic-invalid fixtures** to add (gen_fixtures.py): warnAtMin ≥ that day's quota (quota>0), same domain in
   block+allow, allowlist with empty allowDomains, overlapping categorySchedules windows, unknown timezone
   (`Mars/Olympus`).
9. Cloud implements 2–6 and regenerates validators.

## B. Windows decisions (stream `r2-windows`)
1. **User-writable detection by ACL**: an exe is "user-writable" if the managed SID — or any group in its token
   (Users, Authenticated Users, Everyone, INTERACTIVE, …) — has write/append/create-files/write-DAC/owner on the
   exe file or any parent directory up to the volume root, OR the volume is removable/network. Cache per
   directory (invalidate on policy change / every 10 min). Replaces the path heuristic (keep profile/temp as a
   fast path).
2. `IApprovalStore.MarkRequested(sid, sha256) : bool` (persisted; true the first time) — Abstractions change
   authorised for this stream; Monitoring uses it.
3. Promote `IExtensionHealth` to `Core/Abstractions`; Monitoring blocks `msedge.exe`/`chrome.exe` for a SID while
   the extension is missing for that browser (grace: 3 min after browser start; toast explains why).
4. `IBrowserPolicyWriter.UnregisterNativeHostAsync()`; Service removes policies for SIDs that leave the policy.
5. `tamper.state_tampered` when the stored policy fails re-verification; `foregroundStartedAt` in DeviceState.
6. Seam cleanup: `ISessionActions.CaptureScreenAsync` returns `ScreenCapture?` (record in Abstractions); remove the
   JPEG header parsing path in the dispatcher.
7. Verify (read the code) that Program.cs in MERGED mode calls `IAppMonitor.StartAsync`, `INetGuard.ApplyAsync`
   on start + policy/managed-set change, `IBrowserPolicyWriter.ApplyAsync/RemoveAsync`, `ICloudLink.RunAsync`;
   fix what is missing. Remove `#if MERGED` guards (always merged now).

## C. Android (stream `r2-android`): consume A.2–A.5 (ackedAt + filters, search query/engine, multi-type events
filter for the timeline, foregroundStartedAt → "đang mở · N phút"); empty-day editor semantics (A.7) — the policy
editor offers "Cả ngày" which writes `00:00-24:00`, and "Không dùng" which writes `[]`; netExemptApps editor
requires a path.

## D. M7 installer + VM kit (stream `r2-installer`), owns `installer/**`, `windows/src/MinControl.Setup/**`,
`scripts/**`, `docs/runbooks/**`.
