# Contract requests from win-core

1. **`ISessionActions.CaptureScreenAsync` → `ScreenCapture?`** (lead decision, lands at merge). Core still compiles
   against the current `byte[]?` signature; the only call site is `CommandDispatcher.CaptureAsync`
   (marked `MERGE NOTE`) — replace its body with the 1-liner in the comment. No temporary record was defined.
2. **API.md §2 auth `ts`**: document the lead decision — `"ts"` is an integer (unix seconds) and the signed string is
   `nonce + "|" + deviceId + "|" + <decimal ts>`. Core implements this.
3. **Empty `allowedWindows[day]`**: schema allows `[]`; Core treats it as *no screen time that day* (fail closed).
   Please state this in policy.schema.json (description) so the master app does not send `[]` meaning "any time"
   (use `"00:00-24:00"`).
4. **Semantic rules beyond the 3 fixtures** that Core enforces (please add fixtures via gen_fixtures.py):
   `warnAtMin` value ≥ that weekday's `dailyQuotaMin` (days with quota 0 exempt), same domain in `blockDomains` and
   `allowDomains`, `mode: allowlist` with empty `allowDomains`, overlapping/midnight-crossing
   `categorySchedules` windows, IANA timezone unknown to the device.
5. **`policy_rejected.error`** values: Core reuses the command-ack error enum (`unknown_key`, `bad_signature`,
   `wrong_device`, `replayed`, `expired`, `invalid_body`). Please write that into API.md §2.
6. **DeviceState** has no schema file; Core emits exactly the API.md example shape (`lockedUntil`, `remainingMin`,
   `foregroundExe`, `foregroundTitle`, `policyVersion` may be `null`; `locked` = locked by `lock_now`).
   Suggest a `device-state.schema.json`.
7. **New optional seam (Core-owned, not in Abstractions):** `MinControl.Core.Cloud.IUserSessionStatus`
   `{ (bool Active, bool WorkstationLocked)? Status(string sid); }` — if win-session registers it, DeviceState
   uses it for `loggedOn`/`active`; otherwise derived from `IForegroundTracker`.
8. **Tamper type for a state.db policy that fails re-verification at startup** (`PolicyProvider.StoredPolicyRejected`).
   No suitable `tamper.*` type exists; propose `tamper.state_tampered` (event.schema.json + fixture).
