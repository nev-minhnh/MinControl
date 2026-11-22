# Contract requests / merge notes — win-session (`s-session`)

## For the lead at merge time
1. **Delete `windows/src/MinControl.Service/Stubs/CoreStandIns.cs`** (stand-ins for `AddMinControlCore`,
   `CoreOptions`, `IClock`, `IEventSink`, … under `#if !MERGED`) — or build with `-p:MERGED=true`, which also
   adds the Monitoring/NetGuard/Browser project references and DI calls. If the stub is left in after win-core
   is merged, CS0436 (warning-as-error) fails the build, so it cannot silently shadow the real Core.
2. **Test project (owned by win-core)** — `windows/tests/MinControl.Core.Tests/SessionLogicTests.cs` is
   compiled out until this is added to `MinControl.Core.Tests.csproj` (verified to build locally, then reverted):
   ```xml
   <PropertyGroup><DefineConstants>$(DefineConstants);SESSION_LOGIC_LINKED</DefineConstants></PropertyGroup>
   <ItemGroup><Compile Include="..\..\src\MinControl.Service\Logic\*.cs" LinkBase="SessionLogic" /></ItemGroup>
   ```
   (`Service/Logic/*.cs` is platform-neutral, so the net10.0 test project can link it without referencing the
   net10.0-windows Service.)
3. **Deployment (Setup)**: `MinControl.Session.exe` must be in the same folder as `MinControl.Service.exe`
   (`HelperLauncher.HelperPath = AppContext.BaseDirectory`). `Hosting/ServiceInstaller` (sc.exe + SafeBoot
   keys) is ready for Setup to call; it is never executed by the service.

## Seam change requests (Core/Abstractions)
4. `ISessionActions.CaptureScreenAsync` returns only JPEG bytes, but `IScreenshotUploader.UploadAsync` needs
   width/height. Proposal: return `record ScreenCapture(byte[] Jpeg, int Width, int Height)?`. Meanwhile the
   concrete `SessionActions.CaptureFrameAsync` returns all three (used by win-session's interval screenshots);
   the command dispatcher must otherwise read the JPEG SOF header.
5. `ISessionActions` has no "clear overlay". The enforcer clears it by itself when `Evaluate` turns allowed
   again (unlock / add_time / pause_limits), so the dispatcher does not need it; if it does, add
   `Task ClearOverlayAsync(string sid, CancellationToken ct)` (already implemented on `SessionActions`).
6. I2 wording vs `IUserDirectory.IsManaged` ("in policy AND not admin"): I followed the interface — a
   policy SID that is an administrator is **not** enforced (no helper, no logoff, no kill); it raises
   `tamper.managed_user_is_admin` once per day (policy-tz date). SPEC I2 says "enforcement continues where
   possible"; please reconcile the text.

## Ownership clarifications (please confirm win-core does not duplicate)
7. `usage.tick` is emitted by win-session's Enforcer (per minute per exe, title only if
   `monitoring.foregroundTitles`, group via optional `IAppMonitor.GroupOf`), because only the Service sees the
   window title. `IScreenTimeEngine.RecordUsage` only receives the exe path.
8. Interval screenshots (`monitoring.screenshots`) are scheduled by win-session (active console session,
   `onlyWhenActive` = not idle) and handed to `IScreenshotUploader` with reason `"interval"`.
   Command screenshots stay with the dispatcher via `ISessionActions.CaptureScreenAsync`.
9. `quota.warning` / `quota.exhausted` (scope `total` and `group:<name>`) are emitted by the Enforcer.

## Assumptions about win-core
- `AddMinControlCore(Action<CoreOptions>)` lives in namespace `MinControl.Core` and registers `IClock`,
  `IEventSink`, `IPolicyProvider`, `IScreenTimeEngine`, `ICloudLink`, `IScreenshotUploader`, `IApprovalStore`
  and the command dispatcher (which consumes `ISessionActions` / `IUserDirectory` registered by Program.cs).
  Program.cs passes an empty options lambda.
- `ICloudLink.RunAsync` is started by win-session's `CloudLinkHost` (restarted after 10 s if it throws).
- `IScreenTimeEngine.Evaluate(...).Reason` uses `ok | quota_exhausted | outside_window | locked | not_managed`;
  `RemainingMin` is whole minutes remaining; `ExhaustedGroups` returns appGroup keys (used in `group:<key>`).
- `RecordUsage` deltas: the Enforcer passes ≤ 2000 ms per call (sleep/hibernate never counts) and only for the
  active, unlocked console session; idle time is excluded unless `countIdle`; if the helper is silent the
  time is counted (fail closed) with a null exe.
- `IClock.MonotonicMs` is only used for intervals; clock-jump detection uses `Environment.TickCount64`.
- Merged projects expose `AddMinControlMonitoring/NetGuard/Browser()` (no arguments) in root namespaces
  `MinControl.Monitoring`, `MinControl.NetGuard`, `MinControl.Browser`.
