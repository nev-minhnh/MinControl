# Contract requests / integration notes — win-monitor (`s-monitor`)

Nothing in the read-only contract folders was changed. Items for the lead:

1. **DI cycle IScreenTimeEngine <-> IAppMonitor.** The engine needs `IAppMonitor.GroupOf`, the monitor needs
   `IScreenTimeEngine.ExhaustedGroups`. Monitoring resolves `IScreenTimeEngine` (and the optional
   `ISessionActions`, used for the "blocked" toast) lazily from `IServiceProvider`. win-core should do the
   same (or take `Lazy<IAppMonitor>`), otherwise the container throws on a cycle.
2. **Approval request de-duplication.** `IApprovalStore` has only allow/block/null, so "request once per
   sha256" is kept in memory: after a service restart a still-pending exe can trigger one more
   `request.exe_approval`. Proposal: add `bool MarkRequested(string sid, string sha256)` (true the first time,
   persisted) to `IApprovalStore`.
3. **Who starts the monitor.** `AddMinControlMonitoring()` registers `IAppMonitor` only (no IHostedService);
   the Service host (win-session) must call `IAppMonitor.StartAsync/StopAsync`. Requires `ILoggerFactory`
   (any `AddLogging()` host has it).
4. **Test project.** `windows/tests/MinControl.Core.Tests/MinControl.Core.Tests.csproj` (win-core owned) now
   targets `net10.0-windows` and references `MinControl.Monitoring` so `MonitoringRuleTests.cs` compiles.
5. **userSid on machine-wide events.** `usb.*` and `install.detected` with scope `machine` are emitted with
   `userSid = null` (the schema allows it). `install.detected` scope `user`/`appx` carry the user's SID.
6. **Policy semantics chosen (please confirm in SPEC §5/§8.3):** order = critical %windir% shell exes never
   blocked → `appRules` first match (except-list = rule skipped) → exhausted group (even for allow-listed apps)
   → `allowedBrowsers` (only Authenticode-genuine msedge/chrome count) → `newExecutable` for exes under
   user-writable locations (profile, %windir%\Temp, C:\Users\Public, removable/network/UNC). Approvals from
   `IApprovalStore` apply only on the `newExecutable=ask` path. Note: folders users can create under `C:\` or
   `%ProgramData%` are **not** treated as user-writable (possible bypass; consider adding).
