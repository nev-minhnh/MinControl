# Parallel workstreams (M1–M6)

Each stream works in its own git worktree `D:\Coding_Project\MinControl\<folder>` on its own branch,
branched from `m0-skeleton`. A stream edits **only the paths it owns**. Shared contracts are
`protocol/*` (schemas + `API.md`) and `windows/src/MinControl.Core/{Policy,Events,Abstractions,Protocol}` —
**read-only for every stream**; if a contract is wrong or missing, write the needed change into
`docs/contract-requests/<stream>.md` in your worktree and work around it locally (lead merges).

| Stream | Branch / folder | Owns (write access) | Milestones |
|---|---|---|---|
| cloud | `s-cloud` | `cloud/**` | M1 backend, M6 push/retention/blobs |
| win-core | `s-wincore` | `windows/src/MinControl.Core/**` (except the read-only contract folders above), `MinControl.Setup`, `windows/tests/**` | M2 engine, cloud link, M6 sealing |
| win-session | `s-session` | `windows/src/MinControl.Service/**`, `windows/src/MinControl.Session/**` | M2 enforcement host, M6 capture |
| win-monitor | `s-monitor` | `windows/src/MinControl.Monitoring/**` | M3 |
| netguard | `s-netguard` | `windows/src/MinControl.NetGuard/**` | M4 |
| browser | `s-browser` | `extension/**`, `windows/src/MinControl.Browser/**`, `windows/src/MinControl.NativeHost/**` | M5 |
| android | `s-android` | `android-master/**` | M1 app + all screens, M6 |

Package versions: add to `windows/Directory.Packages.props` only lines for packages your project uses
(merge conflicts there are resolved by the lead).

Rules for every stream: no files outside `D:\Coding_Project\MinControl\`; never run enforcement code
(WFP, logoff, kill, registry writes under HKU/HKLM) on this machine; no real secrets/ids in the repo;
do not run test suites (lead runs everything once after merge) — writing tests is welcome; commit to
your own branch with clear messages; do not push, do not merge.

## Windows split and DI wiring
- **win-core** (`s-wincore`) owns Core implementation + Setup + tests: policy JSON parsing & semantic
  validation, envelope verification, crypto (Ed25519/ES256 verify, device key, sealed box), ULID, local
  SQLite store (policy, seq, overrides, ledger, approvals, outbox), `IScreenTimeEngine`, command dispatcher
  (uses `ISessionActions`), `ICloudLink`, uploader, `IScreenshotUploader`, `IEventSink`, `IPolicyProvider`,
  `IApprovalStore`. Exposes `services.AddMinControlCore(options)` in Core.
- **win-session** (`s-session`) owns `MinControl.Service` + `MinControl.Session`: service host with
  session-change notifications, `IUserDirectory`, `ISessionActions`, `IForegroundTracker`, enforcer loop,
  launching the Session helper as SYSTEM in the user session, IPC, tamper detection, Program/DI.
- Every implementation project exposes one DI extension: `AddMinControlCore`, `AddMinControlMonitoring`,
  `AddMinControlNetGuard`, `AddMinControlBrowser` (static class `ServiceCollectionExtensions` in its root
  namespace). win-session calls all four in Program.cs; until merge the missing ones are compiled out by a
  `#if MERGED` block — lead removes the guard.
