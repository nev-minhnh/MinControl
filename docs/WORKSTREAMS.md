# Parallel workstreams (M1–M6)

Each stream works in its own git worktree `D:\Coding_Project\MinControl\<folder>` on its own branch,
branched from `m0-skeleton`. A stream edits **only the paths it owns**. Shared contracts are
`protocol/*` (schemas + `API.md`) and `windows/src/MinControl.Core/{Policy,Events,Abstractions,Protocol}` —
**read-only for every stream**; if a contract is wrong or missing, write the needed change into
`docs/contract-requests/<stream>.md` in your worktree and work around it locally (lead merges).

| Stream | Branch / folder | Owns (write access) | Milestones |
|---|---|---|---|
| cloud | `s-cloud` | `cloud/**` | M1 backend, M6 push/retention/blobs |
| win-core | `s-wincore` | `windows/src/MinControl.Core/**` (except the read-only contract folders above), `MinControl.Service`, `MinControl.Session`, `MinControl.Setup`, `windows/tests/**` | M2 (+ screenshots M6, outbox, cloud link) |
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
