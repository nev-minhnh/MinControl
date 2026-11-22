# Contract requests — netguard (s-netguard)

1. **Test project TFM / reference.** `windows/tests/MinControl.Core.Tests` targets `net10.0`; NetGuard is
   `net10.0-windows`, so `NetGuardDecisionTests.cs` cannot compile there yet. On merge please set
   `<TargetFramework>net10.0-windows</TargetFramework>` in `MinControl.Core.Tests.csproj` and add
   `<ProjectReference Include="..\..\src\MinControl.NetGuard\MinControl.NetGuard.csproj" />`
   (NetGuard already has `InternalsVisibleTo MinControl.Core.Tests`). Verified locally that the test file compiles
   against NetGuard in a throwaway net10.0-windows project.

2. **`web.blocked.reason` has no value for DoH / port / unknown-caller blocks.** Workaround: reason `blocklist` with
   `category` = `doh` | `port` | `ip`. Optional: extend the enum with `doh`, `port`.

3. **`netExemptApps` entries need a `path`.** WFP permits by image path (`FWPM_CONDITION_ALE_APP_ID`); entries with
   only `exe`/`publisher` cannot be enforced and are skipped with a warning. Suggest: master UI requires `path`
   (optionally + `sha256`), or document it in `policy.schema.json`.

4. **Category list refresh contract.** `CategoryStore.RefreshAsync` is a stub that re-reads
   `%ProgramData%\MinControl\categories\*.txt`. Needs a cloud endpoint / signed blob format for category lists (M6).

5. **Domain pattern semantics** (please confirm and document in `common.schema.json`): `example.com` = exact host
   only; `*.example.com` = `example.com` and all subdomains.

6. **Who calls `INetGuard.ApplyAsync`.** NetGuard expects win-session to call it at service start and whenever the
   managed-SID set or `netExemptApps` change (web rules themselves are read live from `IPolicyProvider.Current`).
   Disposal on service stop intentionally leaves persistent filters in place (I4); only `RemoveAllAsync` (uninstall)
   deletes them.
