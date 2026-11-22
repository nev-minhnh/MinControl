# Contract requests — installer stream (`r2-installer`)

## For r2-windows (Service `Program.cs`) — required before M5 works from an MSI install
1. **Read `%ProgramData%\MinControl\config.json`.** Setup (`install`, also run by the MSI when `SERVERURL` is
   given) writes it with the folder's SYSTEM/Administrators-only ACL. Shape (IConfiguration-friendly):
   ```json
   { "ServerUrl": "https://<worker>.workers.dev",
     "Browser": { "ChromeExtensionId": "<32 a-p>", "EdgeExtensionId": "<32 a-p>" } }
   ```
   Suggested wiring:
   ```csharp
   var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinControl");
   builder.Configuration.AddJsonFile(Path.Combine(dataDir, "config.json"), optional: true, reloadOnChange: false);
   builder.Services.AddMinControlBrowser(o => builder.Configuration.GetSection("Browser").Bind(o));
   ```
   Without this the Service's `BrowserPolicyWriter.ApplyMachine` rewrites the native-host manifest with **empty
   `allowed_origins`** (it overwrites the one Setup wrote) and no extension is force-installed.
   `ServerUrl` is informational for the Service (the cloud link keeps using `state.db` meta `ServerUrl` set by
   `enroll`); `enroll` defaults `--server` to it.
2. **`IBrowserPolicyWriter.UnregisterNativeHostAsync`** (decision B.4): Setup currently calls the concrete
   `BrowserPolicyWriter.UnregisterNativeHostAsync` (see `MinControl.Setup/Cleanup.cs`); switch to the seam
   member once it exists. No behaviour change needed.

## Install layout (for everyone)
- `%ProgramFiles%\MinControl\` — self-contained win-x64 publish of Service, Session, NativeHost, Setup in one
  folder (`HelperLauncher` and `BrowserOptions.NativeHostExePath` rely on `AppContext.BaseDirectory`).
  ACL `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)` (Users read/execute only).
- `%ProgramData%\MinControl\` — created by the MSI with `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (I7), kept on
  uninstall unless `PURGE=1` / `Setup uninstall --purge`.
- Service registration is done by the MSI (`ServiceInstall` + `util:ServiceConfig` restart 0/0/0, reset 1 day,
  `sc failureflag 1`, `sc sidtype unrestricted`), SafeBoot Minimal/Network keys and the HKLM native-host keys
  are MSI registry components. `Hosting/ServiceInstaller` is no longer called by Setup (kept for non-MSI dev
  installs; it can be deleted by its owner).
- MSI uninstall runs `MinControl.Setup uninstall --yes --from-msi` (deferred, SYSTEM) after `StopServices`:
  NetGuard `RemoveAllAsync` (composed by hand from public NetGuard types), `BrowserPolicyWriter.RemoveAsync` for
  every profile SID in ProfileList, `UnregisterNativeHostAsync`, SafeBoot keys. Any constructor change of
  `NetGuardService` / `FilteringProxy` / `BrowserPolicyWriter` must keep Setup compiling (owners: please build
  `MinControl.Setup` too).
