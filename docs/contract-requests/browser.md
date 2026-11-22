# Contract requests — browser stream (s-browser)

1. **Test project reference (win-core owns `windows/tests/**`).** `BrowserPolicyMapperTests.cs` needs in
   `MinControl.Core.Tests.csproj`:
   - `<TargetFramework>net10.0-windows</TargetFramework>` (MinControl.Browser targets net10.0-windows), and
   - `<ProjectReference Include="..\..\src\MinControl.Browser\MinControl.Browser.csproj" />`.
   The file compiles against that setup (verified with a throw-away project, not committed).

2. **Spec §8.5 permission list vs task.** SPEC lists the `history` permission; the extension does not request
   it (visits come from `webNavigation` + `tabs`). Suggest dropping `history` from §8.5.

3. **"Block that browser" when the extension is missing (§8.5).** Browser stream only emits
   `tamper.extension_missing`. It exposes `MinControl.Browser.Events.IExtensionHealth.IsExtensionMissing(sid, browser)`
   (DI singleton). Request: either promote it to `Core/Abstractions` or have win-monitor consume it from
   MinControl.Browser so app control can block `msedge.exe`/`chrome.exe` for that SID.

4. **Who calls `IBrowserPolicyWriter`.** The Service (win-session) must call `ApplyAsync(sid, user.Web, netGuard.ProxyPort)`
   for each managed SID on policy change / startup and `RemoveAsync` when a SID leaves the policy. Uninstall
   (Setup) should call `BrowserPolicyWriter.UnregisterNativeHostAsync` (concrete class, not in the seam).
   Suggest adding `UnregisterNativeHostAsync` to `IBrowserPolicyWriter`.

5. **Configuration.** `BrowserOptions.ChromeExtensionId` / `EdgeExtensionId` must come from service config
   (not the repo). `NativeHostExePath` defaults to `<service dir>\MinControl.NativeHost.exe`; Setup must install
   the native host there (admin-only ACL) — the pipe server rejects clients with any other image path.

6. **`web.blocked` from the extension.** Source is always `extension`; the pipe server rejects `source: "proxy"`
   so a user cannot forge proxy-side events. No schema change needed.
