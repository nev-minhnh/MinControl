# Runbook — Hyper-V VM test (M2–M7 acceptance, SPEC §8.8 tamper checklist)

**Never** install the MSI or run enforcement on the dev PC or on the kids' PCs before this whole runbook
passes (SPEC §11, CLAUDE.md). Everything below happens inside a Hyper-V VM.

Helper scripts (copy `scripts\vm\` into the VM, e.g. `C:\mc-test\`), all Windows PowerShell 5.1, each prints
`[PASS]/[FAIL]/[INFO]` lines with hints and exits 1 on any FAIL:

| Script | Run as | Purpose |
|---|---|---|
| `verify-install.ps1` | admin, elevated | service/recovery/SafeBoot/ACL/native host/config/enrolment (INS-xx) |
| `verify-wfp.ps1 -ManagedUser kid` | admin, elevated | `netsh wfp show filters` → MinControl filters persistent, per-SID (WFP-xx) |
| `test-network.ps1` | **kid** (standard) | direct/IP/DoH/UDP/VPN bypasses must fail, proxy path works (NET-xx) |
| `test-network.ps1 -AsAdminBaseline` | admin, elevated | same tests must all work for the admin (I2) |
| `test-portable.ps1 [-PortableBrowserZip x.zip]` | **kid** | exes from a user-created `C:\Games` (EXE-xx) |
| `test-tamper.ps1` | **kid** | kill helper/service, ACLs, HKCU policy edits, clock/time zone (TAM-xx) |
| `safe-mode.ps1 -Enter Network / -Check / -Leave` | admin, elevated | Safe Mode boot test (SAFE-xx) |
| `collect-logs.ps1` | admin, elevated | zip of everything for a bug report (no secrets) |

Add `-SaveTo C:\mc-test\results-<name>.csv` to any test script to keep the result table.

---

## 1. Prerequisites (host)
- Hyper-V enabled on the host, Windows 11 Pro ISO (x64), ~80 GB free.
- Dev backend deployed: `docs/runbooks/deploy-cloud.md` with `-WorkerName mincontrol-dev …`; master app on the
  phone registered against it.
- Installer built: `powershell -ExecutionPolicy Bypass -File scripts\build-msi.ps1 -Version 0.1.0`
  → `artifacts\MinControl-Setup-0.1.0.exe` (what a parent runs: install + QR pairing) and
  `artifacts\msi\MinControl-0.1.0.msi` (advanced/silent); both also copied to `D:\Coding_Project\MinControl\release\dev\`.
  Needs the cloud side of API.md §10 (`/v1/enroll/start`, `/v1/enroll/claim/<id>`) and the app's QR scanner.
  The dev server URL is baked in as the `SERVERURL` default (read from `tools\secrets\cloud-dev.txt`
  `SERVER_URL=`, or `-ServerUrl https://…`); nothing to type on the target PC.
- Extension ids (Chrome Web Store + Edge Add-ons, unlisted — SPEC §8.5) if M5 is in scope.

## 2. Create the VM (host, elevated PowerShell)
```powershell
$vm = "MC-Test"; $root = "D:\HyperV\$vm"      # any disk with space, outside the repo
New-VM -Name $vm -Generation 2 -MemoryStartupBytes 4GB -NewVHDPath "$root\os.vhdx" -NewVHDSizeBytes 64GB -SwitchName "Default Switch" -Path $root
Set-VMProcessor $vm -Count 2
Set-VMMemory $vm -DynamicMemoryEnabled $false
Set-VMKeyProtector $vm -NewLocalKeyProtector; Enable-VMTPM $vm          # Win11 needs TPM; also enables BitLocker tests
Set-VMFirmware $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
Add-VMDvdDrive $vm -Path "D:\ISO\Win11_x64.iso"
Set-VMFirmware $vm -FirstBootDevice (Get-VMDvdDrive $vm)
Enable-VMIntegrationService $vm -Name "Guest Service Interface"       # Copy-VMFile
Start-VM $vm; vmconnect localhost $vm
```
Install Windows 11 **Pro** with a **local** admin account (`Shift+F10` → `start ms-cxh:localonly`, or
disconnect the network during OOBE). Then inside the VM (elevated):
```powershell
# admin account created in OOBE = "mcadmin". Create the managed child account:
$pw = Read-Host -AsSecureString "password for kid"
New-LocalUser -Name kid -Password $pw -FullName "Kid" -PasswordNeverExpires
Add-LocalGroupMember -Group Users -Member kid           # standard user, NOT Administrators
Set-ExecutionPolicy -Scope LocalMachine RemoteSigned
```
Log on once as `kid` (creates the profile, Edge first run), install Google Chrome as admin (per-machine),
log off. Windows Update fully, then shut down.

Copy files in (host): `Copy-VMFile $vm -SourcePath artifacts\MinControl-Setup-0.1.0.exe -DestinationPath C:\mc-test\MinControl-Setup-0.1.0.exe -CreateFullPath -FileSource Host`
(same for `artifacts\msi\MinControl-0.1.0.msi` and each `scripts\vm\*.ps1`), or use the enhanced-session clipboard.

## 3. Checkpoints (before EVERY test group)
```powershell
Checkpoint-VM -Name MC-Test -SnapshotName "00-clean"          # after section 2, VM shut down
Checkpoint-VM -Name MC-Test -SnapshotName "10-installed"      # after section 4
Checkpoint-VM -Name MC-Test -SnapshotName "20-enrolled-policy" # after section 5 (baseline for all tests)
Restore-VMCheckpoint -VMName MC-Test -Name "20-enrolled-policy" -Confirm:$false   # reset between groups
```
Use **standard** checkpoints (not production) so the running state (logged-on sessions, clock) is captured.
Restoring an enrolled checkpoint replays old `seq` values: if the device rejects policies after a restore,
that is correct replay protection — re-pair from the Start-menu shortcut (**Ghép nối lại**) or `enroll <CODE> --force`.

## 4. Install + connect (VM, signed in as the admin `mcadmin`) — QR pairing, no typing
1. VM: double-click `C:\mc-test\MinControl-Setup-0.1.0.exe` → UAC **Yes**.
2. **Cài đặt MinControl** (welcome) → **Cài đặt** → "Đang cài MinControl…" (embedded MSI, silent, ~1 min).
3. **Kết nối với điện thoại**: QR code, "Mở app MinControl trên điện thoại → Thêm máy tính → Quét mã",
   "Mã nhận dạng máy: xxxx xxxx xxxx", fallback code `XXXX-XXXX` in small text, countdown (15 min; a new QR
   appears automatically when it expires).
4. Phone: master app → Thêm máy tính → scan → check the phone shows the **same** fingerprint → approve.
5. VM (within ~2 s): "Đã kết nối. Chọn tài khoản của con trên điện thoại." → **Đóng**. The service was restarted
   and is online; continue in the app (§5).
6. `C:\mc-test\verify-install.ps1` (admin, elevated) → all PASS. `& "C:\Program Files\MinControl\MinControl.Setup.exe" status`
   shows the device id and `last enrol : ok (ok)`; `C:\ProgramData\MinControl\enroll-status.json` holds the last
   attempt (reason codes: `rejected`, `invalid_code`, `network`, `server`, `no_master`, `no_server`, `error`).

Things to check while doing this (TC-01a…f):
- TC-01a close the window at the QR step → warning "chưa kết nối… Vẫn đóng?" → Yes: MinControl installed,
  service Running but idle (unpaired). Start menu → **Kết nối MinControl với điện thoại** (UAC) → the QR screen again.
- TC-01b reject on the phone → red "Điện thoại đã từ chối…" + **Tạo mã mới**; nothing paired.
- TC-01c let the QR expire (or set the VM clock aside) → a new QR + new fingerprint-stable claim appear by themselves.
- TC-01d run the connect screen on a paired PC → "Máy này đã được kết nối" + **Ghép nối lại** (re-pair: the old
  pairing keeps working until the phone approves the new one).
- TC-01e double-click the plain MSI instead → Welcome → **Cài đặt** → Finish shows "Còn một bước…" with
  **Mở màn hình kết nối** ticked → **Hoàn tất** → UAC → QR screen.
- TC-01f advanced/silent (typed fallback code): `msiexec /i C:\mc-test\MinControl-0.1.0.msi PAIRCODE=XXXXXXXX /qn /l*v C:\Users\Public\mc.log`
  from an elevated prompt → exit 0, enrolled; a wrong code still installs (exit 0) and records `invalid_code`.

## 5. Test policy
1. Compare the master key ids (`Setup status`, `master key` lines) with the fingerprints shown in the app.
2. App: `mcadmin` must be greyed out ("admin - can never be managed").
3. App: choose `kid` as managed (`mcadmin` greyed out), apply **policy T1**:

| Field | T1 value (why) |
|---|---|
| timezone | `Asia/Ho_Chi_Minh` |
| screenTime.dailyQuotaMin | 20 every day (short, so the logoff test runs in minutes) |
| screenTime.allowedWindows | `00:00-24:00` every day except one test day window you set per TC |
| screenTime.warnAtMin | `[5, 1]`, graceSec 60, countIdle false, idleThresholdSec 120 |
| appRules | block `notepad.exe` (test app); allow the rest |
| newExecutable | `block` |
| web.mode | `blocklist`, blockDomains `["example.org"]`, safeSearch true, youtube `strict`, allowedBrowsers `["edge","chrome"]` |
| monitoring | all on, screenshots `intervalMin` 10 |

4. `verify-install.ps1` → all PASS. `verify-wfp.ps1 -ManagedUser kid` → all PASS. Checkpoint `20-enrolled-policy`.

---

## 6. Test cases
Expected results are what SPEC requires. "Master app" = the phone app against the dev backend.
Mark each TC PASS/FAIL in a copy of this table; attach `collect-logs.ps1` output for every FAIL.

### 6.1 Install / uninstall (M7)
| # | Steps | Expected |
|---|---|---|
| TC-01 | §4 install with properties | `verify-install.ps1` INS-01…16, 18 PASS; service Auto, LocalSystem, recovery restart 0/0/0, failureflag TRUE |
| TC-02 | Admin: `sc.exe qc MinControl`; Task Manager → kill `MinControl.Service.exe` | service restarts immediately (recovery); master app gets `tamper.service_stopped`/agent alert per implementation |
| TC-03 | kid: `test-tamper.ps1` TAM-17/18 (msiexec /x, Settings → Uninstall) | UAC asks for **admin credentials**; cancel → still installed |
| TC-04 | Admin: Settings → Apps → MinControl → Uninstall (no PURGE) | uninstall succeeds; afterwards `verify-wfp.ps1` WFP-01 **FAIL (0 filters)** = expected; kid has normal internet (`test-network.ps1` NET-01 now "FAIL" = bypass works = expected after uninstall); Edge/Chrome policies for kid gone (`edge://policy` empty); SafeBoot keys gone; `C:\ProgramData\MinControl` kept |
| TC-05 | Re-install MSI (same SERVERURL) | `Setup status`: same device id, policy present; enforcement resumes without re-enrol |
| TC-06 | `msiexec /x MinControl-0.1.0.msi PURGE=1 /qb` | as TC-04 + `C:\ProgramData\MinControl` deleted; revoke device in master app |
| TC-07 | Major upgrade: build `-Version 0.1.1`, `msiexec /i` over 0.1.0 | one ARP entry v0.1.1; enrolment kept; filters never removed during upgrade (kid has no internet throughout) |

### 6.2 M2 — screen time ("managed user is logged off on time; admin unaffected")
| # | Steps | Expected |
|---|---|---|
| TC-10 | Log on as kid, use the PC (move mouse) | `MinControl.Session` runs in kid's session as SYSTEM (`Get-Process MinControl.Session -IncludeUserName` as admin) |
| TC-11 | Keep using until 5 and 1 min left | warning toasts at 5 and 1 min (`quota.warning` in timeline) |
| TC-12 | Reach the 20-min quota | full-screen overlay on all monitors with countdown, then logoff after `graceSec`; `quota.exhausted`, `session.logoff` events |
| TC-13 | Log on again as kid after exhaustion | overlay "not allowed now" → logoff after 30 s |
| TC-14 | Set today's window to a past slot (e.g. `06:00-07:00`), log on as kid | as TC-13 (`outside_window`) |
| TC-15 | Master app: `add_time 15` while overlay shows | overlay clears, kid can continue 15 min |
| TC-16 | Master app: `lock_now`, then `unlock` | immediate overlay/logoff; unlock allows logon (if quota left) |
| TC-17 | Lock screen (Win+L) kid for 5 min / idle > 120 s | time does not count (remainingMin unchanged in app) |
| TC-18 | Fast user switch: kid logged on, admin logs on and works 30 min | kid's time does not count while kid's session is not the active console; admin never sees an overlay or logoff (I2) |
| TC-19 | Disconnect network (host: `Disconnect-VMNetworkAdapter MC-Test`), use kid until quota | logoff still happens on time (I3); reconnect → events uploaded, `tamper.offline_gap` if the gap rules apply |
| TC-20 | Reboot during kid's session with 10 min left | after reboot remaining ≈ 10 min (ledger persisted every 30 s) |
| TC-21 | kid: `test-tamper.ps1` TAM-16 (time zone → UTC) | schedule and remaining time unchanged (I6); `tamper.timezone_changed` in timeline |
| TC-22 | Admin: change clock +2 h while kid logged on | quota not consumed by the jump; `tamper.clock_jump` |

### 6.3 M3 — app control + monitors ("blocked app dies < 1 s; timeline visible")
| # | Steps | Expected |
|---|---|---|
| TC-30 | kid: start `notepad.exe` | killed < 1 s, toast shown; `process.blocked` in timeline |
| TC-31 | kid: `test-portable.ps1 -PortableBrowserZip C:\mc-test\chromium.zip` | EXE-01/03/04/05 PASS (killed); `request.exe_approval`/`process.blocked` alerts in app |
| TC-32 | Master app: approve the hash from TC-31 (`approve_exe allow`) → kid starts it again | runs; still **no network** (WFP: not in netExemptApps) |
| TC-33 | Admin installs an app (e.g. 7-Zip MSI) | `install.detected` event; admin unaffected |
| TC-34 | Attach a VHDX as removable / USB passthrough, run `game.exe` from it as kid | `usb.attached`; exe killed (B.1: removable = user-writable) |
| TC-35 | kid downloads a file in Edge | `web.download`/download event in timeline |
| TC-36 | Master app timeline for today | sessions, apps (foreground + titles), web visible |

### 6.4 M4 — network guard ("VPN/DoH/QUIC/portable browser all fail; admin browses normally")
| # | Steps | Expected |
|---|---|---|
| TC-40 | Admin: `verify-wfp.ps1 -ManagedUser kid` | WFP-01…09 PASS (persistent, per-SID, no admin SID) |
| TC-41 | kid: `test-network.ps1` | NET-01…06, 08, 10, 11 PASS (blocked); NET-07 PASS (allowed site via proxy) |
| TC-42 | admin: `test-network.ps1 -AsAdminBaseline` | all PASS (everything works for the admin) |
| TC-43 | kid: Edge → `https://www.google.com/search?q=test` and YouTube | SafeSearch forced, YouTube restricted mode strict |
| TC-44 | kid: Edge `--no-proxy-server` (NET-13) | page fails to load |
| TC-45 | Admin: `sc stop MinControl` with kid logged on | kid still has **no** internet (persistent filters, I4); `verify-wfp.ps1` WFP-01/02 still PASS; `sc start` → proxy back |
| TC-46 | Reboot, log on as kid before the network is up | still no direct internet (filters are boot-time persistent) |

### 6.5 M5 — browsers ("URLs + searches visible; InPrivate disabled")
| # | Steps | Expected |
|---|---|---|
| TC-50 | kid opens Edge and Chrome | MinControl extension force-installed, cannot be removed/disabled; `edge://policy` shows ExtensionInstallForcelist, InPrivateModeAvailability=1, DeveloperToolsAvailability=2, BrowserGuestModeEnabled=0, BrowserAddPersonEnabled=0, DnsOverHttpsMode=off, ProxyMode fixed_servers |
| TC-51 | kid: Ctrl+Shift+N / guest / add profile / F12 | all unavailable |
| TC-52 | kid: visit 3 sites, search on Google and Bing | URLs + searches (query + engine) in master app Web history |
| TC-53 | kid: open `example.org` | friendly block page (extension) / connection refused; `web.blocked` |
| TC-54 | kid: start Chrome with `--disable-extensions` | extension missing → after the 3-min grace `tamper.extension_missing` and Chrome is blocked for kid (B.3) |
| TC-55 | Admin installs Firefox; kid starts it | killed (not in allowedBrowsers) |
| TC-56 | kid: `test-tamper.ps1` TAM-11/12/13 | HKCU policy edits refused; a fake HKCU native host cannot talk to the service (pipe checks image path) |

### 6.6 M6 — screenshots, alerts, retention ("screenshot round-trip decrypts only on phone")
| # | Steps | Expected |
|---|---|---|
| TC-60 | Master app: `screenshot` command while kid is active | image appears in app; the R2 object (dashboard / `wrangler r2 object get`) is ciphertext (sealed box), not a JPEG |
| TC-61 | Wait 10 min of kid activity | interval screenshots arrive; none while locked/idle (`onlyWhenActive`) |
| TC-62 | Trigger a tamper (TC-54) | FCM push on the phone within ~1 min; alert listed, ack works |
| TC-63 | Shut the VM down 3 h | `device.offline` alert after > 2 h |

### 6.7 SPEC §8.8 tamper checklist (M7)
| # | Item | How | Expected |
|---|---|---|---|
| TC-70 | Child is a Standard user | `Get-LocalGroupMember -SID S-1-5-32-544` | kid not listed |
| TC-71 | BIOS/UEFI password + boot order locked | VM: Secure Boot on, firmware boot order fixed (`Get-VMFirmware`); **real PCs:** set a UEFI admin password, disable USB/network boot | kid cannot boot other media |
| TC-72 | BitLocker on | admin: `Enable-BitLocker C: -TpmProtector -UsedSpaceOnly`; `manage-bde -status` | protection on (offline attack via WinPE fails) |
| TC-73 | Safe Mode registered | `safe-mode.ps1 -Enter Network` → reboot → log on as admin → `safe-mode.ps1 -Check` → log on as kid → `test-network.ps1` → admin `safe-mode.ps1 -Leave` | SAFE-02…04 PASS; kid has no internet in Safe Mode; repeat with `Minimal` |
| TC-74 | Persistent WFP | TC-45, TC-46 | as there |
| TC-75 | Session runs as SYSTEM | admin: `Get-Process MinControl.Session -IncludeUserName`; kid: `test-tamper.ps1` TAM-01/02 | user = `NT AUTHORITY\SYSTEM`; kill refused; if an **admin** kills it, it is back within 2 s; absence > 30 s → `tamper.agent_killed` + kid logged off |
| TC-76 | Service DACL denies stop for non-admins | kid: TAM-03…06; `verify-install.ps1` INS-08 | all refused |
| TC-77 | Installer refuses to manage admin SIDs | enrol output marks admins; master app greys out `mcadmin`; then admin adds kid to Administrators, kid logs on | enforcement for kid **stops**, critical `tamper.managed_user_is_admin` once per day (I2); remove kid from Administrators → enforcement resumes |
| TC-78 | Clock / time-zone change detection | TC-21, TC-22 | events present, schedule unaffected |
| TC-79 | Offline gap reported on reconnect | TC-19 | `tamper.offline_gap` with the gap duration |
| TC-80 | Data dir unreadable for kid (I7) | kid: TAM-07 | access denied |

## 7. When a test fails
1. Do not fix inside the VM. Run `collect-logs.ps1` (admin) → zip on the Public desktop → copy to the host.
2. Note the TC number, checkpoint name, script output (`-SaveTo` CSV).
3. Restore the checkpoint before the next attempt.

## 8. Exit criteria (M7)
All TC-01…TC-80 PASS (TC-71/72 on the real PCs too). Only then install on a kid's PC — same §4/§5 steps,
real (non-dev) backend, extension ids of the published unlisted extensions, and keep a USB stick with
`MinControl-<version>.msi` + this runbook for recovery (`msiexec /x … PURGE=1` as admin removes everything, including
the WFP lock).

---

## Appendix A — command-line install / enrol (scripted or recovery; uses the typed fallback code)
All from an elevated prompt in the VM.
```powershell
# install only, URL/extension ids on the command line (overrides the baked SERVERURL)
msiexec /i C:\mc-test\MinControl-0.1.0.msi SERVERURL=https://mincontrol-dev.<sub>.workers.dev CHROMEEXTID=<id> EDGEEXTID=<id> /qb /l*v C:\Users\Public\mincontrol-install.log
# install + enrol silently
msiexec /i C:\mc-test\MinControl-0.1.0.msi PAIRCODE=XXXXXXXX /qn /l*v C:\Users\Public\mincontrol-install.log
# MSI built without a URL (-NoServerUrl) and installed without SERVERURL: configure by hand
& "C:\Program Files\MinControl\MinControl.Setup.exe" install --server https://… --chrome-ext <id> --edge-ext <id>
# enrol / re-enrol (--force keeps the old enrolment if the new code fails); --restart-service connects at once
& "C:\Program Files\MinControl\MinControl.Setup.exe" enroll XXXX-XXXX [--force] [--restart-service]
& "C:\Program Files\MinControl\MinControl.Setup.exe" connect      # opens the QR connect window
& "C:\Program Files\MinControl\MinControl.Setup.exe" claim-start [--force]   # QR pairing by hand: prints claimId/code/qr JSON
& "C:\Program Files\MinControl\MinControl.Setup.exe" claim-wait <claimId> --timeout 300 --restart-service
& "C:\Program Files\MinControl\MinControl.Setup.exe" status
```
`enroll` prints the local users; `mcadmin` must be listed as "(admin - can never be managed)".
