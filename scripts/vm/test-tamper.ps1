<#
.SYNOPSIS
  (VM, managed standard user) Local tamper attempts from SPEC 8.1 / 8.8 / I6 / I7. Every attempt must be
  refused (script reports PASS when the attempt fails).
#>
param([string]$SaveTo)
. "$PSScriptRoot\_common.ps1"
Assert-NotAdmin

function Expect-Denied([string]$id, [string]$name, [scriptblock]$attempt, [string]$hint = "") {
    try {
        $out = & $attempt
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { Write-Result $id $name $true "refused (exit $LASTEXITCODE) $out"; return }
        Write-Result $id $name $false "attempt SUCCEEDED $out" $hint
    } catch {
        Write-Result $id $name $true ("refused: " + $_.Exception.Message.Split("`n")[0])
    }
    $global:LASTEXITCODE = 0
}

# --- processes / service (8.1)
$helper = Get-Process -Name "MinControl.Session" -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Result "TAM-00" "helper MinControl.Session runs in this session" ($null -ne $helper -and $helper.SessionId -eq (Get-Process -Id $PID).SessionId) "pid $($helper.Id)" "HelperSupervisor did not start the helper for this user (is the user managed in the policy?)"
if ($helper) {
    Expect-Denied "TAM-01" "Stop-Process MinControl.Session" { Stop-Process -Id $helper.Id -Force -ErrorAction Stop }
    $r = Invoke-Exe "taskkill.exe" @("/F", "/PID", "$($helper.Id)")
    Write-Result "TAM-02" "taskkill /F helper" ($r.Code -ne 0) $r.Out
}
$r = Invoke-Exe "sc.exe" @("stop", "MinControl")
Write-Result "TAM-03" "sc stop MinControl" ($r.Code -ne 0) ($r.Out -split "`n" | Select-Object -First 1)
$r = Invoke-Exe "sc.exe" @("config", "MinControl", "start=", "disabled")
Write-Result "TAM-04" "sc config MinControl start= disabled" ($r.Code -ne 0) ($r.Out -split "`n" | Select-Object -First 1)
$r = Invoke-Exe "sc.exe" @("delete", "MinControl")
Write-Result "TAM-05" "sc delete MinControl" ($r.Code -ne 0) ($r.Out -split "`n" | Select-Object -First 1)
$svcPid = (Get-CimInstance Win32_Service -Filter "Name='MinControl'").ProcessId
if ($svcPid) { Expect-Denied "TAM-06" "Stop-Process service process" { Stop-Process -Id $svcPid -Force -ErrorAction Stop } }

# --- files (I7, install dir ACL)
Expect-Denied "TAM-07" "read %ProgramData%\MinControl (state.db, device.key)" { Get-ChildItem $DataDir -ErrorAction Stop | Out-String }
Expect-Denied "TAM-08" "write into Program Files\MinControl" { Set-Content -Path (Join-Path $InstallDir "x.txt") -Value x -ErrorAction Stop }
Expect-Denied "TAM-09" "replace native host manifest" { Set-Content -Path (Join-Path $InstallDir "com.mincontrol.nativehost.json") -Value "{}" -ErrorAction Stop }
Expect-Denied "TAM-10" "rename MinControl.Session.exe" { Rename-Item (Join-Path $InstallDir "MinControl.Session.exe") "x.exe" -ErrorAction Stop }

# --- registry (8.5 policies, native host, SafeBoot)
Expect-Denied "TAM-11" "delete HKCU\Software\Policies\Microsoft\Edge" { Remove-Item "HKCU:\Software\Policies\Microsoft\Edge" -Recurse -Force -ErrorAction Stop } "browser policy key ACL lets the user write: Browser stream must lock HKU\<SID>\Software\Policies"
Expect-Denied "TAM-12" "set HKCU Chrome policy IncognitoModeAvailability=0" { New-Item "HKCU:\Software\Policies\Google\Chrome" -Force -ErrorAction Stop | Out-Null; Set-ItemProperty "HKCU:\Software\Policies\Google\Chrome" -Name IncognitoModeAvailability -Value 0 -ErrorAction Stop }
Expect-Denied "TAM-13" "add a per-user native host override (HKCU NativeMessagingHosts)" { New-Item "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.mincontrol.nativehost" -Force -ErrorAction Stop | Out-Null; Set-ItemProperty "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.mincontrol.nativehost" -Name "(default)" -Value "C:\Games\fake.json" -ErrorAction Stop } "Chrome prefers HKCU over HKLM for native hosts: the pipe server must still reject a fake host (image path check)"
Remove-Item "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.mincontrol.nativehost" -Force -ErrorAction SilentlyContinue
Expect-Denied "TAM-14" "delete SafeBoot\Minimal\MinControl" { Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MinControl" -Force -ErrorAction Stop }

# --- time (I6)
Expect-Denied "TAM-15" "change system clock (+2 h)" { Set-Date -Date (Get-Date).AddHours(2) -ErrorAction Stop | Out-Null }
$tz = (Get-TimeZone).Id
try {
    Set-TimeZone -Id "UTC" -ErrorAction Stop
    Write-Result "TAM-16" "time zone change allowed for Users (expected) -> schedule must NOT move" $null "changed $tz -> UTC. Check: remaining time / allowed window in master app unchanged; tamper/clock event in timeline"
    Start-Sleep -Seconds 5
    Set-TimeZone -Id $tz
} catch { Write-Result "TAM-16" "time zone change refused" $true $_.Exception.Message }

# --- installer
$code = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object DisplayName -eq "MinControl").PSChildName
if ($code) {
    Write-Result "TAM-17" "manual: msiexec /x $code as this user" $null "must show a UAC prompt asking for ADMIN credentials; cancel it -> product stays installed"
}
Write-Result "TAM-18" "manual: Settings > Apps > MinControl > Uninstall" $null "UAC admin credentials required"
Write-Result "TAM-19" "manual: Task Manager > Services > MinControl > Stop" $null "Access denied"

Write-Summary $SaveTo
