<#
.SYNOPSIS
  (VM, elevated admin) Safe Mode test helper (SPEC 8.1 / 8.8).
    -Enter Minimal|Network : bcdedit safeboot flag + reboot prompt
    -Check                 : run inside Safe Mode (admin): is the service running there?
    -Leave                 : remove the safeboot flag (run in Safe Mode, then reboot)
  The child test itself is manual: log on as the managed user in Safe Mode and run test-network.ps1 /
  test-tamper.ps1 there (Network mode). Expected: service + WFP filters active, no internet for the child.
  Take a Hyper-V checkpoint before -Enter.
#>
param([ValidateSet("Minimal", "Network")][string]$Enter, [switch]$Check, [switch]$Leave, [switch]$NoReboot)
. "$PSScriptRoot\_common.ps1"
Assert-Admin

if ($Enter) {
    $r = Invoke-Exe "bcdedit.exe" @("/set", "{current}", "safeboot", $Enter.ToLower())
    Write-Result "SAFE-00" "bcdedit safeboot $Enter" ($r.Code -eq 0) $r.Out
    foreach ($m in "Minimal", "Network") {
        Write-Result "SAFE-01" "SafeBoot\$m\MinControl registered" ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$m\MinControl" -ErrorAction SilentlyContinue).'(default)' -eq "Service")
    }
    if (-not $NoReboot) { Write-Host "Rebooting into Safe Mode in 10 s (Ctrl+C to cancel)..."; Start-Sleep 10; Restart-Computer -Force }
    exit 0
}
if ($Check) {
    $boot = (Get-CimInstance Win32_ComputerSystem).BootupState
    Write-Result "SAFE-02" "machine is in Safe Mode" ($boot -ne "Normal boot") $boot
    $svc = Get-Service MinControl -ErrorAction SilentlyContinue
    Write-Result "SAFE-03" "MinControl service running in Safe Mode" ($svc -and $svc.Status -eq "Running") "$($svc.Status)" "SafeBoot keys missing or the service depends on a service that Safe Mode does not start"
    $bfe = Get-Service BFE -ErrorAction SilentlyContinue
    Write-Result "SAFE-04" "Base Filtering Engine running (persistent WFP filters enforced)" ($bfe -and $bfe.Status -eq "Running") "$($bfe.Status)"
    Write-Result "SAFE-05" "manual: log on as the child in Safe Mode" $null "Minimal: logon allowed? overlay/logoff on schedule; Network: run test-network.ps1 -> all blocked"
    Write-Summary
}
if ($Leave) {
    $r = Invoke-Exe "bcdedit.exe" @("/deletevalue", "{current}", "safeboot")
    Write-Result "SAFE-06" "safeboot flag removed" ($r.Code -eq 0) $r.Out
    if (-not $NoReboot) { Write-Host "Rebooting normally in 10 s..."; Start-Sleep 10; Restart-Computer -Force }
    exit 0
}
Get-Help $MyInvocation.MyCommand.Path
