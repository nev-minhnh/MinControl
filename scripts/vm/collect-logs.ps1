<#
.SYNOPSIS
  (VM, elevated admin) Collects everything needed to debug a failed test into one zip on the Public desktop:
  Setup status, service config/recovery/DACL, SafeBoot + native host registry, ACLs, WFP filters + state,
  proxy settings per profile, MinControl logs, Application/System event log entries, MSI logs in %TEMP%.
  Does NOT copy state.db or device.key (secrets stay on the VM).
#>
param([string]$OutRoot = "$env:PUBLIC\Desktop", [int]$EventHours = 24)
. "$PSScriptRoot\_common.ps1"
Assert-Admin

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dir = Join-Path $env:TEMP "mincontrol-logs-$stamp"
New-Item -ItemType Directory -Force $dir | Out-Null
function Save([string]$name, [scriptblock]$block) {
    try { & $block *>&1 | Out-File -FilePath (Join-Path $dir $name) -Encoding utf8 -Width 400; Write-Host "  + $name" }
    catch { "ERROR: $($_.Exception.Message)" | Out-File (Join-Path $dir $name) -Encoding utf8; Write-Host "  ! $name failed" -ForegroundColor Yellow }
}

Write-Host "Collecting into $dir"
Save "setup-status.txt" { & (Join-Path $InstallDir "MinControl.Setup.exe") status }
Save "service.txt" { sc.exe qc MinControl; sc.exe queryex MinControl; sc.exe qfailure MinControl; sc.exe qfailureflag MinControl; sc.exe qsidtype MinControl; sc.exe sdshow MinControl }
Save "processes.txt" { Get-CimInstance Win32_Process | Where-Object Name -like "MinControl*" | Select-Object ProcessId, Name, SessionId, ExecutablePath, CommandLine | Format-List }
Save "registry.txt" {
    foreach ($k in "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MinControl", "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\MinControl",
                   "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.mincontrol.nativehost", "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.mincontrol.nativehost",
                   "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings") {
        "== $k"; Get-ItemProperty $k -ErrorAction SilentlyContinue | Format-List
    }
}
Save "user-policies.txt" {
    foreach ($sid in (Get-ChildItem "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }).PSChildName) {
        "==== $sid (loaded hive)"
        foreach ($k in "Software\Policies\Microsoft\Edge", "Software\Policies\Google\Chrome", "Software\Microsoft\Windows\CurrentVersion\Internet Settings") {
            "== $k"; Get-ItemProperty "Registry::HKEY_USERS\$sid\$k" -ErrorAction SilentlyContinue | Format-List
            Get-ChildItem "Registry::HKEY_USERS\$sid\$k" -ErrorAction SilentlyContinue | ForEach-Object { "-- $($_.Name)"; Get-ItemProperty $_.PSPath | Format-List }
        }
    }
}
Save "acl.txt" { icacls $InstallDir; icacls $DataDir; icacls "$DataDir\*" }
Save "config.json" { Get-Content (Join-Path $DataDir "config.json") -Raw }
Save "native-host-manifest.json" { Get-Content (Join-Path $InstallDir "com.mincontrol.nativehost.json") -Raw }
Save "users.txt" { Get-LocalUser | Select-Object Name, SID, Enabled | Format-Table; Get-LocalGroupMember -SID "S-1-5-32-544" | Format-Table }
Save "netsh-proxy.txt" { netsh winhttp show proxy; Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -ErrorAction SilentlyContinue | Format-Table }
Write-Host "  (WFP dump can take a minute)"
& netsh.exe wfp show filters file="$dir\wfp-filters.xml" | Out-Null
& netsh.exe wfp show state file="$dir\wfp-state.xml" | Out-Null
Save "timezone.txt" { Get-TimeZone; Get-Date -Format o; w32tm /query /status }

if (Test-Path (Join-Path $DataDir "logs")) { Copy-Item (Join-Path $DataDir "logs") (Join-Path $dir "agent-logs") -Recurse -ErrorAction SilentlyContinue }
Get-ChildItem $env:TEMP, "$env:SystemRoot\Temp" -Filter "MSI*.LOG" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $dir $_.Name) }
Get-ChildItem $env:PUBLIC -Filter "mincontrol-install*.log" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Copy-Item $_.FullName $dir }

$since = (Get-Date).AddHours(-$EventHours)
Save "eventlog-application.txt" {
    Get-WinEvent -FilterHashtable @{ LogName = "Application"; StartTime = $since } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match "MinControl|\.NET Runtime|Application Error|MsiInstaller" } | Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message
}
Save "eventlog-system.txt" {
    Get-WinEvent -FilterHashtable @{ LogName = "System"; StartTime = $since; ProviderName = "Service Control Manager" } -ErrorAction SilentlyContinue |
        Where-Object Message -match "MinControl" | Format-List TimeCreated, Id, Message
}

$zip = Join-Path $OutRoot "mincontrol-logs-$stamp.zip"
Compress-Archive -Path "$dir\*" -DestinationPath $zip -Force
Remove-Item -Recurse -Force $dir
Write-Host "Saved $zip" -ForegroundColor Green
Write-Host "Copy it to the host (Hyper-V enhanced session clipboard / shared folder) and attach it to the bug report."
