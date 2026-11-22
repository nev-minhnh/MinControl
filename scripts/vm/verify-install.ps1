<#
.SYNOPSIS
  (VM, elevated admin) Verifies what the MSI + Setup put on the machine: service config, recovery, SafeBoot,
  folder ACLs, native host registration, config.json, enrolment. Read-only.
#>
param([string]$SaveTo)
. "$PSScriptRoot\_common.ps1"
Assert-Admin

# --- service
$svc = Get-CimInstance Win32_Service -Filter "Name='MinControl'" -ErrorAction SilentlyContinue
Write-Result "INS-01" "service installed" ($null -ne $svc) "" "MSI not installed or ServiceInstall failed (see msiexec /l*v log)"
if ($svc) {
    Write-Result "INS-02" "service runs as LocalSystem" ($svc.StartName -eq "LocalSystem") $svc.StartName
    Write-Result "INS-03" "start type Auto (not delayed)" ($svc.StartMode -eq "Auto" -and -not $svc.DelayedAutoStart) "StartMode=$($svc.StartMode) Delayed=$($svc.DelayedAutoStart)"
    Write-Result "INS-04" "service running" ($svc.State -eq "Running") $svc.State "check Event Viewer > Application for .NET errors; run collect-logs.ps1"
    Write-Result "INS-05" "binary in Program Files\MinControl" ($svc.PathName -like "*$InstallDir\MinControl.Service.exe*") $svc.PathName
}
$qf = (Invoke-Exe "sc.exe" @("qfailure", "MinControl")).Out
$restarts = ([regex]::Matches($qf, "RESTART -- Delay = 0 milliseconds")).Count
Write-Result "INS-06" "recovery = restart 0/0/0" ($restarts -ge 3) (($qf -split "`n" | Where-Object { $_ -match "RESET|RESTART" }) -join " | ")
$ff = (Invoke-Exe "sc.exe" @("qfailureflag", "MinControl")).Out
Write-Result "INS-07" "failure actions also on non-crash stops" ($ff -match "FAILURE_ACTIONS_ON_NONCRASH_FAILURES:\s*TRUE") (($ff -split "`n" | Select-Object -Last 1).Trim())
$sd = (Invoke-Exe "sc.exe" @("sdshow", "MinControl")).Out
Write-Result "INS-08" "service DACL: no stop/config right for Users/IU" ($sd -notmatch "\(A;;[A-Z]*(RP|WP|DC|SD|WD|WO)[A-Z]*;;;(BU|IU|AU|WD)\)") $sd "the default SCM DACL should be kept (no RP/WP for BU/IU/AU)"

# --- SafeBoot
foreach ($m in "Minimal", "Network") {
    $v = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$m\MinControl" -ErrorAction SilentlyContinue).'(default)'
    Write-Result "INS-09" "SafeBoot\$m\MinControl = Service" ($v -eq "Service") "value=$v"
}

# --- ACLs
function Test-NoUserWrite([string]$path) {
    $acl = Get-Acl $path
    $bad = $acl.Access | Where-Object {
        $_.AccessControlType -eq "Allow" -and
        $_.IdentityReference.Value -notmatch "SYSTEM|Administrators|TrustedInstaller|CREATOR OWNER" -and
        ($_.FileSystemRights.ToString() -match "Write|Modify|FullControl|CreateFiles|AppendData|ChangePermissions|TakeOwnership")
    }
    return @($bad)
}
if (Test-Path $InstallDir) {
    $bad = Test-NoUserWrite $InstallDir
    Write-Result "INS-10" "Program Files\MinControl: only SYSTEM/Admins can write" ($bad.Count -eq 0) (($bad | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; ")
    foreach ($exe in "MinControl.Service.exe", "MinControl.Session.exe", "MinControl.NativeHost.exe", "MinControl.Setup.exe") {
        Write-Result "INS-11" "$exe present next to the service" (Test-Path (Join-Path $InstallDir $exe))
    }
} else { Write-Result "INS-10" "install folder exists" $false $InstallDir }
if (Test-Path $DataDir) {
    $acl = Get-Acl $DataDir
    $others = $acl.Access | Where-Object { $_.IdentityReference.Value -notmatch "NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators" }
    Write-Result "INS-12" "ProgramData\MinControl: SYSTEM + Administrators only (I7)" (@($others).Count -eq 0 -and $acl.AreAccessRulesProtected) (($others | ForEach-Object { "$($_.IdentityReference)" }) -join "; ")
} else { Write-Result "INS-12" "ProgramData\MinControl exists" $false }

# --- native messaging host
$manifest = Join-Path $InstallDir "com.mincontrol.nativehost.json"
foreach ($k in "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.mincontrol.nativehost", "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.mincontrol.nativehost") {
    $v = (Get-ItemProperty $k -ErrorAction SilentlyContinue).'(default)'
    Write-Result "INS-13" "native host registered: $(Split-Path (Split-Path (Split-Path $k)) -Leaf)" ($v -eq $manifest) "value=$v"
}
if (Test-Path $manifest) {
    $m = Get-Content $manifest -Raw | ConvertFrom-Json
    Write-Result "INS-14" "manifest path points at the installed native host" ($m.path -eq (Join-Path $InstallDir "MinControl.NativeHost.exe")) $m.path
    Write-Result "INS-15" "manifest allowed_origins set (extension ids configured)" (@($m.allowed_origins).Count -gt 0) (($m.allowed_origins) -join ", ") "run: MinControl.Setup install --chrome-ext <id> --edge-ext <id>"
} else { Write-Result "INS-14" "native host manifest exists" $false $manifest "MinControl.Setup install was not run (SERVERURL missing at msiexec?)" }

# --- config + enrolment (Setup status)
$cfg = Join-Path $DataDir "config.json"
Write-Result "INS-16" "config.json written" (Test-Path $cfg) $cfg "MinControl.Setup install --server https://<worker>.workers.dev"
$st = Invoke-Exe (Join-Path $InstallDir "MinControl.Setup.exe") @("status") 60
Write-Host $st.Out
Write-Result "INS-17" "MinControl.Setup status reports no problems" ($st.Code -eq 0) "exit $($st.Code)" "not enrolled yet? MinControl.Setup enroll <CODE>"

# --- ARP entry
$arp = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object DisplayName -eq "MinControl"
Write-Result "INS-18" "Programs and Features entry (no Modify)" ($null -ne $arp -and $arp.NoModify -eq 1) "version $($arp.DisplayVersion)"

Write-Summary $SaveTo
