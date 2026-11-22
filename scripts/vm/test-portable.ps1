<#
.SYNOPSIS
  (VM, managed standard user) Portable-executable bypass (SPEC 8.3 newExecutable + decision B.1: user-writable
  detection by ACL). Creates C:\Games (any user may create folders under C:\), copies programs there and runs
  them. Expected: the process is killed within ~1 s (policy newExecutable = block/ask) or, if it is allowed to
  run, it has no network (WFP) and no browser can be used.
.PARAMETER PortableBrowserZip
  Optional zip of a portable browser (e.g. Chromium/Firefox portable) copied into the VM beforehand.
  Its main exe is started from C:\Games\browser.
.PARAMETER BrowserExeName
  Exe name inside the zip (default: chrome.exe; Firefox portable: firefox.exe).
#>
param([string]$PortableBrowserZip, [string]$BrowserExeName = "chrome.exe", [string]$AllowedHost = "www.wikipedia.org", [string]$SaveTo)
. "$PSScriptRoot\_common.ps1"
Assert-NotAdmin

$games = "C:\Games"
try { New-Item -ItemType Directory -Force $games -ErrorAction Stop | Out-Null; $created = $true } catch { $created = $false }
Write-Result "EXE-00" "standard user can create C:\Games (precondition)" $created $games "if Users cannot create folders here, use D:\ or a USB stick instead"
if (-not $created) { Write-Summary $SaveTo }

function Test-Launch([string]$id, [string]$name, [string]$exe, [string[]]$exeArgs) {
    $p = $null
    try { $p = Start-Process -FilePath $exe -ArgumentList $exeArgs -PassThru -WindowStyle Hidden -ErrorAction Stop }
    catch { Write-Result $id "$name blocked at start" $true $_.Exception.Message; return $null }
    Start-Sleep -Milliseconds 1500
    $p.Refresh()
    if ($p.HasExited) {
        Write-Result $id "$name killed within 1.5 s" $true "exit code $($p.ExitCode)"
        return $null
    }
    Write-Result $id "$name still running after 1.5 s" $false "pid $($p.Id)" "policy newExecutable may be 'allow'/'ask' for this test; then the network checks below must still FAIL closed"
    return $p
}

# 1. A renamed system tool (user-owned copy -> new, user-writable executable)
$copy = Join-Path $games "game.exe"
Copy-Item $Curl $copy -Force
$p = Test-Launch "EXE-01" "C:\Games\game.exe (renamed curl)" $copy @("-s", "--noproxy", "*", "--max-time", "8", "-o", "NUL", "https://$AllowedHost/")
if ($p) {
    $p.WaitForExit(15000) | Out-Null
    Write-Result "EXE-02" "renamed curl from C:\Games has no direct network" ($p.ExitCode -ne 0) "exit $($p.ExitCode)"
}

# 2. A user-created folder with a hidden attribute / alternate path forms
$hidden = Join-Path $games ".cache"
New-Item -ItemType Directory -Force $hidden | Out-Null
(Get-Item $hidden).Attributes = "Hidden,Directory"
$copy2 = Join-Path $hidden "svchost.exe"
Copy-Item $Curl $copy2 -Force
$null = Test-Launch "EXE-03" "hidden C:\Games\.cache\svchost.exe" $copy2 @("--version")
$short = (New-Object -ComObject Scripting.FileSystemObject).GetFile($copy2).ShortPath
if ($short -and $short -ne $copy2) { $null = Test-Launch "EXE-04" "8.3 short path $short" $short @("--version") }

# 3. Portable browser
if ($PortableBrowserZip) {
    $dest = Join-Path $games "browser"
    Expand-Archive -Path $PortableBrowserZip -DestinationPath $dest -Force
    $exe = Get-ChildItem $dest -Recurse -Filter $BrowserExeName | Select-Object -First 1
    if ($exe) {
        $bp = Test-Launch "EXE-05" "portable browser $($exe.Name)" $exe.FullName @("--no-first-run", "https://$AllowedHost/")
        if ($bp) {
            Write-Result "EXE-06" "manual: portable browser window shows NO page (no network) and master app got process.* / request.exe_approval" $null "close it afterwards"
        }
    } else { Write-Result "EXE-05" "portable browser exe found in zip" $false $BrowserExeName }
} else {
    Write-Result "EXE-05" "portable browser (skipped: pass -PortableBrowserZip <zip>)" $null ""
}

# 4. Removable / network volumes: manual
Write-Result "EXE-07" "manual: same exe from a USB stick / mapped share" $null "attach a VHDX as removable or map \\host\share; run game.exe -> killed (B.1 removable/network = user-writable)"

Write-Host "Cleanup: Remove-Item -Recurse -Force C:\Games   (after checking the master app timeline)"
Write-Summary $SaveTo
