# Shared helpers for the VM test scripts (dot-source: . "$PSScriptRoot\_common.ps1").
# These scripts run INSIDE the Hyper-V test VM only. Windows PowerShell 5.1 compatible.

$script:Results = New-Object System.Collections.Generic.List[object]

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-IsAdmin)) { Write-Host "Run this script from an elevated PowerShell (admin account)." -ForegroundColor Red; exit 3 }
}

function Assert-NotAdmin {
    if (Test-IsAdmin) {
        Write-Host "Run this script as the MANAGED STANDARD user (not elevated, not admin)." -ForegroundColor Red; exit 3
    }
}

# Record one check. $Ok = $true -> PASS, $false -> FAIL, $null -> INFO/MANUAL.
function Write-Result {
    param([string]$Id, [string]$Name, $Ok, [string]$Detail = "", [string]$Hint = "")
    $status = if ($Ok -eq $true) { "PASS" } elseif ($Ok -eq $false) { "FAIL" } else { "INFO" }
    $color = @{ PASS = "Green"; FAIL = "Red"; INFO = "Yellow" }[$status]
    Write-Host ("[{0}] {1,-7} {2}" -f $status, $Id, $Name) -ForegroundColor $color
    if ($Detail) { Write-Host "        $Detail" }
    if ($status -eq "FAIL" -and $Hint) { Write-Host "        hint: $Hint" -ForegroundColor DarkYellow }
    $script:Results.Add([pscustomobject]@{ Id = $Id; Name = $Name; Status = $status; Detail = $Detail })
}

function Write-Summary {
    param([string]$SaveTo)
    $pass = @($script:Results | Where-Object Status -eq "PASS").Count
    $fail = @($script:Results | Where-Object Status -eq "FAIL").Count
    $info = @($script:Results | Where-Object Status -eq "INFO").Count
    Write-Host ""
    Write-Host ("Summary: {0} PASS, {1} FAIL, {2} INFO/manual" -f $pass, $fail, $info) -ForegroundColor $(if ($fail) { "Red" } else { "Green" })
    if ($SaveTo) {
        $script:Results | Export-Csv -NoTypeInformation -Path $SaveTo -Encoding UTF8
        Write-Host "Results saved to $SaveTo"
    }
    if ($fail) { exit 1 } else { exit 0 }
}

# Runs an external program with a timeout; returns @{ Code; Out; TimedOut }.
function Invoke-Exe {
    param([string]$File, [string[]]$Arguments, [int]$TimeoutSec = 20)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    try { $p = [System.Diagnostics.Process]::Start($psi) } catch { return @{ Code = -1; Out = $_.Exception.Message; TimedOut = $false } }
    $outTask = $p.StandardOutput.ReadToEndAsync(); $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        return @{ Code = -2; Out = "timeout after $TimeoutSec s"; TimedOut = $true }
    }
    return @{ Code = $p.ExitCode; Out = ($outTask.Result + $errTask.Result).Trim(); TimedOut = $false }
}

$script:Curl = Join-Path $env:SystemRoot "System32\curl.exe"
$script:InstallDir = Join-Path $env:ProgramFiles "MinControl"
$script:DataDir = Join-Path $env:ProgramData "MinControl"
