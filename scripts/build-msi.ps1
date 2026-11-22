<#
.SYNOPSIS
  Publishes the Windows agent (self-contained win-x64) and builds the MinControl MSI with WiX.

.DESCRIPTION
  1. dotnet publish MinControl.Service, .Session, .NativeHost, .Setup -> artifacts\publish\agent (one folder:
     Session must sit next to Service; the native host path is pinned by the browser pipe server).
  2. dotnet build installer\MinControl.Installer.wixproj -> artifacts\msi\MinControl.msi

  Self-contained (not framework-dependent): the kids' PCs need no .NET runtime, and a user/admin cannot break
  the agent by uninstalling or downgrading a shared runtime. Cost: ~MSI size; all four apps share one runtime
  copy because they are published into the same folder with the same SDK/runtime pack.

  Only produces files. It never installs anything on this machine.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build-msi.ps1 -Version 0.1.0
#>
[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [string]$Configuration = "Release",
    [switch]$SkipPublish
)
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$toolsEnv = Join-Path (Split-Path -Parent $repo) "tools\env-dotnet.ps1"
if (Test-Path $toolsEnv) { . $toolsEnv } else { Write-Warning "tools\env-dotnet.ps1 not found; using dotnet from PATH" }

$publishDir = Join-Path $repo "artifacts\publish\agent"
$msiDir = Join-Path $repo "artifacts\msi"
$projects = @("MinControl.Service", "MinControl.Session", "MinControl.NativeHost", "MinControl.Setup")

if (-not $SkipPublish) {
    if (Test-Path $publishDir) { Remove-Item -Recurse -Force $publishDir }
    New-Item -ItemType Directory -Force $publishDir | Out-Null
    foreach ($p in $projects) {
        $csproj = Join-Path $repo "windows\src\$p\$p.csproj"
        Write-Host "==> publish $p" -ForegroundColor Cyan
        & dotnet publish $csproj -c $Configuration -r win-x64 --self-contained true `
            -p:PublishSingleFile=false -p:DebugType=none -p:Version=$Version `
            -o $publishDir --nologo -v q
        if ($LASTEXITCODE -ne 0) { throw "publish $p failed ($LASTEXITCODE)" }
    }
}

foreach ($exe in $projects) {
    if (-not (Test-Path (Join-Path $publishDir "$exe.exe"))) { throw "$exe.exe missing from $publishDir" }
}

Write-Host "==> build MSI" -ForegroundColor Cyan
& dotnet build (Join-Path $repo "installer\MinControl.Installer.wixproj") -c $Configuration `
    -p:AgentPublishDir=$publishDir -p:ProductVersion=$Version --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "MSI build failed ($LASTEXITCODE)" }

$msi = Get-ChildItem -Path $msiDir -Filter "MinControl.msi" -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $msi) { throw "MinControl.msi not found under $msiDir" }
$hash = (Get-FileHash $msi.FullName -Algorithm SHA256).Hash
Write-Host ("MSI: {0}  ({1:N1} MB)  sha256 {2}" -f $msi.FullName, ($msi.Length / 1MB), $hash) -ForegroundColor Green
