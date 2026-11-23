<#
.SYNOPSIS
  Builds the Windows deliverables of MinControl <Version> and publishes GitHub release v<Version> on nev-minhnh/MinControl.

.DESCRIPTION
  1. scripts\build-msi.ps1 -Version <Version> (agent publish -> MinControl-<ver>.msi -> MinControl-Setup-<ver>.exe with
     the MSI embedded). Extra switches: -SkipCategoryDownload (default on: reuse the cached category seed), -ServerUrl.
  2. Collects into artifacts\release\<ver>\:
       MinControl-Setup-<ver>.exe, MinControl-<ver>.msi, MinControl-master-<ver>.apk (copied from -ApkPath), SHA256SUMS
     SHA256SUMS uses the sha256sum format ("<hex>  <name>", LF line endings) so `sha256sum -c SHA256SUMS` works.
  3. gh release create v<ver> --repo nev-minhnh/MinControl --title "MinControl <ver>" --notes-file <NotesFile> <files>
     (-Draft / -Prerelease pass through; -SkipGitHub stops after step 2). Fails if the release already exists.

  Never installs anything on this machine. Needs `gh` signed in with push rights to the repository.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -Version 0.4.0 `
      -ApkPath D:\Coding_Project\MinControl\release\dev\MinControl-master-0.4.0.apk -NotesFile docs\release-notes\0.4.0.md
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    # signed release APK of the master app (copied as MinControl-master-<ver>.apk)
    [Parameter(Mandatory = $true)][string]$ApkPath,
    # markdown release notes
    [Parameter(Mandatory = $true)][string]$NotesFile,
    [string]$Repo = "nev-minhnh/MinControl",
    [string]$ServerUrl,
    [bool]$SkipCategoryDownload = $true,
    # reuse artifacts\MinControl-<ver>.msi / MinControl-Setup-<ver>.exe from an earlier build-msi.ps1 run
    [switch]$SkipBuild,
    [switch]$SkipGitHub,
    [switch]$Draft,
    [switch]$Prerelease
)
$ErrorActionPreference = "Stop"

$repoDir = Split-Path -Parent $PSScriptRoot
$tag = "v$Version"

foreach ($f in @($ApkPath, $NotesFile)) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "not found: $f" }
}
$ApkPath = (Resolve-Path -LiteralPath $ApkPath).Path
$NotesFile = (Resolve-Path -LiteralPath $NotesFile).Path
if ([IO.Path]::GetExtension($ApkPath) -ne ".apk") { throw "ApkPath must be an .apk file: $ApkPath" }

if (-not $SkipGitHub) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "gh (GitHub CLI) not found on PATH" }
    # Run through cmd.exe: Windows PowerShell 5.1 turns a native command's stderr into a terminating error under
    # $ErrorActionPreference = "Stop", and "release not found" is the EXPECTED answer here.
    cmd /c "gh auth status >nul 2>nul"
    if ($LASTEXITCODE -ne 0) { throw "gh is not signed in (gh auth login)" }
    cmd /c "gh release view $tag --repo $Repo >nul 2>nul"
    if ($LASTEXITCODE -eq 0) { throw "release $tag already exists on $Repo" }
}

# ------------------------------------------------------------------ build MSI + Setup.exe
$msi = Join-Path $repoDir "artifacts\msi\MinControl-$Version.msi"
$setup = Join-Path $repoDir "artifacts\MinControl-Setup-$Version.exe"
if (-not $SkipBuild) {
    $buildArgs = @{ Version = $Version }
    if ($SkipCategoryDownload) { $buildArgs.SkipCategoryDownload = $true }
    if ($ServerUrl) { $buildArgs.ServerUrl = $ServerUrl }
    & (Join-Path $PSScriptRoot "build-msi.ps1") @buildArgs
    if (-not $?) { throw "build-msi.ps1 failed" }
}
foreach ($f in @($msi, $setup)) { if (-not (Test-Path -LiteralPath $f)) { throw "build output missing: $f" } }

# ------------------------------------------------------------------ stage + SHA256SUMS
$stage = Join-Path $repoDir "artifacts\release\$Version"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null
$files = [ordered]@{
    "MinControl-Setup-$Version.exe"  = $setup
    "MinControl-$Version.msi"        = $msi
    "MinControl-master-$Version.apk" = $ApkPath
}
$sums = New-Object System.Text.StringBuilder
foreach ($name in $files.Keys) {
    $dest = Join-Path $stage $name
    Copy-Item -LiteralPath $files[$name] -Destination $dest -Force
    $hash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLowerInvariant()
    [void]$sums.Append("$hash  $name`n")
    Write-Host ("{0,-34} {1,8:N1} MB  {2}" -f $name, ((Get-Item $dest).Length / 1MB), $hash)
}
$sumsPath = Join-Path $stage "SHA256SUMS"
[IO.File]::WriteAllText($sumsPath, $sums.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "staged in $stage" -ForegroundColor Green

if ($SkipGitHub) { Write-Host "-SkipGitHub: release not created" -ForegroundColor Yellow; return }

# ------------------------------------------------------------------ GitHub release
$assets = @($files.Keys | ForEach-Object { Join-Path $stage $_ }) + $sumsPath
$ghArgs = @("release", "create", $tag, "--repo", $Repo, "--title", "MinControl $Version", "--notes-file", $NotesFile)
if ($Draft) { $ghArgs += "--draft" }
if ($Prerelease) { $ghArgs += "--prerelease" }
$prevEap = $ErrorActionPreference; $ErrorActionPreference = "Continue"   # gh prints upload progress on stderr
& gh @ghArgs @assets 2>&1 | ForEach-Object { "$_" }
$ghExit = $LASTEXITCODE; $ErrorActionPreference = $prevEap
if ($ghExit -ne 0) { throw "gh release create failed ($ghExit)" }
Write-Host "released $tag on $Repo" -ForegroundColor Green
