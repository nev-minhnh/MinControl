<#
.SYNOPSIS
  Publishes the Windows agent (self-contained win-x64) and builds the MinControl MSI with WiX.

.DESCRIPTION
  1. dotnet publish MinControl.Service, .Session, .NativeHost, .Setup, .Connect -> artifacts\publish\agent (one
     folder: Session must sit next to Service; the native host path is pinned by the browser pipe server).
  2. vi-VN.wxl -> artifacts\obj\vi-VN.cp1258.wxl (Vietnamese text in the form codepage 1258 can store:
     base letter + combining tone mark).
  3. dotnet build installer\MinControl.Installer.wixproj -> artifacts\msi\...\MinControl-<version>.msi, copied to
     artifacts\msi\MinControl-<version>.msi and <workspace>\release\dev\.
  4. dotnet publish windows\src\MinControl.Bootstrapper (single-file, self-contained, MSI embedded)
     -> artifacts\MinControl-Setup-<version>.exe and <workspace>\release\dev\. This is what a parent runs on the
     child's PC: install + QR pairing, no command line, no typed URL or code.

  -ServerUrl is baked in as the default of the MSI property SERVERURL, so on the child's PC nobody types a URL.
  Default: SERVER_URL= from <workspace>\tools\secrets\cloud-dev.txt (outside the repo). The URL only ends up in the
  built MSI, never in git; the repo default stays empty.

  Self-contained (not framework-dependent): the kids' PCs need no .NET runtime, and a user/admin cannot break
  the agent by uninstalling or downgrading a shared runtime. Cost: ~MSI size; all apps share one runtime
  copy because they are published into the same folder with the same SDK/runtime pack.

  Only produces files. It never installs anything on this machine.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build-msi.ps1 -Version 0.1.0
  powershell -ExecutionPolicy Bypass -File scripts\build-msi.ps1 -Version 0.1.0 -ServerUrl https://mincontrol.example.workers.dev
#>
[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [string]$Configuration = "Release",
    [string]$ServerUrl,
    [switch]$NoServerUrl,
    [switch]$SkipPublish,
    # UT1 blacklists snapshot (GitHub mirror zip, read-only, no network): hashed into the shipped category seed.
    [string]$Ut1Zip = "D:\Coding_Project\MinControl\tools\ut1\ut1-blacklists-master.zip",
    # build an MSI without the shipped category lists
    [switch]$NoCategories
)
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$workspace = Split-Path -Parent $repo
$toolsEnv = Join-Path $workspace "tools\env-dotnet.ps1"
if (Test-Path $toolsEnv) { . $toolsEnv } else { Write-Warning "tools\env-dotnet.ps1 not found; using dotnet from PATH" }

$publishDir = Join-Path $repo "artifacts\publish\agent"
$objDir = Join-Path $repo "artifacts\obj"
$msiDir = Join-Path $repo "artifacts\msi"
$releaseDir = Join-Path $workspace "release\dev"
$projects = @("MinControl.Service", "MinControl.Session", "MinControl.NativeHost", "MinControl.Setup", "MinControl.Connect")

# ------------------------------------------------------------------ server URL (baked SERVERURL default)
if ($NoServerUrl) { $ServerUrl = "" }
elseif (-not $ServerUrl) {
    $secrets = Join-Path $workspace "tools\secrets\cloud-dev.txt"
    if (Test-Path $secrets) {
        $line = Get-Content $secrets | Where-Object { $_ -match '^\s*SERVER_URL\s*=' } | Select-Object -First 1
        if ($line) { $ServerUrl = ($line -replace '^\s*SERVER_URL\s*=\s*', '').Trim().Trim('"') }
    }
}
if ($ServerUrl) {
    $ServerUrl = $ServerUrl.TrimEnd('/')
    $u = $null
    if (-not [Uri]::TryCreate($ServerUrl, [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne "https" -or $u.AbsolutePath -ne "/" -or $u.Query) {
        throw "ServerUrl must be https://host without path or query (got '$ServerUrl')"
    }
    Write-Host "SERVERURL default: $ServerUrl" -ForegroundColor Cyan
} else {
    Write-Warning "no server URL baked in: the MSI needs SERVERURL=https://... on the msiexec command line"
}

# ------------------------------------------------------------------ publish
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

# ------------------------------------------------------------------ vi-VN.wxl -> cp1258 form
# Codepage 1258 has the Vietnamese base letters (a/e/o with circumflex, a breve, o/u horn, d stroke) but most tone-marked letters only as base + combining
# mark (U+0300/0301/0303/0309/0323). Decompose, re-attach the shape marks, keep the tone marks separate.
function ConvertTo-Cp1258Form([string]$text) {
    $shapeMarks = [char[]]@([char]0x0302, [char]0x0306, [char]0x031B)
    $d = $text.Normalize([Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $d.Length) {
        $base = [string]$d[$i]; $i++
        $tones = ""
        while ($i -lt $d.Length -and [Globalization.CharUnicodeInfo]::GetUnicodeCategory($d[$i]) -eq [Globalization.UnicodeCategory]::NonSpacingMark) {
            if ($shapeMarks -contains $d[$i]) { $base = ($base + $d[$i]).Normalize([Text.NormalizationForm]::FormC) }
            else { $tones += $d[$i] }
            $i++
        }
        [void]$sb.Append($base).Append($tones)
    }
    return $sb.ToString()
}
New-Item -ItemType Directory -Force $objDir | Out-Null
$wxlSrc = Join-Path $repo "installer\vi-VN.wxl"
$wxlOut = Join-Path $objDir "vi-VN.cp1258.wxl"
$wxl = ConvertTo-Cp1258Form ([IO.File]::ReadAllText($wxlSrc, [Text.Encoding]::UTF8))
$cp1258 = [Text.Encoding]::GetEncoding(1258, [Text.EncoderFallback]::ExceptionFallback, [Text.DecoderFallback]::ExceptionFallback)
try { [void]$cp1258.GetBytes($wxl) } catch { throw "vi-VN.wxl has characters codepage 1258 cannot store: $($_.Exception.Message)" }
[IO.File]::WriteAllText($wxlOut, $wxl, (New-Object System.Text.UTF8Encoding($false)))

# ------------------------------------------------------------------ category seed (UT1 snapshot + catalog domains)
$seedDir = ""
if (-not $NoCategories) {
    if (-not (Test-Path $Ut1Zip)) { throw "UT1 snapshot not found: $Ut1Zip (pass -Ut1Zip <path> or -NoCategories)" }
    $seedDir = Join-Path $objDir "categories-seed"
    if (Test-Path $seedDir) { Remove-Item -Recurse -Force $seedDir }
    Write-Host "==> category seed from $Ut1Zip" -ForegroundColor Cyan
    & dotnet run --project (Join-Path $repo "windows\tools\MinControl.CategorySeed\MinControl.CategorySeed.csproj") -c $Configuration `
        --nologo -v q -- --zip $Ut1Zip --out $seedDir
    if ($LASTEXITCODE -ne 0) { throw "category seed failed ($LASTEXITCODE)" }
}

# ------------------------------------------------------------------ MSI
Write-Host "==> build MSI" -ForegroundColor Cyan
& dotnet build (Join-Path $repo "installer\MinControl.Installer.wixproj") -c $Configuration `
    "-p:AgentPublishDir=$publishDir" "-p:ProductVersion=$Version" "-p:DefaultServerUrl=$ServerUrl" "-p:LocalizationFile=$wxlOut" "-p:CategorySeedDir=$seedDir" `
    --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "MSI build failed ($LASTEXITCODE)" }

$name = "MinControl-$Version.msi"
$built = Get-ChildItem -Path $msiDir -Filter $name -Recurse | Where-Object { $_.DirectoryName -ne $msiDir } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $built) { throw "$name not found under $msiDir" }
$msi = Join-Path $msiDir $name
Copy-Item $built.FullName $msi -Force
New-Item -ItemType Directory -Force $releaseDir | Out-Null
Copy-Item $msi (Join-Path $releaseDir $name) -Force

# ------------------------------------------------------------------ bootstrapper MinControl-Setup-<ver>.exe
Write-Host "==> publish MinControl-Setup.exe (MSI embedded)" -ForegroundColor Cyan
$bootDir = Join-Path $repo "artifacts\bootstrapper"
if (Test-Path $bootDir) { Remove-Item -Recurse -Force $bootDir }
& dotnet publish (Join-Path $repo "windows\src\MinControl.Bootstrapper\MinControl.Bootstrapper.csproj") -c $Configuration `
    -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -p:Version=$Version "-p:EmbeddedMsi=$msi" `
    -o $bootDir --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "bootstrapper publish failed ($LASTEXITCODE)" }
$bootName = "MinControl-Setup-$Version.exe"
$boot = Join-Path $repo "artifacts\$bootName"
Copy-Item (Join-Path $bootDir "MinControl-Setup.exe") $boot -Force
Copy-Item $boot (Join-Path $releaseDir $bootName) -Force

foreach ($f in @($msi, $boot)) {
    $hash = (Get-FileHash $f -Algorithm SHA256).Hash
    Write-Host ("{0}  ({1:N1} MB)  sha256 {2}" -f $f, ((Get-Item $f).Length / 1MB), $hash) -ForegroundColor Green
}
Write-Host ("copied to {0}" -f $releaseDir) -ForegroundColor Green
