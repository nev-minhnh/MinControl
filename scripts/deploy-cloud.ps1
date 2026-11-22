<#
.SYNOPSIS
  First-time (and repeat) deployment of the MinControl Cloudflare Worker: D1 + R2 + migrations + secrets + deploy.

.DESCRIPTION
  Runs from the repo's cloud\ folder with the pinned wrangler from cloud\package.json.
  The committed cloud\wrangler.toml only has the placeholder <D1_DATABASE_ID>. This script reads the real D1 id
  back from Cloudflare and writes it into cloud\wrangler.local.toml (git-ignored); every wrangler call then uses
  -c wrangler.local.toml. Nothing with an id, URL or secret is ever written to a tracked file.

  Steps (each idempotent):
    1. npm install (cache in ..\tools\npm-cache), wrangler login check
    2. D1 "mincontrol": create if missing, read its uuid
    3. R2 bucket "mincontrol-blobs": create if missing
    4. write cloud\wrangler.local.toml (refuses if git would track it)
    5. apply D1 migrations (--remote)
    6. wrangler deploy -> prints the *.workers.dev URL
    7. secrets: ADMIN_BOOTSTRAP_SECRET, UPLOAD_TOKEN_SECRET (generated or typed), FCM_SERVICE_ACCOUNT_JSON (file)
    8. GET /health

.PARAMETER WorkerName
  Worker script name (-> https://<WorkerName>.<subdomain>.workers.dev). Use e.g. mincontrol-dev with
  -DatabaseName mincontrol-dev -BucketName mincontrol-dev-blobs for the VM test backend.
.PARAMETER FcmServiceAccountFile
  Path to the Firebase service-account JSON. Omit to skip (no pushes) or set it later.
.PARAMETER SkipSecrets
  Do not touch secrets (repeat deploys).
.PARAMETER BootstrapSecret
  ADMIN_BOOTSTRAP_SECRET to set. When omitted: prompt if the session is interactive, otherwise generate a random one
  (printed once at the end).
.PARAMETER RotateBootstrap
  Generate and set a NEW ADMIN_BOOTSTRAP_SECRET (the recovery code is single use: run this again after it was used)
  and regenerate the recovery QR release\devecovery-qr.png (was setup-qr.png).
#>
[CmdletBinding()]
param(
    [string]$WorkerName = "mincontrol-api",
    [string]$DatabaseName = "mincontrol",
    [string]$BucketName = "mincontrol-blobs",
    [string]$FcmServiceAccountFile,
    [switch]$SkipSecrets,
    [switch]$RotateBootstrap,
    [string]$BootstrapSecret
)
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$cloud = Join-Path $repo "cloud"
$root = Split-Path -Parent $repo
$env:npm_config_cache = Join-Path $root "tools\npm-cache"
$localToml = Join-Path $cloud "wrangler.local.toml"

function Invoke-Wrangler {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$WranglerArgs)
    & npx --no-install wrangler @WranglerArgs
    if ($LASTEXITCODE -ne 0) { throw "wrangler $($WranglerArgs -join ' ') failed ($LASTEXITCODE)" }
}

function New-RandomSecret([int]$bytes = 32) {
    $b = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Set-WorkerSecret([string]$name, [string]$value) {
    # The value goes through stdin, never on the command line / history.
    # Why not `$value | wrangler ...`: Windows PowerShell 5.1 encodes piped text with $OutputEncoding and appends CRLF;
    # the Worker ended up with a leading U+FEFF (BOM) + value, so the real secret never matched (QA B1/B2).
    # So we write the exact bytes ourselves (UTF-8, no BOM, no newline) to a temp file under tools\tmp and let
    # cmd.exe stream the raw bytes into wrangler.
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = $utf8
    [Console]::OutputEncoding = $utf8
    $tmpDir = Join-Path $root "tools\tmp"
    New-Item -ItemType Directory -Force $tmpDir | Out-Null
    $tmp = Join-Path $tmpDir ("secret-" + [guid]::NewGuid().ToString("N") + ".txt")
    try {
        [System.IO.File]::WriteAllText($tmp, $value, $utf8)
        & cmd.exe /c "type `"$tmp`" | npx --no-install wrangler secret put $name -c `"$localToml`""
        if ($LASTEXITCODE -ne 0) { throw "wrangler secret put $name failed" }
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
    }
}

Push-Location $cloud
try {
    # ---------------------------------------------------------------- 1. tooling + login
    Write-Host "==> npm install (cloud)" -ForegroundColor Cyan
    & npm install --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
    & npx --no-install wrangler whoami *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "==> wrangler login (browser opens)" -ForegroundColor Cyan
        Invoke-Wrangler login
    }

    # ---------------------------------------------------------------- 2. D1
    Write-Host "==> D1 $DatabaseName" -ForegroundColor Cyan
    $dbs = (& npx --no-install wrangler d1 list --json) | Out-String | ConvertFrom-Json
    $db = $dbs | Where-Object { $_.name -eq $DatabaseName } | Select-Object -First 1
    if (-not $db) {
        Invoke-Wrangler d1 create $DatabaseName
        $dbs = (& npx --no-install wrangler d1 list --json) | Out-String | ConvertFrom-Json
        $db = $dbs | Where-Object { $_.name -eq $DatabaseName } | Select-Object -First 1
    }
    if (-not $db -or -not $db.uuid) { throw "could not read the D1 id for $DatabaseName" }
    Write-Host "    D1 id read (kept only in wrangler.local.toml)"

    # ---------------------------------------------------------------- 3. R2
    Write-Host "==> R2 $BucketName" -ForegroundColor Cyan
    $buckets = (& npx --no-install wrangler r2 bucket list) | Out-String
    if ($buckets -notmatch "(?m)name:\s+$([regex]::Escape($BucketName))\s*$") {
        Invoke-Wrangler r2 bucket create $BucketName
    } else { Write-Host "    exists" }

    # ---------------------------------------------------------------- 4. local config
    Write-Host "==> write cloud\wrangler.local.toml" -ForegroundColor Cyan
    & git -C $repo check-ignore -q "cloud/wrangler.local.toml"
    if ($LASTEXITCODE -ne 0) { throw "cloud/wrangler.local.toml is not git-ignored; refusing to write ids into a tracked file" }
    $toml = Get-Content (Join-Path $cloud "wrangler.toml") -Raw
    if ($toml -notmatch "<D1_DATABASE_ID>") { throw "wrangler.toml no longer has the <D1_DATABASE_ID> placeholder; update this script" }
    $toml = $toml.Replace('name = "mincontrol-api"', "name = `"$WorkerName`"").Replace("<D1_DATABASE_ID>", $db.uuid).Replace('database_name = "mincontrol"', "database_name = `"$DatabaseName`"").Replace('bucket_name = "mincontrol-blobs"', "bucket_name = `"$BucketName`"")
    $header = "# GENERATED by scripts/deploy-cloud.ps1 from wrangler.toml - git-ignored, never commit.`r`n"
    [System.IO.File]::WriteAllText($localToml, $header + $toml, (New-Object System.Text.UTF8Encoding $false))

    # ---------------------------------------------------------------- 5. migrations
    Write-Host "==> D1 migrations (remote)" -ForegroundColor Cyan
    Invoke-Wrangler d1 migrations apply $DatabaseName --remote -c $localToml

    # ---------------------------------------------------------------- 6. deploy
    Write-Host "==> deploy" -ForegroundColor Cyan
    $deployOut = (& npx --no-install wrangler deploy -c $localToml 2>&1) | Out-String
    Write-Host $deployOut
    if ($LASTEXITCODE -ne 0) { throw "wrangler deploy failed" }
    $url = ([regex]::Match($deployOut, "https://[a-z0-9.-]+\.workers\.dev")).Value

    # ---------------------------------------------------------------- 7. secrets
    $bootstrap = $null
    $recoveryPlain = $null
    if (-not $SkipSecrets) {
        Write-Host "==> secrets" -ForegroundColor Cyan
        $existing = (& npx --no-install wrangler secret list -c $localToml) | Out-String
        if ($existing -notmatch "UPLOAD_TOKEN_SECRET") {
            Set-WorkerSecret "UPLOAD_TOKEN_SECRET" (New-RandomSecret 48)
            Write-Host "    UPLOAD_TOKEN_SECRET set (random, not shown)"
        } else { Write-Host "    UPLOAD_TOKEN_SECRET exists (kept)" }

        if ($RotateBootstrap -or $existing -notmatch "ADMIN_BOOTSTRAP_SECRET") {
            if ($BootstrapSecret) { $plain = $BootstrapSecret.Trim() }
            elseif ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
                $typed = Read-Host "ADMIN_BOOTSTRAP_SECRET (Enter = generate a random one)" -AsSecureString
                $plain = [System.Net.NetworkCredential]::new("", $typed).Password
            } else { $plain = $null }
            if ([string]::IsNullOrWhiteSpace($plain)) { $plain = New-RandomSecret 32; $bootstrap = $plain }
            Set-WorkerSecret "ADMIN_BOOTSTRAP_SECRET" $plain
            Write-Host "    ADMIN_BOOTSTRAP_SECRET set"
            $recoveryPlain = $plain # the recovery QR (API.md section 13B) always matches the secret just set
        } else { Write-Host "    ADMIN_BOOTSTRAP_SECRET exists (kept; -RotateBootstrap to replace)" }

        if ($FcmServiceAccountFile) {
            $fcm = (Get-Content $FcmServiceAccountFile -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 10 -Compress)
            Set-WorkerSecret "FCM_SERVICE_ACCOUNT_JSON" $fcm
            Write-Host "    FCM_SERVICE_ACCOUNT_JSON set from file"
        } elseif ($existing -notmatch "FCM_SERVICE_ACCOUNT_JSON") {
            Write-Host "    FCM_SERVICE_ACCOUNT_JSON not set (no pushes). Re-run with -FcmServiceAccountFile <json>." -ForegroundColor Yellow
        }
    }

    # ---------------------------------------------------------------- 7b. recovery code QR
    if ($recoveryPlain) {
        Write-Host "==> recovery code QR (release\devecovery-qr.png)" -ForegroundColor Cyan
        $qrUrl = $url
        $secretsFile = Join-Path $root "tools\secrets\cloud-dev.txt"
        if (-not $qrUrl -and (Test-Path $secretsFile)) {
            $m = [regex]::Match((Get-Content $secretsFile -Raw), "(?m)^\s*SERVER_URL\s*=\s*(\S+)")
            if ($m.Success) { $qrUrl = $m.Groups[1].Value.Trim('"', "'") }
        }
        if (-not $qrUrl) { Write-Warning "no server URL known; recovery QR not written" }
        else {
            $qrOut = Join-Path $root "release\devecovery-qr.png"
            $env:ADMIN_BOOTSTRAP_SECRET = $recoveryPlain
            $env:SERVER_URL = $qrUrl
            try {
                & node (Join-Path $PSScriptRoot "make-setup-qr.mjs") $secretsFile $qrOut
                if ($LASTEXITCODE -ne 0) { Write-Warning "make-setup-qr.mjs failed (run npm install in scripts\ first)" }
            } finally {
                Remove-Item Env:ADMIN_BOOTSTRAP_SECRET -ErrorAction SilentlyContinue
                Remove-Item Env:SERVER_URL -ErrorAction SilentlyContinue
            }
            Write-Host "    Print recovery-qr.png and keep it safe: it works ONCE (then run -RotateBootstrap again)." -ForegroundColor Yellow
        }
    }

    # ---------------------------------------------------------------- 8. health + next steps
    if ($url) {
        try {
            $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 20
            Write-Host "==> health: $($h | ConvertTo-Json -Compress)" -ForegroundColor Green
        } catch { Write-Warning "health check failed: $($_.Exception.Message)" }
    } else { Write-Warning "could not find the workers.dev URL in the deploy output" }

    Write-Host ""
    Write-Host "Next steps (do NOT paste these values into the repo):" -ForegroundColor Green
    Write-Host "  1. Master app > Settings: server URL = $url , bootstrap secret = the ADMIN_BOOTSTRAP_SECRET above"
    if ($bootstrap) { Write-Host "     generated bootstrap secret (shown once): $bootstrap" -ForegroundColor Yellow }
    Write-Host "     The app calls POST /v1/master/register with its sign + read keys."
    Write-Host "  2. After registering, rotate: scripts\deploy-cloud.ps1 -RotateBootstrap"
    Write-Host "  3. On each PC (elevated): msiexec /i MinControl.msi SERVERURL=$url  then  MinControl.Setup enroll <CODE>"
}
finally {
    Pop-Location
}
