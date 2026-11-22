# Runbook — deploy the cloud backend (Cloudflare Worker + D1 + R2)

Script: `scripts/deploy-cloud.ps1` (idempotent; safe to re-run for every deploy).
The repo is public (SPEC §12.5): **no account id, database id, Worker URL or secret is ever committed.**

## What the script does
| Step | Command (inside `cloud/`) | Notes |
|---|---|---|
| 1 | `npm install`, `wrangler whoami` / `wrangler login` | npm cache in `..\tools\npm-cache`; wrangler version pinned in `cloud/package.json` |
| 2 | `wrangler d1 list --json` → `wrangler d1 create <db>` if missing | the D1 uuid is read back from Cloudflare |
| 3 | `wrangler r2 bucket list` → `wrangler r2 bucket create <bucket>` if missing | |
| 4 | writes `cloud/wrangler.local.toml` | copy of `wrangler.toml` with the real `database_id` (+ worker/db/bucket names). Git-ignored (root `.gitignore`); the script refuses to write it if `git check-ignore` says it would be tracked |
| 5 | `wrangler d1 migrations apply <db> --remote -c wrangler.local.toml` | applies `cloud/migrations/*.sql` not yet applied |
| 6 | `wrangler deploy -c wrangler.local.toml` | prints the `https://<worker>.<subdomain>.workers.dev` URL |
| 7 | `wrangler secret put …` via stdin | `UPLOAD_TOKEN_SECRET` random (only if missing), `ADMIN_BOOTSTRAP_SECRET` typed or random (only if missing or `-RotateBootstrap`), `FCM_SERVICE_ACCOUNT_JSON` from `-FcmServiceAccountFile` |
| 8 | `GET <url>/health` | expects `{"ok":true}` |

Secrets never touch the command line, the repo or a file; a generated bootstrap secret is printed **once**.

## First deployment
```powershell
cd D:\Coding_Project\MinControl\<branch>
# production backend
powershell -ExecutionPolicy Bypass -File scripts\deploy-cloud.ps1 -FcmServiceAccountFile D:\secrets\fcm.json
# separate dev backend for the Hyper-V VM tests (own D1 + R2, can be wiped freely)
powershell -ExecutionPolicy Bypass -File scripts\deploy-cloud.ps1 -WorkerName mincontrol-dev -DatabaseName mincontrol-dev -BucketName mincontrol-dev-blobs
```
Keep the Firebase JSON outside the repo (e.g. `D:\secrets\`). Without it the Worker runs but sends no pushes.

## Register the master app (once per backend)
1. Phone: master app → Settings → server URL = the printed `workers.dev` URL, bootstrap secret = the
   `ADMIN_BOOTSTRAP_SECRET` (typed or the one printed once).
2. The app generates its `sign` (biometric) and `read` keys and calls `POST /v1/master/register`
   (`{"bootstrapSecret","keys":[…],"sealPubKey"}`) → `201 {"keys":[…]}`. `403 forbidden` = wrong secret.
3. Rotate the bootstrap secret right after: `scripts\deploy-cloud.ps1 -RotateBootstrap` (Enter = random,
   do not write it down unless you plan to re-register a new phone). Re-registering replaces all master keys;
   enrolled devices keep the keys pinned at enrolment until re-enrolled.

## Re-deploy after code changes
```powershell
powershell -ExecutionPolicy Bypass -File scripts\deploy-cloud.ps1 -SkipSecrets      # migrations + deploy
```
For the dev backend repeat the same `-WorkerName/-DatabaseName/-BucketName` arguments (each run rewrites
`wrangler.local.toml` for that backend).

## Manual equivalent (if the script fails)
```powershell
cd cloud
$env:npm_config_cache = "..\..\tools\npm-cache"
npm install
npx wrangler login
npx wrangler d1 create mincontrol            # note the database_id (do NOT commit it)
npx wrangler r2 bucket create mincontrol-blobs
copy wrangler.toml wrangler.local.toml        # put the database_id into wrangler.local.toml only
npx wrangler d1 migrations apply mincontrol --remote -c wrangler.local.toml
npx wrangler deploy -c wrangler.local.toml
npx wrangler secret put UPLOAD_TOKEN_SECRET -c wrangler.local.toml
npx wrangler secret put ADMIN_BOOTSTRAP_SECRET -c wrangler.local.toml
npx wrangler secret put FCM_SERVICE_ACCOUNT_JSON -c wrangler.local.toml   # JSON on one line
```

## Troubleshooting
| Symptom | Fix |
|---|---|
| `wrangler d1 list --json` fails / not logged in | `npx wrangler login` (browser), or set `CLOUDFLARE_API_TOKEN` in the shell (never in a file in the repo) |
| `wrangler.toml no longer has the <D1_DATABASE_ID> placeholder` | someone committed a real id: revert that, rotate nothing (ids are not secrets, but the repo must stay clean) |
| deploy OK, `/health` fails | wait 30 s (DNS for a new `workers.dev` subdomain), check `npx wrangler tail -c wrangler.local.toml` |
| devices enrol but uploads fail | `UPLOAD_TOKEN_SECRET` missing → re-run without `-SkipSecrets` |
| D1 write limits (free tier) | SPEC §9: budget fallback is Workers Paid |

## Then: devices
On each PC (elevated), see `docs/runbooks/vm-test.md` §4:
`msiexec /i MinControl.msi SERVERURL=https://<worker>.workers.dev CHROMEEXTID=<id> EDGEEXTID=<id>` then
`"C:\Program Files\MinControl\MinControl.Setup.exe" enroll <CODE>`.
