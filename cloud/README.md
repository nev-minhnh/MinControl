# MinControl cloud (Cloudflare Worker, M0 skeleton)

Layout: `src/index.ts` (router, cron stub), `src/device-hub.ts` (Durable Object stub),
`migrations/0001_init.sql` (D1 schema), `test/` (router + protocol contract tests against `../protocol`).
All API routes except `/health` return 501 until M1.

## Placeholders to fill in (never commit real values)
- `wrangler.toml`: `database_id = "<D1_DATABASE_ID>"` (from `wrangler d1 create mincontrol`).
- Secrets (`wrangler secret put <NAME>`; local dev: copy `.dev.vars.example` to `.dev.vars`):
  - `ADMIN_BOOTSTRAP_SECRET` one-time secret to register the first master key
  - `FCM_SERVICE_ACCOUNT_JSON` Firebase service account for FCM HTTP v1 pushes
- R2 bucket `mincontrol-blobs` must exist (`wrangler r2 bucket create mincontrol-blobs`).

## Commands
```
npm install
npm run typecheck
npm test
npm run dev        # wrangler dev (local only)
```
Deploy steps (`wrangler login`, `d1 migrations apply`, `deploy`) are intentionally not part of M0.
