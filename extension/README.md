# MinControl browser extension (Chromium MV3)

Records `web.visit`, `web.search`, `web.blocked` and `download.completed` for the managed user, applies
block rules pushed by the service, shows the Vietnamese block page, and sends a heartbeat every 60 s.
Talks only to the native host `com.mincontrol.nativehost` (`MinControl.NativeHost.exe`), which relays
to the service over `\\.\pipe\MinControl.Browser`.

## Build / test

```sh
export npm_config_cache='D:\Coding_Project\MinControl\tools\npm-cache'
npm ci
npm run build      # tsc type-check + esbuild -> dist/
npm test           # node:test on test/*.test.ts (Node >= 23 type stripping)
```

Load unpacked for development: `chrome://extensions` -> Developer mode -> Load unpacked -> `dist/`.
The unpacked id differs from the store ids; add it temporarily to the native host manifest
`allowed_origins` on the test VM only.

## Wire protocol (extension <-> native host)

Out: `{t:"hello",browser,version}`, `{t:"heartbeat",browser}`, `{t:"event",type,data}` where `type` is one of
`web.visit | web.search | web.blocked | download.completed` and `data` matches `protocol/event.schema.json`.
In: `{t:"rules",mode,block[],allow[],monitoring?:{history,downloads}}`, `{t:"ping"}`.

## Publishing (unlisted) — required because non-domain-joined Windows only force-installs store extensions

Both stores give the extension a fixed id; those ids go into `BrowserOptions.ChromeExtensionId` /
`EdgeExtensionId` (service config, not the repo) and into the native host manifest `allowed_origins`.
Do not commit a `key` in `manifest.json`.

Package: `npm run build`, then zip the **contents** of `dist/` (manifest.json at the zip root).

### Chrome Web Store
1. Register a developer account at https://chrome.google.com/webstore/devconsole (one-time USD 5 fee, 2-step verification on the Google account).
2. *New item* -> upload the zip.
3. Store listing: description, category (Family / Tools), the 128 px icon, at least one 1280x800 screenshot.
4. Privacy tab: single purpose ("parental-control companion for the MinControl Windows agent"), justify each
   permission (tabs/webNavigation: visit log; downloads: download log; nativeMessaging: talks to the local
   agent; declarativeNetRequest: blocks sites chosen by parents; storage/alarms: queue + heartbeat), declare
   that browsing activity is collected and is sent only to the local device agent / the family's own backend; privacy-policy URL.
5. Distribution -> Visibility: **Unlisted**. Submit for review.
6. After approval copy the 32-char item id -> `ChromeExtensionId`. Update URL is
   `https://clients2.google.com/service/update2/crx` (default in `BrowserOptions`).
7. Updates: bump `version` in `static/manifest.json`, rebuild, upload the new zip in the same item.

### Microsoft Edge Add-ons
1. Register at Partner Center (https://partner.microsoft.com/dashboard/microsoftedge/overview), free.
2. *Create new extension* -> upload the same zip.
3. Availability: **Hidden** (Edge's unlisted mode; reachable only via direct link / policy).
4. Properties + store listing (Vietnamese and/or English), privacy-policy URL, testing notes for reviewers
   ("needs the MinControl Windows agent; without it the extension idles").
5. Submit; after publication copy the Edge id -> `EdgeExtensionId`. Update URL is
   `https://edge.microsoft.com/extensionwebstorebase/v1/crx` (default in `BrowserOptions`).

### After both ids exist
- Put both ids in the service configuration; the service writes `ExtensionInstallForcelist` and
  generates the native host manifest with
  `allowed_origins = ["chrome-extension://<chromeId>/", "chrome-extension://<edgeId>/"]`
  (template: `windows/src/MinControl.NativeHost/com.mincontrol.nativehost.json`).
- Verify on the test VM: `edge://policy` / `chrome://policy` show the forcelist, the extension is installed
  and cannot be disabled, and the service log shows heartbeats.
