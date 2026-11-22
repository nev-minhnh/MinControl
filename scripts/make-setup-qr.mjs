// Usage: node scripts/make-setup-qr.mjs [secretsFile] [outPng]
// Writes the "Ma khoi phuc" (recovery code, API.md section 13B) QR:
// mincontrol://setup?v=1&u=<urlencoded url>&s=<secret>. Prints nothing secret.
// ADMIN_BOOTSTRAP_SECRET / SERVER_URL come from the secrets file, or from the environment variables of the same
// names (they win; deploy-cloud.ps1 -RotateBootstrap passes them that way so the secret never hits a command line).
import { readFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import QRCode from 'qrcode';

// Forward slashes on purpose: in a JS string literal "\t", "\r", "\M" would be escape sequences.
const secretsPath = process.argv[2] ?? 'D:/Coding_Project/MinControl/tools/secrets/cloud-dev.txt';
const outPath = process.argv[3] ?? 'D:/Coding_Project/MinControl/release/dev/recovery-qr.png';

const env = {};
let fileText = '';
try { fileText = readFileSync(secretsPath, 'utf8'); } catch { /* env only */ }
for (const line of fileText.split(/\r?\n/)) {
  const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
  if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, '');
}
const secret = process.env.ADMIN_BOOTSTRAP_SECRET || env.ADMIN_BOOTSTRAP_SECRET;
const url = process.env.SERVER_URL || env.SERVER_URL;
if (!secret || !url) {
  console.error('Missing ADMIN_BOOTSTRAP_SECRET or SERVER_URL in ' + secretsPath);
  process.exit(1);
}
const link = `mincontrol://setup?v=1&u=${encodeURIComponent(url)}&s=${encodeURIComponent(secret)}`;
mkdirSync(dirname(outPath), { recursive: true });
await QRCode.toFile(outPath, link, { errorCorrectionLevel: 'M', margin: 2, scale: 8 });
console.log('Wrote ' + outPath + ' (server ' + new URL(url).host + ')');
