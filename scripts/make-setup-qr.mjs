// Usage: node scripts/make-setup-qr.mjs [secretsFile] [outPng]
// Reads ADMIN_BOOTSTRAP_SECRET + SERVER_URL and writes a QR of
// mincontrol://setup?v=1&u=<urlencoded url>&s=<secret>. Prints nothing secret.
import { readFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import QRCode from 'qrcode';

// Forward slashes on purpose: in a JS string literal "\t", "\r", "\M" would be escape sequences.
const secretsPath = process.argv[2] ?? 'D:/Coding_Project/MinControl/tools/secrets/cloud-dev.txt';
const outPath = process.argv[3] ?? 'D:/Coding_Project/MinControl/release/dev/setup-qr.png';

const env = {};
for (const line of readFileSync(secretsPath, 'utf8').split(/\r?\n/)) {
  const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
  if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, '');
}
const secret = env.ADMIN_BOOTSTRAP_SECRET;
const url = env.SERVER_URL;
if (!secret || !url) {
  console.error('Missing ADMIN_BOOTSTRAP_SECRET or SERVER_URL in ' + secretsPath);
  process.exit(1);
}
const link = `mincontrol://setup?v=1&u=${encodeURIComponent(url)}&s=${encodeURIComponent(secret)}`;
mkdirSync(dirname(outPath), { recursive: true });
await QRCode.toFile(outPath, link, { errorCorrectionLevel: 'M', margin: 2, scale: 8 });
console.log('Wrote ' + outPath + ' (server ' + new URL(url).host + ')');
