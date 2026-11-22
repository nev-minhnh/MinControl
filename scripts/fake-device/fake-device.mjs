#!/usr/bin/env node
// Fake Windows device for MinControl QA. Node >= 22, no dependencies.
//   node fake-device.mjs enroll <code> [--server URL]
//   node fake-device.mjs run [--no-events]
//   node fake-device.mjs claim [--server URL] [--host NAME] [--no-run]   (QR pairing, API.md section 10; state-claim.json)
// State: D:\Coding_Project\MinControl\tools\fake-device\state.json (override with MC_FAKE_STATE)
//   node fake-device.mjs seal-test <pk> <in> <out>   (crypto self-test vs libsodium)
// run: also seals a test JPEG to masterSealPubKey on start (--no-screens to skip) and answers blob_request.
// Log file (optional): MC_FAKE_LOG. While running, create a file "send-events" next to state.json
// to upload another realistic event batch.
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, appendFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash, randomBytes, generateKeyPairSync, createPublicKey, diffieHellman } from 'node:crypto';

const STATE = process.env.MC_FAKE_STATE || (process.argv[2] === 'claim'
  ? 'D:/Coding_Project/MinControl/tools/fake-device/state-claim.json'
  : 'D:/Coding_Project/MinControl/tools/fake-device/state.json');
const TRIGGER = join(dirname(STATE), 'send-events');
const TRIGGER_NEW = join(dirname(STATE), 'send-new'); // new exe approvals (signed + unsigned) + a device-level tamper event
const LOGF = process.env.MC_FAKE_LOG || ''; // use a Windows path (D:/...) for node
const SID_ADMIN = 'S-1-5-21-1000000001-1000000002-1000000003-500';
const SID_BIN = 'S-1-5-21-1000000001-1000000002-1000000003-1001';
const subtle = globalThis.crypto.subtle;
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const nowIso = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');
const log = (...a) => {
  const line = `${new Date().toISOString()} ${a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')}`;
  console.log(line);
  if (LOGF) appendFileSync(LOGF, line + '\n');
};
const load = () => JSON.parse(readFileSync(STATE, 'utf8'));
const save = (s) => { mkdirSync(dirname(STATE), { recursive: true }); writeFileSync(STATE, JSON.stringify(s, null, 2)); };

const ENC = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
let ulidSeq = 0;
function ulid() {
  let t = Date.now(), ts = '';
  for (let i = 0; i < 10; i++) { ts = ENC[t % 32] + ts; t = Math.floor(t / 32); }
  const r = randomBytes(16); let rs = '';
  for (let i = 0; i < 16; i++) rs += ENC[r[i] % 32];
  ulidSeq++;
  return ts + rs;
}

function arg(name, def) { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : def; }
function readServer() {
  const t = readFileSync('D:/Coding_Project/MinControl/tools/secrets/cloud-dev.txt', 'utf8');
  return /SERVER_URL=(\S+)/.exec(t)[1];
}

async function enroll(code) {
  const server = (arg('--server') || readServer()).replace(/\/$/, '');
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const jwk = await subtle.exportKey('jwk', kp.privateKey);
  const body = {
    code: code.replace(/-/g, '').toUpperCase(), devicePubKey: b64u(pub), hostname: 'PC-BIN-FAKE',
    osVersion: '10.0.26100', agentVersion: '0.1.0',
    localUsers: [{ sid: SID_ADMIN, name: 'Ba', isAdmin: true }, { sid: SID_BIN, name: 'Bin', isAdmin: false }],
  };
  const r = await fetch(server + '/v1/enroll', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const txt = await r.text();
  if (r.status !== 201) { log('POST /v1/enroll ->', r.status, txt); process.exit(1); }
  const res = JSON.parse(txt);
  save({ server, deviceId: res.deviceId, privateJwk: jwk, publicKey: b64u(pub), masterKeys: res.masterKeys,
    masterSealPubKey: res.masterSealPubKey, lastSeq: { policy: 0, command: 0 }, policyVersion: null, policy: null,
    applied: {}, remainingMin: 72, usedMin: 48, extraMin: 0, lockedUntil: null });
  log('POST /v1/enroll ->', r.status, txt);
  log('enrolled deviceId', res.deviceId, 'pinned keys', res.masterKeys.map((k) => k.keyId + '/' + k.alg).join(','));
}

// --- envelope verification (protocol/README.md "Signing rules" step 6) ---
async function verifyEnvelope(st, env, kind) {
  const fail = (error, detail) => ({ ok: false, error, detail });
  const key = (st.masterKeys || []).find((k) => k.keyId === env.keyId);
  if (!key) return fail('unknown_key', env.keyId);
  const raw = unb64u(key.publicKey);
  const kid = createHash('sha256').update(raw).digest('hex').slice(0, 16);
  if (kid !== key.keyId) return fail('unknown_key', 'pinned keyId does not match key bytes');
  let ok = false;
  try {
    if (env.alg === 'ed25519') {
      const k = await subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
      ok = await subtle.verify({ name: 'Ed25519' }, k, unb64u(env.sig), unb64u(env.payload));
    } else if (env.alg === 'es256') {
      const k = await subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, unb64u(env.sig), unb64u(env.payload));
    }
  } catch (e) { return fail('bad_signature', String(e)); }
  if (!ok) return fail('bad_signature', 'verify=false');
  let body;
  try { body = JSON.parse(Buffer.from(env.payload, 'base64url').toString('utf8')); } catch { return fail('invalid_body', 'json'); }
  if (body.deviceId !== st.deviceId) return fail('wrong_device', body.deviceId);
  if (body.kind !== kind) return fail('invalid_body', 'kind ' + body.kind);
  const last = st.lastSeq[kind] || 0;
  if (!(body.seq > last)) return { ok: false, error: 'replayed', detail: `seq ${body.seq} <= ${last}`, body };
  const now = Date.now();
  if (now < Date.parse(body.issuedAt) - 5 * 60e3 || now >= Date.parse(body.expiresAt)) return fail('expired', `${body.issuedAt}..${body.expiresAt}`);
  return { ok: true, body, keyId: env.keyId, alg: env.alg };
}

// --- libsodium-compatible crypto_box_seal (X25519 + XSalsa20-Poly1305), Node built-ins + pure JS ---
const M64 = (1n << 64n) - 1n;
const B2IV = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n, 0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
const B2S = [[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],[12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]];
const rotr = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & M64;
// BLAKE2b, no key, single block (input <= 128 bytes), output length outLen
function blake2b(input, outLen) {
  const h = B2IV.slice(); h[0] ^= 0x01010000n ^ BigInt(outLen);
  const blk = Buffer.alloc(128); Buffer.from(input).copy(blk);
  const m = []; for (let i = 0; i < 16; i++) m.push(blk.readBigUInt64LE(i * 8));
  const v = [...h, ...B2IV]; v[12] ^= BigInt(input.length); v[14] ^= M64;
  const G = (a, b, c, d, x, y) => {
    v[a] = (v[a] + v[b] + x) & M64; v[d] = rotr(v[d] ^ v[a], 32); v[c] = (v[c] + v[d]) & M64; v[b] = rotr(v[b] ^ v[c], 24);
    v[a] = (v[a] + v[b] + y) & M64; v[d] = rotr(v[d] ^ v[a], 16); v[c] = (v[c] + v[d]) & M64; v[b] = rotr(v[b] ^ v[c], 63);
  };
  for (let r = 0; r < 12; r++) {
    const s = B2S[r % 10];
    G(0,4,8,12,m[s[0]],m[s[1]]); G(1,5,9,13,m[s[2]],m[s[3]]); G(2,6,10,14,m[s[4]],m[s[5]]); G(3,7,11,15,m[s[6]],m[s[7]]);
    G(0,5,10,15,m[s[8]],m[s[9]]); G(1,6,11,12,m[s[10]],m[s[11]]); G(2,7,8,13,m[s[12]],m[s[13]]); G(3,4,9,14,m[s[14]],m[s[15]]);
  }
  const out = Buffer.alloc(64); for (let i = 0; i < 8; i++) out.writeBigUInt64LE((h[i] ^ v[i] ^ v[i + 8]) & M64, i * 8);
  return out.subarray(0, outLen);
}
const rotl32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
function salsaRounds(x) { // 20 rounds on Uint32Array(16), in place
  const q = (a, b, c, d) => { x[b] ^= rotl32((x[a] + x[d]) >>> 0, 7); x[c] ^= rotl32((x[b] + x[a]) >>> 0, 9); x[d] ^= rotl32((x[c] + x[b]) >>> 0, 13); x[a] ^= rotl32((x[d] + x[c]) >>> 0, 18); };
  for (let i = 0; i < 10; i++) {
    q(0,4,8,12); q(5,9,13,1); q(10,14,2,6); q(15,3,7,11);
    q(0,1,2,3); q(5,6,7,4); q(10,11,8,9); q(15,12,13,14);
  }
}
const SIGMA = Buffer.from('expand 32-byte k');
function salsaInit(k, n16) { // 16 words: sigma, key, nonce/counter
  const x = new Uint32Array(16);
  for (const [i, o] of [[0, 0], [5, 4], [10, 8], [15, 12]]) x[i] = SIGMA.readUInt32LE(o);
  for (let i = 0; i < 4; i++) { x[1 + i] = k.readUInt32LE(i * 4); x[11 + i] = k.readUInt32LE(16 + i * 4); }
  for (let i = 0; i < 4; i++) x[6 + i] = n16.readUInt32LE(i * 4);
  return x;
}
function hsalsa20(k, n16) {
  const x = salsaInit(k, n16); salsaRounds(x);
  const out = Buffer.alloc(32); [0, 5, 10, 15, 6, 7, 8, 9].forEach((w, i) => out.writeUInt32LE(x[w], i * 4)); return out;
}
function salsa20Xor(data, n8, key, skip = 0) { // xor data with the Salsa20 keystream starting at byte offset 'skip'
  const total = skip + data.length; const parts = [];
  for (let ctr = 0n, len = 0; len < total; ctr++, len += 64) {
    const nonce16 = Buffer.alloc(16); n8.copy(nonce16, 0); nonce16.writeBigUInt64LE(ctr, 8);
    const x = salsaInit(key, nonce16), z = x.slice(); salsaRounds(z);
    const b = Buffer.alloc(64); for (let i = 0; i < 16; i++) b.writeUInt32LE((z[i] + x[i]) >>> 0, i * 4);
    parts.push(b);
  }
  const ks = Buffer.concat(parts), out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ ks[skip + i];
  return out;
}
function poly1305(msg, key) {
  const le = (b) => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
  const r = le(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn, s = le(key.subarray(16, 32)), P = (1n << 130n) - 5n;
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const c = msg.subarray(i, i + 16);
    acc = ((acc + le(c) + (1n << BigInt(8 * c.length))) * r) % P;
  }
  const t = (acc + s) & ((1n << 128n) - 1n);
  return Buffer.from(t.toString(16).padStart(32, '0'), 'hex').reverse();
}
function secretbox(msg, nonce24, key) { // returns mac(16) || ciphertext
  const sub = hsalsa20(key, nonce24.subarray(0, 16)), n8 = nonce24.subarray(16, 24);
  const polyKey = salsa20Xor(Buffer.alloc(32), n8, sub);
  const c = salsa20Xor(msg, n8, sub, 32);
  return Buffer.concat([poly1305(c, polyKey), c]);
}
function sealedBox(msg, recipientPk) { // sealed = epk(32) || mac(16) || ciphertext (libsodium crypto_box_seal)
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const epk = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  const peer = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(recipientPk).toString('base64url') }, format: 'jwk' });
  const shared = diffieHellman({ privateKey, publicKey: peer });
  const k = hsalsa20(shared, Buffer.alloc(16));
  const nonce = blake2b(Buffer.concat([epk, recipientPk]), 24);
  return Buffer.concat([epk, secretbox(msg, nonce, k)]);
}
const TEST_JPEG_B64 = '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';

async function run() {
  const st = load();
  const priv = await subtle.importKey('jwk', st.privateJwk, { name: 'Ed25519' }, false, ['sign']);
  let ws, token = null, stateTimer, pingTimer, trig, tickN = 0;
  const startedAt = Date.now();
  const fg = { exe: 'Minecraft.exe', title: 'Minecraft 1.21', startedAt: nowIso() };
  const send = (o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };

  function deviceState() {
    const locked = st.lockedUntil && Date.parse(st.lockedUntil) > Date.now();
    const mins = Math.floor((Date.now() - startedAt) / 60e3);
    const remaining = Math.max(0, st.remainingMin + st.extraMin - mins);
    return { ts: nowIso(), agentVersion: '0.1.0', policyVersion: st.policyVersion,
      users: [
        { sid: SID_ADMIN, loggedOn: false, active: false, locked: false, lockedUntil: null, remainingMin: null, usedMin: null, foregroundExe: null, foregroundTitle: null },
        { sid: SID_BIN, loggedOn: true, active: !locked, locked: !!locked, lockedUntil: locked ? st.lockedUntil : null,
          remainingMin: remaining, usedMin: st.usedMin + mins,
          groups: { games: { usedMin: 23 + mins, remainingMin: Math.max(0, 37 + st.extraMin - mins) } },
          foregroundExe: locked ? null : fg.exe, foregroundTitle: locked ? null : fg.title, foregroundStartedAt: locked ? null : fg.startedAt },
      ] };
  }
  function pushState() { const s = deviceState(); send({ t: 'state', state: s }); log('-> state', { remainingMin: s.users[1].remainingMin, locked: s.users[1].locked, policyVersion: s.policyVersion }); }

  function ev(type, data, sid = SID_BIN, agoSec = 0) {
    const e = { id: ulid(), deviceId: st.deviceId, ts: new Date(Date.now() - agoSec * 1000).toISOString().replace(/\.\d+Z$/, 'Z'),
      monoMs: Date.now() - startedAt + 600000, type, data };
    if (sid) e.userSid = sid;
    return e;
  }
  async function upload(events) {
    if (!token) { log('no upload token yet'); return; }
    const r = await fetch(st.server + '/v1/device/events', { method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ deviceId: st.deviceId, sentAt: nowIso(), events }) });
    log('POST /v1/device/events', events.length, 'events ->', r.status, await r.text());
  }
  // Round 3: screenshots stay on the device (sealed to masterSealPubKey), master fetches them on demand (API.md section 9)
  async function makeScreenshot() {
    const id = ulid(), day = nowIso().slice(0, 10);
    const key = `screens/${st.deviceId}/${day}/${id}.bin`;
    const sealed = sealedBox(Buffer.from(TEST_JPEG_B64, 'base64'), Buffer.from(st.masterSealPubKey, 'base64url'));
    mkdirSync(dirname(join(dirname(STATE), key)), { recursive: true });
    writeFileSync(join(dirname(STATE), key), sealed);
    log('screenshot sealed', key, sealed.length, 'bytes');
    const e = ev('screenshot.taken', { blobKey: key, width: 480, height: 270, reason: 'interval', foregroundExe: fg.exe });
    e.id = id; await upload([e]);
  }
  async function onBlobRequest(msg) {
    const { reqId, key } = msg;
    const ok = typeof key === 'string' && key.startsWith(`screens/${st.deviceId}/`) && !key.includes('..');
    const f = ok ? join(dirname(STATE), key) : null;
    if (!f || !existsSync(f)) { send({ t: 'blob_missing', reqId }); log('<- blob_request', key, '-> blob_missing'); return; }
    const r = await fetch(`${st.server}/v1/device/blobs/${key}?reqId=${encodeURIComponent(reqId)}`, { method: 'PUT',
      headers: { 'content-type': 'application/octet-stream', authorization: 'Bearer ' + token }, body: readFileSync(f) });
    log('<- blob_request', key, '-> PUT', r.status, await r.text());
  }
  function batch() {
    const exes = [['Minecraft.exe', 'games'], ['Minecraft.exe', 'games'], ['msedge.exe', 'web'], ['msedge.exe', 'web'], ['Discord.exe', 'social']];
    const evs = [ev('session.logon', { sessionId: 2 }, SID_BIN, 3600)];
    exes.forEach(([exe, group], i) => {
      const ms = new Date(Date.now() - (50 - i * 10) * 60e3); ms.setSeconds(0, 0);
      evs.push(ev('usage.tick', { minuteStart: ms.toISOString().replace(/\.\d+Z$/, 'Z'), activeSec: 60, exe, title: exe.replace('.exe', ''), group }, SID_BIN, (50 - i * 10) * 60));
    });
    evs.push(ev('web.visit', { url: 'https://www.youtube.com/watch?v=abc123', title: 'Huong dan xay nha Minecraft', browser: 'msedge', durationSec: 360 }, SID_BIN, 2400));
    evs.push(ev('web.visit', { url: 'https://vi.wikipedia.org/wiki/Minecraft', title: 'Minecraft - Wikipedia', browser: 'msedge', durationSec: 120 }, SID_BIN, 1800));
    evs.push(ev('web.search', { engine: 'google', query: 'cach chan pha trong minecraft' }, SID_BIN, 1500));
    evs.push(ev('web.blocked', { host: 'pornsite.example', url: 'https://pornsite.example/', source: 'proxy', reason: 'category', category: 'adult' }, SID_BIN, 900));
    evs.push(ev('process.blocked', { exe: 'FirefoxPortable.exe', path: 'E:\\FirefoxPortable\\FirefoxPortable.exe', pid: 4242, signed: false, rule: 'allowedBrowsers' }, SID_BIN, 600));
    evs.push(ev('request.exe_approval', { exe: 'RobloxPlayerInstaller.exe', path: 'C:\\Users\\Bin\\Downloads\\RobloxPlayerInstaller.exe', pid: 5150,
      sha256: createHash('sha256').update('fake-roblox-installer').digest('hex'), publisher: 'Roblox Corporation', signed: true, sizeBytes: 5242880 }, SID_BIN, 120));
    evs.push(ev('tamper.service_stopped', { detail: 'MinControl service stop requested by user Bin (fake)' }, null, 60));
    return evs;
  }

  async function onEnvelope(msg) {
    const env = msg.envelope;
    let peek; try { peek = JSON.parse(Buffer.from(env.payload, 'base64url').toString('utf8')); } catch { peek = {}; }
    const kind = peek.kind || 'command';
    const v = await verifyEnvelope(st, env, kind);
    log('<- envelope kind=' + kind, 'keyId=' + env.keyId, 'alg=' + env.alg, 'VERIFY', v.ok ? 'OK' : 'FAIL ' + v.error + ' ' + (v.detail || ''));
    log('   decoded body', peek);
    const body = v.body || peek;
    if (kind === 'policy') {
      if (!v.ok) { send({ t: 'policy_rejected', seq: peek.seq, error: v.error }); log('-> policy_rejected', v.error); return; }
      st.lastSeq.policy = body.seq; st.policyVersion = body.body.version ?? body.body.policyVersion ?? body.seq; st.policy = body.body;
      save(st); send({ t: 'policy_applied', version: st.policyVersion, seq: body.seq });
      log('-> policy_applied version', st.policyVersion, 'seq', body.seq); pushState(); return;
    }
    const cmd = body.body || {}; const commandId = cmd.commandId;
    if (st.applied[commandId]) { log('replay of applied command -> ack applied'); send({ t: 'ack', ack: { commandId, status: 'applied', at: nowIso() } }); return; }
    if (!v.ok) { send({ t: 'ack', ack: { commandId, status: 'rejected', at: nowIso(), error: v.error, detail: v.detail } }); log('-> ack rejected', v.error); return; }
    st.lastSeq.command = body.seq;
    if (cmd.type === 'add_time') { st.extraMin += cmd.minutes || 0; log('add_time', cmd.minutes, 'min group', cmd.group); }
    if (cmd.type === 'unlock') { st.lockedUntil = null; log('unlock'); }
    if (cmd.type === 'lock_now') { st.lockedUntil = cmd.until; log('lock_now until', cmd.until); }
    st.applied[commandId] = true; save(st);
    send({ t: 'ack', ack: { commandId, status: 'applied', at: nowIso() } });
    log('-> ack applied', commandId, cmd.type); pushState();
  }

  function connect() {
    ws = new WebSocket(st.server.replace(/^http/, 'ws') + '/v1/device/ws?deviceId=' + st.deviceId);
    ws.onopen = () => log('ws open');
    ws.onclose = (e) => { log('ws close', e.code, e.reason); clearInterval(stateTimer); clearInterval(pingTimer); clearInterval(trig); if (e.code === 4403) process.exit(2); setTimeout(connect, 5000); };
    ws.onerror = () => log('ws error');
    ws.onmessage = async (m) => {
      let msg; try { msg = JSON.parse(m.data); } catch { return; }
      if (msg.t === 'challenge') {
        const ts = Math.floor(Date.now() / 1000);
        const sig = b64u(await subtle.sign({ name: 'Ed25519' }, priv, Buffer.from(`${msg.nonce}|${st.deviceId}|${ts}`)));
        send({ t: 'auth', deviceId: st.deviceId, ts, sig }); log('-> auth ts', ts);
      } else if (msg.t === 'ready') {
        token = msg.uploadToken; log('<- ready', { serverTime: msg.serverTime, tokenExp: msg.uploadTokenExpiresAt });
        pushState();
        stateTimer = setInterval(pushState, 30000);
        pingTimer = setInterval(() => send({ t: 'ping' }), 30000);
        trig = setInterval(async () => {
          tickN++;
          if (existsSync(TRIGGER_NEW)) { try { unlinkSync(TRIGGER_NEW); } catch {} const t = Date.now().toString(36);
            await upload([
              ev('request.exe_approval', { exe: `Signed${t}.exe`, path: `C:\Users\Bin\Downloads\Signed${t}.exe`, pid: 6001, sha256: createHash('sha256').update('s' + t).digest('hex'), publisher: 'Epic Games, Inc.', signed: true, sizeBytes: 3145728 }),
              ev('request.exe_approval', { exe: `Unsigned${t}.exe`, path: `C:\Users\Bin\Downloads\Unsigned${t}.exe`, pid: 6002, sha256: createHash('sha256').update('u' + t).digest('hex'), signed: false, sizeBytes: 912000 }),
              ev('tamper.service_stopped', { detail: 'MinControl service stop requested (fake, device-level ' + t + ')' }, null),
            ]); }
          if (existsSync(TRIGGER)) { try { unlinkSync(TRIGGER); } catch {} await upload(batch()); }
          if (tickN % 30 === 0) { const ms = new Date(); ms.setSeconds(0, 0); await upload([ev('usage.tick', { minuteStart: ms.toISOString().replace(/\.\d+Z$/, 'Z'), activeSec: 60, exe: fg.exe, title: fg.title, group: 'games' })]); }
        }, 2000);
        if (!process.argv.includes('--no-screens') && !fg.screenDone) { fg.screenDone = true; await makeScreenshot(); }
        if (!process.argv.includes('--no-events') && !st.sentInitial) { st.sentInitial = true; save(st); await upload(batch()); }
      } else if (msg.t === 'envelope') await onEnvelope(msg);
      else if (msg.t === 'blob_request') await onBlobRequest(msg);
      else if (msg.t === 'token') { token = msg.uploadToken; log('<- token refreshed'); }
      else if (msg.t !== 'pong') log('<-', msg);
    };
  }
  connect();
}

// --- QR pairing (API.md section 10): device-initiated claim, then continues with run ---
async function claim() {
  const server = (arg('--server') || readServer()).replace(/\/$/, '');
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const jwk = await subtle.exportKey('jwk', kp.privateKey);
  const fp = createHash('sha256').update(pub).digest('hex').slice(0, 12);
  const body = { devicePubKey: b64u(pub), hostname: arg('--host', 'PC-BIN-FAKE'), osVersion: '10.0.26100', agentVersion: '0.1.0',
    localUsers: [{ sid: SID_ADMIN, name: 'Ba', isAdmin: true }, { sid: SID_BIN, name: 'Bin', isAdmin: false }] };
  const r = await fetch(server + '/v1/enroll/start', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const txt = await r.text();
  if (r.status !== 201) { log('POST /v1/enroll/start ->', r.status, txt); process.exit(1); }
  const { claimId, code, expiresAt } = JSON.parse(txt);
  log('POST /v1/enroll/start -> 201 claimId', claimId, 'code', code, 'expiresAt', expiresAt);
  log('PAIR_LINK mincontrol://pair?v=1&c=' + claimId + '&f=' + fp);
  log('FINGERPRINT', fp.toUpperCase().match(/.{4}/g).join('-'), 'FALLBACK_CODE', code);
  const priv = kp.privateKey;
  for (;;) {
    await new Promise((res) => setTimeout(res, 2000));
    const ts = Math.floor(Date.now() / 1000);
    const sig = b64u(await subtle.sign({ name: 'Ed25519' }, priv, Buffer.from(`poll|${claimId}|${ts}`)));
    const pr = await fetch(`${server}/v1/enroll/claim/${claimId}?ts=${ts}&sig=${sig}`);
    const pt = await pr.text();
    if (pr.status === 202) continue;
    if (pr.status === 200) {
      const res = JSON.parse(pt);
      if (res.status !== 'approved') { log('poll 200 unexpected', pt); process.exit(1); }
      save({ server, deviceId: res.deviceId, privateJwk: jwk, publicKey: b64u(pub), masterKeys: res.masterKeys,
        masterSealPubKey: res.masterSealPubKey, lastSeq: { policy: 0, command: 0 }, policyVersion: null, policy: null,
        applied: {}, remainingMin: 72, usedMin: 48, extraMin: 0, lockedUntil: null });
      log('claim APPROVED deviceId', res.deviceId, 'pinned keys', res.masterKeys.map((k) => k.keyId + '/' + k.alg).join(','));
      return true;
    }
    log('poll ->', pr.status, pt);
    process.exit(pr.status === 410 ? 3 : 1);
  }
}

const cmd = process.argv[2];
if (cmd === 'enroll') await enroll(process.argv[3]);
else if (cmd === 'claim') { await claim(); if (!process.argv.includes('--no-run')) await run(); }
else if (cmd === 'run') await run();
else if (cmd === 'seal-test') { // seal-test <recipientPkB64url> <in> <out>: self-test helper
  writeFileSync(process.argv[5], sealedBox(readFileSync(process.argv[4]), Buffer.from(process.argv[3], 'base64url'))); }
else { console.log('usage: fake-device.mjs enroll <code> | claim | run [--no-events]'); process.exit(1); }
