#!/usr/bin/env node
// Fake Windows device for MinControl QA. Node >= 22, no dependencies.
//   node fake-device.mjs enroll <code> [--server URL]
//   node fake-device.mjs run [--no-events]
// State: D:\Coding_Project\MinControl\tools\fake-device\state.json (override with MC_FAKE_STATE)
// Log file (optional): MC_FAKE_LOG. While running, create a file "send-events" next to state.json
// to upload another realistic event batch.
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, appendFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const STATE = process.env.MC_FAKE_STATE || 'D:/Coding_Project/MinControl/tools/fake-device/state.json';
const TRIGGER = join(dirname(STATE), 'send-events');
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
          if (existsSync(TRIGGER)) { try { unlinkSync(TRIGGER); } catch {} await upload(batch()); }
          if (tickN % 30 === 0) { const ms = new Date(); ms.setSeconds(0, 0); await upload([ev('usage.tick', { minuteStart: ms.toISOString().replace(/\.\d+Z$/, 'Z'), activeSec: 60, exe: fg.exe, title: fg.title, group: 'games' })]); }
        }, 2000);
        if (!process.argv.includes('--no-events') && !st.sentInitial) { st.sentInitial = true; save(st); await upload(batch()); }
      } else if (msg.t === 'envelope') await onEnvelope(msg);
      else if (msg.t === 'token') { token = msg.uploadToken; log('<- token refreshed'); }
      else if (msg.t !== 'pong') log('<-', msg);
    };
  }
  connect();
}

const cmd = process.argv[2];
if (cmd === 'enroll') await enroll(process.argv[3]);
else if (cmd === 'run') await run();
else { console.log('usage: fake-device.mjs enroll <code> | run [--no-events]'); process.exit(1); }
