import { applyDnrRules } from './rules.ts';
import { blockReasonFor, parseSearch, recordableUrl, type RuleSet } from './search.ts';
import { isInMessage, type BrowserId, type EventType, type MonitoringFlags, type OutMessage } from './messages.ts';

// MinControl service worker (MV3). Records web.visit / web.search / download.completed / web.blocked,
// applies block rules pushed by the native host, and sends a heartbeat every 60 s.

const HOST_NAME = 'com.mincontrol.nativehost';
const HEARTBEAT_ALARM = 'mc-heartbeat';
const QUEUE_KEY = 'mc.queue';
const RULES_KEY = 'mc.rules';
const VISITS_KEY = 'mc.visits';
const MAX_QUEUE = 500;

const browserId: BrowserId = (() => {
  const uaData = (navigator as Navigator & { userAgentData?: { brands?: { brand: string }[] } }).userAgentData;
  const brands = uaData?.brands ?? [];
  if (brands.some((b) => /edge/i.test(b.brand)) || /\bEdg\//.test(navigator.userAgent)) return 'msedge';
  return 'chrome';
})();

let rules: RuleSet = { mode: 'blocklist', block: [], allow: [] };
let monitoring: MonitoringFlags = { history: true, downloads: true };

// ---------------------------------------------------------------- native port

let port: chrome.runtime.Port | null = null;
let reconnectDelayMs = 1000;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

function connect(): void {
  if (port) return;
  try {
    port = chrome.runtime.connectNative(HOST_NAME);
  } catch {
    port = null;
    scheduleReconnect();
    return;
  }
  port.onMessage.addListener((msg: unknown) => { void onHostMessage(msg); });
  port.onDisconnect.addListener(() => {
    void chrome.runtime.lastError; // read it so Chrome does not log "unchecked runtime.lastError"
    port = null;
    scheduleReconnect();
  });
  reconnectDelayMs = 1000;
  post({ t: 'hello', browser: browserId, version: chrome.runtime.getManifest().version });
  post({ t: 'heartbeat', browser: browserId });
  void flushQueue();
}

function scheduleReconnect(): void {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => { reconnectTimer = null; connect(); }, reconnectDelayMs);
  reconnectDelayMs = Math.min(reconnectDelayMs * 2, 60_000);
}

function post(msg: OutMessage): boolean {
  if (!port) return false;
  try {
    port.postMessage(msg);
    return true;
  } catch {
    port = null;
    scheduleReconnect();
    return false;
  }
}

async function readQueue(): Promise<OutMessage[]> {
  const stored = (await chrome.storage.local.get(QUEUE_KEY))[QUEUE_KEY] as OutMessage[] | undefined;
  return stored ?? [];
}

async function emit(type: EventType, data: Record<string, unknown>): Promise<void> {
  const msg: OutMessage = { t: 'event', type, data };
  if (post(msg)) return;
  const queue = await readQueue();
  queue.push(msg);
  if (queue.length > MAX_QUEUE) queue.splice(0, queue.length - MAX_QUEUE);
  await chrome.storage.local.set({ [QUEUE_KEY]: queue });
}

async function flushQueue(): Promise<void> {
  const queue = await readQueue();
  if (queue.length === 0) return;
  let sent = 0;
  for (const m of queue) {
    if (!post(m)) break;
    sent++;
  }
  await chrome.storage.local.set({ [QUEUE_KEY]: queue.slice(sent) });
}

async function onHostMessage(msg: unknown): Promise<void> {
  if (!isInMessage(msg)) return;
  if (msg.t === 'ping') {
    post({ t: 'heartbeat', browser: browserId });
    return;
  }
  rules = { mode: msg.mode, block: msg.block, allow: msg.allow };
  if (msg.monitoring) monitoring = msg.monitoring;
  await chrome.storage.local.set({ [RULES_KEY]: { rules, monitoring } });
  await applyDnrRules(rules);
}

// ---------------------------------------------------------------- visits and durations

interface Visit { url: string; title?: string; transition?: string; activeMs: number; activeSince: number | null }

const visits = new Map<number, Visit>(); // tabId -> current visit
let activeTabId: number | null = null;
let windowFocused = true;
let persistTimer: ReturnType<typeof setTimeout> | null = null;

function persistVisits(): void {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    void chrome.storage.session.set({ [VISITS_KEY]: [...visits.entries()] });
  }, 1000);
}

function pause(v: Visit, now: number): void {
  if (v.activeSince !== null) {
    v.activeMs += Math.max(0, now - v.activeSince);
    v.activeSince = null;
  }
}

/** Only the active tab of the focused window accumulates time. */
function updateActivity(): void {
  const now = Date.now();
  for (const [tabId, v] of visits) {
    const running = windowFocused && tabId === activeTabId;
    if (running && v.activeSince === null) v.activeSince = now;
    else if (!running) pause(v, now);
  }
  persistVisits();
}

function finishVisit(tabId: number): void {
  const v = visits.get(tabId);
  if (!v) return;
  visits.delete(tabId);
  pause(v, Date.now());
  persistVisits();
  if (!monitoring.history) return;
  const data: Record<string, unknown> = { url: v.url, browser: browserId, durationSec: Math.round(v.activeMs / 1000) };
  if (v.title) data['title'] = v.title.slice(0, 512);
  if (v.transition) data['transition'] = v.transition.slice(0, 32);
  void emit('web.visit', data);
}

function startVisit(tabId: number, rawUrl: string, transition: string | undefined): void {
  finishVisit(tabId);
  const url = recordableUrl(rawUrl);
  if (!url) return;
  visits.set(tabId, { url, transition, activeMs: 0, activeSince: null });
  updateActivity();
  const hit = parseSearch(url);
  if (hit && monitoring.history) void emit('web.search', { engine: hit.engine, query: hit.query });
}

chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  startVisit(d.tabId, d.url, d.transitionType);
});

// SPA navigations (YouTube, Google result paging) change the URL without committing a new document.
chrome.webNavigation.onHistoryStateUpdated.addListener((d) => {
  if (d.frameId !== 0) return;
  const cur = visits.get(d.tabId);
  if (cur && cur.url === recordableUrl(d.url)) return;
  startVisit(d.tabId, d.url, 'history_state');
});

chrome.webNavigation.onErrorOccurred.addListener((d) => {
  if (d.frameId !== 0) return;
  let host: string;
  try {
    host = new URL(d.url).hostname;
  } catch {
    return;
  }
  if (d.error === 'net::ERR_BLOCKED_BY_CLIENT') {
    const reason = blockReasonFor(host, rules);
    if (!reason) return; // blocked by something other than our rules
    const url = recordableUrl(d.url);
    const data: Record<string, unknown> = { host: host.slice(0, 253), source: 'extension', reason };
    if (url) data['url'] = url;
    void emit('web.blocked', data);
    showBlockedPage(d.tabId, host, reason);
  } else if (d.error === 'net::ERR_TUNNEL_CONNECTION_FAILED') {
    // The filtering proxy refuses CONNECT for blocked hosts and emits web.blocked itself.
    showBlockedPage(d.tabId, host, 'proxy');
  }
});

function showBlockedPage(tabId: number, host: string, reason: string): void {
  const page = chrome.runtime.getURL(`blocked.html?host=${encodeURIComponent(host)}&reason=${encodeURIComponent(reason)}`);
  void chrome.tabs.update(tabId, { url: page }).catch(() => undefined);
}

chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  const v = visits.get(tabId);
  if (v && change.title && tab.url && recordableUrl(tab.url) === v.url) {
    v.title = change.title;
    persistVisits();
  }
});

chrome.tabs.onActivated.addListener((info) => {
  activeTabId = info.tabId;
  updateActivity();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  finishVisit(tabId);
  if (activeTabId === tabId) activeTabId = null;
});

chrome.windows.onFocusChanged.addListener((windowId) => {
  windowFocused = windowId !== chrome.windows.WINDOW_ID_NONE;
  if (!windowFocused) {
    updateActivity();
    return;
  }
  void chrome.tabs.query({ active: true, windowId }).then((tabs) => {
    activeTabId = tabs[0]?.id ?? null;
    updateActivity();
  });
});

// ---------------------------------------------------------------- downloads

chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state?.current !== 'complete' || !monitoring.downloads) return;
  void chrome.downloads.search({ id: delta.id }).then((items) => {
    const it = items[0];
    if (!it) return;
    const fileName = (it.filename.split(/[\\/]/).pop() ?? '').slice(0, 260);
    if (!fileName) return;
    const data: Record<string, unknown> = { fileName };
    const url = recordableUrl(it.finalUrl || it.url);
    if (url) data['url'] = url;
    const size = it.fileSize > 0 ? it.fileSize : it.totalBytes;
    if (Number.isInteger(size) && size >= 0) data['sizeBytes'] = size;
    void emit('download.completed', data);
  });
});

// ---------------------------------------------------------------- heartbeat and startup

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name !== HEARTBEAT_ALARM) return;
  if (!port) connect();
  post({ t: 'heartbeat', browser: browserId });
});

async function restore(): Promise<void> {
  const saved = (await chrome.storage.local.get(RULES_KEY))[RULES_KEY] as { rules: RuleSet; monitoring: MonitoringFlags } | undefined;
  if (saved) {
    rules = saved.rules;
    monitoring = saved.monitoring;
  }
  // In-progress visits survive a service-worker restart via storage.session (cleared when the browser exits).
  const stored = (await chrome.storage.session.get(VISITS_KEY))[VISITS_KEY] as [number, Visit][] | undefined;
  for (const [tabId, v] of stored ?? []) if (!visits.has(tabId)) visits.set(tabId, v);
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  activeTabId = tab?.id ?? null;
  updateActivity();
}

void chrome.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: 1 });
chrome.runtime.onStartup.addListener(() => connect());
chrome.runtime.onInstalled.addListener(() => connect());
void restore().finally(connect);
