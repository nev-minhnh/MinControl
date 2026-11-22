import type { RuleSet } from './search.ts';

// Wire messages between the extension and MinControl.NativeHost (native messaging JSON).
// The native host relays them 1:1 over the service pipe; the service accepts only these types.

export type BrowserId = 'msedge' | 'chrome';

export type EventType = 'web.visit' | 'web.search' | 'web.blocked' | 'download.completed';

export type OutMessage =
  | { t: 'hello'; browser: BrowserId; version: string }
  | { t: 'heartbeat'; browser: BrowserId }
  | { t: 'event'; type: EventType; data: Record<string, unknown> };

export interface MonitoringFlags { history: boolean; downloads: boolean }

export type RulesMessage = { t: 'rules'; monitoring?: MonitoringFlags } & RuleSet;
export type InMessage = RulesMessage | { t: 'ping' };

export function isInMessage(m: unknown): m is InMessage {
  if (typeof m !== 'object' || m === null) return false;
  const o = m as Record<string, unknown>;
  if (o.t === 'ping') return true;
  return o.t === 'rules'
    && (o.mode === 'blocklist' || o.mode === 'allowlist')
    && Array.isArray(o.block) && o.block.every((x) => typeof x === 'string')
    && Array.isArray(o.allow) && o.allow.every((x) => typeof x === 'string');
}
