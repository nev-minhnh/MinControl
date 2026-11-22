import { normalizeDomain, type RuleSet } from './search.ts';

// Dynamic DNR rules built from the rule set pushed by the native host.
// Blocks use the plain "block" action (no host permissions needed); the service worker turns the resulting
// net::ERR_BLOCKED_BY_CLIENT navigation error into the friendly blocked.html page.

export const RULE_BLOCK = 1;
export const RULE_ALLOW = 2;
export const RULE_CATCH_ALL = 3;

const FRAMES = ['main_frame', 'sub_frame'] as chrome.declarativeNetRequest.ResourceType[];

function domains(list: readonly string[]): string[] {
  const out = new Set<string>();
  for (const d of list) {
    const n = normalizeDomain(d);
    if (n.length > 0 && /^[a-z0-9.-]+$/.test(n)) out.add(n);
  }
  return [...out];
}

export function buildDnrRules(rules: RuleSet): chrome.declarativeNetRequest.Rule[] {
  const out: chrome.declarativeNetRequest.Rule[] = [];
  const block = domains(rules.block);
  const allow = domains(rules.allow);
  if (rules.mode === 'allowlist') {
    out.push({
      id: RULE_CATCH_ALL, priority: 1,
      action: { type: 'block' as chrome.declarativeNetRequest.RuleActionType },
      condition: { regexFilter: '^https?://', resourceTypes: FRAMES },
    });
  }
  if (allow.length > 0) {
    out.push({
      id: RULE_ALLOW, priority: 2,
      action: { type: 'allow' as chrome.declarativeNetRequest.RuleActionType },
      condition: { requestDomains: allow, resourceTypes: FRAMES },
    });
  }
  if (block.length > 0) {
    out.push({
      id: RULE_BLOCK, priority: 3,
      action: { type: 'block' as chrome.declarativeNetRequest.RuleActionType },
      condition: { requestDomains: block, resourceTypes: FRAMES },
    });
  }
  return out;
}

export async function applyDnrRules(rules: RuleSet): Promise<void> {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((r) => r.id),
    addRules: buildDnrRules(rules),
  });
}
