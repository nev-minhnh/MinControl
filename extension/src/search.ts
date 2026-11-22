// Pure helpers: search-query extraction and host matching. No chrome.* here so it is unit-testable.

export type SearchEngine = 'google' | 'bing' | 'youtube' | 'coccoc';
export interface SearchHit { engine: SearchEngine; query: string }

const MAX_QUERY = 512;

function hostIs(host: string, domain: string): boolean {
  return host === domain || host.endsWith('.' + domain);
}

/** google.com, google.com.vn, google.co.uk ... (any "google" second-level label followed by a public suffix). */
function isGoogleHost(host: string): boolean {
  return /(^|\.)google\.(com|[a-z]{2})(\.[a-z]{2})?$/.test(host) || /(^|\.)google\.co\.[a-z]{2}$/.test(host);
}

function clean(q: string | null | undefined): string | null {
  if (q == null) return null;
  const t = q.replace(/\s+/g, ' ').trim();
  if (t.length === 0) return null;
  return t.length > MAX_QUERY ? t.slice(0, MAX_QUERY) : t;
}

/** Returns the search the URL represents, or null. Handles query string and (for SPA engines) the fragment. */
export function parseSearch(rawUrl: string): SearchHit | null {
  let u: URL;
  try { u = new URL(rawUrl); } catch { return null; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  const host = u.hostname.toLowerCase();
  const path = u.pathname;
  const hashParams = new URLSearchParams(u.hash.startsWith('#') ? u.hash.slice(1) : u.hash);
  const param = (name: string): string | null => u.searchParams.get(name) ?? hashParams.get(name);

  if (hostIs(host, 'youtube.com')) {
    if (path === '/results') {
      const q = clean(param('search_query') ?? param('q'));
      return q ? { engine: 'youtube', query: q } : null;
    }
    return null;
  }
  if (isGoogleHost(host)) {
    if (path === '/search' || path === '/webhp' || path === '/') {
      const q = clean(param('q'));
      return q ? { engine: 'google', query: q } : null;
    }
    return null;
  }
  if (hostIs(host, 'bing.com')) {
    if (path === '/search' || path.startsWith('/images/search') || path.startsWith('/videos/search')) {
      const q = clean(param('q'));
      return q ? { engine: 'bing', query: q } : null;
    }
    return null;
  }
  if (hostIs(host, 'coccoc.com')) {
    if (path === '/search' || path.startsWith('/search/')) {
      const q = clean(param('query') ?? param('q'));
      return q ? { engine: 'coccoc', query: q } : null;
    }
    return null;
  }
  return null;
}

/** Lower-case host without a trailing dot and without leading "www." is NOT stripped (rules match subdomains). */
export function normalizeDomain(d: string): string {
  return d.trim().toLowerCase().replace(/^\*\./, '').replace(/^\.+/, '').replace(/\.+$/, '');
}

/** True when host equals the domain or is a subdomain of it. */
export function hostMatches(host: string, domains: readonly string[]): boolean {
  const h = normalizeDomain(host);
  for (const raw of domains) {
    const d = normalizeDomain(raw);
    if (d.length > 0 && (h === d || h.endsWith('.' + d))) return true;
  }
  return false;
}

export interface RuleSet {
  mode: 'blocklist' | 'allowlist';
  block: string[];
  allow: string[];
}

export type BlockReason = 'blocklist' | 'allowlist_miss';

/** Mirrors the DNR rule priorities built in rules.ts: explicit block > allow > allowlist catch-all. */
export function blockReasonFor(host: string, rules: RuleSet): BlockReason | null {
  if (hostMatches(host, rules.block)) return 'blocklist';
  if (hostMatches(host, rules.allow)) return null;
  return rules.mode === 'allowlist' ? 'allowlist_miss' : null;
}

/** Only http(s) URLs are recorded; strips credentials and caps the length to the schema limit. */
export function recordableUrl(raw: string | undefined): string | null {
  if (!raw) return null;
  let u: URL;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  u.username = '';
  u.password = '';
  const s = u.toString();
  return s.length > 2048 ? s.slice(0, 2048) : s;
}
