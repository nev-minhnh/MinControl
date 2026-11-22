import { test } from 'node:test';
import assert from 'node:assert/strict';
import { blockReasonFor, hostMatches, parseSearch, recordableUrl } from '../src/search.ts';
import { buildDnrRules, RULE_ALLOW, RULE_BLOCK, RULE_CATCH_ALL } from '../src/rules.ts';

test('google search on regional domains', () => {
  assert.deepEqual(parseSearch('https://www.google.com/search?q=minecraft+mods&hl=vi'), { engine: 'google', query: 'minecraft mods' });
  assert.deepEqual(parseSearch('https://www.google.com.vn/search?q=b%C3%A0i+t%E1%BA%ADp+to%C3%A1n'), { engine: 'google', query: 'bài tập toán' });
  assert.deepEqual(parseSearch('https://www.google.co.uk/search?q=x'), { engine: 'google', query: 'x' });
  assert.deepEqual(parseSearch('https://www.google.com/webhp#q=fragment+query'), { engine: 'google', query: 'fragment query' });
});

test('google non-search pages are ignored', () => {
  assert.equal(parseSearch('https://www.google.com/maps?q=hanoi'), null);
  assert.equal(parseSearch('https://mail.google.com/mail/u/0/'), null);
  assert.equal(parseSearch('https://notgoogle.example/search?q=a'), null);
});

test('bing', () => {
  assert.deepEqual(parseSearch('https://www.bing.com/search?q=roblox&form=QBLH'), { engine: 'bing', query: 'roblox' });
  assert.deepEqual(parseSearch('https://www.bing.com/images/search?q=cats'), { engine: 'bing', query: 'cats' });
  assert.equal(parseSearch('https://www.bing.com/maps?q=x'), null);
});

test('youtube', () => {
  assert.deepEqual(parseSearch('https://www.youtube.com/results?search_query=lofi+music'), { engine: 'youtube', query: 'lofi music' });
  assert.deepEqual(parseSearch('https://m.youtube.com/results?search_query=a'), { engine: 'youtube', query: 'a' });
  assert.equal(parseSearch('https://www.youtube.com/watch?v=abc'), null);
});

test('coccoc', () => {
  assert.deepEqual(parseSearch('https://coccoc.com/search?query=th%E1%BB%9Di+ti%E1%BA%BFt'), { engine: 'coccoc', query: 'thời tiết' });
  assert.deepEqual(parseSearch('https://coccoc.com/search#query=game'), { engine: 'coccoc', query: 'game' });
});

test('empty, whitespace and invalid input', () => {
  assert.equal(parseSearch('https://www.google.com/search?q=%20%20'), null);
  assert.equal(parseSearch('not a url'), null);
  assert.equal(parseSearch('chrome://settings/?search=x'), null);
  assert.deepEqual(parseSearch('https://www.bing.com/search?q=a%0A%20%20b'), { engine: 'bing', query: 'a b' });
});

test('query is capped at 512 chars', () => {
  const hit = parseSearch('https://www.google.com/search?q=' + 'a'.repeat(600));
  assert.equal(hit?.query.length, 512);
});

test('host matching covers subdomains only', () => {
  assert.ok(hostMatches('www.tiktok.com', ['tiktok.com']));
  assert.ok(hostMatches('TikTok.com', ['*.tiktok.com']));
  assert.ok(!hostMatches('nottiktok.com', ['tiktok.com']));
});

test('block reason mirrors rule priorities', () => {
  const rules = { mode: 'allowlist' as const, block: ['bad.edu.vn'], allow: ['edu.vn'] };
  assert.equal(blockReasonFor('bad.edu.vn', rules), 'blocklist');
  assert.equal(blockReasonFor('school.edu.vn', rules), null);
  assert.equal(blockReasonFor('example.com', rules), 'allowlist_miss');
  assert.equal(blockReasonFor('example.com', { ...rules, mode: 'blocklist' }), null);
});

test('recordableUrl strips credentials and skips non-http', () => {
  assert.equal(recordableUrl('https://user:pw@example.com/a'), 'https://example.com/a');
  assert.equal(recordableUrl('chrome-extension://abc/blocked.html'), null);
  assert.equal(recordableUrl('https://e.com/' + 'x'.repeat(3000))?.length, 2048);
});

test('DNR rules: blocklist and allowlist shapes', () => {
  const bl = buildDnrRules({ mode: 'blocklist', block: ['TikTok.com', 'tiktok.com', 'bad domain'], allow: [] });
  assert.equal(bl.length, 1);
  assert.equal(bl[0]?.id, RULE_BLOCK);
  assert.deepEqual(bl[0]?.condition.requestDomains, ['tiktok.com']);

  const al = buildDnrRules({ mode: 'allowlist', block: [], allow: ['edu.vn'] });
  assert.deepEqual(al.map((r) => r.id), [RULE_CATCH_ALL, RULE_ALLOW]);
  assert.ok((al[1]?.priority ?? 0) > (al[0]?.priority ?? 0));
});
