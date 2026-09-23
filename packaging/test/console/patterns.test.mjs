// Console pattern card tests — zero dependencies. Evaluates lib.js and
// tab-findings.js in one fresh VM context, as the browser loads them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = { window: {} };
vm.createContext(ctx);
for (const f of ['lib.js', 'tab-findings.js']) {
  vm.runInContext(readFileSync(path.join(webDist, f), 'utf8'), ctx, { filename: f });
}
const { patternHTML, uncoveredFlags, patternsInView } = ctx;

const KEY = 'codex|keychain-access|/Users/x/Library/Keychains/login.keychain-db';
const hourly = Array.from({ length: 24 }, (_, i) => (i === 3 ? 323 : 0));
const pattern = (over) => ({
  key: KEY, agent: 'codex', rule: 'keychain-access', title: 'Agent touched the keychain',
  subject: { kind: 'keychain', label: '~/Library/Keychains/login.keychain-db', sub: 'keychain' },
  count: 323, unacked: 323, first: '2026-09-12T03:00:08Z', last: '2026-09-12T03:08:45Z',
  median_gap_s: 1.2, bursts: 320, cadence: 'in bursts a few seconds apart', hourly,
  pids: [40844, 51364], pid_count: 2, sessions: ['s1'], session_count: 1,
  disposition: { state: 'warning', text: 'Needs a look', why: 'Agent touched the keychain' },
  summary: 'codex touched the login keychain 323 times on Sep 12 between 03:00 and 03:08 (2 processes, 1 session), in bursts a few seconds apart.',
  actions: [
    { id: 'mute-class', label: 'Dismiss this flag class', consequence: 'c1', method: 'POST', path: '/mute', body: { rule: 'keychain-access', host: '*' } },
    { id: 'dismiss-all', label: 'Dismiss all 323 open', consequence: 'c2', method: 'POST', path: '/flags/acknowledge', body: { flag_ids: ['k1', 'k2'] } },
    { id: 'kill', label: 'Kill codex (pid 40844)', consequence: 'c3', method: 'POST', path: '/kill', body: { pid: 40844 }, recommended: true },
  ],
  flag_ids: Array.from({ length: 12 }, (_, i) => 'k' + i),
  ...over,
});
const flag = (id) => ({ id, agent: 'codex', rule: 'keychain-access', pid: 40844, ts: '2026-09-12T03:00:08Z', session_id: 's1' });

test('patternHTML: 24 bars, count, summary, open count; actions in served order, recommended first', () => {
  const html = patternHTML(pattern(), Date.parse('2026-09-23T12:00:00Z'), {});
  assert.equal((html.match(/<i class="h\d"><\/i>/g) || []).length, 24);
  assert.match(html, /<i class="h8"><\/i>/);
  assert.match(html, /class="finding pattern-card disp-warning" data-pattern-key="codex\|keychain-access\|\/Users\/x\/Library\/Keychains\/login\.keychain-db"/);
  assert.match(html, /<span class="pattern-meta">323× · /);
  assert.ok(html.includes('codex touched the login keychain 323 times on Sep 12 between 03:00 and 03:08 (2 processes, 1 session), in bursts a few seconds apart.'));
  assert.ok(html.includes('in bursts a few seconds apart · <b class="pattern-open">323 open</b>'));
  assert.ok(html.includes('<p class="finding-verdict">Needs a look: Agent touched the keychain</p>'));
  const ids = [...html.matchAll(/data-action="explain-act" data-pattern-key="[^"]+" data-action-id="([a-z-]+)"/g)].map(m => m[1]);
  assert.deepEqual(ids, ['kill', 'mute-class', 'dismiss-all']);
  assert.match(html, /<button class="btn btn-danger btn-sm" data-action="explain-act"[^>]*>Kill codex<\/button>/);
  assert.ok(!/disabled/.test(html));
  assert.ok(html.includes('<summary>Individual flags (323)</summary>'));
});

test('patternHTML: a pattern dismissed in place shows 0 open and disabled buttons', () => {
  const html = patternHTML(pattern({ dismissed: true, unacked: 0, disposition: { state: 'acknowledged', text: 'Reviewed', why: '' } }), Date.now(), {});
  assert.ok(html.includes('<b class="pattern-open">0 open</b>'));
  assert.match(html, /disp-acknowledged/);
  const buttons = html.match(/<button [^>]*data-action="explain-act"[^>]*>/g) || [];
  assert.equal(buttons.length, 3);
  assert.ok(buttons.every(b => b.includes(' disabled')));
});

test('patternHTML: the covered flags behind Details, first 10 then Show more', () => {
  const flags = Array.from({ length: 12 }, (_, i) => flag('k' + i)).concat([flag('other')]);
  const html = patternHTML(pattern(), Date.now(), { flags });
  assert.equal((html.match(/<li>/g) || []).length, 10);
  assert.ok(!html.includes('<code>other</code>'));
  assert.match(html, /data-action="show-more" data-key="pattern:codex\|keychain-access\|[^"]+">Show 2 more</);
  const open = patternHTML(pattern(), Date.now(), { flags, expanded: new Set(['pattern:' + KEY]) });
  assert.equal((open.match(/<li>/g) || []).length, 12);
});

test('uncoveredFlags: a flag a pattern covers is not its own row', () => {
  const rows = uncoveredFlags([flag('k1'), flag('k5'), flag('free')], [pattern()]);
  assert.deepEqual(rows.map(f => f.id), ['free']);
  assert.deepEqual(uncoveredFlags([flag('k1')], []).map(f => f.id), ['k1']);
});

test('patternsInView: search, agent/rule selects and session scope apply to patterns', () => {
  const ps = [pattern(), pattern({ key: 'claude|proxy-secret-leak|api.example.com', agent: 'claude', rule: 'proxy-secret-leak',
    title: 'Secret leaving in agent traffic', subject: { kind: 'connect', label: 'api.example.com' }, summary: 'claude sent a secret', sessions: ['s2'], pids: [9] })];
  const keys = o => patternsInView(ps, o).map(p => p.agent);
  assert.deepEqual(keys({}), ['codex', 'claude']);
  assert.deepEqual(keys({ term: 'api.example' }), ['claude']);
  assert.deepEqual(keys({ term: 'login.keychain' }), ['codex']);
  assert.deepEqual(keys({ agent: 'codex' }), ['codex']);
  assert.deepEqual(keys({ rule: 'proxy-secret-leak' }), ['claude']);
  assert.deepEqual(keys({ session: 's1' }), ['codex']);
  assert.deepEqual(keys({ pids: [9] }), ['claude']);
});
