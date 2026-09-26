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
const { patternHTML, uncoveredFlags, patternsInView, patternAfterDismiss } = ctx;

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

test('patternHTML: the card names its processes and launchers, escaped; none when the daemon served none', () => {
  const html = patternHTML(pattern({ processes: [
    { name: 'claude', launcher: 'Claude.app › claude-code 2.1.281', count: 2 },
    { name: '<b>x</b>', count: 1 }] }), Date.parse('2026-09-12T04:00:00Z'), {});
  assert.match(html, /<p class="pattern-processes">claude-code 2\.1\.281 via Claude\.app ×2 · &lt;b&gt;x&lt;\/b&gt; ×1<\/p>/);
  assert.ok(!patternHTML(pattern({}), Date.parse('2026-09-12T04:00:00Z'), {}).includes('pattern-processes'));
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

test('patternsInView: a covered flag from a sixth session or pid admits the pattern to that scope; the flag stays hidden', () => {
  const p = pattern({ sessions: ['s1', 's2', 's3', 's4', 's5'], session_count: 6, pids: [1, 2, 3, 4, 5], pid_count: 6 });
  const other = pattern({ key: 'claude|proxy-secret-leak|api.example.com', agent: 'claude', rule: 'proxy-secret-leak',
    sessions: ['s9'], pids: [9], flag_ids: ['c1'] });
  const sixth = { ...flag('k3'), session_id: 's6', pid: 6 };
  const c1 = { ...flag('c1'), agent: 'claude', rule: 'proxy-secret-leak', session_id: 's9', pid: 9 };
  for (const scope of [{ session: 's6' }, { pids: [6] }]) {
    const inView = patternsInView([p, other], { ...scope, flags: [sixth] });
    assert.deepEqual(inView.map(x => x.key), [KEY]);
    assert.deepEqual(uncoveredFlags([sixth], inView).map(f => f.id), []);
    assert.deepEqual(uncoveredFlags([sixth, c1], inView).map(f => f.id), ['c1']);
  }
  assert.deepEqual(patternsInView([p], { session: 's6', flags: [] }).map(x => x.key), []);
  assert.deepEqual(patternsInView([p], { pids: [6], flags: [flag('free')] }).map(x => x.key), []);
});

test('patternAfterDismiss: a capped dismiss-all of 500 ids leaves 2 of 502 open and the card not dismissed', () => {
  const after = patternAfterDismiss(pattern({ count: 502, unacked: 502 }), 500);
  const html = patternHTML(after, Date.now(), {});
  assert.ok(html.includes('<b class="pattern-open">2 open</b>'));
  assert.ok(!after.dismissed);
  assert.ok(!/disabled/.test(html));
  assert.match(html, /disp-warning/);
  const rest = patternAfterDismiss(after, 2);
  assert.equal(rest.dismissed, true);
  assert.ok(patternHTML(rest, Date.now(), {}).includes('<b class="pattern-open">0 open</b>'));
});

test('muteRowHTML: an agent-scoped mute names its agent and carries it on the unmute button', () => {
  const scoped = ctx.muteRowHTML({ rule: 'keychain-access', host: '*', agent: 'codex' });
  assert.ok(scoped.includes('<span class="mute-pair">keychain-access · all hosts · codex</span>'));
  assert.match(scoped, /data-action="unmute" data-rule="keychain-access" data-host="\*" data-agent="codex"/);
  const every = ctx.muteRowHTML({ rule: 'proxy-secret-leak', host: 'api.example.com' });
  assert.ok(every.includes('<span class="mute-pair">proxy-secret-leak · api.example.com</span>'));
  assert.match(every, /data-agent=""/);
  assert.ok(ctx.muteRowHTML({ rule: 'r', host: 'h', agent: '<b>x</b>' }).includes('&lt;b&gt;x&lt;/b&gt;'));
});

test('patternHTML: the served agent-scoped mute label is the button text', () => {
  const actions = pattern().actions.map(a => a.id === 'mute-class'
    ? { ...a, label: 'Mute keychain access for codex', body: { rule: 'keychain-access', host: '*', agent: 'codex' } }
    : a);
  const html = patternHTML(pattern({ actions }), Date.parse('2026-09-23T12:00:00Z'), {});
  assert.match(html, /data-action-id="mute-class"[^>]*>Mute keychain access for codex<\/button>/);
});
