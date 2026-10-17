import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx = { Date, window: { SA: {} } };
vm.createContext(ctx);
for (const file of ['lib.js', 'session-layout.js', 'session-workbench.js']) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + file, import.meta.url), 'utf8'), ctx);
const row = (script, extra = {}) => ({ harness:'codex', event:'PreToolUse', script, handler_id:script+'-id', config_id:'v1', runs:3, errors:0, blocks:0, cancelled:0, chars:0, total_ms:0, duration_samples:0, char_samples:0, last_at:'2026-10-15T10:00:00Z', ...extra });
const scripts = rows => Array.from(rows, r=>r.script);

test('history search and outcome filters compose identically for each supported runtime', () => {
  assert.equal(typeof ctx.selectHookHistory, 'function');
  for (const harness of ['claude','codex','openclaw','hermes','opencode']) {
    const rows=[row('guard.py',{harness,errors:1}), row('guard-other.py',{harness,blocks:2}), row('cancel.py',{harness,cancelled:1})];
    assert.deepEqual(scripts(ctx.selectHookHistory(rows,{query:' GUARD ',outcome:'errors'})),['guard.py']);
    assert.deepEqual(scripts(ctx.selectHookHistory(rows,{query:'OTHER.PY-ID',outcome:'blocks'})),['guard-other.py']);
    assert.deepEqual(scripts(ctx.selectHookHistory(rows,{query:'pretooluse',outcome:'cancelled'})),['cancel.py']);
    assert.deepEqual(scripts(ctx.selectHookHistory(rows,{query:'missing'})),[]);
    assert.equal(rows[0].script,'guard.py','filtering must not reorder the retained response');
  }
});

test('measurement sorts keep unknown after measured zero and preserve partial sample totals', () => {
  assert.equal(typeof ctx.selectHookHistory, 'function');
  const rows=[row('unknown'),row('zero',{duration_samples:3,char_samples:3}),row('partial',{total_ms:50,duration_samples:1,chars:20,char_samples:1}),row('largest',{total_ms:100,duration_samples:3,chars:200,char_samples:3})];
  for(const sort of ['total_ms','chars']) assert.deepEqual(scripts(ctx.selectHookHistory(rows,{sort})),['largest','partial','zero','unknown']);
  assert.deepEqual(scripts(ctx.selectHookHistory([row('b'),row('a')],{sort:'runs'})),['a','b']);
  assert.deepEqual(scripts(ctx.selectHookHistory([row('legacy',{total_ms:10,duration_samples:undefined}),row('unknown')],{sort:'total_ms'})),['legacy','unknown']);
});

test('filtered empty history retains totals, controls and stale-read notice', () => {
  const html=ctx.sessionHooksHTML([row('guard.py')],{error:'unavailable'},null,{},null,'session',{query:'missing'});
  assert.match(html,/No hook groups match/);
  assert.match(html,/0 of 1/);
  assert.match(html,/last loaded totals/);
  assert.match(html,/data-action="hook-history-clear"/);
  assert.ok(!html.includes('No hook runs recorded'));
});
