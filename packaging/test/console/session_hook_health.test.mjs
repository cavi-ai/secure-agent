import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx = { Date, window: { SA: {} } };
vm.createContext(ctx);
for (const file of ['lib.js', 'tab-findings.js', 'session-workbench.js']) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + file, import.meta.url), 'utf8'), ctx);
const finding = (over = {}) => ({ id: 'hook:h', kind: 'execution-errors', harness: 'hermes', event: 'pre_tool_call', handler_id: 'h', config_id: 'c', title: 'Hook repeatedly failed', detail: 'Three observed errors', next_action: 'Repair the dependency, then retry', limits: ['Action outcome unknown'], count: 3, first_at: '2026-10-13T10:00:00Z', last_at: '2026-10-13T10:01:00Z', needs_action: true, ...over });
const health = (over = {}) => ({ available: true, since: '2026-10-13T09:30:00Z', until: '2026-10-13T10:00:00Z', observed_runs: 3, unattributed_runs: 0, truncated: false, findings: [finding()], ...over });

test('hook findings explain evidence, attribution, action and uncertainty', () => {
  const html = ctx.sessionHookHealthHTML(health(), {});
  for (const text of ['Hook repeatedly failed', 'Three observed errors', 'Repair the dependency', 'Action outcome unknown', 'Handler: h', 'Configuration: c', 'Needs repair']) assert.ok(html.includes(text), text);
  assert.match(ctx.sessionHookHealthHTML(health({ findings: [finding({ needs_action: false })] }), {}), /Advisory/);
});

test('hook history separates cancellation and unknown measurements', () => {
  const row = { event: 'Stop', script: '', runs: 2, errors: 0, cancelled: 2, blocks: 0, chars: 0, total_ms: 0, duration_samples: 0, char_samples: 0, last_at: '2026-10-13T10:00:00Z' };
  const html = ctx.sessionHooksHTML([row], {});
  assert.match(html, /Cancelled/);
  assert.match(html, /unknown/);
  assert.ok(!html.includes('sd-hook-failed'));
  const known = ctx.sessionHooksHTML([{ ...row, duration_samples: 2, char_samples: 2 }], {});
  assert.match(known, /0ms/);
  assert.match(known, /Cumulative runtime/);
});

test('hook assessment distinguishes unavailable, stale, empty and limited evidence', () => {
  assert.match(ctx.sessionHookHealthHTML(null, {}), /unavailable/i);
  const failed = ctx.sessionHookHealthHTML({ available: false, findings: [] }, {});
  assert.match(failed, /unavailable/i);
  assert.ok(!failed.includes('No repair'));
  assert.match(ctx.sessionHookHealthHTML(health(), { error: 'unavailable' }), /may be out of date/);
  assert.match(ctx.sessionHookHealthHTML(health({ truncated: true, unattributed_runs: 7 }), {}), /limited/);
  assert.match(ctx.sessionHookHealthHTML(health({ findings: [] }), {}), /does not establish protection coverage/);
});

test('hook evidence is validated and escaped', () => {
  assert.equal(ctx.validHookHealth(health()), true);
  assert.equal(ctx.validHookHealth(health({ findings: [finding({ count: -1 })] })), false);
  assert.equal(ctx.validHookHealth(health({ findings: [finding({ needs_action: 'yes' })] })), false);
  const html = ctx.sessionHookHealthHTML(health({ findings: [finding({ title: '<img src=x>', next_action: '<script>bad</script>', limits: ['<svg>'] })] }), {});
  assert.ok(!html.includes('<img') && !html.includes('<script>') && !html.includes('<svg>'));
});

test('attention hook action links to its durable session without approval actions', () => {
  const v = ctx.needView({ kind: 'hook', id: 'hook:h', session_id: 's', title: 'Hook failed', hook_finding: finding() }, {});
  assert.equal(v.word, 'hook repair');
  assert.equal(v.items.length, 1);
  assert.match(v.items[0].attrs, /data-action="session-current" data-session="s"/);
  assert.match(v.body(), /Repair the dependency/);
});
