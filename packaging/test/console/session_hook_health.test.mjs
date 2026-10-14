import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx = { Date, window: { SA: {} } };
vm.createContext(ctx);
for (const file of ['lib.js', 'tab-findings.js', 'session-workbench.js']) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + file, import.meta.url), 'utf8'), ctx);
const finding = (over = {}) => ({ id: 'hook:h', kind: 'execution-errors', harness: 'hermes', event: 'pre_tool_call', handler_id: 'h', config_id: 'c', title: 'Hook repeatedly failed', detail: 'Three observed errors', next_action: 'Repair the dependency, then retry', limits: ['Action outcome unknown'], count: 3, first_at: '2026-10-13T10:00:00Z', last_at: '2026-10-13T10:01:00Z', needs_action: true, ...over });
const health = (over = {}) => ({ available: true, since: '2026-10-13T09:30:00Z', until: '2026-10-13T10:00:00Z', observed_runs: 3, unattributed_runs: 0, truncated: false, findings: [finding()], ...over });

test('all harnesses separate source, capture, delivery and persistence health', () => {
  for (const harness of ['claude', 'codex', 'openclaw', 'hermes', 'opencode']) {
    const report = { type: 'hook_forwarder', version: 2, harness, forwarder_id: 'host-1', sequence: 1,
      ts: '2026-10-13T10:00:00Z', state: 'error', pending: 3, delivery_failures: 2, dropped: 1,
      health: { source_state: 'connected', capture_error: 'unsupported-protocol', delivery_error: 'recorder-unavailable', report_error: false,
        outbox: { persisted: 2, recovered: 1, error: 'outbox-full' } } };
    const row = { report, received_at: '2026-10-13T10:00:01Z', freshness: 'recent' };
    assert.equal(ctx.validHookForwarder(row), true, harness);
    const html = ctx.hookForwardersHTML([row], false);
    for (const text of ['Source connected', 'unsupported-protocol', 'recorder-unavailable', 'outbox-full', '2 persisted', '1 recovered', 'original delivery IDs']) assert.ok(html.includes(text), harness + ': ' + text);
    const stale = ctx.hookForwardersHTML([{ ...row, freshness: 'stale' }], false);
    assert.ok(!stale.includes('Source connected'), harness);
    assert.match(stale, /current connection state unknown/);
    const recovered = { ...row, report: { ...report, state: 'connected', pending: 0, health: { source_state: 'connected', report_error: false, outbox: { persisted: 0, recovered: 1 } } } };
    const after = ctx.hookForwardersHTML([recovered], false);
    assert.ok(!after.includes('recorder-unavailable') && !after.includes('outbox-full'));
    assert.match(after, /2 delivery failures/);
    assert.match(after, /1 dropped/);
    assert.equal(ctx.validHookForwarder({ ...row, report: { ...report, health: { ...report.health, capture_error: '<script>' } } }), false);
    assert.equal(ctx.validHookForwarder({ ...row, report: { ...report, state: 'connected' } }), false);
    assert.equal(ctx.validHookForwarder({ ...row, report: { ...report, health: { ...report.health, outbox: { persisted: 4, recovered: 1 } } } }), false);
  }
});

test('host health reports qualify freshness, attribution and delivery evidence', () => {
  const report = { type: 'hook_forwarder', version: 1, harness: 'codex', forwarder_id: 'bridge-1', sequence: 2, ts: '2026-10-13T10:00:00Z', state: 'error', pending: 3, delivery_failures: 2, dropped: 1 };
  const row = { report, received_at: '2026-10-13T10:00:01Z', freshness: 'recent' };
  assert.equal(ctx.validHookForwarder(row), true);
  assert.equal(ctx.validHookForwarder({ ...row, report: { ...report, pending: null } }), false);
  assert.equal(ctx.validHookForwarder({ ...row, freshness: 'healthy' }), false);
  const html = ctx.hookForwardersHTML([row], false);
  for (const text of ['Host reports', '3 queued', '2 delivery failures', '1 dropped', 'original delivery IDs', 'not establish complete delivery']) assert.ok(html.includes(text), text);
  const stale = ctx.hookForwardersHTML([{ ...row, freshness: 'stale', report: { ...report, state: 'connected' } }], false);
  assert.match(stale, /current connection state unknown/i);
  assert.ok(!stale.includes('Source connected'));
  assert.ok(!ctx.hookForwardersHTML([{ ...row, report: { ...report, state: 'connected' } }], false, true).includes('Source connected'));
  assert.match(ctx.hookForwardersHTML([{ ...row, freshness: 'unverified' }], true), /freshness unverified/i);
  assert.match(ctx.hookForwardersHTML([], false), /unknown/i);
  const hostile = ctx.hookForwardersHTML([{ ...row, report: { ...report, forwarder_id: '<img>', session_id: '<svg>' } }], false);
  assert.ok(!hostile.includes('<img>') && !hostile.includes('<svg>'));
});

test('ingestion diagnostics distinguish receipt, rejection and unknown connectivity', () => {
  const ingestion = { available: true, since: '2026-10-13T09:30:00Z', rejected: 2, last_rejected_at: '2026-10-13T10:00:00Z', harnesses: [{ harness: 'codex', accepted: 4, last_received_at: '2026-10-13T10:00:00Z' }] };
  assert.equal(ctx.validHookIngestion(ingestion), true);
  assert.equal(ctx.validHookIngestion({ ...ingestion, harnesses: [{ ...ingestion.harnesses[0], accepted: -1 }] }), false);
  assert.equal(ctx.validHookIngestion({ ...ingestion, harnesses: [{ ...ingestion.harnesses[0], harness: '<img>' }] }), false);
  const html = ctx.hookIngestionHTML(ingestion, {});
  for (const text of ['all sessions', '4 accepted deliveries', '2 rejected', 'connectivity is unknown', 'local receipt', 'recorder', '2026-10-13T10:00:00Z']) assert.ok(html.includes(text), text);
  assert.match(ctx.hookIngestionHTML(ingestion, { error: 'failed' }), /may be out of date/);
  assert.match(ctx.hookIngestionHTML({ ...ingestion, rejected: 0, last_rejected_at: undefined, harnesses: [] }, {}), /No hook deliveries observed/);
  assert.match(ctx.hookIngestionHTML(null, {}), /unavailable/i);
});

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
