import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = { Date, window: { SA: {} } };
vm.createContext(ctx);
for (const file of ['lib.js', 'tab-findings.js', 'tab-sessions.js']) vm.runInContext(readFileSync(path.join(web, file), 'utf8'), ctx, { filename: file });

test('session overview keeps review, risk and coverage limits visible', () => {
  const html = ctx.sessionOverviewHTML({ session_id: 'own', requests: [], findings: [{ id: 'f', title: 'Observed read', assessment: { risk: 'high', review_state: 'reviewed', residual_risk: 'model-exposure', reason: 'Review does not reverse exposure', limits: ['No captured payload'] } }], coverage: { guard: { state: 'observed', detail: 'Only reported outcomes' }, trace: { state: 'not-observed', detail: 'Quiet can be legitimate' }, payload: { state: 'unattributed', detail: 'Other traffic may be uninspected' } }, findings_truncated: true }, {});
  for (const text of ['Model exposure', 'Reviewed', 'Only reported outcomes', 'Quiet can be legitimate', 'Other traffic may be uninspected', 'More findings', 'Risk: high']) assert.ok(html.includes(text), text);
  assert.match(html, /data-action="open-flag" data-id="f"/);
  assert.ok(!html.includes('All clear'));
});

test('failed current-status read keeps evidence and disables live actions', () => {
  const html = ctx.sessionOverviewHTML({ session_id: 'own', requests: [{ id: 'g', detail: 'Read request' }], findings: [], resources: { key: 'r', rss_bytes: 1024, process_count: 2 } }, { error: 'unavailable' });
  assert.match(html, /Last known session status/);
  assert.match(html, /<fieldset[^>]*disabled/);
  assert.match(html, /Read request/);
  assert.match(html, /data-action="session-overview-retry"/);
});

test('first current-status failure does not imply any prior status and retry stays disabled while pending', () => {
  const first = ctx.sessionOverviewHTML(null, { error: 'unavailable' });
  assert.match(first, /Current session status unavailable/);
  assert.ok(!first.includes('Last known'));
  assert.ok(!first.includes('No retained findings'));
  const pending = ctx.sessionOverviewHTML(null, { error: 'unavailable', loading: true });
  assert.match(pending, /data-action="session-overview-retry" disabled/);
  const stale = ctx.sessionOverviewHTML({ session_id: 'own', requests: [{ id: 'g', detail: 'Read request' }], findings: [] }, { error: 'unavailable', loading: true });
  assert.match(stale, /Last known session status/);
  assert.match(stale, /<fieldset[^>]*disabled/);
  assert.match(stale, /data-action="session-overview-retry" disabled/);
});

test('overview escapes identifiers and labels at the DOM boundary', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const html = ctx.sessionOverviewHTML({ session_id: hostile, requests: [{ id: hostile, detail: hostile, path: hostile }], findings: [{ id: hostile, title: hostile, assessment: { residual_risk: hostile } }] }, {});
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
});

test('Home uses durable active sessions and links to their exact record', () => {
  const html = ctx.sessionDailyHTML([{ id: 'a', harness: 'claude', repo: 'project', status: 'active' }, { id: 'b', harness: 'claude', repo: 'project', status: 'idle' }, { id: 'old', status: 'ended' }], null);
  assert.match(html, /data-action="session-current" data-session="a"/);
  assert.match(html, /data-action="session-current" data-session="b"/);
  assert.ok(!html.includes('data-session="old"'));
  assert.match(ctx.sessionDailyHTML(null, null), /Session data unavailable/);
  assert.match(ctx.sessionDailyHTML([], null), /No live sessions/);
});

test('retained activity remains reachable when a session has no live resource family', () => {
  ctx.window.SA.sessionView = 'results';
  const html = ctx.sessionDetailHTML({ id: 'ended', status: 'ended', harness: 'codex' }, [], []);
  assert.ok(!html.includes('data-action="view-family"'));
  assert.match(html, /data-action="session-events" data-id="ended"/);
});
