import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const ctx = { Date, window: { SA: {} } };
vm.createContext(ctx);
for (const file of ['lib.js', 'tab-overview.js', 'tab-sessions.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), ctx);
const at = '2026-10-09T12:00:00Z';
const evidence = Object.fromEntries(['reviews', 'interventions', 'incidents'].map(k => [k, { available: true, at_limit: false, limit: 100 }]));

test('Results keeps receipt revisions, remaining risk, and reported versus verified outcomes distinct', () => {
  const html = ctx.sessionOutcomesHTML({ session_id: 'own', history: { evidence,
    reviews: [{ id: 'review', revision: 2, context: { rule: 'sensitive-read-then-connect' }, decision: { action: 'acknowledge', revision: 1, at }, assessment: { residual_risk: 'possible-exposure' }, evidence_available: false }],
    interventions: [{ id: 'control', kind: 'pause', requested_at: at, status: 'applied', verification: 'pending', limits: ['Captured targets only'] }],
    incidents: [{ id: 'incident', remediation: { steps: [{ id: 'step', item: { name: 'Synthetic key', action: 'Revoke key' }, status: 'reported', verification: 'unverified', reported_at: at, newer_evidence: true }] } }],
  } }, {});
  for (const text of ['Reviewed', 'revision 1', 'newer evidence', 'possible-exposure', 'Source evidence unavailable', 'Applied', 'Observing up to 3 samples', 'Captured targets only', 'External action reported', 'unverified']) assert.ok(html.includes(text), text);
  assert.match(html, /data-action="open-incident"/);
  assert.ok(!html.includes('data-action="guard-resolve"'));
  assert.ok(!html.includes('All clear'));
});

test('Results shows unavailable and bounded sources without claiming empty success', () => {
  const html = ctx.sessionOutcomesHTML({ history: { reviews: [], interventions: [], incidents: [], evidence: { ...evidence, reviews: { available: false }, interventions: { available: true, at_limit: true, limit: 200 } } } }, { error: 'unavailable' });
  for (const text of ['Last known results', 'Review decisions unavailable', '200', 'may be omitted', 'Retry results']) assert.ok(html.includes(text), text);
  assert.ok(!html.includes('No saved decisions or results'));
  assert.match(ctx.sessionOutcomesHTML(null, { loading: true }), /Loading decisions and results/);
});

test('Results escapes source labels, receipt IDs, errors, and limits', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const html = ctx.sessionOutcomesHTML({ history: { evidence, reviews: [], incidents: [], interventions: [{ id: hostile, kind: hostile, requested_at: at, status: hostile, verification: hostile, error: hostile, limits: [hostile] }] } }, {});
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
});

test('an unavailable source labels retained receipts as last known and offers retry', () => {
  const html = ctx.sessionOutcomesHTML({ history: { evidence: { ...evidence, interventions: { available: false, at_limit: false, limit: 200 } }, reviews: [], incidents: [],
    interventions: [{ id: 'saved', kind: 'pause', requested_at: at, status: 'applied', verification: 'pending' }],
  } }, {});
  for (const text of ['Process results unavailable', 'Showing last known receipts', 'Applied', 'Retry results']) assert.ok(html.includes(text), text);
});

test('permission decisions retain their recorded scope without claiming it is still active', () => {
  const reviews = [{ id: 'once', revision: 1, decision: { action: 'expect', revision: 1, at } },
    { id: 'scoped', revision: 2, decision: { action: 'expect', revision: 1, at, scope_ids: ['historical-scope'] } }];
  const html = ctx.sessionOutcomesHTML({ history: { evidence, reviews, incidents: [], interventions: [] } }, {});
  for (const text of ['Expected once', 'Scoped permission recorded', 'expiry or revocation', 'newer evidence']) assert.ok(html.includes(text), text);
  assert.ok(!html.includes('Permission active'));
});
