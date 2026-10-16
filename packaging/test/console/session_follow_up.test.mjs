import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const c = { Date, window: { SA: {} } };
vm.createContext(c);
for (const file of ['lib.js', 'tab-overview.js', 'session-workbench.js', 'decision-permissions.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), c);
const at = '2026-10-16T12:00:00Z';
const evidence = Object.fromEntries(['reviews', 'interventions', 'incidents', 'guards'].map(k => [k, { available: true, at_limit: false, limit: 100 }]));
const history = update => ({ session_id: 'own', observed_at: at, history: { evidence, reviews: [], interventions: [], incidents: [], guards: [], ...update } });
const review = update => ({ id: 'review', revision: 2, context: { rule: 'Sensitive read' }, decision: { action: 'acknowledge', revision: 1, at }, evidence_flag_id: 'flag', evidence_available: true, evidence_flag_available: true, ...update });
const scope = { id: 'scope', kind: 'guard', agent: 'claude', rule_id: 'credentials', operation: 'guard:Read', resource_path: '/workspace/.env', created_at: at, expires_at: '2026-10-17T12:00:00Z', applicability: { label: 'Time-bounded grant', revoke: true } };

test('follow-up precedes receipts and links newer evidence without replaying a decision', () => {
  const data = history({ reviews: [review()] });
  const html = c.sessionOutcomesHTML(data, {});
  assert.ok(html.indexOf('Needs follow-up') < html.indexOf('Decisions and results'));
  assert.match(html, /New evidence/);
  assert.match(html, /revision 1.*revision 2/s);
  assert.match(html, /data-action="open-flag" data-id="flag"/);
  assert.doesNotMatch(html, /data-action="guard-resolve"|data-action="review-decide"/);
  assert.doesNotMatch(c.sessionFollowUpHTML(history({ reviews: [review({ revision: 1 })] }), {}), /Review newer evidence/);
});

test('follow-up distinguishes pending and failed controls from observations and unverified reports', () => {
  const data = history({ interventions: [
    { id: 'pending', kind: 'pause', status: 'applied', verification: 'pending' },
    { id: 'failed', kind: 'terminate', status: 'failed', verification: 'unknown' },
    { id: 'observed', kind: 'pause', status: 'applied', verification: 'observed' },
    { id: 'verified', kind: 'terminate', status: 'applied', verification: 'verified', verified_by: 'captured-family-absent' },
  ], incidents: [{ id: 'incident', remediation: { steps: [{ id: 'step', item: { name: 'API key', action: 'Revoke' }, status: 'reported', verification: 'unverified', newer_evidence: true }] } }] });
  const html = c.sessionFollowUpHTML(data, {});
  assert.match(html, /Observing up to 3 samples/);
  assert.match(html, /Failed/);
  assert.match(html, /not technically verified/);
  assert.match(html, /data-action="open-incident" data-id="incident"/);
  assert.doesNotMatch(html, /data-follow-up-id="(observed|verified)"/);
});

test('linked permissions use only receipt IDs and fresh records, never infer revocation from absence', () => {
  const data = history({ guards: [{ id: 'guard', session_id: 'own', rule_id: 'credentials', verdict: 'allow', scope: 'session', at, scope_ids: ['scope', 'missing'] }] });
  const html = c.sessionFollowUpHTML(data, { permissions: { records: [scope, { ...scope, id: 'unrelated', resource_path: '/unrelated' }], readAt: at } });
  for (const text of ['Time-bounded grant', '/workspace/.env', '2026-10-17', 'Current status unknown', 'Inspect permissions', 'session-guard-permissions']) assert.ok(html.includes(text), text);
  assert.doesNotMatch(html, /unrelated|data-action="session-permission-revoke"/);
  const unavailable = c.sessionFollowUpHTML(data, { permissions: { records: null, error: 'unavailable' } });
  assert.match(unavailable, /Permission status unavailable/);
  assert.doesNotMatch(unavailable, /Time-bounded grant/);
});

test('stale, partial and bounded histories keep uncertainty visible and suppress stale evidence links', () => {
  const data = history({ reviews: [review()], evidence: { ...evidence, reviews: { available: false, at_limit: true, limit: 100 } } });
  const html = c.sessionFollowUpHTML(data, { error: 'unavailable' });
  assert.match(html, /Last known follow-up/);
  assert.match(html, /data-action="session-outcomes-retry"/);
  assert.doesNotMatch(html, /data-action="open-flag"/);
  assert.match(c.sessionFollowUpHTML(data, {}), /missing or bounded/i);
  const noSource = c.sessionFollowUpHTML(history({ reviews: [review({ evidence_flag_available: false })] }), {});
  assert.match(noSource, /Source evidence unavailable/);
  assert.doesNotMatch(noSource, /data-action="open-flag"/);
  assert.doesNotMatch(c.sessionFollowUpHTML(history({}), {}), /All clear|Safe|protected/);
});

test('follow-up escapes external labels and identifiers', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const html = c.sessionFollowUpHTML(history({ reviews: [review({ context: { rule: hostile }, evidence_flag_id: hostile })] }), {});
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img/);
});
