import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const ctx = {};
vm.createContext(ctx);
for (const file of ['lib.js', 'report-health.js', 'tab-findings.js', 'tab-overview.js']) {
  vm.runInContext(readFileSync(new URL(file, assets), 'utf8'), ctx);
}
const assessment = (overrides = {}) => ({ evidence_basis: [], risk: 'unknown', control: 'unknown',
  residual_risk: 'unknown', review_state: 'unreviewed', reason: 'Exposure and control outcome are unknown.',
  limits: ['Recorded evidence does not establish delivery.'], ...overrides });
function flagView(a, actions = []) {
  const f = { id: 'finding', agent: 'codex', rule: 'proxy-secret-leak', severity: 3,
    explain: { assessment: a, actions, disposition: { state: 'critical', text: 'Act now' } } };
  return ctx.needView({ kind: 'flag', id: f.id, assessment: a, group: { agent: f.agent } },
    { flags: new Map([[f.id, f]]), now: 0, advisor: false });
}

test('urgent summary describes priority without claiming established critical risk', () => {
  const view = ctx.consolePosturePresentation({ state: 'critical', needs_you: 1,
    summary: 'Exposure and control outcome are unknown.' }, { lastSnapshotAt: 1 });
  assert.equal(view.state, 'critical');
  assert.equal(view.title, 'Urgent review');
  assert.equal(view.summary, 'Exposure and control outcome are unknown.');
});

test('collapsed Home decisions expose actual outcomes before their actions', () => {
  for (const [a, label, outcome, residual] of [
    [assessment(), 'Risk unknown', 'Control outcome unknown', 'Exposure unknown'],
    [assessment({ risk: 'critical', evidence_basis: ['model-visible-read'], residual_risk: 'model-exposure' }), 'Critical risk', 'Control outcome unknown', 'Model exposure'],
    [assessment({ risk: 'critical', evidence_basis: ['fingerprint-payload'], control: 'observed-only', residual_risk: 'transmission-attempt' }), 'Critical risk', 'Observed only; delivery unknown', 'Transmission attempt'],
    [assessment({ risk: 'critical', evidence_basis: ['fingerprint-payload'], control: 'blocked', residual_risk: 'transmission-attempt' }), 'Critical risk', 'Blocked before forwarding', 'Transmission attempt'],
  ]) {
    const view = flagView(a);
    const html = ctx.needRowHTML(view, false, 0);
    assert.equal(view.word, label);
    assert.ok(html.indexOf(outcome) >= 0 && html.indexOf(outcome) < html.indexOf('class="need-actions"'), html);
    assert.ok(html.includes(residual));
    assert.doesNotMatch(html, /Act now|All clear/);
  }
});

test('the served recommendation shows its exact consequence before execution', () => {
  const a = assessment({ risk: 'critical', recommendation_id: 'inspect-file' });
  const view = flagView(a, [{ id: 'inspect-file', label: 'Inspect .env', consequence: 'Review the recorded file classification; permissions stay unchanged.', recommended: true }]);
  const html = ctx.needRowHTML(view, false, 0);
  const consequence = html.indexOf('Review the recorded file classification; permissions stay unchanged.');
  assert.ok(consequence >= 0 && consequence < html.indexOf('class="need-actions"'));
  assert.match(html, /data-action="explain-act" data-flag-id="finding" data-action-id="inspect-file"/);
  const unknown = ctx.needRowHTML(flagView(assessment(), [{ id: 'allow-host', label: 'Allow', consequence: 'Trust future traffic.', recommended: true }]), false, 0);
  assert.doesNotMatch(unknown, /need-consequence[^]*Trust future traffic/);
});

test('retained flag actions preserve unknown risk and control outcomes', () => {
  const view = ctx.needView({ kind: 'flag', id: 'missing', assessment: assessment(), detail: 'Unknown exposure' }, { flags: new Map() });
  const html = ctx.needRowHTML(view, false, 0);
  assert.match(html, /data-action="open-flag" data-id="missing"/);
  assert.match(html, /data-action="dismiss-flag" data-id="missing"/);
  assert.match(html, /Risk unknown/);
  assert.match(html, /Control outcome unknown/);
  assert.doesNotMatch(html, /data-action="(?:mute-flag|kill)"/);
});

test('headline evidence link targets its exact flag and review links to Home', () => {
  assert.match(ctx.postureItemHTML({ kind: 'flag', id: '<finding>', title: 'Unknown finding', severity: 3 }), /data-action="open-flag" data-id="&lt;finding&gt;"/);
  assert.match(ctx.postureItemHTML({ kind: 'review', id: 'review', title: 'Recorded review', severity: 3 }), /data-action="goto-tab" data-tab="home"/);
});

test('review receipt retains the observation, residual risk and control result', () => {
  const html = ctx.reviewHTML({ id: 'review', revision: 4, count: 1, context: {}, review_state: 'reviewed',
    evidence_available: true, assessment: assessment({ risk: 'critical', control: 'blocked', evidence_basis: ['fingerprint-payload'], residual_risk: 'transmission-attempt', review_state: 'reviewed', reason: 'The proxy rejected this request before forwarding.' }),
    decision: { action: 'acknowledge', revision: 4, at: '2026-10-10T12:00:00Z' } });
  assert.match(html, /The proxy rejected this request before forwarding/);
  assert.match(html, /Transmission attempt/);
  assert.match(html, /Blocked before forwarding/);
  assert.match(html, /acknowledge · revision 4/);
  assert.doesNotMatch(html, />Mark reviewed</);
});

test('review action states its effect before the revision-bound decision', () => {
  const r = { id: 'review', revision: 4, count: 1, context: {}, evidence_available: true, assessment: assessment() };
  const view = ctx.needView({ kind: 'review', id: r.id, review: r }, { SA: {} });
  const html = ctx.needRowHTML(view, false, 0);
  const consequence = html.indexOf('Records this evidence revision as reviewed; risk and control outcomes stay unchanged.');
  assert.ok(consequence >= 0 && consequence < html.indexOf('class="need-actions"'));
  assert.match(html, /data-id="review" data-revision="4" data-decision="acknowledge"/);
});
