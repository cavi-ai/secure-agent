import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx = vm.createContext({ SA: { t: {} } });
for (const name of ['lib.js', 'tab-findings.js']) {
  vm.runInContext(readFileSync(new URL(`../../../daemon/internal/api/web_dist/${name}`, import.meta.url), 'utf8'), ctx);
}

test('payload assessment names the local gate and the match layer without claiming delivery', () => {
  const assessment = { evidence_basis: ['fingerprint-payload'], review_state: 'reviewed', residual_risk: 'transmission-attempt', control: 'blocked', limits: ['Earlier exposure remains unknown.'] };
  const blocked = ctx.assessmentHTML(assessment);
  assert.match(blocked, /Blocked before forwarding/);
  assert.match(blocked, /Registered secret fingerprint/);
  assert.match(blocked, /Reviewed/);
  assert.match(blocked, /Earlier exposure remains unknown/);
  const observed = ctx.assessmentHTML({ ...assessment, evidence_basis: ['pattern-payload'], control: 'observed-only' });
  assert.match(observed, /Observed only; delivery unknown/);
  assert.match(observed, /Typed secret pattern/);
  assert.doesNotMatch(observed, /Blocked before forwarding/);
});

test('incident payload results retain mixed recorded outcomes after reported resolution', () => {
  const inc = { id: 'fixture', summary: 'Fixture incident', workflow: { status: 'resolved', resolution_note: 'Operator reported revocation' }, payload_outcomes: { blocked: 2, observed_only: 1, unknown: 3 } };
  const html = ctx.incidentBodyHTML(inc, { advisor: false, agents: new Map(), now: Date.now() });
  assert.match(html, /2 blocked before forwarding/);
  assert.match(html, /1 observed only/);
  assert.match(html, /3 outcome unknown/);
  assert.match(html, /recorded findings/);
  assert.match(html, /Reported resolution: Operator reported revocation/);
  assert.match(html, /revocation.*not verified/);
});
