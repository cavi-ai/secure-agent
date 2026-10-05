import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx = vm.createContext({});
vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/telemetry-validation.js', import.meta.url), 'utf8'), ctx);
const valid = (key, body) => ctx.isConsoleReport(key, body);

test('slow reports accept optional nil collections and unknown fields for daemon compatibility', () => {
  assert.equal(valid('resources', { sessions: null, host: null, control: { pending: null }, future: true }), true);
  assert.equal(valid('resources', { sessions: [{ samples: null, processes: null, diagnoses: null, control: null }] }), true);
  assert.equal(valid('resource episodes', [{ session: { samples: null }, activities: null, correlations: null }]), true);
  assert.equal(valid('fleet', { hostname: 'local', agents: null }), true);
  assert.equal(valid('fleet', [{ hostname: 'remote', agents: [] }]), true);
  assert.equal(valid('notification rules', { overrides: null, scopes: null }), true);
  assert.equal(valid('recurring egress', { episodes: null, future: true }), true);
  assert.equal(valid('expected egress', { rules: null }), true);
});

for (const [key, body] of [
  ['resources', []], ['resources', { sessions: [null] }],
  ['resources', { sessions: [{ samples: {} }] }],
  ['resources', { sessions: [{ processes: [null] }] }],
  ['resources', { sessions: [{ diagnoses: {} }] }],
  ['resources', { sessions: [{ control: [] }] }],
  ['resources', { host: [] }], ['resources', { control: { pending: [null] } }],
  ['resources', { control: { interventions: {} } }],
  ['resources', { control: { workspace_overrides: [null] } }],
  ['fleet', { agents: {} }], ['fleet', [null]],
  ['notification rules', { overrides: [] }], ['notification rules', { scopes: [null] }],
  ['resource episodes', [{ session: { samples: {} } }]],
  ['resource episodes', [{ activities: {} }]], ['resource episodes', [{ correlations: [null] }]],
  ['resource episodes', [{ diagnosis_codes: {} }]],
  ['recurring egress', { episodes: [null] }], ['recurring egress', []],
  ['recurring egress', { episodes: [{ observed: [] }] }],
  ['recurring egress', { episodes: [{ observed: { intervals: {} } }] }],
  ['recurring egress', { episodes: [{ observed: { session_ids: {} } }] }],
  ['recurring egress', { episodes: [{ observed: { scope: [] } }] }],
  ['expected egress', { rules: {} }],
]) {
  test(`rejects malformed ${key} containers: ${JSON.stringify(body)}`, () => {
    assert.equal(valid(key, body), false);
  });
}
