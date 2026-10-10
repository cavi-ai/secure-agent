import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = { window: {}, Date, structuredClone };
vm.runInNewContext(readFileSync(new URL('../console_dom/fixtures.js', import.meta.url), 'utf8'), context);
const { create, apply } = context.window.ConsoleFixtures;

test('declared payloads and patches are isolated between cases', () => {
  const payload = { state: 'all-clear', needs_you: 0, items: [] };
  const one = create({ now: 0, payloads: { '/posture': payload }, patches: [{ route: '/status', path: ['version'], value: 'fixture' }] });
  const two = create({ now: 0 });
  apply(one);
  assert.equal(one.data['/status'].version, 'fixture');
  assert.equal(two.data['/status'].version, 'v9.9.9-domtest');
  one.data['/posture'].items.push({ id: 'changed' });
  assert.equal(payload.items.length, 0);
  assert.notEqual(two.data['/posture'].state, 'all-clear');
});

test('scenario selection uses complete names', () => {
  const fixture = create({ scenarios: ['tab=resources', 'authhistory'], now: 0 });
  assert.equal(fixture.scenarios.has('resources'), false);
  assert.equal(fixture.scenarios.has('authhistory'), true);
  assert.equal(fixture.scenarios.has('history'), false);
});
