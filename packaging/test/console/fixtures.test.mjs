import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = { window: {}, Date, structuredClone };
vm.runInNewContext(readFileSync(new URL('../console_dom/fixtures.js', import.meta.url), 'utf8'), context);
const { create, apply } = context.window.ConsoleFixtures;

test('System defaults exist without the driver and isolate nested worktree and clutter mutations', () => {
  const one = create({ now: 0 });
  const two = create({ now: 0 });
  const repo = one.data['/worktrees'].repos[0];
  assert.deepEqual(structuredClone(repo.worktrees.map(row => row.state)), ['main', 'remove', 'review', 'keep', 'prune']);
  assert.equal(one.data['/cleanup'].items.length, 3);
  const original = structuredClone(two.data);
  repo.worktrees[1].reasons.push('changed');
  one.data['/worktrees'].advice[repo.worktrees[2].path].rationale = 'changed';
  one.data['/cleanup'].items[0].command = 'changed';
  one.data['/cleanup'].kinds.pop();
  one.data['/cleanup'].advice[repo.path].rationale = 'changed';
  assert.deepEqual(structuredClone(two.data), original);
});

test('System patches select a nested repository and preserve the other worktrees', () => {
  const rows = [{ path: '/fixture/extra', reasons: ['test-owned'] }];
  const fixture = create({ now: 0, patches: [{
    route: '/worktrees', path: ['repos', { path: '/Users/dev/workspace/api-service' }, 'worktrees'], append: rows,
  }] });
  const original = structuredClone(fixture.data['/worktrees'].repos[0].worktrees);
  apply(fixture);
  const worktrees = fixture.data['/worktrees'].repos[0].worktrees;
  assert.deepEqual(structuredClone(worktrees.slice(0, -1)), original);
  worktrees.at(-1).reasons.push('changed');
  assert.deepEqual(rows[0].reasons, ['test-owned']);
});

test('policy and Agent defaults are available without the browser driver and isolate mutations', () => {
  const one = create({ now: 0 });
  const two = create({ now: 0 });
  assert.equal(one.data['/guard/rules'][0].decision, 'allow');
  assert.equal(one.data['/guard/path-allow'][0].rule_id, 'env-file');
  assert.equal(one.data['/agent/status'].enabled, true);
  assert.equal(one.data['/agent/chat'].messages.length, 5);
  assert.equal(one.data['/agent/plans'].length, 2);
  assert.equal(one.data['/agent/runs'].length, 2);
  assert.equal(one.data['/agent/recommendations'].length, 0);
  assert.match(one.data['/agent/skills'][0].body, /<img src=x onerror=alert\(1\)>/);
  const original = structuredClone(two.data);
  one.data['/guard/rules'][0].decision = 'deny';
  one.data['/guard/path-allow'].pop();
  one.data['/agent/status'].skills[0].title = 'Changed';
  one.data['/agent/skills'][0].keywords.push('changed');
  one.data['/agent/chat'].messages[1].proposal.steps.push('changed');
  one.data['/agent/plans'][0].skills.push('changed');
  one.data['/agent/runs'].pop();
  one.data['/agent/recommendations'].push({ id: 'changed' });
  assert.deepEqual(structuredClone(two.data), original);
  assert.equal(one.data['/agent/skills'][0].title, original['/agent/skills'][0].title);
});

test('Agent availability is declared by the case, independent of interaction names', () => {
  const fixture = create({ now: 0, patches: [{ route: '/agent/status', path: ['enabled'], value: false }] });
  apply(fixture);
  assert.equal(fixture.data['/agent/status'].enabled, false);
  assert.equal(create({ now: 0, scenarios: ['agentoff'] }).data['/agent/status'].enabled, true);
});

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

test('declared row patches select identities and preserve unrelated rows', () => {
  const fixture = create({ now: 0, patches: [
    { route: '/flags', path: [{ id: 'flag-2' }, 'title'], value: 'Explained finding' },
    { route: '/flags', path: [], append: [{ id: 'extra', title: 'Additional finding' }] },
    { route: '/posture', path: ['items'], remove: { kind: 'flag', id: 'flag-2' } },
  ] });
  const originalFirst = structuredClone(fixture.data['/flags'][0]);
  apply(fixture);
  assert.deepEqual(structuredClone(fixture.data['/flags'][0]), originalFirst);
  assert.equal(fixture.data['/flags'][1].title, 'Explained finding');
  assert.equal(fixture.data['/flags'].at(-1).id, 'extra');
  assert.ok(fixture.data['/posture'].items.some(row => row.id === 'flag-1'));
  assert.ok(!fixture.data['/posture'].items.some(row => row.id === 'flag-2'));
});

test('row selectors reject missing or ambiguous identities', () => {
  for (const selector of [{ id: 'missing' }, { agent: 'cursor' }]) {
    const fixture = create({ now: 0, patches: [{ route: '/flags', path: [selector, 'title'], value: 'Wrong row' }] });
    const original = structuredClone(fixture.data);
    assert.throws(() => apply(fixture), /exactly one row/);
    assert.deepEqual(structuredClone(fixture.data), original);
  }
});

test('patch operations reject malformed inputs and clone appended payloads', () => {
  for (const patch of [
    { route: '/flags', path: [], value: [], append: [] },
    { route: '/flags', path: [], append: {} },
    { route: '/status', path: [], remove: { id: 'flag-2' } },
  ]) assert.throws(() => apply(create({ now: 0, patches: [patch] })), /Invalid fixture patch/);
  const rows = [{ id: 'extra', evidence: [] }];
  const fixture = create({ now: 0, patches: [{ route: '/flags', path: [], append: rows }] });
  apply(fixture);
  fixture.data['/flags'].at(-1).evidence.push('mutated');
  assert.equal(rows[0].evidence.length, 0);
});
