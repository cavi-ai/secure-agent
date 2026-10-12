import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const root = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const endpoints = { guardRules: '/guard/rules', pathAllows: '/guard/path-allow', mutes: '/mute', expected: '/expected', scopes: '/decision-scopes' };
const kinds = { guardRules: 'guard', pathAllows: 'path', mutes: 'mute', expected: 'expected', scopes: 'scope' };
const rows = {
  guardRules: [{ agent: 'claude', rule_id: 'sensitive-file', decision: 'deny', source: 'prompt' }],
  pathAllows: [{ agent: 'claude', rule_id: 'sensitive-file', path: '/synthetic/.env.test' }],
  mutes: [{ rule: 'sensitive-file', host: '*', agent: '' }],
  expected: [{ key: 'fixture', agent: 'claude', reader: 'gh', path: '/synthetic/credentials', dest: 'example.test' }],
  scopes: [{ id: 'fixture', kind: 'exact', agent: 'claude', rule_id: 'sensitive-file', operation: 'read-connect',
    resource_path: '/synthetic/credentials', created_at: '2026-10-01T12:00:00Z', applicability: { label: 'Timed permission', revoke: true } }],
};
const response = (body, ok = true) => ({ ok, json: async () => body });
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function fixture(fetch) {
  const requests = [], renders = [];
  const ctx = vm.createContext({ window: {} });
  for (const file of ['lib.js', 'decision-permissions.js', 'policy-controller.js']) vm.runInContext(readFileSync(new URL(file, root), 'utf8'), ctx);
  const state = { sessionEnded: false, handoffGeneration: 1, policyState: Object.fromEntries(Object.keys(endpoints).map(key => [key, null])) };
  const actions = { now: () => 1000, markDirty: key => renders.push(key), decisionPermissionRows: ctx.decisionPermissionRows, validExpectedPatterns: ctx.validExpectedPatterns,
    apiFetch: async url => { requests.push(url); return fetch ? fetch(url) : response(rows[Object.keys(endpoints).find(key => endpoints[key] === url)]); } };
  const controller = ctx.createConsolePolicy({ state, actions });
  const html = key => ctx.policyListHTML(kinds[key], state.policyState[key], state.policyState.reports[key]);
  return { ctx, state, controller, actions, requests, renders, html };
}

test('a failed endpoint does not withhold successful sibling lists', async () => {
  for (const failed of Object.keys(endpoints)) {
    const f = fixture(url => url === endpoints[failed] ? response(null, false) : response(rows[Object.keys(endpoints).find(key => endpoints[key] === url)]));
    await f.controller.load();
    assert.equal(f.state.policyState[failed], null);
    assert.match(f.html(failed), /Unavailable. No successful read yet/);
    for (const key of Object.keys(endpoints).filter(key => key !== failed)) {
      assert.equal(f.state.policyState[key].length, 1);
      assert.equal(f.controller.ready(kinds[key]), true);
    }
  }
});

test('healthy lists publish and become usable while one sibling is still pending', async () => {
  const slow = deferred();
  const f = fixture(url => url === '/mute' ? slow.promise : response(rows[Object.keys(endpoints).find(key => endpoints[key] === url)]));
  const loading = f.controller.load();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.controller.ready('scope'), true);
  assert.equal(f.controller.ready('mute'), false);
  assert.equal(f.state.policyState.loading, true);
  slow.resolve(response(rows.mutes));
  await loading;
  assert.equal(f.state.policyState.loading, false);
});

test('stale rows and their success timestamp survive errors, with removal disabled', async () => {
  const f = fixture();
  await f.controller.load();
  f.actions.apiFetch = async () => response(null, false);
  await f.controller.load('scope');
  assert.equal(f.state.policyState.scopes[0].id, 'fixture');
  assert.equal(f.state.policyState.reports.scopes.lastSuccessAt, 1000);
  assert.equal(f.controller.ready('scope'), false);
  assert.match(f.html('scopes'), /Showing last known records/);
  assert.match(f.html('scopes'), /Last successful refresh/);
  assert.doesNotMatch(f.html('scopes'), /data-action="revoke-scope"/);
  await f.controller.load('expected');
  assert.doesNotMatch(f.html('expected'), /data-action="forget-expected"/);
});

test('a failed reread of an empty list never claims current emptiness', async () => {
  const f = fixture(async () => response([]));
  await f.controller.load('scope');
  f.actions.apiFetch = async () => response(null, false);
  await f.controller.load('scope');
  assert.match(f.html('scopes'), /Showing last known records/);
  assert.doesNotMatch(f.html('scopes'), /No scoped permissions/);
});

test('malformed responses retain only the failed list and cannot authorize its actions', async () => {
  for (const key of Object.keys(endpoints)) for (const invalid of [null, {}, [null], [7]]) {
    const f = fixture();
    await f.controller.load();
    f.actions.apiFetch = async () => response(invalid);
    await f.controller.load(kinds[key]);
    assert.equal(f.state.policyState[key].length, 1);
    assert.match(f.state.policyState.reports[key].error, /invalid records/);
    assert.equal(f.controller.ready(kinds[key]), false);
  }
  for (const invalid of [[{ ...rows.guardRules[0], decision: 'invalid' }], [{ ...rows.expected[0], key: '' }], [rows.expected[0], rows.expected[0]]]) {
    const f = fixture(async () => response(invalid));
    await f.controller.load(invalid[0].decision ? 'guard' : 'expected');
    assert.equal(f.controller.ready(invalid[0].decision ? 'guard' : 'expected'), false);
  }
});

test('a retry reads only its selected report and a valid empty response clears its error', async () => {
  const f = fixture(async () => response(null, false));
  await f.controller.load();
  f.requests.length = 0;
  f.actions.apiFetch = async url => { f.requests.push(url); return response([]); };
  await f.controller.load('expected');
  assert.deepEqual(f.requests, ['/expected']);
  assert.equal(f.state.policyState.reports.expected.error, '');
  assert.match(f.html('expected'), /No expected secret reads/);
  assert.match(f.html('mutes'), /Unavailable/);
});

test('repeated retries share the pending report without delaying another report', async () => {
  const pending = deferred();
  const f = fixture(url => url === '/mute' ? pending.promise : response([]));
  const first = f.controller.load('mute');
  await f.controller.load('mute');
  await f.controller.load('expected');
  assert.deepEqual(f.requests, ['/mute', '/expected']);
  assert.equal(f.controller.ready('expected'), true);
  pending.resolve(response([]));
  await first;
});

test('authentication reset clears records and rejects old success or failure responses', async () => {
  for (const ok of [true, false]) {
    const pending = deferred();
    const f = fixture(() => pending.promise);
    const old = f.controller.load('scope');
    f.state.sessionEnded = true;
    f.state.handoffGeneration++;
    f.controller.reset();
    f.state.sessionEnded = false;
    f.actions.apiFetch = async () => response([]);
    await f.controller.load('scope');
    pending.resolve(response(rows.scopes, ok));
    await old;
    assert.equal(f.state.policyState.scopes.length, 0);
    assert.equal(f.state.policyState.reports.scopes.error, '');
    assert.equal(f.state.policyState.reports.scopes.loading, false);
  }
});

test('transport and JSON failures remain local and do not publish raw error details', async () => {
  for (const fetch of [async () => { throw null; }, async () => { throw new Error('private diagnostic'); },
    async () => ({ ok: true, json: async () => { throw new SyntaxError('private diagnostic'); } })]) {
    const f = fixture(fetch);
    await f.controller.load('mute');
    assert.match(f.html('mutes'), /could not be refreshed/);
    assert.doesNotMatch(f.html('mutes'), /private diagnostic/);
  }
});

test('report status text is escaped and cached controls stay disabled during refresh', async () => {
  const f = fixture();
  await f.controller.load();
  const pending = deferred();
  f.actions.apiFetch = () => pending.promise;
  const refresh = f.controller.load('scope');
  assert.match(f.html('scopes'), /Refreshing scoped permissions/);
  assert.match(f.html('scopes'), /data-action="revoke-scope"[^>]* disabled/);
  pending.resolve(response(rows.scopes));
  await refresh;
  f.state.policyState.reports.scopes.error = '<img src=x>';
  assert.match(f.html('scopes'), /&lt;img src=x&gt;/);
  assert.doesNotMatch(f.html('scopes'), /<img/);
});

test('a successful sibling read cannot clear an uncertain removal or revocation', async () => {
  const f = fixture();
  f.state.policyState.expectedMutations = new Map([['fixture', { status: 'unconfirmed' }]]);
  f.state.policyState.scopeMutations = new Map([['fixture', { status: 'unconfirmed' }]]);
  await f.controller.load('mute');
  assert.equal(f.state.policyState.expectedMutations.size, 1);
  assert.equal(f.state.policyState.scopeMutations.size, 1);
  f.actions.apiFetch = async () => response(null, false);
  await f.controller.load('expected');
  assert.equal(f.state.policyState.expectedMutations.size, 1);
  f.actions.apiFetch = async () => response([]);
  await f.controller.load('expected');
  assert.equal(f.state.policyState.expectedMutations.size, 0);
  assert.equal(f.state.policyState.scopeMutations.size, 1);
  await f.controller.load('scope');
  assert.equal(f.state.policyState.scopeMutations.size, 0);
});

test('a write receipt invalidates only its list and rejects its older response', async () => {
  const oldExpected = deferred(), slowMute = deferred();
  const f = fixture(url => url === '/expected' ? oldExpected.promise : slowMute.promise);
  const old = f.controller.load('expected'), sibling = f.controller.load('mute');
  f.controller.invalidate('expected');
  assert.equal(f.state.policyState.reports.expected.loading, false);
  assert.equal(f.state.policyState.reports.mutes.loading, true);
  assert.equal(f.state.policyState.loading, true);
  f.actions.apiFetch = async () => response([]);
  await f.controller.load('expected');
  oldExpected.resolve(response(rows.expected));
  await old;
  assert.equal(f.state.policyState.expected.length, 0);
  slowMute.resolve(response(rows.mutes));
  await sibling;
  assert.equal(f.state.policyState.mutes.length, 1);
});
