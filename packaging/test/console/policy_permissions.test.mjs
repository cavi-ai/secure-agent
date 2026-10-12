import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const app = readFileSync(new URL('app.js', web), 'utf8');
const at = '2026-10-12T01:00:00Z';
const scope = extra => ({ id: 'scope-a', kind: 'exact', agent: 'claude', rule_id: 'read-connect',
  operation: 'read-connect', resource_path: '/work/.env', destination: 'example.test:443',
  workspace: '/work', reader_exe: '/usr/bin/cat', created_at: at, expires_at: '2099-01-01T00:00:00Z',
  applicability: { label: 'Timed permission', revoke: true }, ...extra });
const settle = () => new Promise(resolve => setImmediate(resolve));

function controller() {
  const requests = [], messages = [];
  const c = { window: { saConfirm: async () => true }, sessionEnded: false, handoffGeneration: 0,
    document: { getElementById: () => null }, markDirty() {}, showToast: (...args) => messages.push(args),
    apiFetch: (url, options) => new Promise(resolve => requests.push({ url, options, resolve, answered: false })) };
  vm.createContext(c);
  for (const file of ['lib.js', 'decision-permissions.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), c);
  const start = app.indexOf('  // Policy lists are not telemetry');
  const end = app.indexOf('  // Agent tab:', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(app.slice(start, end), c);
  const state = vm.runInContext('policyState', c);
  const answer = (request, payload, status = 200) => {
    request.answered = true;
    request.resolve({ ok: status === 200, status, json: async () => payload, text: async () => 'Unavailable' });
  };
  const answerReads = (rows = [scope()], status = 200) => {
    for (const request of requests.filter(r => !r.options && !r.answered)) {
      answer(request, request.url === '/decision-scopes' ? rows : [], request.url === '/decision-scopes' ? status : 200);
    }
  };
  return { c, state, requests, messages, answer, answerReads,
    html: () => c.policyListHTML('scope', state.scopes, state),
    async load(rows = [scope()], status = 200) { const pending = c.loadPolicy(); answerReads(rows, status); await pending; } };
}

test('global permissions use daemon applicability and withhold revoke for unknown or stale reads', async () => {
  const t = controller();
  await t.load([scope({ applicability: { label: 'Session ended', revoke: false } })]);
  assert.match(t.html(), /Session ended/); assert.doesNotMatch(t.html(), /data-action="revoke-scope"/);
  await t.c.window.revokeScope('scope-a'); assert.equal(t.requests.length, 5);
  await t.load([scope({ applicability: undefined })]);
  assert.match(t.html(), /Applicability unknown/); assert.doesNotMatch(t.html(), /data-action="revoke-scope"/);
  await t.load(); await t.load(null, 503);
  assert.match(t.html(), /Last known permission records/);
  assert.doesNotMatch(t.html(), /data-action="revoke-scope"/);
  await t.c.window.revokeScope('scope-a'); assert.equal(t.requests.length, 20);
});

test('revocation names the exact saved scope, requires confirmation, and prevents duplicate clicks', async () => {
  const t = controller(); await t.load();
  await t.c.window.revokeScope('unrelated'); assert.equal(t.requests.length, 5);
  let confirm, text;
  t.c.window.saConfirm = message => { text = message; return new Promise(resolve => { confirm = resolve; }); };
  const pending = t.c.window.revokeScope('scope-a');
  assert.match(text, /\/work\/\.env.*example\.test:443/);
  assert.match(text, /does not undo past access/i);
  assert.match(t.html(), /data-action="revoke-scope"[^>]* disabled/);
  await t.c.window.revokeScope('scope-a'); assert.equal(t.requests.length, 5);
  confirm(false); await pending;
  assert.equal(t.requests.length, 5);
  assert.match(t.html(), /data-action="revoke-scope"/);
});

test('only an exact successful receipt confirms revocation; failed rereads retain that confirmation', async () => {
  const t = controller(); await t.load();
  const pending = t.c.window.revokeScope('scope-a'); await settle();
  const write = t.requests[5];
  assert.equal(write.url, '/decision-scopes?id=scope-a'); assert.equal(write.options.method, 'DELETE');
  t.answer(write, { revoked: true, id: 'scope-a' }); await settle();
  assert.match(t.html(), /Revocation saved/);
  assert.doesNotMatch(t.html(), /data-action="revoke-scope"/);
  t.answerReads(null, 503); await pending;
  assert.match(t.html(), /Revocation saved/); assert.match(t.html(), /Last known permission records/);
  assert.equal(t.messages.filter(([, kind]) => kind === 'success').length, 1);
});

test('ambiguous revocation never claims a save or retries before an explicit successful refresh', async () => {
  for (const body of [{ revoked: true, id: 'other' }, { revoked: 'true', id: 'scope-a' }, null]) {
    const t = controller(); await t.load();
    const pending = t.c.window.revokeScope('scope-a'); await settle();
    t.answer(t.requests[5], body); await pending;
    assert.match(t.html(), /Revocation not confirmed/);
    assert.doesNotMatch(t.html(), /Revocation saved|data-action="revoke-scope"/);
    assert.equal(t.messages.filter(([, kind]) => kind === 'success').length, 0);
    await t.c.window.revokeScope('scope-a'); assert.equal(t.requests.length, 6);
    await t.load(); assert.match(t.html(), /data-action="revoke-scope"/);
    assert.equal(t.requests.filter(r => r.options?.method === 'DELETE').length, 1);
  }
});

test('a refresh cannot replace confirmed revocation with an older applicable record', async () => {
  const t = controller(); await t.load();
  const pending = t.c.window.revokeScope('scope-a'); await settle();
  t.answer(t.requests[5], { revoked: true, id: 'scope-a' }); await settle();
  t.answerReads(); await pending;
  assert.match(t.html(), /Revocation saved/);
  assert.doesNotMatch(t.html(), /data-action="revoke-scope"/);
});

test('HTTP failures and unreadable receipts leave revocation unconfirmed without replaying the write', async () => {
  for (const response of [{ ok: false, status: 503 }, { ok: true, json: async () => { throw new Error('Unreadable receipt'); } }]) {
    const t = controller(); await t.load();
    const pending = t.c.window.revokeScope('scope-a'); await settle();
    t.requests[5].resolve(response); await pending;
    assert.match(t.html(), /Revocation not confirmed/);
    assert.doesNotMatch(t.html(), /Revocation saved|data-action="revoke-scope"/);
    assert.equal(t.requests.length, 6);
    assert.equal(t.messages.filter(([, kind]) => kind === 'success').length, 0);
  }
});

test('malformed permission reads retain prior records and disable mutations', async () => {
  const t = controller(); await t.load(); const previous = t.state.scopes;
  for (const rows of [null, {}, [scope(), scope()], [scope({ resource_path: null })]]) {
    await t.load(rows);
    assert.equal(t.state.scopes, previous);
    assert.match(t.html(), /Last known permission records/);
    assert.doesNotMatch(t.html(), /data-action="revoke-scope"/);
  }
});

test('late policy reads cannot repopulate records after authentication changes', async () => {
  const t = controller(); const pending = t.c.loadPolicy();
  t.c.handoffGeneration++; t.c.resetPolicyState(); t.answerReads(); await pending;
  assert.equal(t.state.scopes, null); assert.equal(t.state.loading, false);
  assert.equal(t.state.error, '');
});

test('delayed confirmations and revocation responses cannot cross authentication', async () => {
  const t = controller(); await t.load();
  let confirm; t.c.window.saConfirm = () => new Promise(resolve => { confirm = resolve; });
  const pending = t.c.window.revokeScope('scope-a');
  t.c.handoffGeneration++; t.c.resetPolicyState(); confirm(true); await pending;
  assert.equal(t.requests.length, 5);
  const other = controller(); await other.load();
  const write = other.c.window.revokeScope('scope-a'); await settle();
  other.c.handoffGeneration++; other.c.resetPolicyState();
  other.answer(other.requests[5], { revoked: true, id: 'scope-a' }); await write;
  assert.equal(other.messages.length, 0); assert.equal(other.state.scopes, null);
  assert.equal(other.requests.length, 6);
});

test('permission values and applicability labels stay escaped in global rows', async () => {
  const t = controller(); await t.load([scope({ resource_path: '<img>', applicability: { label: '<script>', revoke: true } })]);
  assert.match(t.html(), /&lt;img&gt;/); assert.match(t.html(), /&lt;script&gt;/);
  assert.doesNotMatch(t.html(), /<img>|<script>/);
});
