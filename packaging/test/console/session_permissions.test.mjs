import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const app = readFileSync(new URL('app.js', web), 'utf8');
const at = '2026-10-09T12:00:00Z';
const receipt = { sessionID: 'session-a', reviewID: 'review-a', revision: 1, at, ids: ['scope-a', 'scope-missing'] };
const scope = (id = 'scope-a', extra = {}) => ({ id, kind: 'exact', agent: 'claude', session_id: 'session-a',
  workspace: '/work/a', reader_exe: '/usr/bin/tool', rule_id: 'sensitive-read-then-connect',
  resource_path: '/work/a/.env', operation: 'read-connect', destination: 'example.test:443',
  created_at: at, expires_at: '2099-10-09T12:00:00Z', identity_basis: 'observed-session',
  applicability: { label: 'Timed permission', revoke: true }, ...extra });
function context() {
  const c = { Date, URLSearchParams, window: { SA: {} } };
  vm.createContext(c);
  for (const file of ['lib.js', 'tab-overview.js', 'tab-sessions.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), c);
  return c;
}
function controller() {
  const requests = [], announcements = [];
  const c = context();
  const body = { innerHTML: '', contains: () => false, querySelectorAll: () => [], scrollTop: 0 };
  Object.assign(c, { selectedSessionId: 'session-a', sessionEnded: false, handoffGeneration: 0, drawerSeq: 0,
    drawerMode: null, drawer: { hidden: true }, drawerBody: body, document: { activeElement: null }, btnDrawerCopy: {}, btnDrawerClose: { focus() {} },
    sessionOutcomes: { session_id: 'session-a', history: { reviews: [{ id: 'review-a', decision: { revision: 1, at, scope_ids: receipt.ids } }] } },
    patchSessionDetail: (_el, _id, html) => { body.innerHTML = html; },
    openDrawer: () => { c.drawerSeq++; c.drawer.hidden = false; },
    closeDrawer: () => { c.drawer.hidden = true; c.drawerMode = null; },
    apiFetch: (url, options) => new Promise(resolve => requests.push({ url, options, resolve })),
  });
  c.window.saConfirm = async () => true;
  c.window.saAnnounce = text => announcements.push(text);
  const start = app.indexOf('  // Permissions from one saved decision');
  const end = app.indexOf('  // Uninspected-egress drill-down:', start);
  assert.ok(start >= 0 && end > start, 'permission controller exists');
  vm.runInContext(app.slice(start, end), c);
  return { c, body, requests, announcements,
    answer(i, payload, status = 200) { requests[i].resolve({ ok: status === 200, status, json: async () => payload }); } };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('pending refresh retains a disabled action without permitting a revocation request', async () => {
  const t = controller();
  const open = t.c.window.openSessionPermissions('review-a', 'session-a');
  t.answer(0, [scope()]); await open;
  const refresh = t.c.window.refreshSessionPermissions();
  assert.match(t.body.innerHTML, /data-action="session-permission-revoke" data-id="scope-a" disabled/);
  await t.c.window.revokeSessionPermission('scope-a');
  assert.equal(t.requests.length, 2, 'only initial and refresh reads were issued');
  t.answer(1, [scope()]); await refresh;
  assert.match(t.body.innerHTML, /data-action="session-permission-revoke" data-id="scope-a">/);
});

test('Results links the exact saved decision and session instead of the global policy page', () => {
  const c = context();
  const evidence = Object.fromEntries(['reviews', 'interventions', 'incidents'].map(key => [key, { available: true }]));
  const html = c.sessionOutcomesHTML({ session_id: 'session-a', history: { evidence, reviews: [{ id: 'review-a', revision: 1,
    decision: { action: 'expect', revision: 1, at, scope_ids: receipt.ids } }], interventions: [], incidents: [] } }, {});
  assert.match(html, /data-action="session-permissions" data-review="review-a" data-session="session-a"/);
  assert.ok(!html.includes('data-tab="policy"'));
});

test('scope details show only receipt IDs, unknown missing status, exact coordinates, and historic revision', () => {
  const c = context();
  const html = c.sessionPermissionsHTML(receipt, { rows: [scope(), scope('unrelated')], readAt: at });
  for (const text of ['revision 1', 'session-a', '/usr/bin/tool', '/work/a/.env', 'example.test:443', 'scope-missing',
    'Current status unknown', 'not signature verified', 'rechecks live session', 'does not grant network access']) assert.ok(html.includes(text), text);
  assert.ok(!html.includes('unrelated'));
  assert.ok(!html.includes('Permission active'));
  assert.match(html, /data-action="session-permission-revoke" data-id="scope-a"/);
});

test('failed refresh retains labeled last-known scopes and disables revocation', () => {
  const c = context();
  const stale = c.sessionPermissionsHTML(receipt, { rows: [scope()], readAt: at, error: 'unavailable' });
  assert.match(stale, /Last known permission records/);
  assert.match(stale, /Timed permission/);
  assert.ok(!stale.includes('data-action="session-permission-revoke"'));
  const hostile = c.sessionPermissionsHTML({ ...receipt, sessionID: '<img>' }, { rows: [scope('scope-a', { workspace: '<img>' })] });
  assert.ok(!hostile.includes('<img>'));
});

test('session permissions render server applicability and hide revoke when it is false or absent', () => {
  const c = context();
  const offered = c.sessionPermissionsHTML(receipt, { rows: [scope('scope-a', { revoked_at: at, applicability: { label: 'Timed permission', revoke: true } })] });
  assert.match(offered, />Timed permission</);
  assert.match(offered, /Expected read\/connect activity/);
  assert.match(offered, /does not grant network access/);
  assert.match(offered, /data-action="session-permission-revoke" data-id="scope-a"/);
  const withheld = c.sessionPermissionsHTML(receipt, { rows: [scope('scope-a', { applicability: { label: 'Expired', revoke: false } })] });
  assert.match(withheld, />Expired</);
  assert.match(withheld, /Expected read\/connect activity/);
  assert.match(withheld, /does not grant network access/);
  assert.ok(!withheld.includes('data-action="session-permission-revoke"'));
  const absent = c.sessionPermissionsHTML(receipt, { rows: [scope('scope-a', { applicability: undefined })] });
  assert.match(absent, /Applicability unknown/);
  assert.match(absent, /Expected read\/connect activity/);
  assert.ok(!absent.includes('data-action="session-permission-revoke"'));
});

test('receipt lookup is bound to its durable session and rejects malformed or oversized ID sets', () => {
  const c = context();
  const data = ids => ({ session_id: 'a', history: { reviews: [{ id: 'r', decision: { revision: 1, at, scope_ids: ids } }] } });
  assert.equal(c.sessionPermissionReceipt(data(['x']), 'r', 'b'), null);
  for (const ids of [[], [null], Array.from({ length: 129 }, (_, i) => 's' + i)]) assert.equal(c.sessionPermissionReceipt(data(ids), 'r', 'a'), null);
  assert.equal(c.sessionPermissionReceipt(data(['x', 'x']), 'r', 'a').ids.length, 1);
});

test('opening and retrying read only the canonical scope endpoint, retaining evidence on malformed reads', async () => {
  const t = controller();
  const open = t.c.window.openSessionPermissions('review-a', 'session-a');
  assert.equal(t.requests[0].url, '/decision-scopes');
  assert.equal(t.requests[0].options, undefined);
  t.answer(0, [scope()]); await open;
  const retry = t.c.window.refreshSessionPermissions();
  t.answer(1, [scope(), scope()]); await retry;
  assert.match(t.body.innerHTML, /Last known permission records/);
  assert.ok(!t.body.innerHTML.includes('data-action="session-permission-revoke"'));
  const recover = t.c.window.refreshSessionPermissions(); t.answer(2, []); await recover;
  assert.match(t.body.innerHTML, /Current status unknown/);
  assert.ok(!t.body.innerHTML.includes('Last known permission records'));
});

test('late reads and delayed confirmations cannot populate another drawer or mutate after selection/auth changes', async () => {
  for (const invalidate of [c => c.drawerSeq++, c => { c.selectedSessionId = 'b'; }, c => c.handoffGeneration++, c => { c.sessionEnded = true; }]) {
    const t = controller();
    const open = t.c.window.openSessionPermissions('review-a', 'session-a');
    invalidate(t.c); t.body.innerHTML = 'new view'; t.answer(0, [scope()]); await open;
    assert.equal(t.body.innerHTML, 'new view');
  }
  const t = controller(); const open = t.c.window.openSessionPermissions('review-a', 'session-a'); t.answer(0, [scope()]); await open;
  let confirm; t.c.window.saConfirm = () => new Promise(resolve => { confirm = resolve; });
  const revoke = t.c.window.revokeSessionPermission('scope-a');
  t.c.selectedSessionId = 'b'; confirm(true); await revoke;
  assert.equal(t.requests.length, 1);
});

test('revocation requires a current linked ID, explicit confirmation, exact receipt, and never automatically retries', async () => {
  const t = controller(); const open = t.c.window.openSessionPermissions('review-a', 'session-a'); t.answer(0, [scope()]); await open;
  await t.c.window.revokeSessionPermission('unrelated'); assert.equal(t.requests.length, 1);
  t.c.window.saConfirm = async () => false;
  await t.c.window.revokeSessionPermission('scope-a'); assert.equal(t.requests.length, 1);
  t.c.window.saConfirm = async () => true;
  const revoke = t.c.window.revokeSessionPermission('scope-a'); await settle();
  const duplicate = t.c.window.revokeSessionPermission('scope-a'); await duplicate;
  assert.equal(t.requests[1].url, '/decision-scopes?id=scope-a');
  assert.equal(t.requests[1].options.method, 'DELETE');
  t.answer(1, { revoked: true, id: 'wrong' }); await revoke;
  assert.match(t.body.innerHTML, /Revocation confirmation unavailable/);
  assert.ok(!t.body.innerHTML.includes('data-action="session-permission-revoke"'));
  assert.equal(t.requests.length, 2, 'no automatic replay or hidden refresh after an ambiguous mutation');
});

test('confirmed revocation survives failed reread and keeps the original saved decision unchanged', async () => {
  const t = controller(); const open = t.c.window.openSessionPermissions('review-a', 'session-a'); t.answer(0, [scope()]); await open;
  const revoke = t.c.window.revokeSessionPermission('scope-a'); await settle();
  t.answer(1, { revoked: true, id: 'scope-a' }); await settle();
  t.answer(2, null, 503); await revoke;
  assert.match(t.body.innerHTML, /Revocation saved/);
  assert.match(t.body.innerHTML, /Last known permission records/);
  assert.ok(!t.body.innerHTML.includes('data-action="session-permission-revoke"'));
  assert.deepEqual(Array.from(t.c.sessionOutcomes.history.reviews[0].decision.scope_ids), receipt.ids);
});
