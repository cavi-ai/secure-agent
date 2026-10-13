import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { loadDrawer } from './drawer-harness.mjs';

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
  for (const file of ['lib.js', 'tab-overview.js', 'session-workbench.js', 'decision-permissions.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), c);
  return c;
}
function controller() {
  const requests = [], announcements = [], drawers = [];
  const c = context();
  const h = loadDrawer({ deps: { collaborators: { auth: { ended: () => c.sessionEnded, generation: () => c.handoffGeneration } } } });
  const body = Object.assign(h.dom.body, { contains: () => false, querySelectorAll: () => [], scrollTop: 0 });
  Object.assign(c, { selectedSessionId: 'session-a', sessionEnded: false, handoffGeneration: 0, reviewResult: null,
    drawer: h.dom.drawer, drawerBody: body, document: h.dom.document, btnDrawerClose: h.dom.closeButton,
    detailDrawer: { ...h.api, open: options => { drawers.push(options); return h.api.open(options); } },
    sessionOutcomes: { session_id: 'session-a', history: { reviews: [{ id: 'review-a', decision: { revision: 1, at, scope_ids: receipt.ids } }] } },
    patchSessionDetail: (_el, _id, html) => { body.innerHTML = html; },
    apiFetch: (url, options) => new Promise(resolve => requests.push({ url, options, resolve })),
  });
  c.window.saConfirm = async () => true;
  c.window.saAnnounce = text => announcements.push(text);
  const start = app.indexOf('  // Permissions from one saved decision');
  const end = app.indexOf('  const familyByKey = key =>', start);
  assert.ok(start >= 0 && end > start, 'permission controller exists');
  c.sessionWorkbench = { get selectedSessionId() { return c.selectedSessionId; }, get sessionOutcomes() { return c.sessionOutcomes; } };
  vm.runInContext(app.slice(start, end), c);
  const resultStart = app.indexOf('  window.openReviewResult = function(');
  vm.runInContext(app.slice(resultStart, app.indexOf('  // Review pagination', resultStart)), c);
  return { c, h, body, requests, announcements, drawers,
    answer(i, payload, status = 200) { requests[i].resolve({ ok: status === 200, status, json: async () => payload }); } };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

const savedResult = () => ({ receipt: { id: 'review-a', revision: 1, action: 'expect', at, scope_ids: receipt.ids },
  review: { context: { session_id: 'session-a', resources: ['/work/a/.env'] } } });

test('result permissions use the original receipt without requiring session history or the selected session', async () => {
  const t = controller(), original = savedResult();
  t.c.window.openReviewResult(original);
  t.c.selectedSessionId = 'another-session'; t.c.sessionOutcomes = null;
  t.c.reviewResult = { ...savedResult(), receipt: { ...original.receipt, id: 'new-review', scope_ids: ['unrelated'] } };
  const open = t.c.window.openReviewResultPermissions();
  assert.equal(t.requests[0].url, '/decision-scopes');
  t.answer(0, [scope(), scope('unrelated')]); await open;
  assert.match(t.body.innerHTML, /scope-missing/);
  assert.doesNotMatch(t.body.innerHTML, /unrelated/);
  const back = t.drawers[0].back;
  assert.equal(back.label, 'Review result');
  back.reopen();
  assert.match(t.body.innerHTML, /review-a|\/work\/a\/\.env/);
  assert.doesNotMatch(t.body.innerHTML, /new-review|unrelated/);
  assert.deepEqual(original.receipt.scope_ids, receipt.ids);
  t.c.handoffGeneration++; back.reopen();
  assert.equal(t.h.calls.closedDocks, 3, 'the return cannot cross authentication');
});

test('result permissions remain tied to their drawer and authentication while session views change', async () => {
  const t = controller(); t.c.window.openReviewResult(savedResult());
  const open = t.c.window.openReviewResultPermissions();
  t.c.window.SA.closeSessionPermissions(); t.c.window.SA.invalidateSessionPermissions();
  t.c.selectedSessionId = 'different';
  t.answer(0, [scope()]); await open;
  assert.equal(t.c.drawer.hidden, false);
  assert.match(t.body.innerHTML, /Timed permission/);
  const refresh = t.c.window.refreshSessionPermissions();
  t.c.handoffGeneration++; t.body.innerHTML = 'new authentication';
  t.answer(1, [scope()]); await refresh;
  assert.equal(t.body.innerHTML, 'new authentication');
});

test('result permission entry rejects once-only, malformed, hidden, and expired-authentication results without reading', async () => {
  for (const change of [r => { r.receipt.scope_ids = []; }, r => { r.receipt.action = 'acknowledge'; },
    r => { r.receipt.at = 'invalid'; }, r => { r.receipt.scope_ids = ['']; }]) {
    const t = controller(), result = savedResult(); change(result);
    t.c.window.openReviewResult(result); await t.c.window.openReviewResultPermissions();
    assert.equal(t.requests.length, 0);
  }
  for (const change of [c => { c.drawer.hidden = true; }, c => { c.detailDrawer.setMode('flag'); }, c => { c.sessionEnded = true; }]) {
    const t = controller(); t.c.window.openReviewResult(savedResult()); change(t.c);
    await t.c.window.openReviewResultPermissions(); assert.equal(t.requests.length, 0);
  }
});

test('result permissions can inspect saved scope IDs when original session evidence is unavailable', async () => {
  const t = controller(), result = savedResult(); result.review = null;
  t.c.window.openReviewResult(result);
  const open = t.c.window.openReviewResultPermissions(); t.answer(0, []); await open;
  assert.match(t.body.innerHTML, /Session unavailable/);
  assert.match(t.body.innerHTML, /Current status unknown/);
  assert.doesNotMatch(t.body.innerHTML, /data-action="session-permission-revoke"/);
});

test('result permission revocation confirms only its linked scope and preserves the saved receipt after rereading', async () => {
  const t = controller(), result = savedResult(); t.c.window.openReviewResult(result);
  const open = t.c.window.openReviewResultPermissions(); t.answer(0, [scope(), scope('unrelated')]); await open;
  await t.c.window.revokeSessionPermission('unrelated'); assert.equal(t.requests.length, 1);
  const revoke = t.c.window.revokeSessionPermission('scope-a'); await settle();
  assert.equal(t.requests[1].url, '/decision-scopes?id=scope-a');
  assert.equal(t.requests[1].options.method, 'DELETE');
  t.answer(1, { revoked: true, id: 'scope-a' }); await settle();
  t.answer(2, [scope('scope-a', { revoked_at: at, applicability: { label: 'Revoked', revoke: false } })]); await revoke;
  assert.match(t.body.innerHTML, /Revocation saved/);
  t.drawers[0].back.reopen();
  assert.match(t.body.innerHTML, /Scoped permission recorded/);
  assert.deepEqual(result.receipt.scope_ids, receipt.ids);
});

test('a delayed result permission confirmation cannot revoke after authentication or drawer changes', async () => {
  for (const invalidate of [c => { c.handoffGeneration++; }, c => { c.detailDrawer.open({ title: 'Another' }); }, c => { c.sessionEnded = true; }]) {
    const t = controller(); t.c.window.openReviewResult(savedResult());
    const open = t.c.window.openReviewResultPermissions(); t.answer(0, [scope()]); await open;
    let confirm; t.c.window.saConfirm = () => new Promise(resolve => { confirm = resolve; });
    const revoke = t.c.window.revokeSessionPermission('scope-a');
    invalidate(t.c); confirm(true); await revoke;
    assert.equal(t.requests.length, 1, 'only the original read was issued');
  }
});

test('one decision view owns ordered rows, missing records, and revoke offers', () => {
  const c = context();
  const rows = c.decisionPermissionRows(receipt, [scope('unrelated'), scope()]);
  assert.deepEqual(Array.from(rows, row => row.id), receipt.ids);
  assert.equal(rows[0].label, 'Timed permission');
  assert.equal(rows[0].revoke, true);
  assert.match(rows[0].effect, /does not grant network access/);
  assert.equal(rows[1].record, null);
  assert.equal(rows[1].label, 'Current status unknown');
  assert.equal(rows[1].revoke, false);
  assert.throws(() => c.decisionPermissionRows(receipt, [scope(), scope()]));
  assert.throws(() => c.decisionPermissionRows(receipt, null));
  const unknown = c.decisionPermissionRows(receipt, [scope('scope-a', { applicability: { label: 'Allowed', revoke: 'yes' } })]);
  assert.equal(unknown[0].revoke, false);
  assert.equal(unknown[0].label, 'Applicability unknown');
  assert.equal(receipt.ids.length, 2, 'the saved receipt is unchanged');
});

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
  const html = c.sessionPermissionsHTML(receipt, { rows: c.decisionPermissionRows(receipt, [scope(), scope('unrelated')]), readAt: at });
  for (const text of ['revision 1', 'session-a', '/usr/bin/tool', '/work/a/.env', 'example.test:443', 'scope-missing',
    'Current status unknown', 'not signature verified', 'rechecks live session', 'does not grant network access']) assert.ok(html.includes(text), text);
  assert.ok(!html.includes('unrelated'));
  assert.ok(!html.includes('Permission active'));
  assert.match(html, /data-action="session-permission-revoke" data-id="scope-a"/);
});

test('failed refresh retains labeled last-known scopes and disables revocation', () => {
  const c = context();
  const stale = c.sessionPermissionsHTML(receipt, { rows: c.decisionPermissionRows(receipt, [scope()]), readAt: at, error: 'unavailable' });
  assert.match(stale, /Last known permission records/);
  assert.match(stale, /Timed permission/);
  assert.ok(!stale.includes('data-action="session-permission-revoke"'));
  const hostile = c.sessionPermissionsHTML({ ...receipt, sessionID: '<img>' }, { rows: c.decisionPermissionRows(receipt, [scope('scope-a', { workspace: '<img>' })]) });
  assert.ok(!hostile.includes('<img>'));
});

test('session permissions render server applicability and hide revoke when it is false or absent', () => {
  const c = context();
  const offered = c.sessionPermissionsHTML(receipt, { rows: c.decisionPermissionRows(receipt, [scope('scope-a', { revoked_at: at, applicability: { label: 'Timed permission', revoke: true } })]) });
  assert.match(offered, />Timed permission</);
  assert.match(offered, /Expected read\/connect activity/);
  assert.match(offered, /does not grant network access/);
  assert.match(offered, /data-action="session-permission-revoke" data-id="scope-a"/);
  const withheld = c.sessionPermissionsHTML(receipt, { rows: c.decisionPermissionRows(receipt, [scope('scope-a', { applicability: { label: 'Expired', revoke: false } })]) });
  assert.match(withheld, />Expired</);
  assert.match(withheld, /Expected read\/connect activity/);
  assert.match(withheld, /does not grant network access/);
  assert.ok(!withheld.includes('data-action="session-permission-revoke"'));
  const absent = c.sessionPermissionsHTML(receipt, { rows: c.decisionPermissionRows(receipt, [scope('scope-a', { applicability: undefined })]) });
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
  for (const invalidate of [c => c.detailDrawer.open({ title: 'Another' }), c => { c.selectedSessionId = 'b'; }, c => c.handoffGeneration++, c => { c.sessionEnded = true; }]) {
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
