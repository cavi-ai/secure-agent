import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadDrawer } from './drawer-harness.mjs';

test('open fills the surface, shows it, reserves room and remembers the opener', () => {
  const h = loadDrawer();
  const opener = { isConnected: true, focus() { this.focused = true; } };
  h.dom.document.activeElement = opener;
  assert.equal(h.api.open({ title: 'Title', icon: 'doc', body: '<p>b</p>', foot: '<b>f</b>', variant: 'wide' }), true);
  assert.equal(h.dom.title.textContent, 'Title');
  assert.equal(h.dom.titleIcon.attributes.get('href'), '#i-doc');
  assert.equal(h.dom.body.innerHTML, '<p>b</p>');
  assert.equal(h.dom.foot.innerHTML, '<b>f</b>');
  assert.equal(h.dom.foot.hidden, false);
  assert.equal(h.dom.drawer.hidden, false);
  assert.equal(h.dom.drawer.className, 'drawer wide');
  assert.deepEqual([...h.dom.classes].sort(), ['drawer-open', 'drawer-wide']);
  assert.equal(h.calls.closedDocks, 1);
  assert.equal(h.api.seq(), 1);
  h.api.close();
  assert.equal(opener.focused, true);
});

test('a drawer opened from inside the open one keeps the original opener', () => {
  const h = loadDrawer();
  const first = { isConnected: true, focus() { this.focused = true; } };
  const inside = { isConnected: true, focus() { this.focused = true; } };
  h.dom.document.activeElement = first;
  h.api.open({ title: 'A' });
  h.dom.document.activeElement = inside;
  h.api.open({ title: 'B' });
  h.api.close();
  assert.equal(first.focused, true);
  assert.equal(inside.focused, undefined);
});

test('close restores focus to the opener, else the attention list; runs onClose once and clears state', () => {
  const h = loadDrawer();
  let closed = 0;
  const opener = { isConnected: true, focus() { this.focused = true; } };
  h.dom.document.activeElement = opener;
  h.api.open({ title: 'A', body: 'x', foot: 'y', onClose: () => { closed++; }, attentionOrigin: { key: 'flag:a' } });
  assert.equal(h.api.selection().key, 'flag:a');
  h.api.close();
  h.api.close();
  assert.equal(closed, 1);
  assert.equal(opener.focused, true);
  assert.equal(h.dom.drawer.hidden, true);
  assert.equal(h.dom.body.innerHTML, '');
  assert.equal(h.dom.foot.hidden, true);
  assert.equal(h.api.selection(), null);
  assert.equal(h.calls.bumps, 1);
  assert.equal(h.dom.classes.size, 0);

  h.dom.document.activeElement = { isConnected: false, focus() { throw new Error('detached opener must not take focus'); } };
  h.api.open({ title: 'B' });
  h.api.close();
  assert.equal(h.dom.attentionHead.focused, 1);
  assert.equal(h.dom.attentionHead.focusOptions.preventScroll, true);
});

test('closing bumps the sequence so a late response cannot paint', () => {
  const h = loadDrawer();
  h.api.open({ title: 'A' });
  const before = h.api.seq();
  h.api.close();
  assert.equal(h.api.seq(), before + 1);
});

test('back target paints a label button, runs reopen, and is removed on close', () => {
  const h = loadDrawer();
  let reopened = 0;
  h.api.open({ title: 'A', back: { label: 'Needs you', reopen: () => { reopened++; } } });
  const button = h.dom.head.children.find(c => c.id === 'btn-drawer-back');
  assert.equal(button.textContent, '‹ Needs you');
  button.fire('click');
  assert.equal(reopened, 1);
  assert.equal(h.api.returnTarget().label, 'Needs you');
  h.api.close();
  assert.equal(h.api.returnTarget(), null);
});

test('back() names the open view and reopens it with the original way back', async () => {
  const h = loadDrawer({ deps: { respond: async () => ({ ok: false, status: 404, text: async () => '', json: async () => ({}) }) } });
  assert.equal(h.api.back(), null);
  const origin = { label: 'session', reopen() {}, sessionReturn: { id: 1 } };
  await h.api.openFileDetail('/w/a.env', { back: origin });
  const back = h.api.back();
  assert.equal(back.label, 'File');
  assert.equal(back.sessionReturn, origin.sessionReturn);
  const before = h.requests.length;
  back.reopen();
  assert.equal(h.api.mode(), 'file');
  assert.equal(h.api.returnTarget(), origin);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.ok(h.requests.length > before);
  h.api.setMode('policy');
  assert.equal(h.api.back(), null);
});

test('back from the attention inspector reselects the queue item and carries its selection', () => {
  const h = loadDrawer();
  h.api.setMode('attention');
  h.api.open({ title: 'Needs you', attentionOrigin: { key: 'flag:a', order: [] } });
  const back = h.api.back();
  assert.equal(back.label, 'Needs you');
  assert.equal(back.attentionOrigin.key, 'flag:a');
  back.reopen();
  assert.deepEqual(h.calls.selected, ['flag:a']);
});

test('review-result back reopens only inside the same authentication generation', () => {
  const h = loadDrawer();
  const result = { receipt: { decision: 'allow', status: 'saved' }, review: null };
  h.api.setMode('review-result');
  h.api.setReviewResult(result);
  h.api.open({ title: 'Result' });
  const back = h.api.back();
  h.state.generation++;
  back.reopen();
  assert.equal(h.api.reviewResult(), result);
  assert.equal(h.api.seq(), 1, 'a stale generation does not reopen the result');
});

test('isFlagOpen and isIncidentOpen follow the open view', async () => {
  const h = loadDrawer({ deps: { respond: async () => ({ ok: false, status: 404, text: async () => '' }) } });
  assert.equal(h.api.isFlagOpen('f1'), false);
  const pending = h.api.openFlagDetail('f1');
  assert.equal(h.api.isFlagOpen('f1'), true);
  assert.equal(h.api.isFlagOpen('f2'), false);
  await pending;
  h.api.close();
  assert.equal(h.api.isFlagOpen('f1'), false);
  const incident = h.api.openIncidentReport('inc-1');
  assert.equal(h.api.isIncidentOpen('inc-1'), true);
  assert.equal(h.dom.copyButton.hidden, false);
  await incident;
  h.api.close();
  assert.equal(h.api.isIncidentOpen('inc-1'), false);
});

test('a response for an older drawer is dropped', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const h = loadDrawer({ deps: { respond: async url => {
    if (url.startsWith('/files/detail?path=%2Fa')) await gate;
    return { ok: true, status: 200, json: async () => ({ path: 'late', facts: [] }), text: async () => '' };
  } } });
  const late = h.api.openFileDetail('/a');
  h.api.open({ title: 'Newer', body: 'newer body' });
  release();
  await late;
  assert.equal(h.dom.body.innerHTML, 'newer body');
  assert.deepEqual(h.calls.loadedPlans, []);
});

test('incident report renders the workflow, keeps the raw Markdown for Copy and loads its plan', async () => {
  const h = loadDrawer({ deps: { respond: async url => ({ ok: true, status: 200, text: async () => '# Original report',
    json: async () => ({ incident: { id: 'inc', remediation: null }, workflow: { status: 'acknowledged' } }) }) } });
  await h.api.openIncidentReport('inc');
  assert.deepEqual(h.requests.map(r => r[0]).sort(), ['/incidents?id=inc', '/incidents?id=inc&format=markdown']);
  assert.equal(h.dom.title.textContent, 'Incident report — inc');
  assert.equal(h.dom.body.innerHTML, h.ctx.incidentReportHTML('inc', { status: 'acknowledged' }, '# Original report', null));
  assert.match(h.dom.body.innerHTML, /incident-workflow-actions/);
  assert.deepEqual(h.calls.loadedPlans, ['incident:inc']);
  let written = null;
  h.ctx.navigator.clipboard = { writeText: async text => { written = text; } };
  await h.dom.copyButton.fire('click');
  assert.equal(written, '# Original report');
  assert.deepEqual(h.toasts.at(-1), ['Incident report copied to clipboard!', 'success']);
});

test('opening an older finding caches its served actions and reports a missing one', async () => {
  const flag = { id: 'older-flag', title: 'File access', rule: 'sensitive-read', agent: 'codex', ts: '2026-09-29T12:00:00Z', evidence: [], explain: { actions: [] } };
  const h = loadDrawer({ deps: { respond: async () => ({ ok: true, status: 200, json: async () => flag }) } });
  await h.api.openFlagDetail(flag.id);
  assert.deepEqual(h.calls.cachedFlags, [flag]);
  assert.match(h.dom.body.innerHTML, /File access/);
  assert.equal(h.dom.title.textContent, 'File access');
  assert.deepEqual(h.calls.loadedPlans, ['flag:older-flag']);
  const missing = loadDrawer({ deps: { respond: async () => ({ ok: false, status: 404, text: async () => '' }) } });
  await missing.api.openFlagDetail('gone');
  assert.match(missing.dom.body.innerHTML, /no longer available/);
});

test('the family drawer refills in place and reports a family that stopped running', () => {
  const h = loadDrawer();
  h.api.openFamilyDrawer('fam');
  assert.equal(h.api.mode(), 'family');
  assert.equal(h.dom.title.textContent, 'Family fam');
  assert.equal(h.dom.foot.innerHTML, 'foot:fam:Family fam');
  h.collaborators.family.byKey = () => undefined;
  h.api.fillFamily();
  assert.match(h.dom.body.innerHTML, /no longer running/);
  assert.equal(h.dom.foot.hidden, true);
  h.api.close();
  assert.equal(h.api.mode(), null);
});

test('the uninspected drawer refills only while it is the one open', () => {
  const h = loadDrawer();
  h.api.openUninspected();
  assert.equal(h.dom.body.innerHTML, 'uninspected rows');
  h.dom.body.innerHTML = '';
  h.api.refillUninspectedDrawer();
  assert.equal(h.dom.body.innerHTML, 'uninspected rows');
  h.api.refillUninspected();
  assert.deepEqual(h.calls.dirty, [['endpoints']]);
  h.api.close();
  h.dom.body.innerHTML = '';
  h.api.refillUninspectedDrawer();
  assert.equal(h.dom.body.innerHTML, '');
});

test('afterClose runs after the opener close hook', () => {
  const h = loadDrawer();
  const order = [];
  h.api.open({ title: 'A', onClose: () => order.push('hook') });
  h.api.afterClose(() => order.push('after'));
  h.api.close();
  assert.deepEqual(order, ['hook', 'after']);
});

test('Escape closes unless a confirmation is up; Tab stays inside a modal drawer', () => {
  const h = loadDrawer({ width: 390 });
  h.api.open({ title: 'A' });
  assert.equal(h.dom.drawer.attributes.get('role'), 'dialog');
  const keydown = h.dom.documentListeners.get('keydown');
  const confirm = { hidden: false };
  h.dom.document.getElementById = (original => id => (id === 'confirm-layer' ? confirm : original(id)))(h.dom.document.getElementById);
  keydown({ key: 'Escape' });
  assert.equal(h.dom.drawer.hidden, false);
  confirm.hidden = true;
  keydown({ key: 'Escape' });
  assert.equal(h.dom.drawer.hidden, true);
});

test('an ended session ignores keys and does not resync the mode', () => {
  const h = loadDrawer({ ended: true });
  h.api.open({ title: 'A' });
  assert.equal(h.dom.drawer.attributes?.get('role'), undefined);
  h.dom.documentListeners.get('keydown')({ key: 'Escape' });
  assert.equal(h.dom.drawer.hidden, false);
});

test('the role container keeps its title relationship across overlay and docked modes', () => {
  const h = loadDrawer({ width: 390 });
  h.api.open({ title: 'A' });
  const { drawer } = h.dom;
  assert.equal(drawer.attributes.get('role'), 'dialog');
  assert.equal(drawer.attributes.get('aria-modal'), 'true');
  assert.equal(drawer.attributes.get('aria-labelledby'), 'drawer-title');
  h.dom.document.documentElement.clientWidth = 1900;
  h.api.syncMode();
  assert.equal(drawer.attributes.get('role'), 'complementary');
  assert.equal(drawer.attributes.has('aria-modal'), false);
  assert.equal(drawer.attributes.get('aria-labelledby'), 'drawer-title');
});

test('the mode follows CSS media changes even when innerWidth stays stale', () => {
  const listeners = new Map();
  const media = new Map(['(min-width: 1180px)', '(min-width: 1340px)'].map(query => [query, {
    matches: false, addEventListener: (event, fn) => listeners.set(query, fn)
  }]));
  const h = loadDrawer({ width: 1179, media });
  h.dom.window.innerWidth = 1900;
  const { drawer } = h.dom;
  const main = h.dom.inertSiblings[0];
  h.api.open({ title: 'A' });
  assert.equal(drawer.attributes.get('role'), 'dialog');
  assert.equal(main.inert, true);
  media.get('(min-width: 1180px)').matches = true;
  listeners.get('(min-width: 1180px)')();
  assert.equal(drawer.attributes.get('role'), 'complementary');
  assert.equal(main.inert, false);
  drawer.className = 'drawer resource-policy';
  h.api.syncMode();
  assert.equal(drawer.attributes.get('role'), 'dialog');
  assert.equal(main.inert, true);
  media.get('(min-width: 1340px)').matches = true;
  listeners.get('(min-width: 1340px)')();
  assert.equal(drawer.attributes.get('role'), 'complementary');
  assert.equal(main.inert, false);
  assert.equal(h.dom.window.innerWidth, 1900);
});
