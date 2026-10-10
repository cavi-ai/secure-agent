import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const app = readFileSync(new URL('app.js', web), 'utf8');
function controller() {
  const start = app.indexOf('  // Session investigation return context.');
  const end = app.indexOf('  // The open drawer as a way back', start);
  assert.ok(start >= 0 && end > start, 'session investigation controller exists');
  const listeners = {}, entries = [{ state: null, url: '#sessions' }];
  let index = 0;
  const body = { scrollTop: 215 }, rail = { scrollTop: 83 };
  const opener = { dataset: { action: 'session-findings', id: 'a' }, isConnected: true,
    closest: s => s === '#session-detail' ? {} : null, focus: () => { c.focused = 'opener'; } };
  const c = { console, URLSearchParams, selectedSessionId: 'a', sessionView: 'trace', activeTab: 'sessions', activeSub: 'board',
    handoffGeneration: 2, sessionEnded: false, timelineSession: 'prior', timelinePids: null, timelinePidLabel: '',
    drawerBack: null,
    filters: { events: { kind: 'all', since: 'all' } }, syncHistoryViews() {},
    suppressFreshOnce: false, location: { pathname: '/dashboard/', search: '', hash: '#sessions' }, calls: [],
    window: { SA: {}, scrollY: 27, scrollTo: (_x, y) => { c.pageY = y; }, addEventListener: (name, fn) => { listeners[name] = fn; } },
    document: { querySelector: s => s === '#session-detail .session-detail-body' ? body : s === '#session-rail' ? rail : null,
      querySelectorAll: () => [opener] },
    renderNow: () => { c.calls.push('render'); }, renderEvents() {}, renderFlags() {}, renderIncidents() {}, paintScopeBar() {},
    closeDrawer: () => { c.calls.push('close'); }, fetchTelemetry: () => { c.calls.push('read'); },
    openConsoleContext: (context, generation) => { c.calls.push({ freshContext: { ...context }, generation }); },
    switchTab: (route, opts) => { const r = c.resolveConsoleRoute(route); c.activeTab = r.tab; c.activeSub = r.sub; c.calls.push({ route, opts }); },
  };
  c.history = {
    get state() { return entries[index].state; },
    replaceState(state, _title, url) { entries[index] = { state, url }; c.location.hash = url.slice(url.indexOf('#')); },
    pushState(state, _title, url) { entries.splice(++index); entries.push({ state, url }); c.location.hash = url.slice(url.indexOf('#')); },
    back() { if (index) { c.location.hash = entries[--index].url.split('#').slice(1).join('#'); c.location.hash = '#' + c.location.hash; listeners.popstate({ state: entries[index].state }); } },
    forward() { if (index + 1 < entries.length) { c.location.hash = '#' + entries[++index].url.split('#').slice(1).join('#'); listeners.popstate({ state: entries[index].state }); } },
  };
  vm.createContext(c);
  vm.runInContext(readFileSync(new URL('event-history.js', web), 'utf8'), c);
  c.eventHistoryPage = c.createEventHistoryPage();
  vm.runInContext(readFileSync(new URL('lib.js', web), 'utf8'), c);
  vm.runInContext(app.slice(start, end), c);
  return { c, opener, body, rail, entries, listeners };
}

test('session finding history scopes evidence and Back restores the same view, prior scope, scroll and focus', () => {
  const { c, opener, body, rail, entries } = controller();
  c.window.openSessionFindings('a', opener);
  assert.equal(c.activeTab, 'home');
  assert.equal(c.timelineSession, 'a');
  assert.equal(c.window.SA.sessionInvestigationReturn, true);
  assert.equal(entries.length, 2);
  assert.ok(!entries.some(e => e.url.includes('ct=')));
  body.scrollTop = 0; rail.scrollTop = 0;
  c.window.returnToSessionInvestigation();
  assert.equal(c.activeTab, 'sessions');
  assert.equal(c.activeSub, 'board');
  assert.equal(c.sessionView, 'trace');
  assert.equal(c.timelineSession, 'prior');
  assert.equal(body.scrollTop, 215); assert.equal(rail.scrollTop, 83);
  assert.equal(c.pageY, 27); assert.equal(c.focused, 'opener');
  assert.equal(c.window.SA.sessionInvestigationReturn, false);
});

test('browser Back and Forward restore their own context without writing or replaying an action', () => {
  const { c, opener } = controller();
  c.window.openSessionFindings('a', opener);
  c.history.back();
  assert.equal(c.activeTab, 'sessions');
  c.history.forward();
  assert.equal(c.activeTab, 'home');
  assert.equal(c.timelineSession, 'a');
  assert.ok(c.calls.every(call => typeof call !== 'string' || ['close', 'render', 'read'].includes(call)));
});

test('resource Events carries the originating session through the process-family drawer', () => {
  const { c, opener } = controller();
  const back = c.sessionDrawerBack(opener);
  assert.equal(back.label, 'session');
  assert.equal(c.window.openSessionFamilyEvents(back.sessionReturn, [8, 9], 'synthetic family'), true);
  assert.equal(c.activeTab, 'sessions'); assert.equal(c.activeSub, 'events');
  assert.deepEqual(Array.from(c.timelinePids), [8, 9]);
  c.history.back();
  assert.equal(c.activeSub, 'board');
  assert.equal(c.timelineSession, 'prior');
});

test('recorded Events needs no live process family and returns to the original view and event filters', () => {
  const { c, opener } = controller();
  c.sessionView = 'results';
  c.filters.events = { kind: '5', since: '24h' };
  c.window.openSessionEvents('a', opener);
  assert.equal(c.activeSub, 'events');
  assert.equal(c.timelineSession, 'a');
  assert.equal(c.timelinePids, null);
  c.filters.events.kind = '0'; c.filters.events.since = 'all';
  c.history.back();
  assert.equal(c.sessionView, 'results');
  assert.deepEqual(c.filters.events, { kind: '5', since: '24h' });
  assert.equal(c.focused, 'opener');
  c.history.forward();
  assert.deepEqual(c.filters.events, { kind: '0', since: 'all' });
});

test('changed authentication or selection invalidates an old return target and late browser navigation', () => {
  for (const change of [c => { c.handoffGeneration++; }, c => { c.sessionEnded = true; }, c => { c.selectedSessionId = 'b'; }]) {
    const { c, opener } = controller();
    const back = c.sessionDrawerBack(opener);
    c.window.openSessionFindings('a', opener);
    change(c);
    const tab = c.activeTab;
    assert.equal(c.window.SA.sessionInvestigationReturn, false);
    c.history.back(); back.reopen();
    assert.equal(c.activeTab, tab);
    assert.notEqual(c.focused, 'opener');
  }
});

test('Back and Forward preserve the event page and its frozen filter boundary', () => {
  const { c, opener } = controller();
  c.window.openSessionEvents('a', opener);
  Object.assign(c.eventHistoryPage, { cursor: 'older', trail: [''], next: 'oldest', since: 'fixed-time', paged: true });
  c.history.back();
  assert.equal(c.eventHistoryPage.cursor, '');
  c.history.forward();
  assert.equal(c.eventHistoryPage.cursor, 'older');
  assert.equal(c.eventHistoryPage.since, 'fixed-time');
  assert.deepEqual(Array.from(c.eventHistoryPage.trail), ['']);
  assert.equal(c.eventHistoryPage.next, 'oldest');
});

test('drawer Back stays local and restores logical focus after its source element is replaced', () => {
  const { c, opener } = controller();
  const back = c.sessionDrawerBack(opener);
  opener.isConnected = false;
  c.document.querySelectorAll = () => [{ dataset: { ...opener.dataset }, focus: () => { c.focused = 'replacement'; } }];
  back.reopen();
  assert.equal(c.focused, 'replacement');
  assert.equal(c.window.SA.sessionInvestigationReturn, false);
});

test('a global or mismatched action cannot invent a session return target', () => {
  const { c, opener, entries } = controller();
  assert.equal(c.sessionDrawerBack({ ...opener, closest: () => null }), null);
  c.window.openSessionFindings('different', opener);
  assert.equal(entries.length, 1);
  assert.equal(c.window.SA.sessionInvestigationReturn, false);
});

test('scope bar offers explicit return while Clear continues to clear evidence filters', () => {
  const { c } = controller();
  const html = c.scopeBarHTML({ session: 'a', events: 2, flags: 1, returnToSession: true });
  assert.match(html, /data-action="session-investigation-return"/);
  assert.match(html, /data-action="clear-scope"/);
  assert.ok(!c.scopeBarHTML({ session: 'a', events: 0, flags: 0 }).includes('session-investigation-return'));
  assert.match(c.scopeBarHTML({ returnToSession: true }), /Evidence filters cleared[\s\S]*session-investigation-return/);
});

test('a cancelled origin uses ordinary authenticated route navigation instead of restoring old cached reading state', () => {
  const { c, opener } = controller();
  c.window.openSessionFindings('a', opener);
  c.window.SA.clearSessionInvestigation();
  c.history.back();
  const fallback = c.calls.find(call => call.freshContext);
  assert.equal(fallback.freshContext.session, 'a');
  assert.equal(fallback.generation, c.handoffGeneration);
  assert.notEqual(c.focused, 'opener');
});

test('invalidating a session closes its nested drawer while retaining an unrelated global drawer', () => {
  const { c, opener } = controller();
  c.drawerBack = c.sessionDrawerBack(opener);
  c.window.SA.clearSessionInvestigation();
  assert.ok(c.calls.includes('close'));
  c.calls = []; c.drawerBack = { label: 'global evidence' };
  c.window.SA.clearSessionInvestigation();
  assert.ok(!c.calls.includes('close'));
});
