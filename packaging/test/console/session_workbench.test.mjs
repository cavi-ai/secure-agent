import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const app = readFileSync(path.join(web, 'app.js'), 'utf8');
const session = (id, status = 'active', last_seen_at = '2026-10-09T10:00:00Z') => ({ id, status, last_seen_at });
const groups = (...sessions) => [{ key: 'codex', live: sessions.map(s => ({ session: s, children: [] })), ended: [] }];
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
function controller(persisted = '') {
  const storage = new Map([['sa.selected-session', persisted]]);
  const requests = [];
  const tasks = [];
  const panel = { dataset: {} };
  const context = { Date, URLSearchParams, AbortController, console,
    sessionStorage: { getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) },
    window: { addEventListener() {}, matchMedia: () => ({ matches: false }) },
    document: { getElementById: id => id === 'session-board-panel' ? panel : null, querySelectorAll: () => [], querySelector: () => null },
    queueMicrotask: cb => tasks.push(cb), requestAnimationFrame: () => 1,
    renderNow() {}, showToast() {}, sessionReadingHistory: () => false,
    apiFetch: url => { const d = deferred(); requests.push({ url, ...d }); return d.promise; },
  };
  vm.createContext(context);
  vm.runInContext(readFileSync(path.join(web, 'lib.js'), 'utf8'), context);
  const logic = app.slice(app.indexOf("  const SESSION_SELECTION_KEY"), app.indexOf('  // Export: copy the session'));
  const actions = app.slice(app.indexOf('  window.selectSession ='), app.indexOf('  // The drawer is shared by two views:'));
  vm.runInContext(logic + actions + `\nwindow.testState = {
    get selected() { return selectedSessionId; }, get mode() { return sessionView; },
    get memory() { return sessionMemoryPage; }, get memoryState() { return sessionMemoryState; }, get trace() { return sessionTimeline; },
    reconcile: reconcileSessionSelection, reveal: takeSessionReveal,
    filter() { sessionFilterTransition = true; },
    refresh: loadSessionMemory, traceRefresh: loadSessionTimeline,
  };`, context);
  return { context, panel, state: context.window.testState, actions: context.window, requests,
    flush: () => { for (const task of tasks.splice(0)) task(); },
    answer: (i, payload) => requests[i].resolve({ ok: true, json: async () => payload }),
  };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('initial selection restores a matching ID; otherwise active recency and ID decide', () => {
  const c = controller('saved');
  c.state.reconcile(groups(session('newest', 'active', '2026-10-09T11:00:00Z'), session('saved')));
  assert.equal(c.state.selected, 'saved');
  assert.equal(c.state.reveal(), true);
  assert.equal(c.state.reveal(), false);
  const choose = c.context.initialSessionId;
  assert.equal(choose([session('idle', 'idle', '2026-10-09T12:00:00Z'), session('b'), session('a')], ''), 'a');
});

test('empty entry can select first arrival; refresh disappearance retains identity; filters choose or empty', () => {
  const c = controller();
  c.state.reconcile(groups());
  assert.equal(c.state.selected, '');
  c.state.reconcile(groups(session('a')));
  assert.equal(c.state.selected, 'a');
  c.state.reconcile(groups(session('b')));
  assert.equal(c.state.selected, 'a', 'refresh does not silently replace a missing session');
  assert.equal(c.state.reveal(), true);
  assert.equal(c.state.reveal(), false);
  c.state.filter(); c.state.reconcile(groups(session('b')));
  assert.equal(c.state.selected, 'b');
  c.state.filter(); c.state.reconcile(groups());
  assert.equal(c.state.selected, '');
});

test('stable rail order keeps survivors despite recency changes and appends new members', () => {
  const c = controller();
  const items = [session('c'), session('b'), session('a')];
  const ordered = c.context.stableSessionOrder(items, ['a', 'b'], s => s.id);
  assert.deepEqual(Array.from(ordered, s => s.id), ['a', 'b', 'c']);
  assert.deepEqual(items.map(s => s.id), ['c', 'b', 'a']);
});

test('repeat selection retains selection, memory and mode; selecting another session in Trace fetches its trace', async () => {
  const c = controller();
  const select = c.actions.selectSession('a');
  c.answer(0, { rows: [{ id: 'row-a' }] }); await select;
  await c.actions.selectSession('a');
  assert.equal(c.state.selected, 'a');
  assert.equal(c.requests.length, 1);
  assert.equal(c.state.memory.rows[0].id, 'row-a');
  const trace = c.actions.setSessionView('trace');
  c.answer(1, [{ id: 'trace-a' }]); await trace;
  const next = c.actions.selectSession('b');
  assert.equal(c.state.mode, 'trace');
  assert.match(c.requests[2].url, /\/sessions\/b\/timeline/);
  c.answer(2, [{ id: 'trace-b' }]); await next;
  assert.equal(c.state.trace[0].id, 'trace-b');
  const memory = c.actions.setSessionView('memory');
  assert.match(c.requests[3].url, /\/sessions\/b\/memory/);
  c.answer(3, { rows: [{ id: 'row-b' }] }); await memory;
  assert.equal(c.state.memory.rows[0].id, 'row-b');
});

test('late Memory and Trace responses cannot overwrite a subsequent selection, including A to B to A', async () => {
  const c = controller();
  const first = c.actions.selectSession('a');
  const second = c.actions.selectSession('b');
  c.answer(1, { rows: [{ id: 'row-b' }] }); await second;
  c.answer(0, { rows: [{ id: 'late-a' }] }); await first;
  assert.equal(c.state.memory.rows[0].id, 'row-b');
  const traceB = c.actions.setSessionView('trace');
  const traceA = c.actions.selectSession('a');
  const backB = c.actions.selectSession('b');
  c.answer(4, [{ id: 'fresh-b' }]); await backB;
  c.answer(2, [{ id: 'old-b' }]); await traceB;
  c.answer(3, [{ id: 'late-a' }]); await traceA;
  assert.equal(c.state.trace[0].id, 'fresh-b');
});

test('Back pane survives refresh; loading earlier deduplicates and a latest refresh retains loaded history', async () => {
  const c = controller();
  const select = c.actions.selectSession('a');
  c.answer(0, { rows: [{ id: 'recent', at: '2026-10-09T12:00:00Z' }], has_earlier: true, next_cursor: 'older' }); await select;
  c.actions.showSessionList();
  c.state.reconcile(groups(session('a')));
  assert.equal(c.panel.dataset.pane, 'list');
  const earlier = c.actions.loadEarlierSessionMemory();
  c.answer(1, { rows: [{ id: 'old', at: '2026-10-09T10:00:00Z' }, { id: 'recent', at: '2026-10-09T12:00:00Z' }], has_earlier: false }); await earlier;
  const refresh = c.state.refresh('a');
  c.answer(2, { rows: [{ id: 'latest', at: '2026-10-09T13:00:00Z' }], has_earlier: true, next_cursor: 'ignored' }); await refresh;
  assert.deepEqual(Array.from(c.state.memory.rows, row => row.id), ['old', 'recent', 'latest']);
  assert.equal(c.state.memory.has_earlier, false);
  await settle();
});


test('latest refresh failure retains memory, identifies latest operation and accepts latest retry without earlier history', async () => {
  const c = controller();
  const select = c.actions.selectSession('a');
  c.answer(0, { rows: [{ id: 'retained' }], has_earlier: false }); await select;
  const refresh = c.state.refresh('a');
  c.requests[1].resolve({ ok: false, status: 503 }); await refresh;
  assert.equal(c.state.memory.rows[0].id, 'retained');
  assert.equal(c.state.memory.has_earlier, false);
  assert.equal(c.state.memoryState.error, 'latest');
  assert.equal(c.state.memoryState.loading, false);
  const retry = c.state.refresh('a');
  assert.equal(c.state.memoryState.error, '');
  assert.equal(c.requests[2].url, '/sessions/a/memory');
  c.answer(2, { rows: [{ id: 'fresh' }], has_earlier: false }); await retry;
  assert.equal(c.state.memory.rows[0].id, 'fresh');
  assert.equal(c.state.memoryState.error, '');
});

test('earlier page failure retains rows and cursor, identifies earlier operation and accepts earlier retry', async () => {
  const c = controller();
  const select = c.actions.selectSession('a');
  c.answer(0, { rows: [{ id: 'recent' }], has_earlier: true, next_cursor: 'older' }); await select;
  const earlier = c.actions.loadEarlierSessionMemory();
  c.requests[1].resolve({ ok: false, status: 503 }); await earlier;
  assert.equal(c.state.memory.rows[0].id, 'recent');
  assert.equal(c.state.memory.next_cursor, 'older');
  assert.equal(c.state.memoryState.error, 'earlier');
  assert.equal(c.state.memoryState.loadingEarlier, false);
  const retry = c.actions.loadEarlierSessionMemory();
  assert.equal(c.state.memoryState.error, '');
  assert.equal(c.requests[2].url, '/sessions/a/memory?before=older');
  c.answer(2, { rows: [{ id: 'old' }], has_earlier: false }); await retry;
  assert.deepEqual(Array.from(c.state.memory.rows, row => row.id), ['old', 'recent']);
  assert.equal(c.state.memoryState.error, '');
});


test('shifted newest page preserves initial displayed history and cursor only while reading history', async () => {
  const c = controller();
  const row = id => ({ id, at: '2026-10-09T' + ({ anchor: '10', recent: '11', latest: '12', newest: '13' }[id]) + ':00:00Z' });
  const select = c.actions.selectSession('a');
  c.answer(0, { rows: [row('anchor'), row('recent')], has_earlier: true, next_cursor: 'before-anchor' }); await select;
  c.context.sessionReadingHistory = () => true;
  const readingRefresh = c.state.refresh('a');
  c.answer(1, { rows: [row('recent'), row('latest')], has_earlier: true, next_cursor: 'before-recent' }); await readingRefresh;
  assert.deepEqual(Array.from(c.state.memory.rows, row => row.id), ['anchor', 'recent', 'latest']);
  assert.equal(c.state.memory.next_cursor, 'before-anchor');
  c.context.sessionReadingHistory = () => false;
  const followingRefresh = c.state.refresh('a');
  c.answer(2, { rows: [row('latest'), row('newest')], has_earlier: true, next_cursor: 'before-latest' }); await followingRefresh;
  assert.deepEqual(Array.from(c.state.memory.rows, row => row.id), ['latest', 'newest'], 'following latest returns to bounded newest page');
  assert.equal(c.state.memory.next_cursor, 'before-latest');
});

test('history detection uses current visible scroll position and saved history while Back hides detail', () => {
  const context = { window: {}, document: { getElementById: () => detail } };
  const body = { scrollHeight: 1000, clientHeight: 300, scrollTop: 200, getClientRects: () => [1] };
  const detail = { _sessionReadingKey: 'a|memory', querySelector: () => body };
  vm.createContext(context);
  vm.runInContext(readFileSync(path.join(web, 'tab-overview.js'), 'utf8'), context);
  assert.equal(context.sessionReadingHistory('a', 'memory'), true);
  body.scrollTop = 700;
  assert.equal(context.sessionReadingHistory('a', 'memory'), false);
  body.getClientRects = () => [];
  vm.runInContext("sessionReadingState.set('a|memory', { nearLatest: false });", context);
  assert.equal(context.sessionReadingHistory('a', 'memory'), true);
  vm.runInContext("sessionReadingState.set('a|memory', { nearLatest: true });", context);
  assert.equal(context.sessionReadingHistory('a', 'memory'), false);
  assert.equal(context.sessionReadingHistory('b', 'memory'), false);
});
