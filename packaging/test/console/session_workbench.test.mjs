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
const traceEvent = (session_id, id = 'saved') => ({ id, session_id, kind: 12, ts: '2026-10-09T10:00:00Z', tool: id, tool_status: 'ok', duration_ms: 10 });
function controller(persisted = '', manualOverview = false) {
  const storage = new Map([['sa.selected-session', persisted]]);
  const requests = [];
  const tasks = [];
  const panel = { dataset: {} };
  const context = { Date, URLSearchParams, AbortController, console,
    activeTab: 'sessions', activeSub: 'board', location: { pathname: '/dashboard/', search: '', hash: '' },
    history: { replaceState(_state, _title, url) { context.location.hash = url.slice(url.indexOf('#')); } },
    sessionStorage: { getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) },
    window: { SA: {}, addEventListener() {}, matchMedia: () => ({ matches: false }) },
    document: { getElementById: id => id === 'session-board-panel' ? panel : null, querySelectorAll: () => [], querySelector: () => null },
    queueMicrotask: cb => tasks.push(cb), requestAnimationFrame: () => 1,
    renderNow() {}, showToast() {}, sessionReadingHistory: () => false,
    apiFetch: url => {
      if (url.endsWith('/overview') && !manualOverview) return Promise.resolve({ ok: true, json: async () => ({ session_id: decodeURIComponent(url.split('/')[2]), requests: [], findings: [] }) });
      const d = deferred(); requests.push({ url, ...d }); return d.promise;
    },
  };
  vm.createContext(context);
  vm.runInContext(readFileSync(path.join(web, 'lib.js'), 'utf8'), context);
  vm.runInContext(readFileSync(path.join(web, 'tab-sessions.js'), 'utf8'), context);
  const logic = app.slice(app.indexOf("  const SESSION_SELECTION_KEY"), app.indexOf('  // Export: copy the session'));
  const actions = app.slice(app.indexOf('  window.selectSession ='), app.indexOf('  // The drawer is shared by two views:'));
  vm.runInContext(logic + actions + `\nwindow.testState = {
    get selected() { return selectedSessionId; }, get mode() { return sessionView; },
    get memory() { return sessionMemoryPage; }, get memoryState() { return sessionMemoryState; }, get trace() { return sessionTimeline; },
    get traceState() { return typeof sessionTimelineState === 'undefined' ? undefined : sessionTimelineState; },
    get results() { return sessionOutcomes; }, get resultState() { return sessionOutcomesState; },
    get overview() { return sessionOverview; }, get overviewState() { return sessionOverviewState; },
    reconcile: reconcileSessionSelection, reveal: takeSessionReveal,
    filter() { sessionFilterTransition = true; },
    refresh: loadSessionMemory, traceRefresh: loadSessionTimeline,
    resultRefresh: loadSessionOutcomes,
    overviewRefresh: loadSessionOverview,
  };`, context);
  return { context, panel, state: context.window.testState, actions: context.window, requests,
    flush: () => { for (const task of tasks.splice(0)) task(); },
    answer: (i, payload) => requests[i].resolve({ ok: true, json: async () => payload }),
  };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('malformed current status retains prior facts and keeps access decisions unavailable until recovery', async () => {
  const c = controller('', true);
  const selected = c.actions.selectSession('a');
  const saved = { session_id: 'a', observed_at: '2026-10-10T06:00:00Z', requests: [{ kind: 'guard', id: 'g', detail: 'Recorded request' }],
    findings: [{ id: 'f', title: 'Recorded finding', assessment: { risk: 'high', limits: ['Retained evidence'] } }],
    findings_truncated: false, coverage: null, resources: null };
  c.answer(0, { rows: [] }); c.answer(1, saved); await selected;
  assert.equal(c.state.overview, saved);
  const invalid = [
    { ...saved, requests: [null] },
    { ...saved, requests: [{ kind: 'guard', id: 'g', available_scopes: {} }] },
    { ...saved, findings: [{ id: 'f', assessment: { limits: {} } }] },
    { ...saved, coverage: { session_id: 'b', guard: {}, trace: {}, payload: {} } },
    { ...saved, resources: { key: 'r', rss_bytes: 'unknown', diagnoses: [] } },
  ];
  for (const data of invalid) {
    const read = c.state.overviewRefresh('a');
    c.answer(c.requests.length - 1, data); await read;
    assert.equal(c.state.overview, saved);
    assert.equal(c.state.overviewState.error, 'unavailable');
  }
  const retry = c.state.overviewRefresh('a');
  assert.equal(c.state.overviewState.loading, true);
  assert.equal(c.state.overviewState.error, 'unavailable');
  const recovered = { ...saved, requests: [], findings: [] };
  c.answer(c.requests.length - 1, recovered); await retry;
  assert.equal(c.state.overview, recovered);
  assert.equal(c.state.overviewState.error, '');
});

test('obsolete current-status failures cannot mark a newly selected session stale', async () => {
  const c = controller('', true);
  const a = c.actions.selectSession('a'); c.answer(0, { rows: [] });
  const b = c.actions.selectSession('b'); c.answer(2, { rows: [] });
  c.answer(3, { session_id: 'b', requests: [], findings: [] }); await b;
  c.requests[1].resolve({ ok: false, status: 503 }); await a;
  assert.equal(c.state.overview.session_id, 'b');
  assert.equal(c.state.overviewState.error, '');
});

const outcomes = (session_id, id = 'saved') => ({ session_id, history: {
  reviews: [], incidents: [], interventions: [{ id, requested_at: '2026-10-09T10:00:00Z', status: 'failed', verification: 'unknown' }],
  evidence: Object.fromEntries(['reviews', 'incidents', 'interventions'].map(k => [k, { available: true, at_limit: false, limit: 100 }])),
} });

test('Results stays scoped through A to B to A and rejects late obsolete receipts', async () => {
  const c = controller();
  const first = c.actions.selectSession('a'); c.answer(0, { rows: [] }); await first;
  const old = c.actions.setSessionView('results');
  assert.match(c.requests[1].url, /\/sessions\/a\/outcomes$/);
  const b = c.actions.selectSession('b');
  const a = c.actions.selectSession('a');
  c.answer(3, outcomes('a', 'new')); await a;
  c.answer(2, outcomes('b')); await b;
  c.answer(1, outcomes('a', 'obsolete')); await old;
  assert.equal(c.state.mode, 'results');
  assert.equal(c.state.results.history.interventions[0].id, 'new');
});

test('Results retains last-known receipts on failed, mismatched, or malformed reads and recovers with valid empty history', async () => {
  const c = controller();
  const first = c.actions.selectSession('a'); c.answer(0, { rows: [] }); await first;
  const open = c.actions.setSessionView('results'); c.answer(1, outcomes('a')); await open;
  for (const bad of [null, outcomes('b'), { ...outcomes('a'), history: { ...outcomes('a').history, interventions: [null] } }]) {
    const refresh = c.state.resultRefresh('a'); c.answer(c.requests.length - 1, bad); await refresh;
    assert.equal(c.state.results.history.interventions[0].id, 'saved');
    assert.equal(c.state.resultState.error, 'unavailable');
  }
  const fail = c.state.resultRefresh('a'); c.requests.at(-1).resolve({ ok: false, status: 503 }); await fail;
  assert.equal(c.state.results.history.interventions[0].id, 'saved');
  const partial = c.state.resultRefresh('a');
  const degraded = outcomes('a'); degraded.history.interventions = []; degraded.history.evidence.interventions.available = false;
  c.answer(c.requests.length - 1, degraded); await partial;
  assert.equal(c.state.results.history.interventions[0].id, 'saved', 'an independently failed source retains its last known receipts');
  assert.equal(c.state.results.history.evidence.interventions.available, false);
  const recover = c.state.resultRefresh('a');
  c.answer(c.requests.length - 1, { ...outcomes('a'), history: { ...outcomes('a').history, interventions: [] } }); await recover;
  assert.equal(c.state.resultState.error, '');
  assert.equal(c.state.results.history.interventions.length, 0);
});

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
  c.answer(1, [traceEvent('a', 'trace-a')]); await trace;
  const next = c.actions.selectSession('b');
  assert.equal(c.state.mode, 'trace');
  assert.match(c.requests[2].url, /\/sessions\/b\/timeline/);
  c.answer(2, [traceEvent('b', 'trace-b')]); await next;
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
  c.answer(4, [traceEvent('b', 'fresh-b')]); await backB;
  c.answer(2, [traceEvent('b', 'old-b')]); await traceB;
  c.answer(3, [traceEvent('a', 'late-a')]); await traceA;
  assert.equal(c.state.trace[0].id, 'fresh-b');
});

test('Trace identifies a first-load failure and retries without claiming an empty history', async () => {
  const c = controller();
  const select = c.actions.selectSession('a'); c.answer(0, { rows: [] }); await select;
  const open = c.actions.setSessionView('trace');
  assert.equal(c.state.traceState?.loading, true);
  c.requests[1].resolve({ ok: false, status: 503 }); await open;
  assert.equal(c.state.traceState.error, 'unavailable');
  assert.equal(c.state.traceState.loaded, false);
  const retry = c.actions.retrySessionTrace(); c.answer(2, []); await retry;
  assert.equal(c.state.traceState.error, '');
  assert.equal(c.state.traceState.loaded, true);
  assert.equal(c.state.trace.length, 0);
});

test('Trace retains last loaded rows on failed or malformed reads and recovers with valid empty history', async () => {
  const c = controller();
  const select = c.actions.selectSession('a'); c.answer(0, { rows: [] }); await select;
  const open = c.actions.setSessionView('trace'); c.answer(1, [traceEvent('a')]); await open;
  for (const bad of [null, {}, [null], [traceEvent('b')], [{ ...traceEvent('a'), ts: 'invalid' }],
    [{ ...traceEvent('a'), kind: '12' }], [{ ...traceEvent('a'), cost_usd: '1.0' }],
    [{ ...traceEvent('a'), duration_ms: Infinity }], Array.from({ length: 501 }, () => traceEvent('a'))]) {
    const refresh = c.state.traceRefresh('a', true); c.answer(c.requests.length - 1, bad); await refresh;
    assert.equal(c.state.trace?.[0]?.id, 'saved');
    assert.equal(c.state.traceState?.error, 'unavailable');
    assert.equal(c.state.traceState.loaded, true);
    assert.equal(c.state.traceState.loading, false);
  }
  const failure = c.state.traceRefresh('a', true);
  c.requests.at(-1).resolve({ ok: false, status: 503 }); await failure;
  assert.equal(c.state.trace[0].id, 'saved');
  assert.equal(c.state.traceState.error, 'unavailable');
  const retry = c.actions.retrySessionTrace();
  assert.equal(c.actions.retrySessionTrace(), undefined, 'repeated retry while loading makes no new request');
  c.answer(c.requests.length - 1, []); await retry;
  assert.equal(c.state.trace.length, 0);
  assert.equal(c.state.traceState.loaded, true);
  assert.equal(c.state.traceState.error, '');
});

test('Trace selection resets availability and an obsolete failure cannot mark the new session stale', async () => {
  const c = controller();
  const select = c.actions.selectSession('a'); c.answer(0, { rows: [] }); await select;
  const open = c.actions.setSessionView('trace'); c.answer(1, [traceEvent('a')]); await open;
  const old = c.state.traceRefresh('a', true);
  const next = c.actions.selectSession('b');
  assert.equal(c.state.traceState?.loaded, false);
  assert.equal(c.state.trace.length, 0);
  c.answer(3, [traceEvent('b', 'new')]); await next;
  c.requests[2].resolve({ ok: false, status: 503 }); await old;
  assert.equal(c.state.trace[0].id, 'new');
  assert.equal(c.state.traceState.error, '');
  assert.equal(c.state.traceState.loading, false);
});

test('Trace rendering distinguishes unavailable, stale, empty and bounded history', () => {
  const c = controller();
  c.context.window.SA.sessionView = 'trace';
  const render = (rows, state) => {
    c.context.window.SA.sessionTimelineState = state;
    return c.context.sessionDetailHTML({ id: 'a', harness: 'codex', status: 'ended' }, rows, []);
  };
  const failed = render([], { loaded: false, loading: false, error: 'unavailable' });
  assert.match(failed, /Trace unavailable/);
  assert.match(failed, /data-action="trace-retry"/);
  assert.doesNotMatch(failed, /No trace events/);
  const busy = render([], { loaded: false, loading: true, error: '' });
  assert.match(busy, /Loading trace/);
  assert.doesNotMatch(busy, /No trace events/);
  assert.doesNotMatch(render([traceEvent('a')], { loaded: true, loading: true, error: '' }), /Loading trace/,
    'routine background reads do not flash a loading notice over healthy history');
  const stale = render([traceEvent('a', 'SavedTool')], { loaded: true, loading: false, error: 'unavailable' });
  assert.match(stale, /last successfully loaded/);
  assert.match(stale, /SavedTool/);
  const full = render(Array.from({ length: 500 }, () => traceEvent('a')), { loaded: true, loading: false, error: '' });
  assert.match(full, /500.*earlier history may be omitted/i);
  assert.match(full, /data-action="session-events" data-id="a"/);
  assert.match(render([], { loaded: true, loading: false, error: '' }), /No trace events/);
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
