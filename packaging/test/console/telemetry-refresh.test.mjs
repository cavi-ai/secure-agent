import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const app = readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js', import.meta.url), 'utf8');
function source(begin, end) {
  const start = app.indexOf(begin), finish = app.indexOf(end, start);
  assert.ok(start >= 0 && finish > start);
  return app.slice(start, finish);
}
function response(body, status = 200) {
  return { status, ok: status === 200, json: async () => body };
}
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}
function fixture(fetch) {
  const requests = [], renders = [], connections = [], failures = [], retries = [];
  let stops = 0, ended = 0;
  const ctx = {
    sessionEnded: false, SS_TOKEN_KEY: 'fixture',
    telemetryFetchGen: 0, telemetrySlowGen: 0,
    historyScopes: { flags: null, events: null },
    filters: { flags: { agent: 'all', rule: 'all', minsev: 'all', since: 'all' }, events: { kind: 'all', since: 'all' } },
    sessionStorage: { removeItem() {} },
    liveUpdates: { stop: () => stops++ }, sparkTimer: 1,
    clearInterval() {}, clearTimeout() {},
    setTimeout: fn => { retries.push(fn); return 2; },
    showSessionEnded: () => ended++,
    apiFetch: path => { requests.push(path); return fetch(path); },
    telemetryData: { status: { uptime: 'prior' }, flags: [], events: [], guardPending: [{ id: 'prior' }], costs: { refreshing: true } },
    failedEndpoints: new Set(), noteEndpointFailure: key => failures.push(key),
    prevUptimeSec: 0, parseUptimeSec: () => 1, showToast() {},
    renderReportHealth() {}, loadSpend() {}, sparkIngestEvents() {}, reconcileRetriage() {},
    isFlagsFiltered: () => false, isEventsFiltered: () => false,
    flagsQuery: () => '/flags?fixture', eventsQuery: () => '/events?fixture',
    setConnState: state => connections.push(state),
    booted: true, PANELS: [['flags'], ['notify'], ['resources'], ['audit']], SLOW_ONLY: new Set(['resources', 'audit']), notifyCfgHash: '',
    markDirty: (...panels) => renders.push(panels), renderAll: () => renders.push('all'),
    fillFamilyDrawer() {}, renderNow: panels => renders.push(panels),
    spendGen: 0, spendPollTimer: 2, spendPolls: 0, SPEND_POLLS: 30, SPEND_POLL_MS: 2000,
    spendCardPath: () => '/costs?card'
  };
  vm.createContext(ctx);
  vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/report-health.js', import.meta.url), 'utf8'), ctx);
  vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/telemetry-validation.js', import.meta.url), 'utf8'), ctx);
  ctx.reportHealth = ctx.createConsoleReportHealth();
  vm.runInContext(source('  function endSession()', '  function setConnState(') +
    source('  function reportSucceeded(', '  // parseUptimeSec reads') +
    source('  function syncHistoryViews()', '  function flagsQuery()') +
    source('  async function fetchTelemetry(', '  // Every panel is a candidate:'), ctx);
  return { ctx, requests, renders, connections, failures, retries, stops: () => stops, ended: () => ended };
}
const snapshot = () => response({ status: { uptime: 'new' }, flags: [], events: [] });

test('a guard endpoint 403 ends the session even when the snapshot succeeds', async () => {
  const f = fixture(async path => path === '/snapshot' ? snapshot() : response(null, 403));
  const prior = f.ctx.telemetryData.status;
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.sessionEnded, true);
  assert.equal(f.stops(), 1);
  assert.equal(f.ended(), 1);
  assert.equal(f.ctx.telemetryData.status, prior);
  assert.equal(f.renders.length, 0);
});

test('authentication failure ends the session before a slower sibling request returns', async () => {
  const waiting = deferred();
  const f = fixture(path => path === '/snapshot' ? waiting.promise : Promise.resolve(response(null, 403)));
  const refresh = f.ctx.fetchTelemetry({ slow: false });
  await new Promise(setImmediate);
  try {
    assert.equal(f.ctx.sessionEnded, true);
    assert.equal(f.stops(), 1);
  } finally {
    waiting.resolve(snapshot());
    await refresh;
  }
});

test('an overlapping refresh cannot publish its response after session expiry', async () => {
  const oldSnapshot = deferred(), oldGuard = deferred();
  let calls = 0;
  const f = fixture(path => {
    if (++calls <= 2) return path === '/snapshot' ? oldSnapshot.promise : oldGuard.promise;
    return Promise.resolve(path === '/snapshot' ? response(null, 403) : response([]));
  });
  const prior = f.ctx.telemetryData.status;
  const old = f.ctx.fetchTelemetry({ slow: false });
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.sessionEnded, true);
  const renderCount = f.renders.length, connectionCount = f.connections.length;
  oldSnapshot.resolve(snapshot());
  oldGuard.resolve(response([{ id: 'late' }]));
  await old;
  assert.equal(f.ctx.telemetryData.status, prior);
  assert.equal(f.ctx.telemetryData.guardPending[0].id, 'prior');
  assert.equal(f.renders.length, renderCount);
  assert.equal(f.connections.length, connectionCount);
  assert.equal(f.stops(), 1);
});

test('a slow telemetry endpoint 403 also ends the session', async () => {
  const f = fixture(async path => path === '/snapshot' ? snapshot()
    : path.startsWith('/audit?') ? response(null, 403) : response([]));
  await f.ctx.fetchTelemetry();
  assert.equal(f.ctx.sessionEnded, true);
  assert.equal(f.stops(), 1);
  assert.equal(f.connections.length, 0);
  assert.equal(f.renders.length, 0);
});

test('filtered history authentication failure prevents the next history request', async () => {
  const f = fixture(async path => path === '/snapshot' ? snapshot()
    : path.startsWith('/flags?') ? response(null, 403) : response([]));
  f.ctx.isFlagsFiltered = f.ctx.isEventsFiltered = () => true;
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.sessionEnded, true);
  assert.equal(f.requests.includes('/events?fixture'), false);
  assert.equal(f.connections.length, 0);
});

function enableSpend(f) {
  vm.runInContext(source('  async function loadSpend(', '  // Spend card controls:'), f.ctx);
}

test('spend responses arriving after shutdown cannot render or arm another retry', async () => {
  const waiting = deferred();
  const f = fixture(() => waiting.promise);
  enableSpend(f);
  const prior = f.ctx.telemetryData.costs;
  const load = f.ctx.loadSpend(false);
  f.ctx.endSession();
  waiting.resolve(response({ refreshing: true, total: 99 }));
  await load;
  assert.equal(f.ctx.telemetryData.costs, prior);
  assert.equal(f.renders.length, 0);
  assert.equal(f.retries.length, 0);
});

test('a spend endpoint 403 ends the session without waiting for snapshot polling', async () => {
  const f = fixture(async () => response(null, 403));
  enableSpend(f);
  await f.ctx.loadSpend(false);
  assert.equal(f.ctx.sessionEnded, true);
  assert.equal(f.stops(), 1);
  assert.equal(f.retries.length, 0);
});

test('ordinary endpoint failure retains prior data without ending the session', async () => {
  const f = fixture(async path => path === '/snapshot' ? snapshot() : response(null, 503));
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.sessionEnded, false);
  assert.equal(f.ctx.telemetryData.guardPending[0].id, 'prior');
  assert.deepEqual(f.failures, ['guard decisions']);
  assert.deepEqual(f.connections, ['ok']);
});

test('an older full refresh cannot replace fast state but still supplies its slow reports', async () => {
  const oldSnapshot = deferred(), oldResources = deferred();
  let snapshotReads = 0, guardReads = 0;
  const f = fixture(path => {
    if (path === '/snapshot') return ++snapshotReads === 1 ? oldSnapshot.promise : Promise.resolve(snapshot());
    if (path === '/guard/pending') return Promise.resolve(response([{ id: ++guardReads === 1 ? 'old' : 'new' }]));
    if (path === '/resources') return oldResources.promise;
    return Promise.resolve(response(path.startsWith('/audit?') ? [{ id: 'slow-report' }] : []));
  });
  const old = f.ctx.fetchTelemetry();
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.telemetryData.status.uptime, 'new', 'fast guard refresh cannot wait for resources');
  oldSnapshot.resolve(response({ status: { uptime: 'old' }, flags: [{ id: 'old' }], events: [] }));
  oldResources.resolve(response({ host: { state: 'fresh-slow' } }));
  await old;
  assert.equal(f.ctx.telemetryData.status.uptime, 'new');
  assert.equal(f.ctx.telemetryData.guardPending[0].id, 'new');
  assert.equal(f.ctx.telemetryData.flags.length, 0);
  assert.equal(f.ctx.telemetryData.resources.host.state, 'fresh-slow');
  assert.equal(f.ctx.telemetryData.audit[0].id, 'slow-report');
  assert.deepEqual(f.connections, ['ok']);
  assert.ok(f.renders.some(panels => panels.includes('resources') && panels.includes('audit')));
});

test('a newer full refresh owns slow reports even when an old report arrives last', async () => {
  const oldAudit = deferred(), auditStarted = deferred();
  let auditReads = 0;
  const f = fixture(path => {
    if (path === '/snapshot') return Promise.resolve(snapshot());
    if (path.startsWith('/audit?')) {
      if (++auditReads === 1) { auditStarted.resolve(); return oldAudit.promise; }
      return Promise.resolve(response([{ id: 'new' }]));
    }
    return Promise.resolve(response([]));
  });
  const old = f.ctx.fetchTelemetry();
  await auditStarted.promise;
  await f.ctx.fetchTelemetry();
  oldAudit.resolve(response([{ id: 'old' }]));
  await old;
  assert.equal(f.ctx.telemetryData.audit[0].id, 'new');
});

test('filtered results from an older refresh cannot replace the current history', async () => {
  const oldFlags = deferred(), flagsStarted = deferred();
  let flagReads = 0;
  const f = fixture(path => {
    if (path === '/snapshot') return Promise.resolve(snapshot());
    if (path.startsWith('/flags?')) {
      if (++flagReads === 1) { flagsStarted.resolve(); return oldFlags.promise; }
      return Promise.resolve(response([{ id: 'new' }]));
    }
    return Promise.resolve(response([]));
  });
  f.ctx.isFlagsFiltered = () => true;
  const old = f.ctx.fetchTelemetry({ slow: false });
  await flagsStarted.promise;
  await f.ctx.fetchTelemetry({ slow: false });
  oldFlags.resolve(response([{ id: 'old' }]));
  await old;
  assert.equal(f.ctx.telemetryData.flagsView[0].id, 'new');
});

test('an obsolete endpoint error cannot replace a newer successful connection', async () => {
  const oldSnapshot = deferred();
  let snapshots = 0;
  const f = fixture(path => path === '/snapshot'
    ? (++snapshots === 1 ? oldSnapshot.promise : Promise.resolve(snapshot()))
    : Promise.resolve(response([])));
  const old = f.ctx.fetchTelemetry({ slow: false });
  await f.ctx.fetchTelemetry({ slow: false });
  oldSnapshot.resolve(response(null, 503));
  await old;
  assert.equal(f.ctx.telemetryData.connected, true);
  assert.deepEqual(f.connections, ['ok']);
  assert.deepEqual(f.failures, []);
});

test('authentication rejection from an obsolete refresh remains terminal', async () => {
  const oldSnapshot = deferred();
  let snapshots = 0;
  const f = fixture(path => path === '/snapshot'
    ? (++snapshots === 1 ? oldSnapshot.promise : Promise.resolve(snapshot()))
    : Promise.resolve(response([])));
  const old = f.ctx.fetchTelemetry({ slow: false });
  await f.ctx.fetchTelemetry({ slow: false });
  oldSnapshot.resolve(response(null, 403));
  await old;
  assert.equal(f.ctx.sessionEnded, true);
  assert.equal(f.stops(), 1);
});


test('guard request failure is visible without discarding last-good decisions', async () => {
  let fail = false;
  const f = fixture(async path => {
    if (path === '/snapshot') return snapshot();
    if (fail) throw new Error('timeout');
    return response([{ id: 'saved' }]);
  });
  await f.ctx.fetchTelemetry({ slow: false });
  fail = true;
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.telemetryData.guardPending[0].id, 'saved');
  assert.equal(f.ctx.reportHealth.failures(['guard decisions'])[0].state, 'stale');
  assert.equal(f.ctx.telemetryData.connected, true);
});

test('first-load failure is unavailable and only valid JSON clears it', async () => {
  let mode = 'http';
  const f = fixture(async path => {
    if (path === '/snapshot') return snapshot();
    if (mode === 'http') return response(null, 503);
    if (mode === 'invalid') return { status: 200, ok: true, json: async () => { throw new SyntaxError('bad JSON'); } };
    if (mode === 'null') return response(null);
    return response([]);
  });
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.reportHealth.failures(['guard decisions'])[0].state, 'unavailable');
  mode = 'invalid';
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.reportHealth.failures(['guard decisions'])[0].state, 'unavailable');
  mode = 'null';
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.reportHealth.failures(['guard decisions']).length, 1);
  mode = 'good';
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.reportHealth.failures(['guard decisions']).length, 0);
  assert.equal(f.ctx.telemetryData.guardPending.length, 0);
});

test('late obsolete failures cannot make a newer successful report stale', async () => {
  const oldGuard = deferred();
  let guards = 0;
  const f = fixture(async path => path === '/snapshot' ? snapshot()
    : (++guards === 1 ? oldGuard.promise : response([])));
  const old = f.ctx.fetchTelemetry({ slow: false });
  await f.ctx.fetchTelemetry({ slow: false });
  oldGuard.resolve(response(null, 503));
  await old;
  assert.equal(f.ctx.reportHealth.failures(['guard decisions']).length, 0);
});

test('obsolete success cannot clear the current failure', async () => {
  const oldGuard = deferred();
  let guards = 0;
  const f = fixture(async path => path === '/snapshot' ? snapshot()
    : (++guards === 1 ? oldGuard.promise : response(null, 503)));
  const old = f.ctx.fetchTelemetry({ slow: false });
  await f.ctx.fetchTelemetry({ slow: false });
  oldGuard.resolve(response([]));
  await old;
  assert.equal(f.ctx.reportHealth.failures(['guard decisions'])[0].state, 'unavailable');
});

test('slow report failure remains visible through a healthy fast refresh', async () => {
  const f = fixture(async path => path === '/snapshot' ? snapshot()
    : path.startsWith('/audit?') ? response(null, 503) : response([]));
  await f.ctx.fetchTelemetry();
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.reportHealth.failures(['audit'])[0].state, 'unavailable');
  assert.equal(f.ctx.telemetryData.connected, true);
});


test('a failed refresh preserves the last-success timestamp in its notice', async () => {
  let clock = 100, fail = false;
  const f = fixture(async path => path === '/snapshot' ? snapshot()
    : fail ? response(null, 503) : response([]));
  f.ctx.reportHealth = f.ctx.createConsoleReportHealth({ now: () => clock });
  await f.ctx.fetchTelemetry({ slow: false });
  fail = true;
  clock = 200;
  await f.ctx.fetchTelemetry({ slow: false });
  const failures = f.ctx.reportHealth.failures(['guard decisions']);
  assert.equal(failures[0].lastSuccessAt, 100);
  assert.match(f.ctx.consoleReportHealthText(failures, ms => `time-${ms}`), /Stale.*time-100.*HTTP 503/);
});

test('an obsolete spend response cannot clear a newer spend failure', async () => {
  const old = deferred();
  let cardReads = 0;
  const f = fixture(async path => path === '/costs?card'
    ? (++cardReads === 1 ? old.promise : response(null, 503)) : response({}));
  enableSpend(f);
  const first = f.ctx.loadSpend(false);
  await f.ctx.loadSpend(false);
  old.resolve(response({ total: { cost_usd: 100 } }));
  await first;
  assert.equal(f.ctx.reportHealth.failures(['spend card'])[0].state, 'unavailable');
  assert.equal(f.ctx.telemetryData.costsCard, undefined);
});


test('a failed new spend view is unavailable instead of claiming old-view data is retained', async () => {
  const f = fixture(async () => response(null, 503));
  f.ctx.reportHealth.success('spend card');
  f.ctx.telemetryData.costsCard = { total: { cost_usd: 100 } };
  Object.assign(f.ctx, { spendBySel: { value: 'provider' }, spendSinceSel: { value: '7d' },
    SPEND_BY: ['repo', 'provider'], SPEND_SINCE: ['24h', '7d'] });
  vm.runInContext(source('  const onSpendView = () => {', '  spendBySel?.addEventListener') + '\nonSpendView();', f.ctx);
  enableSpend(f);
  await f.ctx.loadSpend(false);
  assert.equal(f.ctx.telemetryData.costsCard, null);
  assert.equal(f.ctx.reportHealth.failures(['spend card'])[0].state, 'unavailable');
});


test('a malformed snapshot cannot partially replace the last-good status and findings', async () => {
  let bad = false;
  const f = fixture(async path => path === '/snapshot'
    ? response(bad ? { status: { uptime: 'corrupt' }, flags: { error: 'wrong shape' } }
      : { status: { uptime: 'good' }, flags: [{ id: 'saved' }], events: [] }) : response([]));
  await f.ctx.fetchTelemetry({ slow: false });
  bad = true;
  await assert.doesNotReject(f.ctx.fetchTelemetry({ slow: false }));
  assert.equal(f.ctx.telemetryData.status.uptime, 'good');
  assert.equal(f.ctx.telemetryData.flags[0].id, 'saved');
  assert.equal(f.ctx.reportHealth.failures(['snapshot'])[0].state, 'stale');
  assert.equal(f.ctx.telemetryData.connected, false);
  assert.equal(f.connections.at(-1), 'invalid-response');
});

for (const body of [{}, [], { status: [] }, { status: { uptime: 7 } },
  { status: { uptime: 'bad', agents: {} } }, { status: { uptime: 'bad', trees: [null] } },
  { status: { uptime: 'bad' }, events: [null] }, { status: { uptime: 'bad' }, sessions: {} },
  { status: { uptime: 'bad' }, posture: { items: {} } }]) {
  test(`invalid hot snapshot is unavailable and retains prior state: ${JSON.stringify(body)}`, async () => {
    const f = fixture(async path => path === '/snapshot' ? response(body) : response([]));
    await assert.doesNotReject(f.ctx.fetchTelemetry({ slow: false }));
    assert.equal(f.ctx.telemetryData.status.uptime, 'prior');
    assert.equal(f.ctx.reportHealth.failures(['snapshot'])[0].state, 'unavailable');
  });
}

test('malformed guard decisions preserve the pending decisions and warn independently', async () => {
  const f = fixture(async path => path === '/snapshot' ? snapshot() : response({ error: 'not a list' }));
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.telemetryData.guardPending[0].id, 'prior');
  assert.equal(f.ctx.reportHealth.failures(['guard decisions'])[0].state, 'unavailable');
  assert.equal(f.ctx.telemetryData.connected, true);
});

test('malformed filtered findings leave the selected view unavailable without discarding core findings', async () => {
  const f = fixture(async path => path === '/snapshot'
    ? response({ status: { uptime: 'good' }, flags: [{ id: 'saved' }], events: [] })
    : path.startsWith('/flags?') ? response([null]) : response([]));
  f.ctx.isFlagsFiltered = () => true;
  await assert.doesNotReject(f.ctx.fetchTelemetry({ slow: false }));
  assert.equal(f.ctx.telemetryData.flagsView, null);
  assert.equal(f.ctx.telemetryData.flags[0].id, 'saved');
  assert.equal(f.ctx.reportHealth.failures(['flags'])[0].state, 'unavailable');
});

test('a valid snapshot recovers after rejection and accepts absent or null optional fields', async () => {
  let bad = true;
  const f = fixture(async path => path === '/snapshot'
    ? response(bad ? { status: { uptime: 'bad' }, flags: {} }
      : { status: { uptime: 'good', agents: null, future_field: { enabled: true } }, flags: [], events: null }) : response([]));
  await assert.doesNotReject(f.ctx.fetchTelemetry({ slow: false }));
  bad = false;
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.telemetryData.status.uptime, 'good');
  assert.equal(f.ctx.reportHealth.failures(['snapshot']).length, 0);
  assert.equal(f.ctx.telemetryData.connected, true);
});


test('guard rows without usable decision IDs cannot replace actionable pending decisions', async () => {
  for (const rows of [[null], [{}], [{ id: '' }], [{ id: 5 }]]) {
    const f = fixture(async path => path === '/snapshot' ? snapshot() : response(rows));
    await f.ctx.fetchTelemetry({ slow: false });
    assert.equal(f.ctx.telemetryData.guardPending[0].id, 'prior');
    assert.equal(f.ctx.reportHealth.failures(['guard decisions'])[0].state, 'unavailable');
  }
});

test('malformed filtered events leave the selected view unavailable and retain core events', async () => {
  const f = fixture(async path => path === '/snapshot'
    ? response({ status: { uptime: 'good' }, flags: [], events: [{ kind: 8, ts: '2026-10-05T00:00:00Z', pid: 1 }] })
    : path.startsWith('/events?') ? response({ error: 'not a list' }) : response([]));
  f.ctx.isEventsFiltered = () => true;
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.telemetryData.eventsView, null);
  assert.equal(f.ctx.telemetryData.events[0].kind, 8);
  assert.equal(f.ctx.reportHealth.failures(['events'])[0].state, 'unavailable');
  assert.equal(f.ctx.telemetryData.connected, true);
});


for (const kind of ['flags', 'events']) {
  test(`failed ${kind} refresh preserves last-good results for the active filter`, async () => {
    let fail = false;
    const f = fixture(async path => path === '/snapshot'
      ? response({ status: { uptime: 'good' }, flags: [{ id: 'broad' }], events: [{ kind: 5, pid: 2 }] })
      : path.startsWith('/' + kind + '?') ? fail ? response(null, 503) : response([{ id: 'filtered', kind: 8, pid: 1 }]) : response([]));
    f.ctx[kind === 'flags' ? 'isFlagsFiltered' : 'isEventsFiltered'] = () => true;
    await f.ctx.fetchTelemetry({ slow: false });
    fail = true;
    await f.ctx.fetchTelemetry({ slow: false });
    assert.equal(f.ctx.telemetryData[kind + 'View'][0].id, 'filtered');
    assert.equal(f.ctx.reportHealth.failures([kind])[0].state, 'stale');
    assert.equal(f.ctx.telemetryData.connected, true);
  });

  test(`changing ${kind} filters clears foreign results before the new request completes`, async () => {
    const pending = deferred();
    let changed = false;
    const f = fixture(async path => path === '/snapshot' ? snapshot()
      : path.startsWith('/' + kind + '?') ? changed ? pending.promise : response([{ id: 'old-query', kind: 8, pid: 1 }]) : response([]));
    f.ctx[kind === 'flags' ? 'isFlagsFiltered' : 'isEventsFiltered'] = () => true;
    await f.ctx.fetchTelemetry({ slow: false });
    changed = true;
    f.ctx.filters[kind][kind === 'flags' ? 'agent' : 'kind'] = kind === 'flags' ? 'codex' : '5';
    const next = f.ctx.fetchTelemetry({ slow: false });
    const clearedImmediately = f.ctx.telemetryData[kind + 'View'] === null;
    pending.resolve(response(null, 503));
    await next;
    assert.equal(clearedImmediately, true);
    assert.equal(f.ctx.telemetryData[kind + 'View'], null);
    assert.equal(f.ctx.reportHealth.failures([kind])[0].state, 'unavailable');
  });
}

test('relative-window URL timestamps do not invalidate last-good results for the same selected window', async () => {
  let reads = 0, queryClock = 0;
  const f = fixture(async path => path === '/snapshot' ? snapshot()
    : path.startsWith('/flags?') ? ++reads === 1 ? response([{ id: 'window-result' }]) : response(null, 503) : response([]));
  f.ctx.isFlagsFiltered = () => true;
  f.ctx.filters.flags.since = '1h';
  f.ctx.flagsQuery = () => '/flags?since=' + ++queryClock;
  await f.ctx.fetchTelemetry({ slow: false });
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(queryClock, 2);
  assert.equal(f.ctx.telemetryData.flagsView[0].id, 'window-result');
  assert.equal(f.ctx.reportHealth.failures(['flags'])[0].state, 'stale');
});

test('a successful empty filtered result recovers from an unavailable first load', async () => {
  let fail = true;
  const f = fixture(async path => path === '/snapshot' ? snapshot()
    : path.startsWith('/flags?') ? fail ? response(null, 503) : response([]) : response([]));
  f.ctx.isFlagsFiltered = () => true;
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.telemetryData.flagsView, null);
  fail = false;
  await f.ctx.fetchTelemetry({ slow: false });
  assert.equal(f.ctx.telemetryData.flagsView.length, 0);
  assert.equal(f.ctx.reportHealth.failures(['flags']).length, 0);
});

test('clearing a filter restores live results and rejects a late filtered result', async () => {
  const pending = deferred();
  const f = fixture(async path => path === '/snapshot'
    ? response({ status: { uptime: 'good' }, flags: [{ id: 'live' }], events: [] })
    : path.startsWith('/flags?') ? pending.promise : response([]));
  let filtered = true;
  f.ctx.isFlagsFiltered = () => filtered;
  const old = f.ctx.fetchTelemetry({ slow: false });
  await new Promise(setImmediate);
  filtered = false;
  await f.ctx.fetchTelemetry({ slow: false });
  pending.resolve(response([{ id: 'filtered' }]));
  await old;
  assert.equal(f.ctx.telemetryData.flagsView[0].id, 'live');
  assert.equal(f.ctx.reportHealth.failures(['flags']).length, 0);
});


test('changing a filter after applying a saved view updates the active query', () => {
  const f = fixture(async () => response([]));
  let change;
  const select = { value: 'all', addEventListener: (_event, fn) => { change = fn; } };
  const queries = [];
  Object.assign(f.ctx, { window: {}, URLSearchParams, sinceParam: () => '',
    document: { getElementById: id => id === 'flags-agent' ? select : null },
    loadViews: () => [{ name: 'saved', flags: { agent: 'claude' } }],
    syncFilterControls() { select.value = f.ctx.filters.flags.agent; },
    fetchTelemetry: () => queries.push(f.ctx.flagsQuery()) });
  vm.runInContext(source('  function flagsQuery()', '  // ---------- saved views ----------') +
    source('  window.applyView = function(name)', '  window.removeView'), f.ctx);
  f.ctx.window.applyView('saved');
  select.value = 'codex';
  change();
  assert.match(queries.at(-1), /agent=codex/);
  assert.equal(f.ctx.filters.flags.agent, 'codex');
});
