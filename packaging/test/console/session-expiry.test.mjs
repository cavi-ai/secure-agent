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
    sessionStorage: { removeItem() {} },
    liveUpdates: { stop: () => stops++ }, sparkTimer: 1,
    clearInterval() {}, clearTimeout() {},
    setTimeout: fn => { retries.push(fn); return 2; },
    showSessionEnded: () => ended++,
    apiFetch: path => { requests.push(path); return fetch(path); },
    telemetryData: { status: { uptime: 'prior' }, flags: [], events: [], guardPending: [{ id: 'prior' }], costs: { refreshing: true } },
    failedEndpoints: new Set(), noteEndpointFailure: key => failures.push(key),
    prevUptimeSec: 0, parseUptimeSec: () => 1, showToast() {},
    loadSpend() {}, sparkIngestEvents() {}, reconcileRetriage() {},
    isFlagsFiltered: () => false, isEventsFiltered: () => false,
    flagsQuery: () => '/flags?fixture', eventsQuery: () => '/events?fixture',
    setConnState: state => connections.push(state),
    booted: true, PANELS: [['flags'], ['notify']], SLOW_ONLY: new Set(), notifyCfgHash: '',
    markDirty: (...panels) => renders.push(panels), renderAll: () => renders.push('all'),
    fillFamilyDrawer() {}, renderNow: panels => renders.push(panels),
    spendGen: 0, spendPollTimer: 2, spendPolls: 0, SPEND_POLLS: 30, SPEND_POLL_MS: 2000,
    spendCardPath: () => '/costs?card'
  };
  vm.createContext(ctx);
  vm.runInContext(source('  function endSession()', '  function setConnState(') +
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
