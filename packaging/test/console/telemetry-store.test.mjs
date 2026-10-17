import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

function store(data = {}) {
  const ctx = vm.createContext({});
  vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/telemetry-store.js', import.meta.url), 'utf8'), ctx);
  return ctx.createTelemetryStore(data);
}

test('a newer refresh supersedes hot reports; only a newer slow refresh supersedes slow reports', () => {
  const s = store();
  const slow = s.beginRefresh(true);
  const fast = s.beginRefresh(false);
  assert.equal(slow.current(), false);
  assert.equal(slow.currentSlow(), true);
  assert.equal(fast.current(), true);
  assert.equal(fast.currentSlow(), false);
  const newer = s.beginRefresh(true);
  assert.equal(slow.currentSlow(), false);
  assert.equal(newer.currentSlow(), true);
});

test('invalidate makes every refresh in flight obsolete', () => {
  const s = store();
  const slow = s.beginRefresh(true);
  s.invalidate();
  assert.equal(slow.current(), false);
  assert.equal(slow.currentSlow(), false);
});

test('expected-egress reads and slow refreshes supersede each other in start order', () => {
  const s = store();
  const refresh = s.beginRefresh(true);
  const read = s.beginExpectedEgressRead();
  assert.equal(refresh.ownsExpectedEgress(), false);
  assert.equal(read(), true);
  const later = s.beginRefresh(true);
  assert.equal(read(), false);
  assert.equal(later.ownsExpectedEgress(), true);
  s.beginRefresh(false);
  assert.equal(later.ownsExpectedEgress(), true, 'a fast refresh does not read expected egress');
});

test('a snapshot publishes its reports, keeps paged reviews and reports a daemon restart', () => {
  const data = { reviews: { page: 2 }, incidents: [{ id: 'kept' }] };
  const s = store(data);
  assert.equal(s.lastSnapshotAt, 0);
  const snap = { status: { uptime: 'x' }, flags: [{ id: 'a' }, { id: 'b', acknowledged: true }], reviews: [{ id: 'first' }], events: [], posture: { state: 'all-clear' } };
  assert.equal(s.applySnapshot(snap, { uptime: 100, keepReviews: true }), false);
  assert.ok(s.lastSnapshotAt > 0);
  assert.deepEqual(data.flags.map(f => f.id), ['a']);
  assert.deepEqual(data.reviews, { page: 2 });
  assert.deepEqual(data.incidents, [{ id: 'kept' }], 'an absent report keeps its last-good data');
  assert.equal(data.posture.state, 'all-clear');
  assert.equal(s.applySnapshot(snap, { uptime: 97 }), false, 'within the five-second tolerance');
  assert.equal(s.applySnapshot(snap, { uptime: 3 }), true);
  assert.deepEqual(data.reviews, [{ id: 'first' }]);
});

test('slow reports publish only what arrived and report a changed notification config once', () => {
  const data = { audit: [{ id: 'kept' }] };
  const s = store(data);
  const cfg = { overrides: {}, scopes: [] };
  assert.equal(s.applySlowReports({ fleet: [{ host: 'h' }], notifyCfg: cfg, egressEpisodes: { episodes: [{ id: 'e' }] }, expectedEgress: { rules: [{ id: 'r' }] } }, false), true);
  assert.deepEqual(data.audit, [{ id: 'kept' }]);
  assert.deepEqual(data.egressEpisodes, [{ id: 'e' }]);
  assert.equal(data.expectedEgress, undefined, 'a superseded expected-egress read does not publish');
  assert.equal(s.applySlowReports({ notifyCfg: { overrides: {}, scopes: [] }, expectedEgress: { rules: [{ id: 'r' }] } }, true), false);
  assert.deepEqual(data.expectedEgress, [{ id: 'r' }]);
});
