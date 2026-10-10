import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const app = readFileSync(new URL('app.js', assets), 'utf8');
function fixture(posture, health = { lastSnapshotAt: 1234, error: '' }) {
  const ids = ['posture-banner', 'posture-state', 'posture-summary', 'posture-items', 'posture-health', 'posture-retry', 'tabs-posture', 'tabs-posture-text'];
  const nodes = new Map(ids.map(id => [id, { dataset: {}, textContent: '', innerHTML: '', hidden: false }]));
  const ctx = { window: { SA: { t: { posture, flags: [] }, postureHealth: health, activeTab: 'sessions' } },
    document: { getElementById: id => nodes.get(id) } };
  ctx.telemetryData = ctx.window.SA.t;
  vm.createContext(ctx);
  for (const name of ['lib.js', 'report-health.js', 'tab-overview.js']) {
    vm.runInContext(readFileSync(new URL(name, assets), 'utf8'), ctx);
  }
  const start = app.indexOf('  function paintTabsPosture()');
  const end = app.indexOf('\n  function ', start + 1);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(app.slice(start, end), ctx);
  return { ctx, nodes, paint() { ctx.renderPosture(); ctx.paintTabsPosture(); } };
}

test('both primary status surfaces wait for a published snapshot without claiming all clear', () => {
  const f = fixture({ state: 'all-clear', needs_you: 0, summary: 'Agents monitored, no action needed' }, { lastSnapshotAt: 0, error: '' });
  f.paint();
  assert.equal(f.nodes.get('posture-state').textContent, 'Waiting for telemetry');
  assert.equal(f.nodes.get('tabs-posture-text').textContent, 'Waiting for telemetry');
  assert.equal(f.nodes.get('posture-banner').dataset.state, 'unknown');
  assert.equal(f.nodes.get('posture-retry').hidden, true);
  assert.equal(f.nodes.get('posture-summary').textContent, '');
});

test('first read failure shows unavailable and Retry without inventing a safe status', () => {
  const f = fixture(null, { lastSnapshotAt: 0, error: 'HTTP 503' });
  f.paint();
  assert.equal(f.nodes.get('posture-state').textContent, 'Telemetry unavailable');
  assert.equal(f.nodes.get('tabs-posture-text').textContent, 'Telemetry unavailable');
  assert.match(f.nodes.get('posture-health').textContent, /No complete telemetry snapshot/);
  assert.equal(f.nodes.get('posture-retry').hidden, false);
});

test('failed refresh retains critical severity, decisions and evidence with a visible freshness warning', () => {
  const f = fixture({ state: 'critical', needs_you: 2, summary: 'Two decisions need review',
    items: [{ kind: 'guard', id: 'retained', title: 'Synthetic retained decision', severity: 3 }] },
  { lastSnapshotAt: 1234, error: 'HTTP 503' });
  f.paint();
  assert.equal(f.nodes.get('posture-banner').dataset.state, 'critical');
  assert.equal(f.nodes.get('tabs-posture').dataset.state, 'critical');
  assert.equal(f.nodes.get('posture-state').textContent, 'Critical');
  assert.equal(f.nodes.get('posture-summary').textContent, 'Two decisions need review');
  assert.match(f.nodes.get('posture-items').innerHTML, /Synthetic retained decision/);
  assert.match(f.nodes.get('posture-health').textContent, /Status stale.*last complete telemetry/);
  assert.equal(f.nodes.get('tabs-posture-text').textContent, '2 need you · refresh failed');
});

test('coverage gaps remain visible even with zero pending decisions and an all-clear input', () => {
  const f = fixture({ state: 'all-clear', needs_you: 0, coverage_count: 1, summary: 'One collector is silent' });
  f.paint();
  assert.equal(f.nodes.get('posture-state').textContent, 'Monitoring needs attention');
  assert.equal(f.nodes.get('tabs-posture-text').textContent, 'Monitoring gap');
  assert.equal(f.nodes.get('tabs-posture').dataset.state, 'attention');
});

test('stale quiet data cannot claim no pending decisions; recovery restores the bounded current status', () => {
  const f = fixture({ state: 'all-clear', needs_you: 0, coverage_count: 0, summary: 'No pending decisions' },
    { lastSnapshotAt: 1234, error: 'Invalid response' });
  f.paint();
  assert.equal(f.nodes.get('posture-state').textContent, 'Status stale');
  assert.equal(f.nodes.get('tabs-posture-text').textContent, 'Status stale');
  assert.equal(f.nodes.get('posture-banner').dataset.state, 'unknown');
  assert.equal(f.nodes.get('posture-summary').textContent, '');
  f.ctx.window.SA.postureHealth = { lastSnapshotAt: 5678, error: '' };
  f.paint();
  assert.equal(f.nodes.get('posture-state').textContent, 'No pending decisions');
  assert.equal(f.nodes.get('tabs-posture-text').textContent, 'No pending decisions');
  assert.equal(f.nodes.get('posture-health').hidden, true);
  assert.equal(f.nodes.get('posture-retry').hidden, true);
});

test('critical SSE observations remain visible before a complete snapshot has loaded', () => {
  const f = fixture({ state: 'critical', needs_you: 1, summary: 'Known observation needs review' },
    { lastSnapshotAt: 0, error: 'HTTP 503' });
  f.paint();
  assert.equal(f.nodes.get('posture-state').textContent, 'Critical');
  assert.equal(f.nodes.get('tabs-posture-text').textContent, '1 needs you · refresh failed');
  assert.match(f.nodes.get('posture-health').textContent, /No complete telemetry snapshot/);
});

test('a successful snapshot without a posture report cannot claim all clear', () => {
  const f = fixture(null);
  f.paint();
  assert.equal(f.nodes.get('posture-state').textContent, 'Status unavailable');
  assert.equal(f.nodes.get('tabs-posture').dataset.state, 'unknown');
});
