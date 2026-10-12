import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
import { controller } from './controllers.mjs';
const app = readFileSync(new URL('app.js', assets), 'utf8');
function fixture() {
  const ids = ['posture-banner', 'posture-state', 'posture-summary', 'posture-items', 'posture-health', 'posture-retry', 'tabs-posture', 'tabs-posture-text'];
  const nodes = new Map(ids.map(id => [id, { hidden: false, dataset: {}, textContent: '', innerHTML: '' }]));
  const panels = ['snapshot', 'snapshot|guard decisions', 'snapshot|flags', 'resources'].map(reports =>
    ({ dataset: { reports }, textContent: '', hidden: true }));
  const toasts = [];
  const ctx = { window: { SA: { t: { posture: { state: 'critical', needs_you: 1, summary: 'Known finding needs review' }, flags: [] }, activeTab: 'home' } },
    document: { getElementById: id => nodes.get(id), querySelectorAll: () => panels },
    telemetryData: null, sessionEnded: false, failedEndpoints: new Set(),
    showToast: (...args) => toasts.push(args), isFlagsFiltered: () => true, isEventsFiltered: () => false, homeGroupOpen: () => false };
  ctx.telemetryData = ctx.window.SA.t;
  vm.createContext(ctx);
  for (const name of ['lib.js', 'report-health.js', 'tab-overview.js']) vm.runInContext(readFileSync(new URL(name, assets), 'utf8'), ctx);
  ctx.reportHealth = ctx.createConsoleReportHealth({ now: () => 1234 });
  Object.defineProperty(ctx.window.SA, 'postureHealth', { get() {
    return { lastSnapshotAt: 1234, error: ctx.reportHealth.failures(['snapshot'])[0]?.error || '' };
  } });
  Object.assign(ctx, controller('console-lifecycle.js', 'createConsoleLifecycle', ctx));
  ctx.renderPosture();
  return { ctx, nodes, panels, toasts };
}

test('snapshot failure updates the headline immediately and does not repeat across panels or toast', () => {
  const f = fixture();
  f.ctx.noteEndpointFailure('snapshot');
  f.ctx.reportFailed('snapshot', 'HTTP 503');
  assert.equal(f.nodes.get('posture-state').textContent, 'Urgent review');
  assert.equal(f.nodes.get('posture-health').hidden, false);
  assert.match(f.nodes.get('posture-health').textContent, /Status stale/);
  assert.equal(f.nodes.get('tabs-posture-text').textContent, '1 needs you · refresh failed');
  assert.equal(f.panels.filter(p => p.dataset.reports.includes('snapshot')).every(p => p.hidden), true);
  assert.equal(f.toasts.length, 0);
});

test('consolidated snapshot status preserves independent guard, filtered finding and resource failures', () => {
  const f = fixture();
  f.ctx.reportFailed('snapshot', 'HTTP 503');
  for (const key of ['guard decisions', 'flags', 'resources']) f.ctx.reportFailed(key, 'Invalid response');
  assert.equal(f.panels[0].hidden, true);
  for (const [index, label] of [[1, 'Guard decisions'], [2, 'Filtered findings'], [3, 'Resources']]) {
    assert.equal(f.panels[index].hidden, false);
    assert.match(f.panels[index].textContent, new RegExp(label + ': Unavailable'));
    assert.doesNotMatch(f.panels[index].textContent, /Live telemetry/);
  }
});

test('a missing or hidden headline falls back to panel status and the deduplicated snapshot toast', () => {
  for (const absent of [false, true]) {
    const f = fixture();
    if (absent) f.nodes.delete('posture-health');
    else f.nodes.get('posture-banner').hidden = true;
    f.ctx.noteEndpointFailure('snapshot');
    f.ctx.noteEndpointFailure('snapshot');
    f.ctx.reportFailed('snapshot', 'HTTP 503');
    assert.equal(f.toasts.length, 1);
    assert.equal(f.panels[0].hidden, false);
    assert.match(f.panels[0].textContent, /Live telemetry: Unavailable/);
  }
});

test('snapshot recovery clears the headline while unrelated report failures remain visible', () => {
  const f = fixture();
  f.ctx.reportFailed('snapshot', 'HTTP 503');
  f.ctx.reportFailed('guard decisions', 'HTTP 503');
  f.ctx.reportSucceeded('snapshot');
  assert.equal(f.nodes.get('posture-health').hidden, true);
  assert.equal(f.nodes.get('posture-retry').hidden, true);
  assert.equal(f.nodes.get('tabs-posture-text').textContent, '1 needs you');
  assert.equal(f.panels[0].hidden, true);
  assert.equal(f.panels[1].hidden, false);
  assert.match(f.panels[1].textContent, /Guard decisions: Unavailable/);
});
