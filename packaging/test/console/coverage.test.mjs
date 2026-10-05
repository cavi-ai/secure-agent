import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
function render(status, posture = {}) {
  const nodes = new Map(['coverage-center', 'coverage-list', 'badge-coverage-count'].map(id => [id, {hidden: false, innerHTML: '', textContent: ''}]));
  const ctx = {window: {SA: {t: {status, posture}}}, document: {getElementById: id => nodes.get(id)}};
  vm.createContext(ctx);
  for (const name of ['lib.js', 'tab-findings.js']) vm.runInContext(readFileSync(new URL(name, assets), 'utf8'), ctx);
  ctx.renderCoverage();
  return nodes;
}

test('coverage distinguishes harness capabilities and activity from payload inspection', () => {
  const nodes = render({proxy_enabled: false, coverage: {harnesses: [
    {name: 'codex', trace_supported: true, trace_last_seen: '2026-10-05T12:00:00Z', guard_supported: false},
    {name: '<unknown>', trace_supported: false, guard_supported: false},
  ]}});
  assert.equal(nodes.get('coverage-center').hidden, false);
  const html = nodes.get('coverage-list').innerHTML;
  assert.match(html, /codex/);
  assert.match(html, /Trace: activity observed/);
  assert.match(html, /Guard: not supported/);
  assert.match(html, /Payload inspection is off/);
  assert.match(html, /&lt;unknown&gt;/);
  assert.doesNotMatch(html, /<unknown>/);
});

test('storage loss gives a storage remedy instead of a hook setup instruction', () => {
  const nodes = render({}, {coverage_count: 1, coverage_items: [{kind: 'storage_loss', title: 'Evidence could not be saved', detail: 'One write failed'}]});
  const html = nodes.get('coverage-list').innerHTML;
  assert.match(html, /disk space/);
  assert.doesNotMatch(html, /Check Setup/);
});
