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

const harnesses = {proxy_enabled: false, coverage: {harnesses: [
  {name: 'codex', trace_supported: true, trace_last_seen: '2026-10-05T12:00:00Z', guard_supported: false},
  {name: '<unknown>', trace_supported: false, guard_supported: false},
]}};

test('session evidence remains visible without a machine gap and is not borrowed by a sibling', () => {
  const path = (state, last_seen = '') => ({supported: true, state, last_seen, detail: 'This session only'});
  const nodes = render({coverage: {sessions: [
    {session_id: 'a', harness: 'claude', workspace: '/work/observed', guard: path('observed', '2026-10-09T12:00:00Z'), trace: path('observed'), payload: path('off')},
    {session_id: 'b', harness: 'claude', workspace: '/work/<silent>', guard: path('not-observed'), trace: path('not-observed'), payload: path('off')},
  ]}});
  assert.equal(nodes.get('coverage-center').hidden, false);
  const html = nodes.get('coverage-list').innerHTML;
  assert.match(html, /\/work\/observed/);
  assert.match(html, /\/work\/&lt;silent&gt;/);
  assert.match(html, /Guard:.*observed/i);
  assert.match(html, /Guard:.*not observed/i);
  assert.doesNotMatch(html, /<silent>/);
});

test('the monitoring-gap panel stays hidden while harnesses exist but no gap does', () => {
  const nodes = render(harnesses, {coverage_count: 0, coverage_items: []});
  assert.equal(nodes.get('coverage-center').hidden, true);
});

test('coverage distinguishes harness capabilities and activity from payload inspection', () => {
  const nodes = render(harnesses, {coverage_count: 1, coverage_items: [{kind: 'collector_silent', title: 'Silent', detail: 'No events'}]});
  assert.equal(nodes.get('coverage-center').hidden, false);
  const html = nodes.get('coverage-list').innerHTML;
  assert.match(html, /<details class="coverage-harness"><summary>Per-agent coverage<\/summary>/);
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
