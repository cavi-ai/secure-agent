import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);

function load(posture, t = {}) {
  const nodes = new Map(['attention-center', 'attention-list', 'badge-attention-count', 'coverage-center', 'coverage-list', 'badge-coverage-count']
    .map(id => [id, { hidden: false, innerHTML: '', textContent: '', children: [] }]));
  const badges = [];
  const sa = { t: { status: {}, flags: [], incidents: [], patterns: [], routine: [], posture, ...t },
    expanded: new Set(), setTabBadge: (id, n) => badges.push([id, n]) };
  const ctx = { window: { SA: sa }, document: { getElementById: id => nodes.get(id) } };
  vm.createContext(ctx);
  for (const name of ['lib.js', 'tab-findings.js']) vm.runInContext(readFileSync(new URL(name, assets), 'utf8'), ctx);
  const patched = [];
  ctx.patchList = (_node, items, opts) => patched.push({ items, opts });
  return { ctx, nodes, badges, patched, sa };
}

const guardItem = { kind: 'guard', priority: 5, id: 'g1', title: 'Guard decision', detail: 'Bash wants access to /tmp/x', rule: 'r1', path: '/tmp/x', scopeText: 'This path' };
const group = (items, over = {}) => ({ key: 'session:1', label: 'repo', agent: 'codex', workspace: '/work/repo', items, ...over });
const bars = html => {
  const [bar, menu = ''] = html.split('<details class="act-more">');
  const labels = s => [...s.matchAll(/<button[^>]*>([^<]+)<\/button>/g)].map(m => m[1]);
  return { bar: labels(bar.split('<div class="need-actions">')[1] || ''), more: labels(menu) };
};

test('an empty queue hides the needs panel and the Home badge', () => {
  const { ctx, nodes, badges, patched } = load({ state: 'all-clear', needs_you: 0, items: [], groups: [], coverage_items: [] });
  ctx.renderAttention();
  assert.equal(nodes.get('attention-center').hidden, true);
  assert.deepEqual(badges, [['home', 0]]);
  assert.equal(patched[0].items.length, 0);
});

test('a queued item shows the panel with its count', () => {
  const { ctx, nodes, badges } = load({ needs_you: 1, items: [{}], groups: [group([guardItem])], coverage_items: [] });
  ctx.renderAttention();
  assert.equal(nodes.get('attention-center').hidden, false);
  assert.equal(nodes.get('badge-attention-count').textContent, 1);
  assert.deepEqual(badges, [['home', 1]]);
});

test('a guard prompt has Allow once and Deny on the row and the rules under More', () => {
  const { ctx } = load({ needs_you: 1, groups: [group([guardItem])] });
  const html = ctx.needHTML({ ...guardItem, group: group([guardItem]) }, '');
  const { bar, more } = bars(html);
  assert.deepEqual(bar, ['Allow once', 'Deny']);
  assert.deepEqual(more, ['Allow rule', 'Deny rule']);
  assert.match(html, /data-verdict="deny" data-scope="once"/);
});

test('the queue lists higher priority first and keeps served order within a priority', () => {
  const resource = { kind: 'resource', priority: 4, id: 'r1', action: 'terminate', title: 'Resource pressure', detail: 'big' };
  const flagA = { kind: 'flag', priority: 2, id: 'fa', title: 'Critical finding', detail: 'a' };
  const flagB = { kind: 'flag', priority: 2, id: 'fb', title: 'Critical finding', detail: 'b' };
  const { ctx } = load({});
  const order = ctx.needsItems({ groups: [group([flagA, flagB]), group([resource, guardItem], { key: 'session:2' })] });
  assert.deepEqual([...order.map(i => i.id)], ['g1', 'r1', 'fa', 'fb']);
});

test('a critical flag has one row button, the recommended action, and the rest under More', () => {
  const flag = { id: 'f1', agent: 'codex', rule: 'tcc-tamper', severity: 3, ts: '2026-10-08T10:00:00Z', explain: {
    what: 'codex read a secret then connected out', disposition: { state: 'critical', text: 'Act now', why: 'Unknown destination' },
    actions: [
      { id: 'dismiss', label: 'Dismiss', consequence: 'c', method: 'POST', path: '/flags/acknowledge', body: {} },
      { id: 'allow-host', label: 'Allow api.example.com', consequence: 'c', method: 'POST', path: '/allowlist', body: { agent: 'codex', host: 'api.example.com' }, recommended: true },
    ] } };
  const item = { kind: 'flag', priority: 2, id: 'f1', title: 'Critical finding', detail: 'x' };
  const { ctx } = load({}, { flags: [flag] });
  const html = ctx.needHTML({ ...item, group: group([item]) }, '');
  const { bar, more } = bars(html);
  assert.deepEqual(bar, ['Allow api.example.com']);
  assert.ok(more.includes('Dismiss') && more.includes('What to do'));
  assert.match(html, /codex read a secret then connected out/);
  assert.match(html, /Unknown destination/);
});

test('without a recommended action What to do is the one row button', () => {
  const flag = { id: 'f2', agent: 'codex', rule: 'tcc-tamper', severity: 3, explain: {
    what: 'w', disposition: { state: 'critical', text: 'Act now', why: 'y' },
    actions: [{ id: 'dismiss', label: 'Dismiss', consequence: 'c', method: 'POST', path: '/flags/acknowledge', body: {} }] } };
  const item = { kind: 'flag', priority: 2, id: 'f2', title: 'Critical finding', detail: 'x' };
  const { ctx } = load({}, { flags: [flag] });
  const { bar, more } = bars(ctx.needHTML({ ...item, group: group([item]) }, ''));
  assert.deepEqual(bar, ['What to do']);
  assert.deepEqual(more, ['Dismiss']);
});
