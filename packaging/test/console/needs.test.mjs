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
// needRow: one queue item rendered as its closed row.
const needRow = (ctx, sa, item) => ctx.needRowHTML(ctx.needView(item, ctx.homeContext(sa)), false, Date.now());

test('incident dismissal is available even when detail is outside the telemetry snapshot', () => {
  const item = {kind: 'incident', id: 'older', status: 'open', title: 'Critical incident'};
  const {ctx, sa} = load({needs_you: 1, groups: [group([item])]});
  const html = needRow(ctx, sa, {...item, group: group([item])});
  assert.deepEqual(bars(html).bar, ['View report', 'Dismiss']);
  assert.match(html, /data-id="older" data-status="acknowledged"/);
});

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

test('a guard prompt with unknown identity offers only Allow once and Deny', () => {
  const { ctx, sa } = load({ needs_you: 1, groups: [group([guardItem])] });
  const html = needRow(ctx, sa, { ...guardItem, group: group([guardItem]) });
  const { bar, more } = bars(html);
  assert.deepEqual(bar, ['Allow once', 'Deny']);
  assert.deepEqual(more, []);
  assert.match(html, /data-verdict="deny" data-scope="once"/);
});

test('a guard prompt offers only daemon-supported bounded future choices', () => {
  const item = {...guardItem, available_scopes:[{kind:'once'},{kind:'session'},{kind:'exact',expiry:'24h'},{kind:'exact',expiry:'7d'}]};
  const {ctx,sa} = load({needs_you:1,groups:[group([item])]});
  const html = needRow(ctx,sa,{...item,group:group([item])});
  const {bar,more}=bars(html);
  assert.deepEqual(bar,['Allow once','Deny']);
  assert.deepEqual(more,['Allow for this session','Allow for 24 hours','Allow for 7 days']);
  assert.match(html,/data-scope="exact" data-expiry="24h"/);
  assert.doesNotMatch(html,/data-scope="always"/);
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
  const { ctx, sa } = load({}, { flags: [flag] });
  const html = needRow(ctx, sa, { ...item, group: group([item]) });
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
  const { ctx, sa } = load({}, { flags: [flag] });
  const { bar, more } = bars(needRow(ctx, sa, { ...item, group: group([item]) }));
  assert.deepEqual(bar, ['What to do']);
  assert.deepEqual(more, ['Dismiss']);
});

test('leadOnly: the recommended item leads, else the fallback, else the first; the fallback always joins', () => {
  const { ctx } = load({});
  const lead = items => [...items.filter(i => i.bar).map(i => i.label)];
  const a = { label: 'A', bar: true }, b = { label: 'B', bar: true, recommended: true }, plan = { label: 'Plan' };
  assert.deepEqual(lead(ctx.leadOnly([a, b], plan)), ['B']);
  assert.deepEqual([...ctx.leadOnly([a, b], plan).map(i => i.label)], ['A', 'B', 'Plan']);
  assert.deepEqual(lead(ctx.leadOnly([a], plan)), ['Plan']);
  assert.deepEqual(lead(ctx.leadOnly([a, { label: 'C', bar: true }])), ['A']);
});

test('reviewedAfterOptimistic: reviewed ids leave the live lists, patterns drop their open counts, fully covered routine groups and their items leave', () => {
  const { ctx } = load({});
  const t = {
    flags: [{ id: 'f1' }, { id: 'f2' }, { id: 'f3' }], flagsView: [{ id: 'f1' }, { id: 'f3' }],
    patterns: [{ key: 'p', flag_ids: ['f1', 'f2'], unacked: 2 }],
    routine: [{ key: 'r', flag_ids: ['f1', 'f2'] }, { key: 'r2', flag_ids: ['f2', 'f3'] }],
    posture: { needs_you: 3, items: [{ kind: 'flag', id: 'f1' }, { kind: 'routine', id: 'r' }, { kind: 'routine', id: 'r2' }],
      groups: [{ key: 'g', items: [{ kind: 'flag', id: 'f1' }, { kind: 'routine', id: 'r' }, { kind: 'routine', id: 'r2' }] }] },
  };
  const next = ctx.reviewedAfterOptimistic(t, ['f1', 'f2']);
  assert.deepEqual([...next.flags.map(f => f.id)], ['f3']);
  assert.equal(next.flagsView.find(f => f.id === 'f1').acknowledged, true);
  assert.equal(next.patterns[0].dismissed, true);
  assert.deepEqual([...next.routine.map(r => r.key)], ['r2']);
  assert.equal(next.posture.needs_you, 1);
  assert.equal(t.flags.length, 3, 'the saved snapshot is untouched');
});
