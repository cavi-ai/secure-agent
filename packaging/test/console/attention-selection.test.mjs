import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const app = readFileSync(new URL('app.js', assets), 'utf8');
function fn(name, next) {
  const start = app.indexOf('  function ' + name + '(');
  const end = app.indexOf(next, start);
  assert.ok(start >= 0 && end > start);
  return app.slice(start, end);
}
function load(keys = ['flag:a', 'guard:b', 'incident:c']) {
  const items = keys.map(key => { const [kind, id] = key.split(':'); return { kind, id }; });
  const buttons = [{ disabled: false }];
  const ctx = {
    window: { saAnnounce() {} }, attentionSelection: { key: keys[0], order: keys }, attentionGeneration: 1,
    attentionWrites: new Set(), drawerSeq: 2, handoffGeneration: 3, sessionEnded: false,
    drawer: { hidden: false, querySelectorAll: () => buttons }, btnDrawerClose: { focus() { ctx.focused = true; } },
    telemetryData: { posture: { groups: [{ key: 'g', items }] } },
    attentionItems: () => ctx.telemetryData.posture.groups.flatMap(g => g.items),
    refreshAttentionInspector() {}, renderNow() { ctx.reconcileAttention(); },
    selectAttention(key, options) { ctx.selected.push(key); ctx.attentionSelection = { key, order: ctx.attentionItems().map(i => i.kind + ':' + i.id) }; ctx.focused = options.focus; },
    openDrawer(options) { ctx.empty = options; }, selected: [], focused: false,
  };
  vm.createContext(ctx);
  vm.runInContext(readFileSync(new URL('lib.js', assets), 'utf8'), ctx);
  vm.runInContext(fn('reconcileAttention', '  function beginAttentionWrite'), ctx);
  vm.runInContext(fn('beginAttentionWrite', '  function openDrawer'), ctx);
  vm.runInContext(fn('stage', '  // posture.groups'), ctx);
  return { ctx, buttons };
}
function remove(ctx, id) {
  return ctx.stage(['posture'], ['attention'], () => {
    ctx.telemetryData.posture = { groups: [{ key: 'g', items: ctx.attentionItems().filter(it => it.id !== id) }] };
  });
}

test('queue selection retains identity and advances through the pre-action successor order', () => {
  const { ctx } = load();
  const items = [{kind:'guard',id:'b'}, {kind:'flag',id:'new'}, {kind:'incident',id:'c'}];
  assert.equal(ctx.nextAttentionKey('flag:a', ['flag:a','incident:c','guard:b'], items), 'incident:c');
  assert.equal(ctx.nextAttentionKey('guard:b', ['flag:a','guard:b'], items), 'guard:b');
  assert.equal(ctx.nextAttentionKey('flag:a', ['flag:a'], items), 'guard:b');
  assert.equal(ctx.nextAttentionKey('flag:a', ['flag:a'], []), '');
});

test('optimistic removal keeps the inspector until the complete write succeeds', () => {
  const { ctx, buttons } = load();
  const revert = remove(ctx, 'a');
  assert.equal(ctx.attentionSelection.key, 'flag:a');
  assert.equal(buttons[0].disabled, true);
  assert.equal(ctx.selected.length, 0);
  revert.commit();
  assert.equal(ctx.attentionSelection.key, 'guard:b');
  assert.equal(ctx.focused, true);
  assert.equal(buttons[0].disabled, false);
});

test('failed write restores the queue and retains selected identity', () => {
  const { ctx, buttons } = load();
  const revert = remove(ctx, 'a');
  revert();
  assert.equal(ctx.attentionSelection.key, 'flag:a');
  assert.equal(ctx.attentionItems().length, 3);
  assert.equal(ctx.selected.length, 0);
  assert.equal(buttons[0].disabled, false);
});

test('last successful removal clears stale inspector actions and shows an explicit empty state', () => {
  const { ctx } = load(['flag:a']);
  remove(ctx, 'a').commit();
  assert.equal(ctx.attentionSelection, null);
  assert.equal(ctx.empty.foot, '');
  assert.match(ctx.empty.body, /No items need your attention/);
  assert.equal(ctx.focused, true);
});

for (const race of ['drawerSeq', 'handoffGeneration', 'selection']) {
  test('late action cannot replace a newer ' + race, () => {
    const { ctx } = load();
    const revert = remove(ctx, 'a');
    if (race === 'selection') ctx.attentionSelection = { key: 'incident:c', order: ['incident:c'] };
    else ctx[race]++;
    revert.commit();
    assert.equal(ctx.selected.length, 0);
    assert.equal(ctx.empty, undefined);
  });
}

test('authoritative removal reconciles selected queue identity, while a historical inspector has no queue ownership', () => {
  const { ctx } = load();
  ctx.telemetryData.posture = { groups: [{ items: [{kind:'incident',id:'c'}] }] };
  ctx.reconcileAttention();
  assert.deepEqual(ctx.selected, ['incident:c']);
  ctx.selected.length = 0;
  ctx.attentionSelection = null;
  ctx.telemetryData.posture = { groups: [] };
  ctx.reconcileAttention();
  assert.equal(ctx.selected.length, 0);
  assert.equal(ctx.empty, undefined);
});

test('failed mutation restores existing disabled state rather than enabling unavailable choices', () => {
  const { ctx, buttons } = load();
  buttons.push({ disabled: true });
  remove(ctx, 'a')();
  assert.equal(buttons[0].disabled, false);
  assert.equal(buttons[1].disabled, true);
});

test('actual drawer role container retains its title relationship across overlay and docked modes', () => {
  const attributes = new Map();
  const ctx = {
    window: { innerWidth: 390 }, drawerDockMedia: null, drawerWideDockMedia: null, sessionEnded: false, drawerModal: false, drawerInert: new Map(),
    drawer: { hidden: false, classList: { contains: () => false }, dataset: {},
      setAttribute: (key, value) => attributes.set(key, value), removeAttribute: key => attributes.delete(key) },
    document: { querySelectorAll: () => [] },
  };
  vm.createContext(ctx);
  vm.runInContext(fn('syncDrawerMode', "  window.addEventListener('resize'"), ctx);
  ctx.syncDrawerMode();
  assert.equal(attributes.get('role'), 'dialog');
  assert.equal(attributes.get('aria-modal'), 'true');
  assert.equal(attributes.get('aria-labelledby'), 'drawer-title');
  const html = readFileSync(new URL('index.html', assets), 'utf8');
  assert.match(html, /id="drawer-title"/);
  ctx.window.innerWidth = 1900;
  ctx.syncDrawerMode();
  assert.equal(attributes.get('role'), 'complementary');
  assert.equal(attributes.has('aria-modal'), false);
  assert.equal(attributes.get('aria-labelledby'), 'drawer-title');
});

test('Home restoration respects saved closed/open booleans and preserves defaults for absent or invalid keys', () => {
  const start = app.indexOf("  try {\n    const saved = JSON.parse(sessionStorage.getItem(HOME_GROUPS_KEY)");
  const end = app.indexOf("  document.querySelectorAll('details.home-group').forEach(d => d.addEventListener", start);
  assert.ok(start >= 0 && end > start);
  const groups = [
    { dataset: { group: 'spend' }, open: true },
    { dataset: { group: 'findings' }, open: false },
    { dataset: { group: 'sessions' }, open: true },
    { dataset: { group: 'trends' }, open: false },
  ];
  const ctx = { HOME_GROUPS_KEY: 'fixture', document: { querySelectorAll: () => groups },
    sessionStorage: { getItem: () => JSON.stringify({ spend: false, findings: true, trends: 'true' }) } };
  vm.runInNewContext(app.slice(start, end), ctx);
  assert.deepEqual(groups.map(group => group.open), [false, true, true, false]);
});

test('drawer mode follows CSS media changes even when innerWidth remains stale', () => {
  const attributes = new Map(), listeners = new Map();
  let wide = false;
  const main = { inert: false, contains: () => false };
  const media = new Map(['(min-width: 1180px)', '(min-width: 1340px)'].map(query => [query, {
    matches: false, addEventListener: (event, fn) => listeners.set(query, fn)
  }]));
  const ctx = {
    window: { innerWidth: 1900, matchMedia: query => media.get(query), addEventListener() {} },
    sessionEnded: false, drawerModal: false, drawerInert: new Map(),
    drawer: { hidden: false, classList: { contains: () => wide }, dataset: {},
      setAttribute: (key, value) => attributes.set(key, value), removeAttribute: key => attributes.delete(key) },
    document: { documentElement: { clientWidth: 1179 }, querySelectorAll: () => [main] },
  };
  vm.createContext(ctx);
  const start = app.indexOf('  const drawerDockMedia =');
  const end = app.indexOf('  function attentionItems()', start);
  vm.runInContext(app.slice(start, end), ctx);
  ctx.syncDrawerMode();
  assert.equal(attributes.get('role'), 'dialog');
  assert.equal(main.inert, true);
  media.get('(min-width: 1180px)').matches = true;
  listeners.get('(min-width: 1180px)')();
  assert.equal(attributes.get('role'), 'complementary');
  assert.equal(main.inert, false);
  wide = true;
  ctx.syncDrawerMode();
  assert.equal(attributes.get('role'), 'dialog');
  assert.equal(main.inert, true);
  media.get('(min-width: 1340px)').matches = true;
  listeners.get('(min-width: 1340px)')();
  assert.equal(attributes.get('role'), 'complementary');
  assert.equal(main.inert, false);
  assert.equal(ctx.window.innerWidth, 1900);
});
