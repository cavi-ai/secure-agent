import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { loadDrawer } from './drawer-harness.mjs';
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
    detailDrawer: {
      selection: () => ctx.attentionSelection, clearSelection() { ctx.attentionSelection = null; },
      seq: () => ctx.drawerSeq, setMode() {}, open(options) { ctx.empty = options; }
    },
    selected: [], focused: false,
  };
  vm.createContext(ctx);
  vm.runInContext(readFileSync(new URL('lib.js', assets), 'utf8'), ctx);
  vm.runInContext(fn('reconcileAttention', '  function beginAttentionWrite'), ctx);
  vm.runInContext(fn('beginAttentionWrite', '  // Confirmation / prompt.'), ctx);
  vm.runInContext(readFileSync(new URL('staged-write.js', assets), 'utf8'), ctx);
  ctx.stage = ctx.createStagedWrite({
    telemetry: () => ctx.telemetryData, render: names => ctx.renderNow(names),
    beginAttentionWrite: () => ctx.beginAttentionWrite(), request: () => { throw new Error('no requests in this test'); }
  }).stage;
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
  const { api, dom } = loadDrawer({ width: 390 });
  api.open({ title: 'Drawer' });
  assert.equal(dom.drawer.attributes.get('role'), 'dialog');
  assert.equal(dom.drawer.attributes.get('aria-modal'), 'true');
  assert.equal(dom.drawer.attributes.get('aria-labelledby'), 'drawer-title');
  const html = readFileSync(new URL('index.html', assets), 'utf8');
  assert.match(html, /id="drawer-title"/);
  dom.document.documentElement.clientWidth = 1900;
  api.syncMode();
  assert.equal(dom.drawer.attributes.get('role'), 'complementary');
  assert.equal(dom.drawer.attributes.has('aria-modal'), false);
  assert.equal(dom.drawer.attributes.get('aria-labelledby'), 'drawer-title');
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
  const listeners = new Map();
  const media = new Map(['(min-width: 1180px)', '(min-width: 1340px)'].map(query => [query, {
    matches: false, addEventListener: (event, fn) => listeners.set(query, fn)
  }]));
  const { api, dom } = loadDrawer({ width: 1179, media });
  dom.window.innerWidth = 1900;
  const main = dom.inertSiblings[0];
  api.open({ title: 'Drawer' });
  const attributes = dom.drawer.attributes;
  assert.equal(attributes.get('role'), 'dialog');
  assert.equal(main.inert, true);
  media.get('(min-width: 1180px)').matches = true;
  listeners.get('(min-width: 1180px)')();
  assert.equal(attributes.get('role'), 'complementary');
  assert.equal(main.inert, false);
  dom.drawer.className = 'drawer resource-policy';
  api.syncMode();
  assert.equal(attributes.get('role'), 'dialog');
  assert.equal(main.inert, true);
  media.get('(min-width: 1340px)').matches = true;
  listeners.get('(min-width: 1340px)')();
  assert.equal(attributes.get('role'), 'complementary');
  assert.equal(main.inert, false);
  assert.equal(dom.window.innerWidth, 1900);
});

function inspectorHarness() {
  const controls = [], focusCalls = [];
  const selection = { signature: 'old' };
  const document = { activeElement: null };
  const drawer = { contains: node => controls.includes(node) || node === close,
    querySelectorAll: () => controls };
  const close = {isConnected:true,focus(options) { document.activeElement=this; focusCalls.push({node:this,options}); }};
  const make = (dataset, options = {}) => {
    const button = {dataset, isConnected:true, disabled:false, parentElement:drawer,
      matches() { return this.disabled; },
      closest(selector) {
        if (selector === 'details') return this.disclosure || null;
        return this.hidden || this.inert || this.ariaHidden ? this : null;
      },
      getClientRects() { return this.disclosure && !this.disclosure.open ? [] : [{}]; },
      focus(opts) { document.activeElement=this; focusCalls.push({node:this,options:opts}); }, ...options
    };
    return button;
  };
  const ctx = {document,drawer,btnDrawerClose:close,detailDrawer:{mode:()=>'attention',selection:()=>selection},
    attentionSignature:()=>ctx.signature,signature:'new',homeContext:()=>({}),
    needView:()=>({word:'Request',agent:'codex',what:'Recorded request',why:'Recorded evidence',items:[{}]}),
    window:{SA:{}},escapeHTML:s=>s,actionBarHTML:()=>'',drawerTitle:{},
    drawerBody:{querySelectorAll:()=>[]},drawerFoot:{next:[],set innerHTML(value) {
      controls.forEach(node=>{node.isConnected=false;}); controls.splice(0,controls.length,...this.next);
    }},getComputedStyle:node=>({display:node.display||'block',visibility:node.visibility||'visible'})};
  vm.createContext(ctx);
  vm.runInContext(fn('refreshAttentionInspector','  function reconcileAttention'),ctx);
  return {ctx,make,controls,focusCalls,close,refresh:()=>ctx.refreshAttentionInspector({id:'request'})};
}

test('attention refresh retains Deny rather than the first Allow choice sharing its action and ID', () => {
  const f=inspectorHarness();
  const old=f.make({action:'guard-resolve',id:'guard-1',verdict:'deny',scope:'once'});
  const allow=f.make({action:'guard-resolve',id:'guard-1',verdict:'allow',scope:'once'});
  const deny=f.make({...old.dataset});
  f.controls.push(old); f.ctx.document.activeElement=old; f.ctx.drawerFoot.next=[allow,deny];
  f.refresh();
  assert.equal(f.ctx.document.activeElement,deny);
  assert.equal(f.focusCalls.length,1);
  assert.equal(f.focusCalls[0].options.preventScroll,true);
});

for (const [name, choice, other] of [
  ['guard scope and expiry',{action:'guard-resolve',id:'g',verdict:'allow',scope:'exact',expiry:'24h'},{expiry:'7d'}],
  ['review decision and revision',{action:'review-decision',id:'r',decision:'close_reported',revision:'4'},{decision:'acknowledge'}],
  ['resource intervention',{action:'resource-control',id:'p',decision:'apply',intervention:'pause',session:'s'},{intervention:'terminate'}],
  ['served action ID',{action:'explain-act',flagId:'f',actionId:'deny',patternKey:'pattern'},{actionId:'allow-host'}],
  ['remediation evidence',{action:'incident-remediation',id:'i',stepId:'step',revision:'3',evidence:'e1'},{evidence:'e2'}],
]) test('attention refresh matches the complete ' + name, () => {
  const f=inspectorHarness(); const old=f.make(choice), opposite=f.make({...choice,...other});
  // Attribute insertion order does not change the served choice identity.
  const exact=f.make(Object.fromEntries(Object.entries(choice).reverse()));
  f.controls.push(old); f.ctx.document.activeElement=old; f.ctx.drawerFoot.next=[opposite,exact];
  f.refresh(); assert.equal(f.ctx.document.activeElement,exact);
});

test('exact choice inside replaced More disclosure is revealed before focus', () => {
  const f=inspectorHarness(); const data={action:'guard-resolve',id:'g',verdict:'allow',scope:'exact',expiry:'24h'};
  const old=f.make(data), disclosure={open:false,parentElement:{closest:()=>null}};
  const exact=f.make({...data},{disclosure});
  f.controls.push(old); f.ctx.document.activeElement=old; f.ctx.drawerFoot.next=[exact];
  f.refresh(); assert.equal(disclosure.open,true); assert.equal(f.ctx.document.activeElement,exact);
});

for (const [name, change] of [
  ['removed',null],['new revision',{dataset:{action:'review-decision',id:'r',decision:'acknowledge',revision:'5'}}],
  ['disabled',{disabled:true}],['hidden',{hidden:true}],['inert',{inert:true}],['aria hidden',{ariaHidden:true}],
  ['CSS hidden',{display:'none'}],['invisible',{visibility:'hidden'}],['unrendered',{getClientRects:()=>[]}],
]) test('attention refresh uses neutral Close when the exact choice is ' + name, () => {
  const f=inspectorHarness(); const data={action:'review-decision',id:'r',decision:'acknowledge',revision:'4'};
  const old=f.make(data); f.controls.push(old); f.ctx.document.activeElement=old;
  f.ctx.drawerFoot.next=change ? [f.make({...data},change)] : [];
  f.refresh(); assert.equal(f.ctx.document.activeElement,f.close); assert.equal(f.focusCalls.length,1);
});

test('unchanged inspector and focus outside its drawer receive no extra focus', () => {
  const f=inspectorHarness(), old=f.make({action:'guard-resolve',id:'g',verdict:'deny',scope:'once'});
  f.controls.push(old); f.ctx.document.activeElement=old; f.ctx.signature='old';
  f.refresh(); assert.equal(f.ctx.document.activeElement,old); assert.equal(old.isConnected,true);
  const outside=f.make({action:'refresh'}); f.ctx.document.activeElement=outside; f.ctx.signature='new';
  f.ctx.drawerFoot.next=[f.make({...old.dataset})]; f.refresh();
  assert.equal(f.ctx.document.activeElement,outside); assert.equal(f.focusCalls.length,0);
});
