// Console navigation tests — zero dependencies. Evaluates lib.js in a fresh
// VM context, as the browser loads it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = { window: {}, URLSearchParams };
vm.createContext(ctx);
vm.runInContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), ctx, { filename: 'lib.js' });
const { resolveConsoleRoute, routeKey, consoleRouteHash, isConsoleRoute, consoleBootState, policyListHTML } = ctx;
const key = id => routeKey(resolveConsoleRoute(id));
// The real worktree controller inside a switchTab runtime: request answers
// each report read, visible follows the runtime's active System view.
const reportRead = url => (url === '/worktrees' ? 'worktrees' : url === '/cleanup' ? 'clutter' : 'ledger');
function attachWorktreeController(runtime, request) {
  for (const file of ['tab-worktrees.js', 'worktree-controller.js']) {
    vm.runInContext(readFileSync(path.join(webDist, file), 'utf8'), runtime, { filename: file });
  }
  runtime.worktreeController = runtime.createWorktreeController({
    request,
    toast() {}, confirm: async () => false, render() {}, markDirty() {}, discuss() {},
    history: { open: () => false, paint() {} },
    visible: view => runtime.activeTab === 'system' && runtime.activeSystemSub === view,
    now: Date.now,
    toastHost: { show() {}, hideWhenEmpty() {} }
  });
  return runtime.worktreeController;
}

test('record handoffs strip the credential and round-trip exact context on reload', () => {
  const id = 'session +&?#/π';
  const raw = new URLSearchParams({ ct: 'fixture-token', tab: 'sessions', session: id, flag: 'flag&other=1', return: 'https://outside.invalid' });
  const context = ctx.consoleContextFromHash('#' + raw);
  assert.deepEqual({ ...context }, { route: 'sessions', session: id, flag: 'flag&other=1', incident: '', file: '' });
  const hash = ctx.consoleContextHash(context);
  assert.ok(!hash.includes('ct=') && !hash.includes('fixture-token') && !hash.includes('return'));
  assert.deepEqual({ ...ctx.consoleContextFromHash(hash) }, { ...context });
  assert.equal(key(hash), 'sessions/board');
  assert.equal(isConsoleRoute(hash), true);
});

test('legacy tab and file handoffs remain scoped to the console', () => {
  for (const route of ['egress', 'findings', 'sessions/events']) {
    assert.equal(ctx.consoleContextFromHash('#ct=fixture&tab=' + encodeURIComponent(route)).route, route);
  }
  const context = ctx.consoleContextFromHash('#ct=fixture&file=%2Fworkspace%2Fa%2Bb.env');
  assert.equal(context.file, '/workspace/a+b.env');
  assert.equal(ctx.consoleContextFromHash('#ct=fixture&tab=https%3A%2F%2Foutside.invalid').route, '');
  assert.equal(ctx.consoleContextFromHash('#ct=fixture&flag=f&incident=i').incident, '', 'one detail target per handoff');
});

test('every old tab id resolves to its new tab[/sub]', () => {
  const want = {
    overview: 'home', findings: 'home', agents: 'sessions/processes', resources: 'system/resources',
    history: 'system/resources', worktrees: 'system/worktrees', cleanup: 'system/clutter', clutter: 'system/clutter', events: 'sessions/events',
    sessions: 'sessions/board', egress: 'protection/traffic', policy: 'protection/rules', system: 'system/worktrees',
  };
  for (const [id, route] of Object.entries(want)) assert.equal(key(id), route, id);
  assert.equal(resolveConsoleRoute('findings').focus, 'attention');
  assert.equal(resolveConsoleRoute('overview').focus, '');
});

test('System routes preserve Resources, Worktrees and Clutter legacy destinations', () => {
  assert.deepEqual([...vm.runInContext('CONSOLE_TABS', ctx)], ['home', 'sessions', 'monitoring', 'protection', 'system', 'agent']);
  assert.deepEqual([...vm.runInContext('SESSIONS_SUBS', ctx)], ['board', 'processes', 'events']);
  assert.deepEqual([...vm.runInContext('SYSTEM_SUBS', ctx)], ['resources', 'worktrees', 'clutter']);
  const aliases = {
    resources: 'resources', history: 'resources', 'sessions/resources': 'resources', 'sessions/history': 'resources',
    worktrees: 'worktrees', 'sessions/worktrees': 'worktrees', system: 'worktrees', 'system/nope': 'worktrees',
    cleanup: 'clutter', clutter: 'clutter',
  };
  for (const [id, sub] of Object.entries(aliases)) {
    for (const route of [id, '#' + id]) {
      assert.deepEqual({ ...resolveConsoleRoute(route) }, { tab: 'system', sub, focus: '' }, route);
      assert.equal(consoleRouteHash(resolveConsoleRoute(route)), '#system/' + sub);
    }
  }
  for (const sub of ['resources', 'worktrees', 'clutter']) {
    assert.equal(key('system/' + sub), 'system/' + sub);
    assert.equal(isConsoleRoute('#system/' + sub), true);
    const context = ctx.consoleContextFromHash('#ct=fixture&tab=' + encodeURIComponent('system/' + sub));
    assert.equal(key(ctx.consoleContextHash(context)), 'system/' + sub);
    assert.ok(!ctx.consoleContextHash(context).includes('ct='));
  }
});

test('new ids, sub-view hashes and unknown ids', () => {
  assert.equal(key('home'), 'home');
  assert.equal(key('system'), 'system/worktrees');
  assert.equal(key('#sessions/events'), 'sessions/events');
  assert.equal(key('sessions/processes'), 'sessions/processes');
  assert.equal(key('sessions/nope'), 'sessions/board');
  assert.equal(key('policy/x'), 'protection/rules');
  assert.equal(key('#protection'), 'protection/traffic');
  assert.equal(key('#protection/nope'), 'protection/traffic');
  for (const view of ['traffic', 'rules', 'sources', 'audit']) {
    const r = resolveConsoleRoute('protection/' + view);
    assert.equal(key(consoleRouteHash(r)), 'protection/' + view);
    assert.equal(isConsoleRoute(consoleRouteHash(r)), true);
  }
  for (const id of ['', 'nope', 'file=%2Fx', 'toString', '__proto__', undefined, null]) assert.equal(key(id), 'home', String(id));
  assert.equal(isConsoleRoute('agents'), true);
  assert.equal(isConsoleRoute('#sessions/worktrees'), true);
  assert.equal(isConsoleRoute('#system'), true);
  assert.equal(isConsoleRoute('file=%2Fx'), false);
  assert.equal(isConsoleRoute('toString'), false);
});

test('address-bar form: #sessions for the board, #sessions/<sub> otherwise', () => {
  assert.equal(consoleRouteHash(resolveConsoleRoute('sessions')), '#sessions');
  assert.equal(consoleRouteHash(resolveConsoleRoute('agents')), '#sessions/processes');
  assert.equal(consoleRouteHash(resolveConsoleRoute('findings')), '#home');
  assert.equal(key(consoleRouteHash(resolveConsoleRoute('events'))), 'sessions/events');
});

test('ended-state decision: no token → ended; a token → normal', () => {
  assert.equal(consoleBootState('', ''), 'ended');
  assert.equal(consoleBootState(null, ''), 'ended');
  assert.equal(consoleBootState(undefined, undefined), 'ended');
  assert.equal(consoleBootState('fresh', ''), 'normal');
  assert.equal(consoleBootState('', 'kept'), 'normal');
});

test('policy lists: rows escaped, empty states say what fills them, loading and error', () => {
  const guard = policyListHTML('guard', [{ agent: 'claude', rule_id: 'env<file', decision: 'deny', source: 'prompt', created_at: '2026-09-20T10:00:00Z' }], {});
  assert.match(guard, /data-policy="guard"/);
  assert.ok(guard.includes('env&lt;file') && guard.includes('class="policy-decision deny"') && guard.includes('2026-09-20'));
  const mute = policyListHTML('mute', [{ rule: 'keychain-access', host: '*' }, { rule: 'r', title: 'Nice <title>', host: 'x.com' }], {});
  assert.ok(mute.includes('<b>keychain-access</b>') && mute.includes('all hosts') && mute.includes('Nice &lt;title&gt;') && !mute.includes('<b>r</b>'));
  const scoped = policyListHTML('mute', [{ rule: 'keychain-access', host: '*', agent: 'co<dex' }, { rule: 'keychain-access', host: '*' }], {});
  assert.ok(scoped.includes('all hosts · co&lt;dex') && scoped.includes('all hosts · all agents'), 'a scoped mute names its agent; an unscoped one says all agents');
  assert.ok(policyListHTML('path', [], {}).includes('No file exceptions yet.'));
  assert.ok(policyListHTML('guard', [], {}).includes('No legacy guard decisions.'));
  assert.ok(policyListHTML('mute', [], {}).includes('No muted flag classes.'));
  assert.ok(policyListHTML('expected', [], {}).includes('No expected secret reads.'));
  const expected = policyListHTML('expected', [
    { key: 'claude|gh|/u/.config/gh/hosts.yml|<GitHub>', agent: 'claude', reader: 'gh', path: '/u/.config/gh/hosts.yml', dest: '<GitHub>', hits: 3, created_at: '2026-09-25T10:00:00Z' },
    { key: 'k2', agent: 'codex', reader: 'tool', path: '/u/.env', dest: 'x.com', created_at: '2026-09-25T11:00:00Z' }], {});
  assert.ok(expected.includes('<b>gh</b> reads <code>/u/.config/gh/hosts.yml</code>, then reaches <b>&lt;GitHub&gt;</b>'));
  assert.ok(expected.includes('claude · legacy policy · no expiry · Legacy provider exception is inactive; review an exact host') && expected.includes('2026-09-25'));
  assert.ok(expected.includes('data-action="forget-expected" data-key="claude|gh|/u/.config/gh/hosts.yml|&lt;GitHub&gt;"'));
  assert.ok(expected.includes('<b>an agent tool</b> reads') && expected.includes('codex · legacy policy · no expiry · 0 since the daemon started'));
  assert.ok(policyListHTML('guard', null, {}).includes('Loading'));
  assert.ok(policyListHTML('guard', null, { error: 'boom <x>' }).includes('boom &lt;x&gt;'));
});


test('Protection subviews retain selected ARIA and visibility without receiving Sessions listeners', () => {
  const source = readFileSync(path.join(webDist, 'app.js'), 'utf8');
  const start = source.indexOf('  function switchTab(');
  const end = source.indexOf('  // Tab badges:', start);
  assert.ok(start >= 0 && end > start);
  const make = (id, dataset = {}) => ({
    id, dataset, hidden: false, attributes: {}, listeners: [],
    classList: { values: new Set(), toggle(name, on) { on ? this.values.add(name) : this.values.delete(name); } },
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, action) { this.listeners.push(action); },
    click() { this.listeners.forEach(listener => listener()); },
  });
  const primary = ['home', 'sessions', 'protection', 'system', 'agent'].map(tab => make('tab-button-' + tab, {tab}));
  const sections = ['traffic', 'rules', 'sources', 'audit'].map(view => make('protection-' + view, {protectionSection:view}));
  const protection = sections.map(section => make('protection-tab-' + section.dataset.protectionSection, {protectionView:section.dataset.protectionSection}));
  const sessions = ['board', 'processes', 'events'].map(subtab => make('session-tab-' + subtab, {subtab}));
  const system = ['resources', 'worktrees', 'clutter'].map(systemSubtab => make('system-tab-' + systemSubtab, {systemSubtab}));
  const systemViews = system.map(button => make('system-' + button.dataset.systemSubtab, {systemView:button.dataset.systemSubtab}));
  const sessionViews = sessions.map(button => make('sub-' + button.dataset.subtab));
  const panels = ['home', 'sessions', 'egress', 'policy', 'system', 'agent'].map(tab => make('tab-' + tab));
  const nav = make('protection-nav');
  const document = {
    body: make('body'),
    querySelectorAll(selector) {
      return ({'.tab-btn':primary, '.tabpanel':panels, '[data-protection-section]':sections,
        '[data-protection-view]':protection, '#tab-sessions .subtab-btn[data-subtab]':sessions,
        '#tab-system [data-system-subtab]':system, '#tab-system .system-subview':systemViews,
        '#tab-sessions .subview':sessionViews})[selector] || [];
    },
    querySelector(selector) {
      return primary.find(button => selector === `.tab-btn[data-tab="${button.dataset.tab}"]`)
        || system.find(button => selector === `#tab-system [data-system-subtab="${button.dataset.systemSubtab}"]`)
        || sessions.find(button => selector === `#tab-sessions .subtab-btn[data-subtab="${button.dataset.subtab}"]`) || null;
    },
    getElementById(id) { return id === nav.id ? nav : null; },
  };
  const saved = new Map();
  const hashes = [];
  const loads = [];
  const history = {replaceState(_a, _b, url) { hashes.push(url); }};
  const runtime = {document, window:{history}, history, location:{pathname:'/console',search:''},
    sessionStorage:{setItem(key, value){saved.set(key,value);}},
    activeTab:'home', activeSub:'board', activeProtection:'traffic', activeSystemSub:'worktrees', detailDrawer:{selection:()=>null}, protectionContext:null, clearProtectionContext(){},
    PANELS:[], dirtyPanels:new Set(), renderDirty(){}, loadPolicy(){}, loadAgent(){}};
  vm.createContext(runtime);
  vm.runInContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), runtime);
  attachWorktreeController(runtime, url => { loads.push(reportRead(url)); return new Promise(() => {}); });
  vm.runInContext(source.slice(start, end), runtime);
  assert.equal(sessions.every(button => button.listeners.length === 1), true);
  assert.equal(system.every(button => button.listeners.length === 1), true);
  assert.equal(protection.every(button => button.listeners.length === 0), true, 'Sessions handlers must not bind to Protection buttons');
  for (const [route, view] of [['egress','traffic'], ['policy','rules'], ['protection/sources','sources'], ['protection/audit','audit']]) {
    runtime.switchTab(route);
    assert.equal(runtime.activeTab, 'protection');
    assert.equal(nav.hidden, false);
    assert.deepEqual(sections.filter(section => !section.hidden).map(section => section.dataset.protectionSection), [view]);
    assert.deepEqual(protection.filter(button => button.attributes['aria-selected'] === 'true').map(button => button.dataset.protectionView), [view]);
    assert.deepEqual(protection.filter(button => button.classList.values.has('active')).map(button => button.dataset.protectionView), [view]);
  }
  sessions.find(button => button.dataset.subtab === 'events').listeners[0]();
  assert.equal(runtime.activeTab, 'sessions');
  assert.equal(runtime.activeSub, 'events');
  assert.equal(nav.hidden, true);
  assert.equal(protection.every(button => button.attributes['aria-selected'] === 'false'), true);
  for (const view of ['resources', 'worktrees', 'clutter']) {
    const before = loads.length;
    system.find(button => button.dataset.systemSubtab === view).listeners[0]();
    assert.equal(runtime.activeTab, 'system');
    assert.equal(runtime.activeSystemSub, view);
    assert.equal(runtime.activeSub, 'events', 'System navigation preserves the Sessions selection');
    assert.deepEqual(systemViews.filter(section => !section.hidden).map(section => section.dataset.systemView), [view]);
    assert.deepEqual(system.filter(button => button.attributes['aria-selected'] === 'true').map(button => button.dataset.systemSubtab), [view]);
    assert.deepEqual(loads.slice(before), view === 'worktrees' ? ['worktrees','ledger'] : view === 'clutter' ? ['clutter'] : []);
    assert.equal(saved.get('sa.console-tab'), 'system/' + view);
    assert.equal(hashes.at(-1), '/console#system/' + view);
  }
  primary.find(button => button.dataset.tab === 'sessions').listeners[0]();
  assert.equal(runtime.activeSub, 'events');
  assert.deepEqual(sessionViews.filter(section => !section.hidden).map(section => section.id), ['sub-events']);
  primary.find(button => button.dataset.tab === 'system').listeners[0]();
  assert.equal(runtime.activeSystemSub, 'clutter', 'primary System reopens its last selected view');
  runtime.switchTab('system/nope');
  assert.equal(runtime.activeSystemSub, 'worktrees', 'invalid direct routes preserve the Worktrees landing');
  const fixture = readFileSync(path.resolve(webDist, '../../../../packaging/test/console_dom/mock_dom.js'), 'utf8');
  const helperStart = fixture.indexOf('  const openTab =');
  const helperEnd = fixture.indexOf("  if (scenarios.has('authrecover'))", helperStart);
  vm.runInContext(fixture.slice(helperStart, helperEnd) + '\n globalThis.fixtureOpenTab = openTab;', runtime);
  for (const [route,sub] of [['resources','resources'],['system/clutter','clutter'],['worktrees','worktrees'],['sessions/history','resources']]) {
    runtime.fixtureOpenTab(route);
    assert.equal(runtime.activeTab, 'system', route);
    assert.equal(runtime.activeSystemSub, sub, route);
    assert.deepEqual(systemViews.filter(section => !section.hidden).map(section => section.dataset.systemView), [sub]);
  }
  runtime.fixtureOpenTab('sessions');
  assert.equal(runtime.activeTab, 'sessions');
  assert.equal(runtime.activeSub, 'board');
});


test('Resource and memory panels render only in System Resources', () => {
  const source = readFileSync(path.join(webDist, 'app.js'), 'utf8');
  const start = source.indexOf('  const PANEL_VIEW =');
  const end = source.indexOf('  // Panel → the element', start);
  const runtime = { activeTab:'home', activeSub:'board', activeProtection:'traffic', activeSystemSub:'worktrees', homeGroupOpen:() => true };
  vm.createContext(runtime);
  vm.runInContext(source.slice(start, end), runtime);
  for (const name of ['resources', 'history', 'chart-memory', 'worktrees', 'clutter']) assert.equal(runtime.panelOnScreen(name), false, name);
  runtime.activeTab = 'system';
  for (const view of ['resources', 'worktrees', 'clutter']) {
    runtime.activeSystemSub = view;
    for (const name of ['resources', 'history', 'chart-memory', 'worktrees', 'clutter']) {
      assert.equal(runtime.panelOnScreen(name), (['resources','history','chart-memory'].includes(name) ? 'resources' : name) === view, view + '/' + name);
    }
  }
  runtime.activeTab = 'sessions'; runtime.activeSub = 'processes';
  assert.equal(runtime.panelOnScreen('agents'), true);
  assert.equal(runtime.panelOnScreen('chart-memory'), false);
});

test('saved views capture the independent System sub-view and retain filters', () => {
  const source = readFileSync(path.join(webDist, 'app.js'), 'utf8');
  const start = source.indexOf('  function currentViewSnapshot(');
  const end = source.indexOf('  window.saveCurrentView', start);
  const runtime = {activeTab:'system', activeSub:'events', activeProtection:'audit', activeSystemSub:'resources',
    filters:{flags:{agent:'codex'},events:{type:'model'}}, document:{getElementById:() => ({value:'api-service'})}};
  vm.createContext(runtime);
  vm.runInContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), runtime);
  vm.runInContext(source.slice(start, end), runtime);
  for (const view of ['resources','worktrees','clutter']) {
    runtime.activeSystemSub = view;
    const saved = runtime.currentViewSnapshot('My view');
    assert.equal(saved.tab, 'system/' + view);
    assert.equal(saved.search, 'api-service');
    assert.equal(saved.flags.agent, 'codex');
    assert.equal(saved.events.type, 'model');
    assert.notEqual(saved.flags, runtime.filters.flags);
  }
  runtime.activeTab = 'sessions';
  assert.equal(runtime.currentViewSnapshot('My view').tab, 'sessions/events');
});


test('returning to a pending System report resumes bounded followup after its hidden-view timer expires', async () => {
  const source = readFileSync(path.join(webDist, 'app.js'), 'utf8');
  const timers = new Map();
  let timerID = 0;
  const reads = [];
  const served = { '/worktrees': {}, '/cleanup': {} };
  const runtime = {
    document:{body:{classList:{toggle(){}}}, querySelectorAll:() => [], getElementById:() => null},
    window:{history:{}}, sessionStorage:{setItem(){}},
    activeTab:'home', activeSub:'board', activeProtection:'traffic', activeSystemSub:'worktrees',
    detailDrawer:{selection:()=>null}, protectionContext:null,
    PANELS:[], dirtyPanels:new Set(), renderDirty(){}, loadPolicy(){}, loadAgent(){},
    setTimeout(fn,delay){const id=++timerID; timers.set(id,{fn,delay}); return id;}, clearTimeout(id){timers.delete(id);},
  };
  vm.createContext(runtime);
  vm.runInContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), runtime);
  const controller = attachWorktreeController(runtime, async url => {
    reads.push(reportRead(url));
    return { ok: true, json: async () => served[url] || {} };
  });
  const switchStart = source.indexOf('  function switchTab(');
  vm.runInContext(source.slice(switchStart, source.indexOf('  // Tab badges:', switchStart)), runtime);
  const settle = () => new Promise(res => setImmediate(res));
  const fire = () => {
    assert.equal(timers.size, 1);
    const [id,{fn,delay}] = [...timers][0]; timers.delete(id); fn(); return delay;
  };
  const fresh = (worktrees, clutter) => {
    Object.assign(controller.worktreesState, { report: worktrees, loadedAt: Date.now(), ledger: {}, ledgerAt: Date.now() });
    Object.assign(controller.clutterState, { report: clutter, loadedAt: Date.now() });
  };
  for (const [view,pending] of [['worktrees',{sizing:true}],['worktrees',{refreshing:true}],['worktrees',{asks:{task:{status:'running'}}}],['clutter',{sizing:true}],['clutter',{refreshing:true}]]) {
    fresh(view === 'worktrees' ? pending : {}, view === 'clutter' ? pending : {});
    reads.length = 0;
    runtime.switchTab('system/' + view);
    assert.deepEqual(reads, [], 'a fresh pending report resumes its timer without an immediate scan');
    runtime.switchTab('system/resources');
    assert.equal(fire(), 5000);
    assert.deepEqual(reads, [], 'sizing and asks stop rereading while their view is hidden');
    runtime.switchTab('system/' + view);
    assert.equal(fire(), 5000);
    assert.deepEqual(reads, [view], 'reopening within 60 seconds resumes the pending report');
    await settle();
  }
  assert.equal(timers.size, 0);
  for (const [view, url] of [['worktrees', '/worktrees'], ['clutter', '/cleanup']]) {
    served[url] = { sizing: true };
    fresh(view === 'worktrees' ? { sizing: true } : {}, view === 'clutter' ? { sizing: true } : {});
    runtime.switchTab('system/' + view);
    let fires = 0;
    while (timers.size) {
      assert.equal(fire(), 5000);
      fires++;
      await settle();
      assert.ok(fires <= 60, 'followup is bounded');
    }
    assert.equal(fires, 60, view + ' followup stops at the sizing cap');
    runtime.switchTab('system/resources');
    runtime.switchTab('system/' + view);
    assert.equal(timers.size, 0, 'navigation does not reset the existing sizing cap');
    served[url] = {};
  }
  controller.worktreesState.report = {removals:{path:{state:'running'}}};
  runtime.switchTab('system/worktrees'); runtime.switchTab('system/resources');
  assert.equal(fire(), 1500);
  assert.equal(reads.at(-1), 'worktrees', 'running removals retain their cross-view followup');
});
