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
    overview: 'home', findings: 'home', agents: 'sessions/processes', resources: 'sessions/resources',
    history: 'sessions/resources', worktrees: 'system', cleanup: 'system', clutter: 'system', events: 'sessions/events',
    sessions: 'sessions/board', egress: 'protection/traffic', policy: 'protection/rules', system: 'system',
  };
  for (const [id, route] of Object.entries(want)) assert.equal(key(id), route, id);
  assert.equal(resolveConsoleRoute('findings').focus, 'attention');
  assert.equal(resolveConsoleRoute('overview').focus, '');
});

test('System follows grouped Protection; the Cleanup sub-view left Sessions and its old routes land on System', () => {
  const tabs = vm.runInContext('CONSOLE_TABS', ctx);
  assert.deepEqual([...tabs], ['home', 'sessions', 'protection', 'system', 'agent']);
  assert.deepEqual([...vm.runInContext('SESSIONS_SUBS', ctx)], ['board', 'processes', 'resources', 'events']);
  // Saved views, the stored tab and bookmarks kept "sessions/worktrees".
  for (const id of ['sessions/worktrees', '#sessions/worktrees', 'worktrees', 'cleanup', 'clutter', 'system']) {
    const r = resolveConsoleRoute(id);
    assert.deepEqual({ ...r }, { tab: 'system', sub: '', focus: '' }, id);
  }
  assert.equal(consoleRouteHash(resolveConsoleRoute('sessions/worktrees')), '#system');
  assert.equal(key('sessions/nope'), 'sessions/board');
});

test('new ids, sub-view hashes and unknown ids', () => {
  for (const id of ['home', 'system']) assert.equal(key(id), id);
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
  assert.ok(policyListHTML('guard', [], {}).includes('No guard decisions yet.'));
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
  });
  const primary = ['home', 'sessions', 'protection', 'system', 'agent'].map(tab => make('tab-button-' + tab, {tab}));
  const sections = ['traffic', 'rules', 'sources', 'audit'].map(view => make('protection-' + view, {protectionSection:view}));
  const protection = sections.map(section => make('protection-tab-' + section.dataset.protectionSection, {protectionView:section.dataset.protectionSection}));
  const sessions = ['board', 'processes', 'resources', 'events'].map(subtab => make('session-tab-' + subtab, {subtab}));
  const panels = ['home', 'sessions', 'egress', 'policy', 'system', 'agent'].map(tab => make('tab-' + tab));
  const nav = make('protection-nav');
  const document = {
    body: make('body'),
    querySelectorAll(selector) {
      return ({'.tab-btn':primary, '.tabpanel':panels, '[data-protection-section]':sections,
        '[data-protection-view]':protection, '.subtab-btn[data-subtab]':sessions,
        '.subtab-btn':[...sessions, ...protection], '.subview':[]})[selector] || [];
    },
    getElementById(id) { return id === nav.id ? nav : null; },
  };
  const runtime = {document, window:{history:{}}, sessionStorage:{setItem(){}},
    activeTab:'home', activeSub:'board', activeProtection:'traffic', attentionSelection:null,
    PANELS:[], dirtyPanels:new Set(), renderDirty(){}, loadPolicy(){}, loadAgent(){}};
  vm.createContext(runtime);
  vm.runInContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), runtime);
  vm.runInContext(source.slice(start, end), runtime);
  assert.equal(sessions.every(button => button.listeners.length === 1), true);
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
});
