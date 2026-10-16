import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const app = readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js', import.meta.url), 'utf8');
function controller() {
  const input = { value: 'ARCHIVE' }, calls = [], timers = [];
  const opener = { dataset: { session: 'ended' }, closest: () => ({}), focus: () => calls.push('focus') };
  const entries = [{ state: null }]; let index = 0, release;
  const c = { Object, Array, JSON, console, activeTab: 'home', sessionEnded: false, handoffGeneration: 1,
    telemetryData: { sessions: [{ id: 'ended' }] }, globalSearch: 'archive',
    harnessFilter: { text: 'original', liveOnly: true, harnesses: { codex: false } }, HARNESS_FILTER_KEY: 'filter',
    timelineSession: 'prior', timelinePids: [7], timelinePidLabel: 'Prior scope', location: { pathname: '/', search: '' },
    document: { documentElement: { classList: { add() {}, remove() {} } }, getElementById: id => id === 'global-search' ? input : { focus() {} }, querySelectorAll: () => [opener], querySelector: () => ({ focus() {} }) },
    sessionStorage: { setItem() {} }, detailDrawer: { close() {} },
    syncHarnessFilterControls() {}, syncHistoryViews() {}, paintScopeBar() {}, renderAll() {}, renderNow() {},
    switchTab: tab => { c.activeTab = tab; }, showToast: text => calls.push(text),
    consoleContextHash: context => '#sessions?session=' + context.session,
    setTimeout: fn => timers.push(fn),
    window: { SA: {}, scrollY: 320, scrollTo: options => calls.push(options.top),
      filterTimelineToSession: async id => { c.activeTab = 'sessions'; c.sessionWorkbench.selectedSessionId = id; await new Promise(resolve => { release = resolve; }); },
      setSessionView: async view => calls.push(view) },
    sessionWorkbench: { selectedSessionId: '', filterChanged() {} },
  };
  c.history = {
    get state() { return entries[index].state; },
    replaceState(state) { entries[index] = { state }; },
    pushState(state) { entries.splice(++index); entries.push({ state }); },
    back() { if (index) c.window.SA.restoreRecentWorkHistory(entries[--index].state.saRecentWork); },
  };
  vm.createContext(c);
  const start = app.indexOf('  // Home recent work keeps');
  vm.runInContext(app.slice(start, app.indexOf('  // Session investigation return context.', start)), c);
  return { c, opener, input, calls, entries, release: () => release(), flush: () => { for (const fn of timers.splice(0)) fn(); } };
}

test('returning Home cancels a pending Results navigation and restores the captured scope and filters', async () => {
  const t = controller();
  const open = t.c.window.openRecentSessionResults('ended', t.opener);
  t.c.window.returnToRecentWork(); t.release(); await open; t.flush();
  assert.equal(t.c.activeTab, 'home');
  assert.equal(t.c.harnessFilter.text, 'original');
  assert.equal(t.c.harnessFilter.liveOnly, true);
  assert.equal(t.c.globalSearch, 'archive');
  assert.equal(t.c.timelineSession, 'prior');
  assert.equal(t.c.window.SA.recentWorkReturn, false);
  assert.ok(!t.calls.includes('results'));
  assert.ok(t.calls.includes(320));
});

test('expired authentication and a different session reject late navigation completions', async () => {
  for (const change of [c => c.handoffGeneration++, c => { c.sessionWorkbench.selectedSessionId = 'other'; c.window.SA.clearRecentWorkReturn('other'); }]) {
    const t = controller();
    const open = t.c.window.openRecentSessionResults('ended', t.opener);
    change(t.c); t.release(); await open;
    assert.ok(!t.calls.includes('results'));
    assert.equal(t.c.window.SA.recentWorkReturn, false);
  }
});

test('a missing retained session stays on Home without substituting another session', async () => {
  const t = controller();
  t.c.telemetryData.sessions = [];
  await t.c.window.openRecentSessionResults('ended', t.opener);
  assert.equal(t.c.activeTab, 'home');
  assert.equal(t.entries.length, 1);
  assert.equal(t.c.sessionWorkbench.selectedSessionId, '');
});
