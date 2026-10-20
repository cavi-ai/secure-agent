import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
function context(storage = new Map()) {
  const c = vm.createContext({Date, window: {SA: {}, addEventListener() {}}, document: {},
    localStorage: {getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value)},
    sessionStorage: {getItem: () => 'selected'},
  });
  for (const file of ['lib.js', 'session-layout.js', 'session-workbench.js']) vm.runInContext(readFileSync(new URL(file, assets), 'utf8'), c);
  return c;
}

test('workspace grouping keeps identical repository names in different checkouts separate', () => {
  const c = context();
  const input = [
    {id: 'one', repo: 'api', workspace: '/work/api', harness: 'codex', status: 'active'},
    {id: 'two', repo: 'api', workspace: '/other/api', harness: 'codex', status: 'active'},
    {id: 'three', repo: 'api', workspace: '/work/api', harness: 'claude', status: 'idle'},
    {id: 'unknown', repo: 'api', workspace: '/', harness: 'codex', status: 'active'},
  ];
  const groups = c.groupSessionWorkspaces(c.groupSessionsByHarness(input, [], []));
  assert.equal(groups.length, 3);
  assert.deepEqual(Array.from(groups.find(g => g.key === 'workspace:/work/api').live, f => f.session.id).sort(), ['one', 'three']);
  assert.equal(groups.find(g => g.key === 'session:unknown').live.length, 1);
  for (const group of groups) {
    const html = c.sessionGroupHTML(group, true, false);
    assert.match(html, /href="#i-folder"/);
    assert.doesNotMatch(html, /href="#logo-codex"/);
  }
});

test('view preference survives a new workbench without changing its selected session', () => {
  const storage = new Map();
  const c = context(storage);
  const make = () => c.createSessionWorkbench({apiFetch() {throw Error('unexpected fetch');}, renderNow() {}});
  const first = make();
  assert.equal(first.sessionListView, 'harness');
  first.setListView('sessions');
  assert.equal(first.selectedSessionId, 'selected');
  assert.equal(make().sessionListView, 'sessions');
  first.setListView('invalid');
  assert.equal(first.sessionListView, 'sessions');
  first.setListView('harness');
  assert.equal(make().sessionListView, 'harness');
});

test('termination is available only through selected-session actions and retains process identity', () => {
  const c = context();
  const s = {id: 'one', repo: 'api', branch: 'feat/a', root_pid: 42, harness: 'codex', status: 'active'};
  const trees = [{root: {pid: 42, started_at: '2026-10-20T12:00:00Z'}, rss_bytes: 22000000000}];
  assert.doesNotMatch(c.sessionRailCardHTML(s, trees, 'other'), /data-action="kill"/);
  const selected = c.sessionRailCardHTML(s, trees, 'one');
  assert.match(selected, /<details class="sc-actions">/);
  assert.match(selected, /data-pid="42" data-started="2026-10-20T12:00:00Z"/);
  assert.doesNotMatch(selected, /GB|sc-state|#i-power/);
});

test('folded sessions retain repository and branch hierarchy without repeating status pills', () => {
  const c = context();
  const sessions = ['one', 'two'].map(id => ({id, repo: 'api', branch: 'feat/long-branch', harness: 'codex'}));
  const html = c.sessionDupRowHTML({key: 'fold', status: 'active', title: 'api@feat/long-branch', sessions}, [], '', false, 'live');
  assert.match(html, /class="sc-label"[^>]*>api<\/span>/);
  assert.match(html, /class="sc-branch">feat\/long-branch<\/span>/);
  assert.doesNotMatch(html, /class="sc-state/);
});
