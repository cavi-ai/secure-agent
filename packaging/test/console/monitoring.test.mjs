import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import vm from 'node:vm';

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
function load() {
  const c = vm.createContext({ URLSearchParams, Date, window: {} });
  vm.runInContext(readFileSync(new URL('lib.js', web), 'utf8'), c);
  vm.runInContext(readFileSync(new URL('telemetry-validation.js', web), 'utf8'), c);
  const file = new URL('tab-monitoring.js', web);
  if (existsSync(file)) vm.runInContext(readFileSync(file, 'utf8'), c);
  return c;
}
const path = (state = 'observed') => ({ state, supported: state !== 'unsupported', last_seen: '2026-10-20T16:00:00Z' });

test('acknowledged loss remains an incomplete history even with no active issue', () => {
  const c = load();
  const model = c.monitoringModel({status:{active_agents:0,coverage:{sessions:[]},bus_drops:22,bus_dropping:false,es_service:{bytes_lost:30937721,losing:false}},posture:{coverage_items:[]}});
  assert.equal(model.historyIncomplete,true);
  assert.equal(model.issues.length,0);
});
const row = (session_id, root_pid, workspace = '/work/api') => ({ session_id, root_pid, workspace, harness: 'codex', identity_basis: 'transcript', guard: path('unsupported'), trace: path(), payload: path('not-observed') });
const data = rows => ({ status: { coverage: { sessions: rows } }, sessions: [{ id: 'one', repo: 'api', branch: 'main' }], posture: { coverage_items: [] } });

test('Monitoring is a reloadable primary destination', () => {
  const c = load();
  assert.equal(c.isConsoleRoute('monitoring'), true);
  assert.equal(c.resolveConsoleRoute('#monitoring').tab, 'monitoring');
  assert.equal(c.consoleContextFromHash('#tab=monitoring').route, 'monitoring');
});

test('only exact durable identities enter the linked session list', () => {
  const c = load();
  assert.equal(typeof c.monitoringModel, 'function', 'Monitoring model is missing');
  const model = c.monitoringModel(data([row('one', 42), row('', 43, '/'), row('', 44, '/plugins/provider')]));
  assert.equal(model.linked.length, 1);
  assert.equal(model.unlinked.length, 2);
  assert.equal(model.linked[0].title, 'api');
  assert.equal(model.unlinked[0].title, 'Workspace not identified');
  assert.equal(model.unlinked[0].session, null, 'a process must not borrow another session');
  assert.equal(model.linked[0].session.id, 'one');
});

test('search finds a workspace, harness, session identity or process without changing totals', () => {
  const c = load();
  assert.equal(typeof c.monitoringModel, 'function');
  const input = data([row('one', 42), row('two', 43, '/work/artist-brain'), row('', 44, '/plugins/provider')]);
  const result = c.monitoringModel(input, 'ARTIST');
  assert.equal(result.linked.length, 1);
  assert.equal(result.linked[0].id, 'two');
  assert.equal(result.linkedCount, 2);
  assert.equal(result.unlinkedCount, 1);
  assert.equal(c.monitoringModel(input, '44').unlinked.length, 1);
});

test('unsupported, idle, unknown and stale paths never read as protection failures or fresh observations', () => {
  const c = load();
  assert.equal(typeof c.monitoringPath, 'function');
  assert.equal(c.monitoringPath(path('unsupported'), 'guard').label, 'Not supported');
  assert.equal(c.monitoringPath(path('unsupported'), 'guard').tone, 'neutral');
  assert.equal(c.monitoringPath(path('not-observed'), 'trace').label, 'No recent activity');
  assert.equal(c.monitoringPath(path('not-observed'), 'payload').label, 'No linked evidence');
  assert.equal(c.monitoringPath(path('future-state'), 'trace').tone, 'neutral');
  assert.notEqual(c.monitoringPath(path(), 'trace', true).tone, 'observed');
  assert.match(c.monitoringPath(path(), 'trace', true).label, /[Ll]ast.known/);
});

test('a removed selection does not silently open another session', () => {
  const c = load();
  assert.equal(typeof c.monitoringSelection, 'function');
  const model = c.monitoringModel(data([row('one', 42), row('two', 43)]));
  assert.equal(c.monitoringSelection(model, null).id, 'one');
  assert.equal(c.monitoringSelection(model, 'session:two').id, 'two');
  assert.equal(c.monitoringSelection(model, 'session:removed'), null);
});

test('invalid coverage is unavailable and never appears as an empty healthy list', () => {
  const c = load();
  assert.equal(typeof c.monitoringModel, 'function');
  for (const [sessions, snapshotAccepted] of [[undefined, true], [{}, false], [[null], false], [[{ root_pid: 1 }], true]]) {
    const input = data(sessions);
    assert.equal(c.monitoringModel(input).available, false);
    assert.equal(c.isConsoleReport('snapshot', { ...input, status: { ...input.status, uptime: '1h' } }), snapshotAccepted);
  }
});

test('snapshot and coverage refresh failures keep last-known rows visibly stale', () => {
  const c = load();
  assert.equal(typeof c.monitoringModel, 'function');
  const input = data([row('one', 42)]);
  input.status.coverage.sessions_stale = true;
  assert.equal(c.monitoringModel(input).stale, true);
  input.status.coverage.sessions_stale = false;
  assert.equal(c.monitoringModel(input, '', { error: 'HTTP 503' }).stale, true);
});

test('the inspector renders recorded timestamps and escapes source details', () => {
  const c = load();
  const input = data([row('one', 42)]);
  input.status.coverage.sessions[0].trace.detail = '<script>unsafe()</script>';
  const model = c.monitoringModel(input);
  const html = c.monitoringDetailHTML(model.rows[0], model);
  assert.match(html, /Last observed/);
  assert.match(html, /Open session evidence/);
  assert.ok(!html.includes('<script>'));
  assert.match(html, /&lt;script&gt;/);
  const stale = c.monitoringDetailHTML(model.rows[0], { ...model, stale: true });
  assert.match(stale, /data-monitoring-action="open" disabled/);
});

test('an empty daemon report with no running agents is an empty state, not a refresh failure', () => {
  const c = load(), input = data(undefined);
  input.status.active_agents = 0;
  assert.equal(c.monitoringModel(input).available, true);
  assert.equal(c.monitoringModel(input).rows.length, 0);
});

test('unlinked detections cannot display credited observations or an evidence link', () => {
  const c = load(), model = c.monitoringModel(data([row('', 42)]));
  const html = c.monitoringDetailHTML(model.rows[0], model);
  assert.ok(!html.includes('monitoring-state observed'));
  assert.ok(!html.includes('data-monitoring-action="open"'));
  assert.match(html, /Session not linked/);
});
