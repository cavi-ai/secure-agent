import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = { Date, window: { SA: {} } };
vm.createContext(ctx);
for (const file of ['lib.js', 'tab-findings.js', 'session-workbench.js']) vm.runInContext(readFileSync(path.join(web, file), 'utf8'), ctx, { filename: file });

test('session overview keeps review, risk and coverage limits visible', () => {
  const html = ctx.sessionOverviewHTML({ session_id: 'own', requests: [], findings: [{ id: 'f', title: 'Observed read', assessment: { risk: 'high', review_state: 'reviewed', residual_risk: 'model-exposure', reason: 'Review does not reverse exposure', limits: ['No captured payload'] } }], coverage: { guard: { state: 'observed', detail: 'Only reported outcomes' }, trace: { state: 'not-observed', detail: 'Quiet can be legitimate' }, payload: { state: 'unattributed', detail: 'Other traffic may be uninspected' } }, findings_truncated: true }, {});
  for (const text of ['Model exposure', 'Reviewed', 'Only reported outcomes', 'Quiet can be legitimate', 'Other traffic may be uninspected', 'More findings', 'Risk: high']) assert.ok(html.includes(text), text);
  assert.match(html, /data-action="open-flag" data-id="f"/);
  assert.ok(!html.includes('All clear'));
});

test('failed current-status read keeps evidence and disables live actions', () => {
  const html = ctx.sessionOverviewHTML({ session_id: 'own', requests: [{ id: 'g', detail: 'Read request' }], findings: [], resources: { key: 'r', rss_bytes: 1024, process_count: 2 } }, { error: 'unavailable' });
  assert.match(html, /Last known session status/);
  assert.match(html, /<fieldset[^>]*disabled/);
  assert.match(html, /Read request/);
  assert.match(html, /data-action="session-overview-retry"/);
});

test('first current-status failure does not imply any prior status and retry stays disabled while pending', () => {
  const first = ctx.sessionOverviewHTML(null, { error: 'unavailable' });
  assert.match(first, /Current session status unavailable/);
  assert.ok(!first.includes('Last known'));
  assert.ok(!first.includes('No retained findings'));
  const pending = ctx.sessionOverviewHTML(null, { error: 'unavailable', loading: true });
  assert.match(pending, /data-action="session-overview-retry" disabled/);
  const stale = ctx.sessionOverviewHTML({ session_id: 'own', requests: [{ id: 'g', detail: 'Read request' }], findings: [] }, { error: 'unavailable', loading: true });
  assert.match(stale, /Last known session status/);
  assert.match(stale, /<fieldset[^>]*disabled/);
  assert.match(stale, /data-action="session-overview-retry" disabled/);
});

test('overview escapes identifiers and labels at the DOM boundary', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const html = ctx.sessionOverviewHTML({ session_id: hostile, requests: [{ id: hostile, detail: hostile, path: hostile }], findings: [{ id: hostile, title: hostile, assessment: { residual_risk: hostile } }] }, {});
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
});

test('Home uses durable active sessions and links to their exact record', () => {
  const html = ctx.sessionDailyHTML([{ id: 'a', harness: 'claude', repo: 'project', status: 'active' }, { id: 'b', harness: 'claude', repo: 'project', status: 'idle' }, { id: 'old', status: 'ended' }], null);
  assert.match(html, /data-action="session-current" data-session="a"/);
  assert.match(html, /data-action="session-current" data-session="b"/);
  assert.ok(!html.includes('data-session="old"'));
  assert.match(ctx.sessionDailyHTML(null, null), /Session data unavailable/);
  assert.match(ctx.sessionDailyHTML([], null), /No live sessions/);
});

test('retained activity remains reachable when a session has no live resource family', () => {
  ctx.window.SA.sessionView = 'results';
  const html = ctx.sessionDetailHTML({ id: 'ended', status: 'ended', harness: 'codex' }, [], []);
  assert.ok(!html.includes('data-action="view-family"'));
  assert.match(html, /data-action="session-events" data-id="ended"/);
});


test('Home search matches session identity and reports no matches', () => {
  const sessions = [{ id: 'session-a', harness: 'claude', repo: 'api-service', branch: 'main', workspace: '/workspace/api-service', status: 'active' }, { id: 'session-b', harness: 'codex', repo: 'web-app', status: 'idle' }];
  for (const query of ['API-SERVICE', 'session-a', 'claude', 'main', '/workspace/api']) {
    const html = ctx.sessionDailyHTML(sessions, null, query);
    assert.match(html, /data-session="session-a"/);
    assert.ok(!html.includes('data-session="session-b"'));
  }
  assert.match(ctx.sessionDailyHTML(sessions, null, 'unmatched'), /No live sessions match/);
  assert.match(ctx.sessionDailyHTML(sessions, null, 'unmatched'), /data-action="clear-global-search"/);
  assert.match(ctx.sessionDailyHTML(null, null, 'unmatched'), /Session data unavailable/);
});


test('session search intersects the workspace filter and keeps harness exclusions', () => {
  const a = {id:'a', harness:'claude', repo:'api', branch:'main', status:'active'};
  const b = {id:'b', harness:'claude', repo:'api', branch:'release', status:'active'};
  const groups = ctx.groupSessionsByHarness([a,b], [], []);
  const selected = ctx.visibleSessionMembers(ctx.applySessionFilters(groups, {text:'api', search:'release'}));
  assert.deepEqual(Array.from(selected, s => s.id), ['b']);
  assert.equal(ctx.visibleSessionMembers(ctx.applySessionFilters(groups, {text:'api', search:'release', harnesses:{claude:false}})).length, 0);
  assert.equal(ctx.visibleSessionMembers(ctx.applySessionFilters(groups, {text:'missing', search:'release'})).length, 0);
});


const coverageBox = (data, state = {}) => ctx.sessionOverviewHTML({session_id:'own', requests:[], findings:[], ...data}, state).match(/<section class="sd-coverage"[^>]*>([\s\S]*?)<\/section>/)[1];
const coveragePath = (state, supported = true) => ({state, supported, detail:'Only reported activity', last_seen:'2026-10-15T12:00:00Z'});

test('coverage provides scoped evidence, setup guidance and deliberate traffic review', () => {
  const html = coverageBox({coverage:{guard:coveragePath('not-observed'), trace:coveragePath('observed'), payload:coveragePath('off')}});
  assert.match(html, /data-action="session-coverage-guide" data-id="own" data-path="guard"/);
  assert.match(html, /data-action="session-events" data-id="own"/);
  assert.match(html, /data-action="session-coverage-traffic" data-id="own"/);
  assert.match(html, /data-action="session-overview-retry"/);
  assert.match(html, /Last observed/);
  assert.ok(!html.includes('data-action="hook-setup"'), 'Guard setup is distinct from hook-completion integration');
});

test('unsupported, unknown and stale paths do not offer configuration changes', () => {
  for (const state of ['unsupported', 'future-state', 'stale']) {
    const html = coverageBox({coverage:{guard:coveragePath(state,false), trace:coveragePath(state,false), payload:coveragePath(state,false)}});
    assert.ok(!html.includes('session-coverage-traffic'));
    assert.ok(!html.includes('data-action="session-events"'));
    assert.match(html, /Refresh observations|Retry/);
  }
});

test('unattributed inspection leads to clearly separate machine traffic', () => {
  const html = coverageBox({coverage:{guard:coveragePath('unsupported',false), trace:coveragePath('not-observed'), payload:coveragePath('unattributed')}});
  assert.match(html, /Machine-wide traffic/);
  assert.match(html, /does not establish this session/);
  assert.match(html, /data-action="session-coverage-traffic" data-id="own"/);
});

test('failed overview retains observations and offers only refresh', () => {
  const html = coverageBox({coverage:{guard:coveragePath('observed'), trace:coveragePath('not-observed'), payload:coveragePath('off')}}, {error:'unavailable'});
  assert.match(html, /Last known/);
  assert.ok(!html.includes('data-action="session-events"'));
  assert.ok(!html.includes('session-coverage-traffic'));
  assert.ok(!html.includes('session-coverage-guide'));
  assert.match(html, /data-action="session-overview-retry"/);
});

test('absent current coverage keeps retained events reachable without claiming live protection', () => {
  const html = coverageBox({coverage:null});
  assert.match(html, /No current coverage/);
  assert.match(html, /data-action="session-events" data-id="own"/);
  assert.ok(!html.includes('session-coverage-guide'));
});
