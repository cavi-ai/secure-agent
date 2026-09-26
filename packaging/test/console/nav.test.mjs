// Console navigation tests — zero dependencies. Evaluates lib.js in a fresh
// VM context, as the browser loads it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = { window: {} };
vm.createContext(ctx);
vm.runInContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), ctx, { filename: 'lib.js' });
const { resolveConsoleRoute, routeKey, consoleRouteHash, isConsoleRoute, consoleBootState, policyListHTML } = ctx;
const key = id => routeKey(resolveConsoleRoute(id));

test('every old tab id resolves to its new tab[/sub]', () => {
  const want = {
    overview: 'home', findings: 'home', agents: 'sessions/processes', resources: 'sessions/resources',
    history: 'sessions/resources', worktrees: 'sessions/worktrees', events: 'sessions/events',
    sessions: 'sessions/board', egress: 'egress',
  };
  for (const [id, route] of Object.entries(want)) assert.equal(key(id), route, id);
  assert.equal(resolveConsoleRoute('findings').focus, 'attention');
  assert.equal(resolveConsoleRoute('overview').focus, '');
});

test('new ids, sub-view hashes and unknown ids', () => {
  for (const id of ['home', 'egress', 'policy']) assert.equal(key(id), id);
  assert.equal(key('#sessions/events'), 'sessions/events');
  assert.equal(key('sessions/processes'), 'sessions/processes');
  assert.equal(key('sessions/nope'), 'sessions/board');
  assert.equal(key('policy/x'), 'policy');
  for (const id of ['', 'nope', 'file=%2Fx', 'toString', '__proto__', undefined, null]) assert.equal(key(id), 'home', String(id));
  assert.equal(isConsoleRoute('agents'), true);
  assert.equal(isConsoleRoute('#sessions/worktrees'), true);
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
  assert.ok(expected.includes('claude · 3 since the daemon started') && expected.includes('2026-09-25'));
  assert.ok(expected.includes('data-action="forget-expected" data-key="claude|gh|/u/.config/gh/hosts.yml|&lt;GitHub&gt;"'));
  assert.ok(expected.includes('<b>an agent tool</b> reads') && expected.includes('codex · 0 since the daemon started'));
  assert.ok(policyListHTML('guard', null, {}).includes('Loading'));
  assert.ok(policyListHTML('guard', null, { error: 'boom <x>' }).includes('boom &lt;x&gt;'));
});
