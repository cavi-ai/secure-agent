import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const plain = x => JSON.parse(JSON.stringify(x));

// Builds the controller with fake collaborators. respond(url, req) answers
// each request; a thrown error models a network failure.
function build({ telemetry = {}, respond = () => ({ ok: true, json: async () => ({}) }), window: win = {}, flagList = [], dropFlag } = {}) {
  const ctx = { Date, setTimeout: fn => { fn(); }, window: { saConfirm: async () => true, ...win } };
  vm.createContext(ctx);
  for (const file of ['lib.js', 'tab-findings.js', 'staged-write.js', 'finding-actions.js']) {
    vm.runInContext(readFileSync(path.join(web, file), 'utf8'), ctx, { filename: file });
  }
  const log = { requests: [], toasts: [], notes: [], refetches: 0, refills: 0, closed: [], dropped: 0 };
  const state = { t: telemetry };
  const request = async (url, req) => {
    log.requests.push({ url, method: req.method, body: req.body ? JSON.parse(req.body) : undefined });
    return respond(url, req);
  };
  const writes = ctx.createStagedWrite({
    telemetry: () => state.t,
    render: () => {},
    beginAttentionWrite: () => Object.assign(() => true, { isCurrent: () => true }),
    request
  });
  const actions = ctx.createFindingActions({
    request,
    toast: (message, type) => log.toasts.push({ message, type }),
    refetch: () => { log.refetches++; },
    writes,
    telemetry: () => state.t,
    cardNote: (...args) => log.notes.push(args),
    cssq: x => x,
    loadPolicy: () => { log.policy = (log.policy || 0) + 1; },
    flags: {
      find: id => flagList.find(f => f.id === id),
      drop: dropFlag || (() => { log.dropped++; const revert = () => { log.dropped--; }; revert.commit = () => {}; return revert; })
    },
    drawer: {
      back: () => undefined,
      refill: () => { log.refills++; },
      refillOpen: () => { log.refills++; },
      closeFlag: id => log.closed.push(id)
    }
  });
  return { actions, state, log, ctx };
}

const failing = { ok: false, text: async () => 'write unavailable' };
const rejecting = () => { throw new Error('network down'); };

for (const [id, route, body] of [
  ['allow-host', '/allowlist', { agent: 'codex', host: '203.0.113.24' }],
  ['allow-path', '/guard/path-allow', { agent: 'codex', rule_id: 'env-files', path: '/workspace/.env' }],
]) {
  test(`${id} from a loaded flag drawer saves the decision and clears the queue`, async () => {
    const flag = { id: 'flag-1', agent: 'codex', explain: { actions: [{ id, method: 'POST', path: route, body }] } };
    const { actions, log } = build({ telemetry: { flags: [], flagsView: [] }, flagList: [flag] });
    await actions.explainAct(flag.id, id, body.host);
    assert.deepEqual(log.requests.map(r => r.url), [route, '/flags/acknowledge']);
    assert.deepEqual(log.requests[0].body, body);
    assert.equal(log.requests[1].body.flag_id, flag.id);
    assert.equal(log.dropped, 1);
    assert.deepEqual(log.closed, [flag.id]);
    assert.equal(log.toasts.at(-1).type, 'success');
  });
}

test('failed file exception keeps the finding in the queue', async () => {
  const flag = { id: 'flag-2', explain: { actions: [{ id: 'allow-path', method: 'POST', path: '/guard/path-allow', body: { agent: 'codex', rule_id: 'env-files', path: '/workspace/.env' } }] } };
  const { actions, log } = build({ telemetry: { flags: [flag] }, flagList: [flag], respond: () => failing });
  await actions.explainAct(flag.id, 'allow-path');
  assert.equal(log.dropped, 0);
  assert.equal(log.toasts.at(-1).type, 'danger');
});

test('selected finding enters local review without dismissal or shell execution', async () => {
  const calls = [];
  const flag = { id: 'selected', explain: { actions: [{ id: 'review-local', body: { flag_ids: ['selected'] } }] } };
  const { actions, state } = build({ telemetry: { flags: [flag] }, flagList: [flag],
    window: { analyzeAgentActivity: async ids => calls.push(Array.from(ids)) } });
  await actions.explainAct('selected', 'review-local');
  assert.deepEqual(calls, [['selected']]);
  assert.equal(state.t.flags.length, 1);
});

test('file exception confirmation does not optimistically dismiss mixed evidence', async () => {
  const flag = { id: 'mixed', explain: { actions: [{ id: 'expect-file', path: '/expected', method: 'POST', consequence: 'Exact file only', body: { flag_id: 'mixed', scope: 'file' } }] } };
  const { actions, state, log } = build({ telemetry: { flags: [flag] }, flagList: [flag] });
  await actions.explainAct('mixed', 'expect-file');
  assert.equal(log.requests.length, 1);
  assert.deepEqual(log.requests[0], { url: '/expected', method: 'POST', body: { flag_id: 'mixed', scope: 'file' } });
  assert.equal(state.t.flags.length, 1);
});

test('group approval sends the selected served endpoint without a stale flag lookup', async () => {
  const body = { flag_id: 'older', path: '/home/.config/gh/hosts.yml', host: '140.82.114.6' };
  const telemetry = { patterns: [{ key: 'group', actions: [{ id: 'expect', method: 'POST', path: '/expected', body, consequence: 'This endpoint only' }] }] };
  const { actions, log, ctx } = build({ telemetry });
  await actions.patternAct('group', 'expect', body.host);
  assert.deepEqual(log.requests.map(r => [r.url, r.body]), [['/expected', body]]);
  ctx.window.saConfirm = async () => false;
  await actions.patternAct('group', 'expect', body.host);
  assert.equal(log.requests.length, 1);
});

test('allowHost keeps the staged allowlist row, tells the operator and refetches', async () => {
  const telemetry = { allowlist: [], suggestions: [{ agent: 'codex', host: 'h.example' }], uninspected: [{ agent: 'codex', host: 'h.example' }, { agent: 'codex', host: 'other.example' }] };
  const { actions, state, log } = build({ telemetry });
  await actions.allowHost('codex', 'h.example');
  assert.deepEqual(log.requests, [{ url: '/allowlist', method: 'POST', body: { agent: 'codex', host: 'h.example' } }]);
  assert.deepEqual(plain(state.t.allowlist), [{ agent: 'codex', host: 'h.example' }]);
  assert.deepEqual(plain(state.t.suggestions), []);
  assert.deepEqual(plain(state.t.uninspected), [{ agent: 'codex', host: 'other.example' }]);
  assert.deepEqual(log.toasts, [{ message: 'Allowlisted h.example for codex', type: 'success' }]);
  assert.equal(log.refetches, 1);
  assert.equal(log.notes.length, 1);
});

for (const [name, respond, message] of [
  ['rejected', () => failing, 'Failed to allowlist h.example.'],
  ['unreachable', rejecting, 'Error allowlisting h.example: Error: network down'],
]) {
  test(`allowHost restores the telemetry when the write is ${name}`, async () => {
    const telemetry = { allowlist: [], suggestions: [{ agent: 'codex', host: 'h.example' }], uninspected: [{ agent: 'codex', host: 'h.example' }] };
    const before = plain(telemetry);
    const { actions, state, log } = build({ telemetry, respond });
    await actions.allowHost('codex', 'h.example');
    assert.deepEqual(plain(state.t), before);
    assert.deepEqual(log.toasts, [{ message, type: 'danger' }]);
    assert.equal(log.refetches, 0);
  });
}

test('bulkAllowHosts allowlists each host in order and reports the tally', async () => {
  const { actions, state, log } = build({ telemetry: { allowlist: [] } });
  await actions.bulkAllowHosts('codex', 'a.example,b.example');
  assert.deepEqual(log.requests.map(r => r.body.host), ['a.example', 'b.example']);
  assert.deepEqual(plain(state.t.allowlist).map(p => p.host), ['a.example', 'b.example']);
  assert.deepEqual(log.toasts, [{ message: 'Allowlisted 2 of 2 hosts for codex', type: 'success' }]);
  assert.equal(log.refetches, 1);
});

test('bulkAllowHosts restores the telemetry when no host lands', async () => {
  const { actions, state, log } = build({ telemetry: { allowlist: [] }, respond: () => failing });
  await actions.bulkAllowHosts('codex', 'a.example,b.example');
  assert.deepEqual(plain(state.t.allowlist), []);
  assert.deepEqual(log.toasts, [{ message: 'Allowlisted 0 of 2 hosts for codex', type: 'danger' }]);
});

test('assessHost loads a stored verdict and refreshes the open drawer', async () => {
  const { actions, state, log } = build({ telemetry: { uninspected: [] }, respond: () => ({ ok: true, json: async () => ({ verdict: 'benign' }) }) });
  await actions.assessHost('codex', 'h.example');
  assert.deepEqual(log.requests, [{ url: '/advisor/assess-host', method: 'POST', body: { agent: 'codex', host: 'h.example' } }]);
  assert.deepEqual(log.toasts, [{ message: 'Advisor verdict loaded', type: 'info' }]);
  assert.equal(log.refetches, 1);
  assert.equal(log.refills, 1);
  assert.deepEqual(plain(state.t), { uninspected: [] });
});

test('assessHost reports a disabled advisor and a failed request without touching telemetry', async () => {
  const off = build({ telemetry: { uninspected: [] }, respond: () => ({ ok: false, status: 503 }) });
  await off.actions.assessHost('codex', 'h.example');
  assert.deepEqual(off.log.toasts, [{ message: 'Advisor is off — enable it in Settings for endpoint guidance.', type: 'info' }]);
  const bad = build({ telemetry: { uninspected: [] }, respond: () => ({ ok: false, status: 500, text: async () => 'boom' }) });
  await bad.actions.assessHost('codex', 'h.example');
  assert.deepEqual(bad.log.toasts, [{ message: 'Advisor assessment failed: boom', type: 'danger' }]);
  for (const t of [off, bad]) {
    assert.equal(t.log.refetches, 0);
    assert.deepEqual(plain(t.state.t), { uninspected: [] });
  }
});

function routineTelemetry() {
  return { routine: [{ key: 'grp', flag_ids: ['f1', 'f2'] }], patterns: [], flags: [{ id: 'f1' }, { id: 'f2' }, { id: 'f3' }], flagsView: null, posture: undefined };
}
const dismissAll = { id: 'dismiss-all', label: 'Dismiss all', method: 'POST', path: '/flags/acknowledge', body: { flag_ids: ['f1', 'f2'] } };

test('routineAct removes the group and its flags, then reports and refetches', async () => {
  const telemetry = routineTelemetry();
  telemetry.routine[0].actions = [dismissAll];
  const { actions, state, log } = build({ telemetry });
  await actions.routineAct('grp', 'dismiss-all');
  assert.deepEqual(log.requests, [{ url: '/flags/acknowledge', method: 'POST', body: { flag_ids: ['f1', 'f2'] } }]);
  assert.deepEqual(plain(state.t.routine), []);
  assert.deepEqual(plain(state.t.flags), [{ id: 'f3' }]);
  assert.deepEqual(log.toasts, [{ message: 'Dismissed 2 flags — the rules keep watching', type: 'success' }]);
  assert.equal(log.refetches, 1);
});

test('routineAct puts the group and flags back when the write fails', async () => {
  const telemetry = routineTelemetry();
  telemetry.routine[0].actions = [dismissAll];
  const before = plain(telemetry);
  const { actions, state, log } = build({ telemetry, respond: () => failing });
  await actions.routineAct('grp', 'dismiss-all');
  assert.deepEqual(plain(state.t), before);
  assert.deepEqual(log.toasts, [{ message: 'Dismiss all failed: write unavailable', type: 'danger' }]);
  assert.equal(log.refetches, 0);
});

const statusTelemetry = () => ({ status: { firewall_stats: { 'rule-a': { mode: 'monitor' }, 'rule-b': { mode: 'monitor' } } } });

test('promoteRule blocks only the chosen rule and announces it', async () => {
  const { actions, state, log } = build({ telemetry: statusTelemetry() });
  await actions.promoteRule('rule-a');
  assert.deepEqual(log.requests, [{ url: '/firewall/mode', method: 'POST', body: { rule: 'rule-a', mode: 'block' } }]);
  assert.equal(state.t.status.firewall_stats['rule-a'].mode, 'block');
  assert.equal(state.t.status.firewall_stats['rule-b'].mode, 'monitor');
  assert.deepEqual(log.toasts, [{ message: 'Rule “rule-a” promoted to block.', type: 'success' }]);
  assert.equal(log.refetches, 1);
});

test('promoteRule restores the monitor mode when the write fails', async () => {
  const { actions, state, log } = build({ telemetry: statusTelemetry(), respond: () => failing });
  await actions.promoteRule('rule-a');
  assert.equal(state.t.status.firewall_stats['rule-a'].mode, 'monitor');
  assert.deepEqual(log.toasts, [{ message: 'Failed to promote “rule-a”.', type: 'danger' }]);
  assert.equal(log.refetches, 0);
});

test('removeAllowlistEntry drops the row and tells the operator', async () => {
  const telemetry = { allowlist: [{ agent: 'codex', host: 'a.example' }, { agent: 'codex', host: 'b.example' }] };
  const { actions, state, log } = build({ telemetry });
  await actions.removeAllowlistEntry('codex', 'a.example');
  assert.deepEqual(log.requests, [{ url: '/allowlist', method: 'DELETE', body: { agent: 'codex', host: 'a.example' } }]);
  assert.deepEqual(plain(state.t.allowlist), [{ agent: 'codex', host: 'b.example' }]);
  assert.deepEqual(log.toasts, [{ message: 'Removed a.example for codex.', type: 'info' }]);
});

test('removeAllowlistEntry restores the row when the write fails', async () => {
  const telemetry = { allowlist: [{ agent: 'codex', host: 'a.example' }] };
  const { actions, state, log } = build({ telemetry, respond: () => failing });
  await actions.removeAllowlistEntry('codex', 'a.example');
  assert.deepEqual(plain(state.t.allowlist), [{ agent: 'codex', host: 'a.example' }]);
  assert.deepEqual(log.toasts, [{ message: 'Failed to remove a.example.', type: 'danger' }]);
});
