import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

function deferred() {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return {promise,resolve,reject};
}
function controller(fetch) {
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/agent-controller.js', import.meta.url), 'utf8'), ctx);
  const state = {AGENT_PATHS:{status:'/status',chat:'/chat'},agentState:{actionRequests:new Set(),readVersion:{},chat:{},runs:[]}};
  const api = ctx.createAgentController({state,actions:{agentFetch:fetch,fillAgentHarnesses(){},markDirty(){},followAgent(){}}});
  return {api,state};
}

test('an obsolete refresh failure cannot replace the latest successful agent status', async () => {
  const old = deferred();
  let reads = 0;
  const {api,state} = controller(() => ++reads === 1 ? old.promise : Promise.resolve({enabled:true}));
  const first = api.loadAgent(['status']);
  await api.loadAgent(['status']);
  old.reject(new Error('obsolete timeout'));
  await first;
  assert.equal(state.agentState.status.enabled, true);
  assert.equal(state.agentState.error, '');
});

test('an obsolete refresh success cannot erase the current failure', async () => {
  const old = deferred();
  let reads = 0;
  const {api,state} = controller(() => ++reads === 1 ? old.promise : Promise.reject(new Error('current timeout')));
  const first = api.loadAgent(['status']);
  await api.loadAgent(['status']);
  old.resolve({enabled:true});
  await first;
  assert.match(state.agentState.error, /current timeout/);
  assert.equal(state.agentState.status, undefined);
});

test('an unrelated report refresh cannot hide a current status failure', async () => {
  const old = deferred();
  const {api,state} = controller(path => path === '/status' ? old.promise : Promise.resolve({messages:[]}));
  const first = api.loadAgent(['status']);
  await api.loadAgent(['chat']);
  old.reject(new Error('current status timeout'));
  await first;
  assert.match(state.agentState.error, /current status timeout/);
  await api.loadAgent(['chat']);
  assert.match(state.agentState.error, /current status timeout/);
});

test('a failed independent report does not discard successfully refreshed data or its own error', async () => {
  let statusFails = false;
  const {api,state} = controller(path => path === '/status'
    ? statusFails ? Promise.reject(new Error('status timeout')) : Promise.resolve({enabled:true})
    : Promise.reject(new Error('chat timeout')));
  await api.loadAgent(['status','chat']);
  assert.equal(state.agentState.status.enabled, true);
  assert.match(state.agentState.error, /chat timeout/);
  statusFails = true;
  await api.loadAgent(['status']);
  assert.match(state.agentState.error, /chat timeout/);
  assert.equal(state.agentState.status.enabled, true);
});
