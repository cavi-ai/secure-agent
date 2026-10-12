import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js', import.meta.url), 'utf8');
const begin = source.indexOf('  window.applyAgentInstruction = async function');
const end = source.indexOf('  async function fetchPlan(', begin);
assert.ok(begin >= 0 && end > begin);
const revision = 'a'.repeat(64);
const preview = { path: '/work/AGENTS.md', instruction: 'Never print credentials.', revision, ready: true, applied: false };

function context(fetch) {
  const requests = [], toasts = [];
  const c = { window: {}, planResponseCache: new Map([['flag:f1', { subject: 'flag:f1', instruction: { ...preview } }]]),
    instructionRequests: new Map(), paintPlanSlots() {},
    showToast: (...args) => toasts.push(args),
    apiFetch: async (...args) => { requests.push(args); return fetch(...args); },
    loadPlanSlot: async () => { c.planResponseCache.get('flag:f1').instruction.revision = 'b'.repeat(64); } };
  vm.runInNewContext(source.slice(begin, end), c);
  return { c, requests, toasts };
}

test('one click applies only the displayed subject and revision and blocks duplicate clicks', async () => {
  let resolve;
  const { c, requests, toasts } = context(() => new Promise(r => { resolve = r; }));
  const first = c.window.applyAgentInstruction('flag:f1', revision);
  await c.window.applyAgentInstruction('flag:f1', revision);
  assert.equal(requests.length, 1);
  assert.equal(requests[0][0], '/agent/instructions');
  assert.deepEqual(JSON.parse(requests[0][1].body), { subject: 'flag:f1', revision });
  resolve({ ok: true, json: async () => ({ ...preview, applied: true }) });
  await first;
  assert.equal(c.planResponseCache.get('flag:f1').instruction.applied, true);
  assert.equal(toasts.length, 1);
  await c.window.applyAgentInstruction('flag:f1', revision);
  assert.equal(requests.length, 1);
});

test('failed or unconfirmed writes refresh the preview without retrying or claiming success', async () => {
  for (const response of [{ ok: false, text: async () => 'file changed' }, { ok: true, json: async () => ({ ...preview, path: '/other/AGENTS.md', applied: true }) }]) {
    const { c, requests, toasts } = context(async () => response);
    await c.window.applyAgentInstruction('flag:f1', revision);
    assert.equal(requests.length, 1);
    assert.equal(c.planResponseCache.get('flag:f1').instruction.applied, false);
    assert.equal(c.planResponseCache.get('flag:f1').instruction.revision, 'b'.repeat(64));
    assert.equal(toasts.length, 0);
    assert.ok(c.instructionRequests.get('flag:f1').error);
    assert.equal(c.instructionRequests.get('flag:f1').busy, false);
  }
});

test('missing, disabled and stale actions cannot send a write', async () => {
  const { c, requests } = context(async () => { throw new Error('should not send'); });
  await c.window.applyAgentInstruction('flag:missing', revision);
  await c.window.applyAgentInstruction('flag:f1', 'old');
  c.planResponseCache.get('flag:f1').instruction.ready = false;
  await c.window.applyAgentInstruction('flag:f1', revision);
  assert.equal(requests.length, 0);
});
