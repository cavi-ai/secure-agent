import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const root = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const app = readFileSync(new URL('app.js', root), 'utf8');
const start = app.indexOf('  const policyState =');
const end = app.indexOf('  // Agent tab:', start);
assert.ok(start >= 0 && end > start);
const record = (extra = {}) => ({ key: 'fixture +&?#', agent: 'claude', reader: 'gh',
  path: '/synthetic/credentials', dest: 'example.test', created_at: '2026-10-01T12:00:00Z', ...extra });
const response = (body, ok = true) => ({ ok, json: async () => body, text: async () => 'Unavailable' });
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}
function fixture({ records = [record()], confirm = async () => true, remove, read } = {}) {
  const requests = [], confirmations = [], toasts = [];
  const ctx = { window: { saConfirm: async (...args) => { confirmations.push(args); return confirm(...args); } },
    sessionEnded: false, handoffGeneration: 1, markDirty() {},
    showToast: (...args) => toasts.push(args), document: { getElementById: () => null },
    apiFetch: async (url, options) => {
      requests.push([url, options?.method || 'GET']);
      if (options?.method === 'DELETE') return remove ? remove(url) : response({ status: 'ok', key: record().key });
      return url === '/expected' ? read ? read() : response(records) : response([]);
    } };
  vm.createContext(ctx);
  vm.runInContext(readFileSync(new URL('lib.js', root), 'utf8'), ctx);
  vm.runInContext(readFileSync(new URL('decision-permissions.js', root), 'utf8'), ctx);
  vm.runInContext(readFileSync(new URL('policy-controller.js', root), 'utf8'), ctx);
  vm.runInContext(app.slice(start, end), ctx);
  ctx.consolePolicyControllerModule();
  const state = vm.runInContext('policyState', ctx);
  state.expected = records;
  const html = () => ctx.policyListHTML('expected', state.expected, { ...state, ...state.reports.expected });
  const deletes = () => requests.filter(([, method]) => method === 'DELETE');
  return { ctx, state, requests, confirmations, toasts, html, deletes };
}

test('exception removal names its exact scope; cancellation and duplicate clicks do not write', async () => {
  const confirmation = deferred();
  const f = fixture({ confirm: () => confirmation.promise });
  const action = f.ctx.window.forgetExpected(record().key);
  await f.ctx.window.forgetExpected(record().key);
  assert.equal(f.confirmations.length, 1);
  assert.match(f.confirmations[0][0], /claude: gh reads \/synthetic\/credentials, then reaches example.test/);
  assert.match(f.confirmations[0][0], /remaining exceptions and policies/);
  assert.match(f.confirmations[0][0], /Past activity and exposure are unchanged/);
  confirmation.resolve(false);
  await action;
  assert.equal(f.deletes().length, 0);
  assert.equal(f.state.expectedMutations.size, 0);
});

test('file exception confirmation explains its agent, file, and all-reader scope', async () => {
  const f = fixture({ records: [record({ scope: 'file', reader: '*', dest: '*', path: '/synthetic/.env.test' })], confirm: async () => false });
  await f.ctx.window.forgetExpected(record().key);
  assert.match(f.confirmations[0][0], /non-secret file exception for claude: \/synthetic\/.env.test/);
  assert.match(f.confirmations[0][0], /all readers and destinations for this agent and file/);
  assert.match(f.html(), />Remove exception<\/button>/);
  assert.match(f.html(), /aria-label="Remove exception for claude: \/synthetic\/.env.test"/);
});

test('exact removal receipt removes only its row and survives a failed reread', async () => {
  const other = record({ key: 'unrelated', path: '/synthetic/other' });
  const f = fixture({ records: [record(), other], read: async () => response(null, false) });
  await f.ctx.window.forgetExpected(record().key);
  assert.deepEqual(f.deletes(), [['/expected?key=fixture%20%2B%26%3F%23', 'DELETE']]);
  assert.equal(f.state.expected.length, 1);
  assert.equal(f.state.expected[0].key, other.key);
  assert.equal(f.state.expectedRemoval.key, record().key);
  assert.match(f.html(), /Exception removal saved/);
  assert.match(f.html(), /current status is unavailable/);
  assert.doesNotMatch(f.html(), /data-action="forget-expected"/);
  assert.equal(f.toasts.filter(([, kind]) => kind === 'success').length, 1);
});

test('unconfirmed receipts preserve the row and require a current read before retry', async () => {
  for (const receipt of [null, {}, { status: 'ok' }, { status: 'ok', key: 'wrong' }, { status: 'error', key: record().key }]) {
    const f = fixture({ remove: async () => response(receipt) });
    await f.ctx.window.forgetExpected(record().key);
    assert.equal(f.state.expected.length, 1);
    assert.equal(f.state.expectedRemoval, null);
    assert.match(f.html(), /Removal not confirmed/);
    assert.doesNotMatch(f.html(), /data-action="forget-expected"/);
    await f.ctx.window.forgetExpected(record().key);
    assert.equal(f.deletes().length, 1);
    await f.ctx.loadPolicy();
    await f.ctx.window.forgetExpected(record().key);
    assert.equal(f.deletes().length, 2);
    assert.equal(f.toasts.filter(([, kind]) => kind === 'success').length, 0);
  }
});

test('HTTP, transport, and unreadable receipt failures remain uncertain without replay', async () => {
  for (const remove of [async () => response({}, false), async () => { throw new Error('disconnected'); },
    async () => ({ ok: true, json: async () => { throw new Error('invalid JSON'); } })]) {
    const f = fixture({ remove });
    await f.ctx.window.forgetExpected(record().key);
    await f.ctx.window.forgetExpected(record().key);
    assert.equal(f.deletes().length, 1);
    assert.match(f.html(), /Removal not confirmed/);
    assert.equal(f.state.expected[0].key, record().key);
  }
});

test('invalid lists cannot replace known exceptions or authorize removal', async () => {
  for (const records of [null, {}, [record(), record()], [record({ key: '' })], [record({ scope: 'workspace' })]]) {
    const f = fixture({ read: async () => response(records) });
    await f.ctx.loadPolicy();
    assert.equal(f.state.expected[0].key, record().key);
    assert.match(f.state.reports.expected.error, /invalid records/);
    await f.ctx.window.forgetExpected(record().key);
    assert.equal(f.deletes().length, 0);
  }
  const f = fixture();
  f.state.reports.expected.loading = true;
  await f.ctx.window.forgetExpected(record().key);
  f.state.reports.expected.loading = false;
  await f.ctx.window.forgetExpected('unknown');
  assert.equal(f.confirmations.length, 0);
});

test('changed exception scope during confirmation requires a new choice', async () => {
  const confirmation = deferred();
  const f = fixture({ confirm: () => confirmation.promise });
  const action = f.ctx.window.forgetExpected(record().key);
  f.state.expected = [record({ dest: 'other.test' })];
  confirmation.resolve(true);
  await action;
  assert.equal(f.deletes().length, 0);
});

test('old list reads cannot restore a row after its exact removal receipt', async () => {
  const write = deferred(), oldRead = deferred();
  let reads = 0;
  const f = fixture({ remove: () => write.promise, read: () => ++reads === 1 ? oldRead.promise : response([]) });
  const removal = f.ctx.window.forgetExpected(record().key);
  await new Promise(resolve => setImmediate(resolve));
  const stale = f.ctx.loadPolicy();
  write.resolve(response({ status: 'ok', key: record().key }));
  await removal;
  oldRead.resolve(response([record()]));
  await stale;
  assert.equal(f.state.expected.length, 0);
  assert.match(f.html(), /Exception removal saved/);
});

test('late confirmation, write, and read responses cannot cross the ended session', async () => {
  for (const stage of ['confirm', 'write', 'read']) {
    const pending = deferred();
    const f = fixture({ confirm: stage === 'confirm' ? () => pending.promise : async () => true,
      remove: stage === 'write' ? () => pending.promise : undefined,
      read: stage === 'read' ? () => pending.promise : undefined });
    const action = stage === 'read' ? f.ctx.loadPolicy() : f.ctx.window.forgetExpected(record().key);
    await new Promise(resolve => setImmediate(resolve));
    f.ctx.sessionEnded = true;
    f.ctx.handoffGeneration++;
    f.ctx.resetPolicyState();
    pending.resolve(stage === 'confirm' ? true : response(stage === 'read' ? [record()] : { status: 'ok', key: record().key }));
    await action;
    assert.equal(f.state.expected, null);
    assert.equal(f.state.expectedRemoval, null);
    assert.equal(f.state.expectedMutations.size, 0);
    assert.equal(f.toasts.length, 0);
    if (stage === 'confirm') assert.equal(f.deletes().length, 0);
  }
});

test('exception identities and retained removal feedback are escaped', () => {
  const malicious = record({ key: '"><img src=x>', agent: '<script>x</script>', path: '/synthetic/<img src=x>' });
  const f = fixture({ records: [malicious] });
  f.state.expectedRemoval = malicious;
  assert.doesNotMatch(f.html(), /<script>|<img/);
  assert.match(f.html(), /&lt;img/);
  assert.match(f.html(), /&quot;&gt;&lt;img/);
});
