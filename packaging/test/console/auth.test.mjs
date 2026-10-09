import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../../../daemon/internal/api/web_dist/console-auth.js', import.meta.url), 'utf8');
function fixture(fetchImpl, token = 'first') {
  const ctx = vm.createContext({ AbortController, DOMException, Headers, setTimeout, clearTimeout });
  vm.runInContext(source, ctx);
  let rejected = 0;
  return { auth: ctx.createConsoleAuth({ token, fetchImpl, onRejected: () => rejected++ }), rejected: () => rejected };
}
const deferred = () => {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
};

test('requests use the current credential and cannot override it', async () => {
  const tokens = [];
  const f = fixture(async (_, init) => { tokens.push(init.headers.get('X-SecureAgent-Console-Token')); return new Response('{}'); });
  await f.auth.fetch('/status', { headers: { 'X-SecureAgent-Console-Token': 'wrong' } });
  f.auth.replaceToken('second');
  await f.auth.fetch('/status');
  assert.deepEqual(tokens, ['first', 'second']);
});

test('no credential means no network request', async () => {
  let calls = 0;
  const f = fixture(async () => { calls++; }, '');
  await assert.rejects(f.auth.fetch('/status'), { name: 'AbortError' });
  assert.equal(calls, 0);
});

test('credentials cannot follow an external endpoint or redirect', async () => {
  let calls = 0;
  const f = fixture(async (_, init) => { calls++; assert.equal(init.redirect, 'error'); return new Response('{}'); });
  for (const path of ['https://example.com/status', '//example.com/status', '/\\example.com/status', '/\n/example.com']) {
    await assert.rejects(f.auth.fetch(path), /Invalid console endpoint/);
  }
  assert.equal(calls, 0);
  await f.auth.fetch('/status');
});

test('credential rejection clears requests once; permission denial retains authentication', async () => {
  const f = fixture(async path => new Response(JSON.stringify({ error: path === '/status' ? 'console token required' : 'method not permitted for the console token' }), { status: 403 }));
  const denied = await f.auth.fetch('/guard/rules');
  assert.equal(denied.status, 403);
  assert.equal(f.rejected(), 0);
  await assert.rejects(f.auth.fetch('/status'), { name: 'AbortError' });
  assert.equal(f.rejected(), 1);
  await assert.rejects(f.auth.fetch('/status'), { name: 'AbortError' });
  assert.equal(f.rejected(), 1);
});

test('old credential rejection cannot end the replacement session', async () => {
  const waiting = deferred();
  const f = fixture(() => waiting.promise);
  const old = f.auth.fetch('/status');
  f.auth.replaceToken('second');
  waiting.resolve(new Response('{"error":"console token required"}', { status: 403 }));
  await assert.rejects(old, { name: 'AbortError' });
  assert.equal(f.rejected(), 0);
});

test('late bodies and pending requests cannot publish across credential replacement', async () => {
  const body = deferred(), pending = deferred();
  const f = fixture(async path => path === '/body' ? { status: 200, ok: true, json: () => body.promise }
    : pending.promise);
  const response = await f.auth.fetch('/body');
  const parsed = response.json();
  const old = f.auth.fetch('/pending');
  f.auth.replaceToken('second');
  body.resolve({ old: true });
  pending.resolve(new Response('{}'));
  await assert.rejects(parsed, { name: 'AbortError' });
  await assert.rejects(old, { name: 'AbortError' });
});

test('replacement aborts the previous transport and request timeout aborts a hung endpoint', async () => {
  const signals = [];
  const f = fixture((_, init) => new Promise((_, reject) => {
    signals.push(init.signal);
    init.signal.addEventListener('abort', () => reject(new DOMException('cancelled', 'AbortError')));
  }));
  const old = f.auth.fetch('/status');
  f.auth.replaceToken('second');
  await assert.rejects(old, { name: 'AbortError' });
  assert.equal(signals[0].aborted, true);
  await assert.rejects(f.auth.fetch('/status', { timeoutMs: 5 }), { name: 'AbortError' });
});

test('a response body that stalls after headers cannot wedge connection recovery', async () => {
  const f = fixture(async () => ({ status: 200, json: () => new Promise(() => {}) }));
  const response = await f.auth.fetch('/snapshot', { timeoutMs: 5 });
  await assert.rejects(response.json(), { name: 'AbortError' });
});

test('a transport that ignores cancellation cannot publish after its deadline', async () => {
  const waiting = deferred();
  const f = fixture(() => waiting.promise);
  const request = f.auth.fetch('/snapshot', { timeoutMs: 5 });
  await new Promise(resolve => setTimeout(resolve, 10));
  waiting.resolve(new Response('{}'));
  await assert.rejects(request, { name: 'AbortError' });
});
