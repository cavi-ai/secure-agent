import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../../../daemon/internal/api/web_dist/live-updates.js', import.meta.url), 'utf8');

function clock() {
  let now = 0, nextID = 1;
  const pending = new Map();
  const add = (fn, delay, interval) => {
    const id = nextID++;
    pending.set(id, { fn, at: now + delay, interval });
    return id;
  };
  return {
    pending,
    setTimeout: (fn, delay) => add(fn, delay, 0),
    setInterval: (fn, delay) => add(fn, delay, delay),
    clearTimeout: id => pending.delete(id),
    clearInterval: id => pending.delete(id),
    tick(ms) {
      const until = now + ms;
      while (true) {
        const next = [...pending].sort((a, b) => a[1].at - b[1].at)[0];
        if (!next || next[1].at > until) break;
        const [id, timer] = next;
        now = timer.at;
        if (timer.interval) timer.at += timer.interval;
        else pending.delete(id);
        timer.fn();
      }
      now = until;
    }
  };
}

function fixture({ streaming = true, handlers = {} } = {}) {
  const timers = clock(), calls = [], streams = [];
  class Stream {
    closed = false;
    listeners = new Map();
    closes = 0;
    constructor(url) { this.url = url; streams.push(this); }
    addEventListener(kind, fn) { this.listeners.set(kind, fn); }
    emit(kind, message = {}) { this.listeners.get(kind)?.(message); }
    open() { this.onopen(); }
    error() { this.onerror(); }
    close() { this.closes++; this.closed = true; }
  }
  const context = vm.createContext({});
  vm.runInContext(source, context);
  const controller = context.createConsoleLiveUpdates({
    refresh: options => calls.push(options?.slow === false ? 'fast' : 'full'),
    connectStream: streaming ? () => new Stream('/events/stream') : null,
    handlers,
    timers
  });
  return { controller, timers, calls, streams, Stream };
}

test('streaming starts once, keeps the slow refresh, and stops cleanly', () => {
  const f = fixture();
  f.controller.start();
  f.controller.start();
  assert.deepEqual(f.calls, ['full']);
  assert.equal(f.streams.length, 1);
  assert.equal(f.streams[0].url, '/events/stream');
  f.streams[0].open();
  f.timers.tick(30000);
  assert.deepEqual(f.calls, ['full', 'full', 'full']);
  f.controller.stop();
  f.controller.stop();
  f.controller.start();
  assert.equal(f.streams[0].closes, 1);
  assert.equal(f.timers.pending.size, 0);
  assert.equal(f.streams.length, 1);
});

test('the authenticated request delivers split frames and aborts on stop', async () => {
  const context = vm.createContext({ AbortController, TextDecoder });
  vm.runInContext(source, context);
  const timers = clock();
  const requests = [], delivered = [];
  let body;
  const stream = context.connectConsoleStream((path, opts) => {
    requests.push({ path, opts });
    return new Response(new ReadableStream({
      start(controller) {
        body = controller;
        opts.signal.addEventListener('abort', () => controller.error(opts.signal.reason));
      }
    }), { headers: { 'Content-Type': 'text/event-stream' } });
  }, timers);
  stream.onopen = () => delivered.push('open');
  stream.onerror = () => assert.fail('stopping must not emit an error');
  stream.addEventListener('flag', frame => delivered.push(JSON.parse(frame.data).value));
  assert.equal(requests[0].path, '/events/stream');
  assert.equal(requests[0].opts.credentials, 'omit');
  assert.equal(requests[0].opts.headers.Accept, 'text/event-stream');
  const bytes = new TextEncoder().encode(': ready\n\nevent: flag\ndata: {"value":"é"}\n\n');
  const split = bytes.indexOf(0xc3) + 1;
  body.enqueue(bytes.slice(0, split));
  body.enqueue(bytes.slice(split));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(delivered, ['open', 'é']);
  stream.close();
  assert.equal(requests[0].opts.signal.aborted, true);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(timers.pending.size, 0);
});

test('a non-stream response closes the transport and starts polling', async () => {
  const context = vm.createContext({ AbortController, TextDecoder });
  vm.runInContext(source, context);
  const timers = clock(), calls = [];
  const controller = context.createConsoleLiveUpdates({
    refresh: options => calls.push(options?.slow === false ? 'fast' : 'full'),
    connectStream: () => context.connectConsoleStream(() => new Response('unavailable', { status: 503 }), timers),
    timers
  });
  controller.start();
  await new Promise(resolve => setImmediate(resolve));
  timers.tick(2000);
  assert.deepEqual(calls, ['full', 'fast']);
  controller.stop();
});

test('an interrupted stream reconnects and reconciles on the next open', async () => {
  const context = vm.createContext({ AbortController, TextDecoder });
  vm.runInContext(source, context);
  const timers = clock(), calls = [], bodies = [];
  const controller = context.createConsoleLiveUpdates({
    refresh: () => calls.push('refresh'),
    connectStream: () => context.connectConsoleStream(() => new Response(new ReadableStream({
      start(body) { bodies.push(body); }
    }), { headers: { 'Content-Type': 'text/event-stream' } }), timers),
    timers
  });
  controller.start();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(bodies.length, 1);
  assert.equal(calls.length, 2);
  bodies[0].close();
  await new Promise(resolve => setImmediate(resolve));
  timers.tick(3000);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(bodies.length, 2);
  assert.equal(calls.length, 3);
  controller.stop();
  bodies[1].close();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(timers.pending.size, 0);
});

test('without a stream, polling refreshes the fast set every two seconds', async () => {
  const f = fixture({ streaming: false });
  f.controller.start();
  f.timers.tick(2000);
  await new Promise(resolve => setImmediate(resolve));
  f.timers.tick(2000);
  assert.deepEqual(f.calls, ['full', 'fast', 'fast']);
  assert.equal(f.streams.length, 0);
  f.controller.stop();
  f.timers.tick(30000);
  assert.equal(f.calls.length, 3);
});

test('a polling cycle slower than the interval finishes before the next starts', async () => {
  const timers = clock(), calls = [];
  let finish;
  const context = vm.createContext({});
  vm.runInContext(source, context);
  const controller = context.createConsoleLiveUpdates({
    refresh: options => {
      calls.push(options?.slow === false ? 'fast' : 'full');
      if (options?.slow === false) return new Promise(resolve => { finish = resolve; });
    },
    connectStream: null, timers
  });
  controller.start();
  timers.tick(2000);
  timers.tick(2000);
  timers.tick(2000);
  assert.deepEqual(calls, ['full', 'fast'], 'an unfinished cycle is not superseded');
  finish();
  await new Promise(resolve => setImmediate(resolve));
  timers.tick(2000);
  assert.deepEqual(calls, ['full', 'fast', 'fast']);
  controller.stop();
});

test('repeated stream errors fall back once and an open resets the failure count', () => {
  const f = fixture();
  f.controller.start();
  const stream = f.streams[0];
  for (let i = 0; i < 5; i++) stream.error();
  f.timers.tick(2000);
  assert.equal(f.calls.length, 1);
  stream.error();
  stream.error();
  f.timers.tick(2000);
  assert.equal(f.calls.length, 2, 'fallback must not stack polling timers');
  stream.open();
  for (let i = 0; i < 5; i++) stream.error();
  f.timers.tick(2000);
  assert.equal(f.calls.length, 3, 'opening reconciles, resets failures and cancels polling');
});

test('each stream open reconciles missed deltas immediately', () => {
  const f = fixture();
  f.controller.start();
  const stream = f.streams[0];
  stream.open();
  assert.deepEqual(f.calls, ['full', 'full']);
  stream.error();
  stream.open();
  assert.deepEqual(f.calls, ['full', 'full', 'full']);
  f.controller.stop();
  stream.open();
  assert.equal(f.calls.length, 3, 'queued opens after shutdown must not refresh');
});

test('a hard-closed stream immediately enables polling', () => {
  const f = fixture();
  f.controller.start();
  f.streams[0].closed = true;
  f.streams[0].error();
  f.timers.tick(2000);
  assert.equal(f.calls.length, 2);
});

test('guard lifecycle events coalesce without delaying the first refresh', () => {
  const f = fixture();
  f.controller.start();
  f.streams[0].emit('guard-prompt');
  f.timers.tick(300);
  f.streams[0].emit('guard-resolved');
  f.timers.tick(99);
  assert.deepEqual(f.calls, ['full']);
  f.timers.tick(1);
  assert.deepEqual(f.calls, ['full', 'fast']);
});

test('flag bursts reconcile two seconds after the last flag', () => {
  const flags = [];
  const f = fixture({ handlers: { flag: msg => flags.push(msg.data) } });
  f.controller.start();
  f.streams[0].emit('flag', { data: 'first' });
  f.timers.tick(1500);
  f.streams[0].emit('flag', { data: 'second' });
  f.timers.tick(1999);
  assert.deepEqual(f.calls, ['full']);
  f.timers.tick(1);
  assert.deepEqual(f.calls, ['full', 'fast']);
  assert.deepEqual(flags, ['first', 'second']);
});

test('typed deltas reach their existing handlers unchanged', () => {
  const received = [];
  const kinds = ['event', 'flag', 'incident', 'session', 'posture', 'review'];
  const message = { data: 'fixture' };
  const handlers = Object.fromEntries(kinds.map(kind => [kind, msg => received.push([kind, msg])]));
  const f = fixture({ handlers });
  f.controller.start();
  for (const kind of kinds) f.streams[0].emit(kind, message);
  assert.deepEqual(received, kinds.map(kind => [kind, message]));
});

test('ending a session cancels all refreshes and ignores already queued callbacks', () => {
  let deltas = 0;
  const f = fixture({ handlers: { flag: () => deltas++, event: () => deltas++ } });
  f.controller.start();
  const stream = f.streams[0];
  stream.emit('flag');
  stream.emit('guard-prompt');
  stream.closed = true;
  stream.error();
  const queuedTimers = [...f.timers.pending.values()].map(timer => timer.fn);
  f.controller.stop();
  assert.equal(f.timers.pending.size, 0);
  // Timer callbacks and stream messages may already be queued at shutdown.
  for (const callback of queuedTimers) callback();
  stream.open();
  stream.error();
  stream.emit('event');
  stream.emit('flag');
  stream.emit('guard-resolved');
  f.timers.tick(30000);
  assert.deepEqual(f.calls, ['full']);
  assert.equal(deltas, 1);
  assert.equal(f.timers.pending.size, 0);
});
