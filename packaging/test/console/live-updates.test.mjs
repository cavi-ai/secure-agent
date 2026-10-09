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
    static CLOSED = 2;
    readyState = 0;
    listeners = new Map();
    closes = 0;
    constructor(url) { this.url = url; streams.push(this); }
    addEventListener(kind, fn) { this.listeners.set(kind, fn); }
    emit(kind, message = {}) { this.listeners.get(kind)?.(message); }
    open() { this.readyState = 1; this.onopen(); }
    error() { this.onerror(); }
    close() { this.closes++; this.readyState = Stream.CLOSED; }
  }
  const context = vm.createContext({});
  vm.runInContext(source, context);
  const controller = context.createConsoleLiveUpdates({
    refresh: options => calls.push(options?.slow === false ? 'fast' : 'full'),
    streamURL: '/events/stream?ct=fixture',
    EventSourceImpl: streaming ? Stream : null,
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
  assert.equal(f.streams[0].url, '/events/stream?ct=fixture');
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

test('without a stream, polling refreshes every two seconds', () => {
  const f = fixture({ streaming: false });
  f.controller.start();
  f.timers.tick(4000);
  assert.deepEqual(f.calls, ['full', 'full', 'full']);
  assert.equal(f.streams.length, 0);
  f.controller.stop();
  f.timers.tick(30000);
  assert.equal(f.calls.length, 3);
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
  stream.readyState = 0;
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
  f.streams[0].readyState = f.Stream.CLOSED;
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
  const kinds = ['event', 'flag', 'incident', 'session', 'posture'];
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
  stream.readyState = f.Stream.CLOSED;
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
