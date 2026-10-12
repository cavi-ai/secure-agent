import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../../../daemon/internal/api/web_dist/staged-write.js', import.meta.url), 'utf8');

function build({ telemetry = {}, respond = () => ({ ok: true }) } = {}) {
  const ctx = vm.createContext({});
  vm.runInContext(source, ctx, { filename: 'staged-write.js' });
  const state = { t: telemetry, renders: [], tickets: [], requests: [] };
  const writes = ctx.createStagedWrite({
    telemetry: () => state.t,
    render: panels => state.renders.push([...panels]),
    beginAttentionWrite: () => {
      const ticket = { outcomes: [], current: true };
      const finish = success => ticket.outcomes.push(success);
      finish.isCurrent = () => ticket.current;
      state.tickets.push(ticket);
      return finish;
    },
    request: async (path, req) => { state.requests.push({ path, req }); return respond(path, req); }
  });
  return { writes, state };
}

test('stage applies the mutation and renders the panels', () => {
  const { writes, state } = build({ telemetry: { sources: ['a'] } });
  writes.stage(['sources'], ['sources'], () => { state.t.sources = ['a', 'b']; });
  assert.deepEqual(state.t.sources, ['a', 'b']);
  assert.deepEqual(state.renders, [['sources']]);
});

test('revert restores the staged keys and renders again', () => {
  const { writes, state } = build({ telemetry: { sources: ['a'], flags: [1] } });
  const revert = writes.stage(['sources', 'flags'], ['sources'], () => { state.t.sources = []; state.t.flags = []; });
  revert();
  assert.deepEqual(state.t.sources, ['a']);
  assert.deepEqual(state.t.flags, [1]);
  assert.equal(state.renders.length, 2);
});

test('revert keeps a key something else replaced after the stage', () => {
  const { writes, state } = build({ telemetry: { sources: ['a'], flags: [1] } });
  const revert = writes.stage(['sources', 'flags'], ['sources'], () => { state.t.sources = []; state.t.flags = []; });
  const fresh = [9];
  state.t.flags = fresh;
  revert();
  assert.deepEqual(state.t.sources, ['a']);
  assert.equal(state.t.flags, fresh);
});

test('a posture stage opens an attention ticket that commit, revert and isCurrent drive', () => {
  const { writes, state } = build({ telemetry: { posture: { v: 1 } } });
  const keep = writes.stage(['posture'], ['attention'], () => { state.t.posture = { v: 2 }; });
  assert.equal(state.tickets.length, 1);
  assert.equal(keep.isCurrent(), true);
  state.tickets[0].current = false;
  assert.equal(keep.isCurrent(), false);
  keep.commit();
  assert.deepEqual(state.tickets[0].outcomes, [true]);
  const drop = writes.stage(['posture'], ['attention'], () => { state.t.posture = { v: 3 }; });
  drop();
  assert.deepEqual(state.tickets[1].outcomes, [false]);
});

test('a stage without posture opens no ticket; commit does nothing and isCurrent is true', () => {
  const { writes, state } = build({ telemetry: { sources: [] } });
  const revert = writes.stage(['sources'], ['sources'], () => { state.t.sources = ['x']; });
  assert.equal(state.tickets.length, 0);
  assert.equal(revert.commit(), undefined);
  assert.equal(revert.isCurrent(), true);
});

function handlers(log) {
  return {
    ok: res => { log.push(['ok', res.tag]); },
    failed: res => { log.push(['failed', res.tag]); },
    error: err => { log.push(['error', err.message]); }
  };
}

test('write runs ok on success and returns true without reverting', async () => {
  const { writes } = build();
  const log = [];
  const revert = () => log.push('revert');
  assert.equal(await writes.write(revert, async () => ({ ok: true, tag: 'saved' }), handlers(log)), true);
  assert.deepEqual(log, [['ok', 'saved']]);
});

test('write reverts before failed on a non-ok response and returns false', async () => {
  const { writes } = build();
  const log = [];
  const revert = () => log.push('revert');
  assert.equal(await writes.write(revert, async () => ({ ok: false, tag: 'denied' }), handlers(log)), false);
  assert.deepEqual(log, ['revert', ['failed', 'denied']]);
});

test('write reverts before error when the request throws and returns false', async () => {
  const { writes } = build();
  const log = [];
  const revert = () => log.push('revert');
  assert.equal(await writes.write(revert, async () => { throw new Error('network down'); }, handlers(log)), false);
  assert.deepEqual(log, ['revert', ['error', 'network down']]);
});

test('write treats a throw inside ok as an error and reverts', async () => {
  const { writes } = build();
  const log = [];
  const revert = () => log.push('revert');
  const run = async () => ({ ok: true });
  const ok = () => { throw new Error('bad body'); };
  assert.equal(await writes.write(revert, run, { ...handlers(log), ok }), false);
  assert.deepEqual(log, ['revert', ['error', 'bad body']]);
});

test('send posts JSON and resolves with the response', async () => {
  const response = { ok: true, tag: 'sent' };
  const { writes, state } = build({ respond: () => response });
  assert.equal(await writes.send('POST', '/flags/acknowledge', { flag_id: 'f1' }), response);
  assert.equal(state.requests.length, 1);
  assert.equal(state.requests[0].path, '/flags/acknowledge');
  assert.equal(state.requests[0].req.method, 'POST');
  assert.equal(state.requests[0].req.headers['Content-Type'], 'application/json');
  assert.equal(state.requests[0].req.body, '{"flag_id":"f1"}');
});

test('send throws with the response body on a non-ok response', async () => {
  const { writes } = build({ respond: () => ({ ok: false, text: async () => 'write unavailable' }) });
  await assert.rejects(writes.send('POST', '/x', {}), { message: 'write unavailable' });
});
