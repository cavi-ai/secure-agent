import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const app = readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js', import.meta.url), 'utf8');
function source(begin, end) {
  const start = app.indexOf(begin);
  const finish = app.indexOf(end, start);
  assert.ok(start >= 0 && finish > start);
  return app.slice(start, finish);
}
function composer(fetch) {
  const paints = [];
  const ctx = {
    window: {}, agentInput: { value: 'Check Git signing' }, agentWorkdirInput: { value: '/repo' },
    agentState: { status: { enabled: true }, chat: { messages: [] }, runs: [], readVersion: {}, actionRequests: new Set() },
    agentFetch: fetch, renderNow: () => paints.push(true), followAgent: () => {},
    showToast: () => {}, loadAgent: async () => {},
  };
  vm.runInNewContext(source('  function agentBusy()', '  async function loadAgent(') +
    source('  window.sendAgentMessage = async function()', '  window.saveAgentRequest = async function()'), ctx);
  return { ctx, paints };
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
}

test('Enter provides feedback before delivery completes and repeated Enter sends once', async () => {
  const delivery = deferred();
  let calls = 0;
  const { ctx, paints } = composer(() => { calls++; return delivery.promise; });
  const first = ctx.window.sendAgentMessage();
  assert.ok(ctx.agentState.sending, 'sending state is set synchronously');
  assert.equal(paints.length, 1, 'UI paints before waiting for HTTP');
  await ctx.window.sendAgentMessage();
  assert.equal(calls, 1);
  delivery.resolve({ message: { id: 7, role: 'user', content: 'Check Git signing' } });
  await first;
  assert.equal(ctx.agentState.sending, false);
  assert.equal(ctx.agentState.chat.messages.length, 1);
});

test('accepted delivery preserves a new draft typed while the request was in flight', async () => {
  const delivery = deferred();
  const { ctx } = composer(() => delivery.promise);
  const sent = ctx.window.sendAgentMessage();
  ctx.agentInput.value = 'Now check SSH';
  delivery.resolve({ message: { id: 7, role: 'user', content: 'Check Git signing' } });
  await sent;
  assert.equal(ctx.agentInput.value, 'Now check SSH');
});

test('failed delivery retains the draft and leaves persistent feedback', async () => {
  const { ctx } = composer(async () => { throw new Error('connection lost'); });
  await ctx.window.sendAgentMessage();
  assert.equal(ctx.agentInput.value, 'Check Git signing');
  assert.match(ctx.agentState.sendError, /connection lost/);
  assert.equal(ctx.agentState.sending, false);
});

test('an older chat refresh cannot erase a newly accepted message', async () => {
  const oldRead = deferred();
  const { ctx } = composer((path, options) => options?.method === 'POST'
    ? Promise.resolve({ message: { id: 7, role: 'user', content: 'Check Git signing' } }) : oldRead.promise);
  ctx.markDirty = () => {};
  ctx.fillAgentHarnesses = () => {};
  vm.runInNewContext(source('  async function loadAgent(', '  function followAgent('), ctx);
  const refresh = ctx.loadAgent(['chat']);
  await ctx.window.sendAgentMessage();
  oldRead.resolve({ messages: [], chatting: false });
  await refresh;
  assert.equal(ctx.agentState.chat.messages[0].id, 7);
  assert.equal(ctx.agentState.chat.chatting, true);
});

test('repeated command clicks open one confirmation and cancellation executes nothing', async () => {
  const confirmation = deferred();
  const { ctx } = composer(() => { throw new Error('No command may run'); });
  let dialogs = 0;
  ctx.window.saConfirm = () => { dialogs++; return confirmation.promise; };
  ctx.agentState.chat.messages = [{ id: 3, local_command: { command: 'pwd', mode: 'headless', workdir: '/repo' } }];
  vm.runInNewContext(source('  window.runLocalAgentAction = async function(', '  window.analyzeAgentActivity = async function('), ctx);
  const first = ctx.window.runLocalAgentAction(3);
  await ctx.window.runLocalAgentAction(3);
  assert.equal(dialogs, 1);
  confirmation.resolve(false);
  await first;
  assert.equal(ctx.agentState.actionRequests.size, 0);
  assert.equal(ctx.agentState.chat.messages[0].local_run_id, undefined);
});

test('a confirmed command is linked immediately without moving the conversation to History', async () => {
  const { ctx } = composer(async () => ({ run: { id: 9, status: 'running' } }));
  ctx.window.saConfirm = async () => true;
  ctx.agentState.chat.messages = [{ id: 3, local_command: { command: 'pwd', mode: 'headless', workdir: '/repo' } }];
  vm.runInNewContext(source('  window.runLocalAgentAction = async function(', '  window.analyzeAgentActivity = async function('), ctx);
  await ctx.window.runLocalAgentAction(3);
  assert.equal(ctx.agentState.chat.messages[0].local_run_id, 9);
  assert.equal(ctx.agentState.runs[0].status, 'running');
});

const render = { window: {} };
vm.createContext(render);
for (const name of ['lib.js', 'tab-agent.js']) {
  vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + name, import.meta.url), 'utf8'), render);
}
test('sending and model wait states expose animated, accessible feedback without echoing unmasked input', () => {
  const items = render.agentThreadItems({ messages: [] }, {}, [], { sending: true });
  assert.match(items.at(-1).html, /Sending your message/);
  assert.match(items.at(-1).html, /agent-spinner/);
  assert.match(items.at(-1).html, /role="status"/);
  assert.match(render.agentThreadItems({ messages: [], chatting: true }, {}).at(-1).html, /agent-spinner/);
});
test('confirmed shell command status and escaped output appear beside the chat proposal', () => {
  const message = { id: 3, role: 'assistant', content: 'Check this', local_run_id: 9,
    local_command: { command: 'git config user.name', workdir: '/repo', mode: 'headless' } };
  const html = render.agentThreadItems({ messages: [message] }, {}, [{ id: 9, status: 'done', exit_code: 0, output: '<img src=x>' }])[0].html;
  assert.match(html, /Completed/);
  assert.match(html, /&lt;img src=x&gt;/);
  assert.match(html, /exit 0/);
  assert.ok(!html.includes('data-action="agent-run-local"'));
});

test('Terminal handoff and missing run history never claim execution has finished', () => {
  const message = { id: 3, role: 'assistant', content: '', local_run_id: 9,
    local_command: { command: 'ssh-keygen', workdir: '/repo', mode: 'terminal' } };
  const html = render.agentThreadItems({ messages: [message] }, {}, [{ id: 9, status: 'opened' }])[0].html;
  assert.match(html, /Opened in Terminal/);
  assert.ok(!html.includes('Completed'));
  const missing = render.agentThreadItems({ messages: [message] }, {}, [])[0].html;
  assert.match(missing, /Run recorded/);
  assert.ok(!missing.includes('agent-spinner'));
});
