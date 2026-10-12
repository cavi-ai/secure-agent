import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const ctx = vm.createContext({});
for (const file of ['lib.js', 'tab-agent.js']) {
  vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + file, import.meta.url), 'utf8'), ctx);
}
const message = (id, extra = {}) => ({ id, role: 'assistant', content: 'Reply', ...extra });

test('arrival tracking waits for actual chat history and never animates the initial baseline', () => {
  const loading = ctx.agentMessageArrivals(null, null);
  assert.equal(loading.seen, null);
  assert.equal(loading.arrived.size, 0);
  const first = ctx.agentMessageArrivals({ messages: [message(1)] }, loading.seen);
  assert.deepEqual([...first.seen], ['m1']);
  assert.equal(first.arrived.size, 0);
});

test('only new acknowledged IDs arrive; polling, content changes and restored history do not replay', () => {
  const initial = ctx.agentMessageArrivals({ messages: [message(1)] }, null);
  const delivered = ctx.agentMessageArrivals({ messages: [message(1), message(2, { role: 'user' })] }, initial.seen);
  assert.deepEqual([...delivered.arrived], ['m2']);
  const reply = ctx.agentMessageArrivals({ messages: [message(1), message(2), message(3), message(4, { origin: 'analysis' })] }, delivered.seen);
  assert.deepEqual([...reply.arrived], ['m3']);
  const changed = ctx.agentMessageArrivals({ messages: [message(3, { content: 'Updated command status' })] }, reply.seen);
  assert.equal(changed.arrived.size, 0);
  const restored = ctx.agentMessageArrivals({ messages: [message(1), message(2), message(3)] }, changed.seen);
  assert.equal(restored.arrived.size, 0);
});

test('unread chat counts accepted visible arrivals only while reading earlier messages', () => {
  const items = keys => keys.map(key => ({key}));
  const first = ctx.agentMessageArrivals({messages: [message(1)]}, null);
  let unread = ctx.agentUnreadMessageKeys(items(['m1']), first.arrived, new Set(), false);
  assert.equal(unread.size, 0, 'initial history is a baseline');
  const next = ctx.agentMessageArrivals({messages: [message(1), message(2), message(3, {origin: 'analysis'})]}, first.seen);
  unread = ctx.agentUnreadMessageKeys(items(['m1', 'm2', 'pending']), next.arrived, unread, false);
  assert.deepEqual([...unread], ['m2']);
  const poll = ctx.agentMessageArrivals({messages: [message(1, {content: 'Edited'}), message(2)]}, next.seen);
  unread = ctx.agentUnreadMessageKeys(items(['m1', 'm2', 'pending']), poll.arrived, unread, false);
  assert.deepEqual([...unread], ['m2'], 'content and pending updates do not increase the count');
  const more = ctx.agentMessageArrivals({messages: [message(1), message(2), message(4, {role: 'user'})]}, poll.seen);
  unread = ctx.agentUnreadMessageKeys(items(['m1', 'm2', 'm4']), more.arrived, unread, false);
  assert.deepEqual([...unread], ['m2', 'm4']);
  assert.deepEqual([...ctx.agentUnreadMessageKeys(items(['m1', 'm4']), new Set(), unread, false)], ['m4'], 'removed messages no longer count');
  assert.equal(ctx.agentUnreadMessageKeys(items(['m1', 'm4']), new Set(), unread, true).size, 0);
  assert.equal(ctx.agentUnreadMessageKeys([], new Set(), unread, false).size, 0);
});

function readingController() {
  const app = readFileSync(new URL('../../../daemon/internal/api/web_dist/app.js', import.meta.url), 'utf8');
  const calls = [];
  let visible = true, top = 200, rowTop = 0, hidden = false;
  const thread = {children: [{_saKey: 'm1', getBoundingClientRect: () => ({top: rowTop - top, bottom: rowTop - top + 500})}],
    scrollHeight: 1400, clientHeight: 400, getClientRects: () => visible ? [{}] : [],
    getBoundingClientRect: () => ({top: 0}), addEventListener(_event, handler, options) {assert.equal(options.passive, true); thread.onScroll = handler;}};
  Object.defineProperty(thread, 'scrollTop', {get: () => top, set(value) {top = Math.min(1000, value); calls.push('scroll');}});
  const button = {textContent: ''};
  Object.defineProperty(button, 'hidden', {get: () => hidden, set(value) {hidden = value; calls.push('visibility');}});
  const input = {value: 'Retained draft', isConnected: true, disabled: false, getClientRects: () => [{}],
    focus(options) {assert.equal(options.preventScroll, true); assert.equal(hidden, false); calls.push('focus');}};
  const state = {status: {enabled: true}, chat: {messages: [message(1), message(2)]}, unreadMessageKeys: new Set(['m2']), reading: null, restoreReading: false};
  const context = vm.createContext({agentState: state, document: {getElementById: id => ({'agent-thread': thread, 'agent-jump-latest': button, 'agent-input': input})[id]}});
  const start = app.indexOf('  function captureAgentThreadReading(');
  assert.ok(start > 0);
  vm.runInContext(app.slice(start, app.indexOf('  function openAgentDock(', start)), context);
  return {context, state, thread, button, input, calls, setVisible: value => {visible = value;}, shiftRow: value => {rowTop = value;}};
}

test('Jump to latest preserves the draft and focuses the composer before hiding the control', () => {
  const c = readingController();
  c.context.jumpToLatestAgentMessage();
  assert.ok(c.calls.indexOf('focus') < c.calls.indexOf('visibility'));
  assert.equal(c.input.value, 'Retained draft'); assert.equal(c.thread.scrollTop, 1000);
  assert.equal(c.state.unreadMessageKeys.size, 0); assert.equal(c.button.hidden, true);
  assert.equal(c.state.reading.follow, true);
});

test('reading snapshot retains the visible message anchor through reflow and hidden moves', () => {
  const c = readingController();
  const reading = c.context.captureAgentThreadReading();
  assert.equal(reading.anchor, 'm1'); assert.equal(reading.follow, false);
  c.state.reading = reading; c.state.restoreReading = true;
  c.setVisible(false); c.thread.onScroll();
  c.context.restoreAgentThreadReading(reading);
  assert.equal(c.state.reading, reading); assert.equal(c.state.restoreReading, true);
  assert.equal(c.state.unreadMessageKeys.size, 1, 'hidden geometry must not acknowledge unread messages');
  c.setVisible(true); c.shiftRow(75); c.context.restoreAgentThreadReading(reading);
  assert.equal(c.thread.scrollTop, 275, 'anchor retains its prior viewport offset');
  assert.equal(c.state.restoreReading, false);
});

test('manual bottom scroll clears unread state while empty or disabled chat hides the control', () => {
  const c = readingController();
  c.thread.onScroll();
  assert.equal(c.button.textContent, '1 new message · Jump to latest'); assert.equal(c.button.hidden, false);
  c.thread.scrollTop = 1000; c.thread.onScroll();
  assert.equal(c.button.hidden, true); assert.equal(c.state.unreadMessageKeys.size, 0);
  for (const disabled of [false, true]) {
    c.state.unreadMessageKeys.add('m2');
    c.state.chat.messages = disabled ? [message(1)] : [];
    c.state.status.enabled = !disabled;
    c.context.updateAgentJumpLatest({follow: false});
    assert.equal(c.button.hidden, true); assert.equal(c.state.unreadMessageKeys.size, 0);
  }
});

test('pending motion shell stays identical as truthful work labels and timing change', () => {
  const pending = chat => ctx.agentThreadItems(chat, {}, [], {}).at(-1);
  const sending = ctx.agentThreadItems({ messages: [] }, {}, [], { sending: true }).at(-1);
  const preparing = pending({ messages: [], chatting: true, work: { state: 'preparing' } });
  const waiting = pending({ messages: [], chatting: true, work: { elapsed_ms: 2500 } });
  const inspecting = pending({ messages: [], chatting: true, work: { state: 'inspecting', active_tool: 'inspect_snapshot', elapsed_ms: 5500, tool_calls: 2 } });
  for (const item of [preparing, waiting, inspecting]) assert.equal(item.html, sending.html);
  assert.match(sending.label, /Sending your message/);
  assert.match(preparing.label, /Preparing skills and snapshot/);
  assert.match(waiting.label, /Waiting for local Ollama.*2s/);
  assert.match(inspecting.label, /Inspecting findings snapshot.*5s.*2 read calls/);
  assert.match(sending.html, /agent-working-dots.*aria-hidden="true"/);
  assert.match(sending.html, /role="status" aria-live="polite"/);
  assert.equal(ctx.agentThreadItems({ messages: [], chatting: false }, {}).length, 0);
});
