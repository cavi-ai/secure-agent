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
