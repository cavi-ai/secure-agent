// Playbook and advisor plan renderer — lib.js in a fresh VM context.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = {};
vm.runInNewContext(readFileSync(path.join(webDist, 'lib.js'), 'utf8'), ctx, { filename: 'lib.js' });
const { planHTML, planSlotHTML } = ctx;

const now = Date.parse('2026-09-23T20:00:00Z');
const playbook = {
  rule: 'secret-in-transcript', title: 'Secret in an agent transcript', why: 'A secret <appeared>.',
  now: ['Rotate the secret.'], prevent: [{ kind: 'guard-rule', step: 'Deny env', detail: 'Refuse env.' }], actions: ['open-incident', 'dismiss'],
};
const flag = {
  id: 'f1', agent: 'codex', rule: 'secret-in-transcript',
  explain: { actions: [
    { id: 'dismiss', label: 'Dismiss this flag', consequence: 'marks it reviewed', method: 'POST', path: '/flags/acknowledge', body: { flag_id: 'f1' } },
    { id: 'kill', label: 'Kill codex', consequence: 'ends the process', method: 'POST', path: '/kill', body: { pid: 7 } },
  ] },
};
const plan = {
  summary: 'An env dump <printed> the key.', why: ['env ran'], risk: 'high',
  prevent: [{ kind: 'agent-instruction', step: 'Tell codex', detail: 'never echo keys' }],
  behavior: ['Use variable names'], remediate: ['Rotate the key'], actions: ['kill', 'allow-path', 'dismiss'],
  confidence: 0.8, model: 'qwen3.8:27b-mlx', created_at: '2026-09-23T19:58:00Z',
};

test('playbook alone, with the ask button enabled when the advisor is ready', () => {
  const html = planHTML({ subject: 'file:/w/a"b', status: 'none', playbook, advisor_ready: true }, now);
  assert.ok(html.includes('A secret &lt;appeared&gt;.'));
  assert.ok(html.includes('<span class="plan-kind">Guard rule</span> <strong>Deny env</strong>. Refuse env.'));
  assert.ok(html.includes('data-action="ask-plan" data-subject="file:/w/a&quot;b">Ask the advisor for a plan'));
  assert.ok(!html.includes(' disabled>'));
});

test('advisor plan renders escaped, with offered actions as buttons only', () => {
  const html = planHTML({ subject: 'flag:f1', status: 'ready', playbook, plan, flag, advisor_ready: true }, now);
  assert.ok(html.includes('plan-risk-high') && html.includes('An env dump &lt;printed&gt; the key.'));
  assert.ok(html.includes('data-action="explain-act" data-flag-id="f1" data-action-id="kill"'));
  assert.ok(html.includes('data-action-id="dismiss"'));
  assert.ok(!html.includes('data-action-id="allow-path"'), 'allow-path is not offered on this flag');
  assert.ok(html.includes('Local advisor · qwen3.8:27b-mlx · 2m ago'));
  assert.ok(html.includes('<details class="plan-playbook"><summary>Playbook: Secret in an agent transcript</summary>'));
  assert.ok(html.includes('Ask the advisor again'));
});

test('status lines: pending disables asking; stale and disabled explain themselves', () => {
  const pending = planHTML({ subject: 'flag:f1', status: 'pending', playbook, advisor_ready: true }, now);
  assert.ok(pending.includes('writing a plan') && pending.includes(' disabled>'));
  const stale = planHTML({ subject: 'flag:f1', status: 'stale', playbook, plan, flag, advisor_ready: true }, now);
  assert.ok(stale.includes('Written before newer evidence'));
  const off = planHTML({ subject: 'flag:f1', status: 'disabled', playbook, advisor_ready: false, reason: 'the local advisor is off <x>' }, now);
  assert.ok(off.includes('the local advisor is off &lt;x&gt;') && off.includes(' disabled>'));
});

test('planSlotHTML escapes the subject', () => {
  assert.ok(planSlotHTML('file:/w/"x"').includes('data-plan-subject="file:/w/&quot;x&quot;"'));
});

const { labelsLineHTML, markButtonsHTML, labelsHTML } = ctx;

test('labels line counts routine and not-ok judgments, empty when none', () => {
  assert.equal(labelsLineHTML({ ok: 0, not_ok: 0 }), '');
  assert.equal(labelsLineHTML(null), '');
  assert.ok(labelsLineHTML({ ok: 3, not_ok: 1 }).includes('You marked similar cases 3 as routine and 1 as not ok.'));
});

test('mark buttons carry the subject, escaped', () => {
  const html = markButtonsHTML('file:/w/"x"');
  assert.ok(html.includes('data-action="mark-label" data-subject="file:/w/&quot;x&quot;" data-label="ok"'));
  assert.ok(html.includes('data-label="not_ok"'));
});

test('history: similar judgments escaped, suggestion button only when offered', () => {
  const labels = {
    summary: { ok: 3, not_ok: 0 },
    similar: [{ label: 'ok', source: 'mark', pattern: '/w/.npmrc', reason: 'npm <routine>', created_at: '2026-09-23T18:00:00Z' }],
    suggestion: { label: 'ok', text: 'You marked this 3 times as routine for codex.', action_id: 'dismiss' },
  };
  const html = labelsHTML({ subject: 'flag:f1', labels, flag }, now);
  assert.ok(html.includes('npm &lt;routine&gt;') && html.includes('Routine · mark · 2h ago · /w/.npmrc'));
  assert.ok(html.includes('You marked this 3 times as routine for codex.'));
  assert.ok(html.includes('data-action="explain-act" data-flag-id="f1" data-action-id="dismiss"'));
  const notOffered = labelsHTML({ subject: 'flag:f1', labels: { ...labels, suggestion: { ...labels.suggestion, action_id: 'allow-path' } }, flag }, now);
  assert.ok(!notOffered.includes('data-action-id="allow-path"'));
  const empty = labelsHTML({ subject: 'flag:f1', labels: { summary: { ok: 0, not_ok: 0 }, similar: [] } }, now);
  assert.ok(empty.includes('No earlier judgments on cases like this.') && empty.includes('data-action="mark-label"'));
});
