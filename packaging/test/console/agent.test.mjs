// Console Agent tab tests — zero dependencies. Evaluates lib.js and
// tab-agent.js in one fresh VM context, as the browser loads them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const webDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist');
const ctx = { window: {} };
vm.createContext(ctx);
for (const f of ['lib.js', 'tab-agent.js']) {
  vm.runInContext(readFileSync(path.join(webDist, f), 'utf8'), ctx, { filename: f });
}
const { agentStateText, agentOffHTML, agentMessageHTML, agentThreadItems, agentPlanHTML, agentRunHTML, agentRunCommand,
  agentHarnessesHTML, agentSkillsHTML, agentHarnessOptionsHTML, agentDispatchMessage, agentEmptyThreadHTML, resolveConsoleRoute, routeKey } = ctx;

const XSS = '<img src=x onerror=alert(1)>';
const status = () => ({
  enabled: true, endpoint: 'http://127.0.0.1:11434', reachable: true, ollama_version: '0.15.1',
  model: 'qwen3:latest', harness_model: 'qwen3-coder', models: ['qwen3:latest', 'qwen3-coder:latest'],
  harnesses: [
    { id: 'claude', label: 'Claude Code', bin: 'claude', installed: true, ready: true },
    { id: 'codex', label: 'Codex', bin: 'codex', installed: false, ready: false, reason: 'Codex is not installed where the daemon can find it (codex)' },
    { id: 'openclaw', label: 'OpenClaw', bin: 'openclaw', installed: false, ready: false, reason: 'OpenClaw is not installed' },
    { id: 'hermes', label: 'Hermes Agent', bin: 'hermes', installed: true, ready: true },
  ],
  skills: [{ id: 'ssh', title: 'SSH keys and the SSH agent', summary: 'Create keys' }, { id: 'signing', title: 'Commit and tag signing', summary: 'Sign "commits"' }],
  chatting: false, terminal: true, home: '/Users/x',
});

test('the Agent tab is a console route', () => {
  assert.equal(routeKey(resolveConsoleRoute('agent')), 'agent');
  assert.equal(routeKey(resolveConsoleRoute('#agent')), 'agent');
  assert.equal(routeKey(resolveConsoleRoute('agents')), 'sessions/processes', 'the old agents id still means the process list');
});

test('agentStateText: loading, off, Ollama down, a reason, ready', () => {
  assert.equal(agentStateText(null), 'Loading…');
  assert.equal(agentStateText({ enabled: false }), 'Off');
  assert.equal(agentStateText({ enabled: true, reachable: false, endpoint: 'http://127.0.0.1:11434' }), 'Ollama is not answering at http://127.0.0.1:11434');
  assert.equal(agentStateText({ enabled: true, reachable: true, reason: 'model x is not pulled' }), 'model x is not pulled');
  assert.equal(agentStateText(status()), 'qwen3:latest on Ollama 0.15.1 · stays on this machine');
});

test('agentOffHTML: says how to turn it on and offers the snippet to copy', () => {
  const html = agentOffHTML();
  assert.match(html, /system_agent:\n  enabled: true/);
  assert.match(html, /data-action="agent-copy" data-text="system_agent:/);
  assert.match(html, /~\/\.config\/secure-agent\/config\.yaml/);
});

test('agentMessageHTML: every role escapes its text; the operator turn shows its route', () => {
  const user = agentMessageHTML({ id: 1, role: 'user', content: XSS, harness: 'codex', workdir: '/w/<b>' }, status());
  assert.ok(!user.includes('<img'), user);
  assert.match(user, /agent-msg user/);
  assert.match(user, /→ Codex · \/w\/&lt;b&gt;/);
  const note = agentMessageHTML({ id: 2, role: 'note', content: XSS }, status());
  assert.ok(!note.includes('<img') && note.includes('agent-msg note'));
  const reply = agentMessageHTML({ id: 3, role: 'assistant', content: XSS, skills: ['ssh', '"x'] }, status());
  assert.ok(!reply.includes('<img'));
  assert.match(reply, /data-action="agent-skill" data-skill="ssh"/);
  assert.match(reply, /data-skill="&quot;x"/);
});

test('agentMessageHTML: a proposal offers Save plan and a dispatch; once saved, the plan dispatch', () => {
  const proposal = { title: 'Sign ' + XSS, harness: 'claude', mode: 'terminal', workdir: '/repo', task: 'do ' + XSS, steps: ['one', XSS], skills: ['signing'] };
  const fresh = agentMessageHTML({ id: 7, role: 'assistant', content: 'ok', proposal }, status());
  assert.ok(!fresh.includes('<img'), fresh);
  assert.match(fresh, /data-action="agent-save-proposal" data-message="7"/);
  assert.match(fresh, /data-action="agent-dispatch-proposal" data-message="7" data-mode="terminal">Open in terminal/);
  assert.match(fresh, /<ol class="agent-steps"><li>one<\/li><li>&lt;img/);
  assert.match(fresh, /Claude Code · <code>\/repo<\/code>/);
  assert.ok(!fresh.includes('disabled'), fresh);
  const saved = agentMessageHTML({ id: 7, role: 'assistant', content: 'ok', proposal: { ...proposal, mode: 'headless' }, plan_id: 12 }, status());
  assert.match(saved, /Saved as plan #12/);
  assert.match(saved, /data-action="agent-dispatch" data-plan="12" data-mode="headless">Run headless/);
  assert.ok(!saved.includes('agent-save-proposal'));
});

test('agentMessageHTML: a proposal for a harness that cannot run keeps Save plan and disables the dispatch with the reason', () => {
  const html = agentMessageHTML({ id: 8, role: 'assistant', content: 'ok',
    proposal: { title: 't', harness: 'openclaw', mode: 'terminal', workdir: '/w', task: 'x', steps: [] } }, status());
  assert.match(html, /data-action="agent-save-proposal" data-message="8">Save plan/);
  assert.match(html, /data-action="agent-dispatch-proposal" data-message="8" data-mode="terminal" disabled title="OpenClaw is not installed">Open in terminal/);
  assert.match(html, /agent-plan-reason">OpenClaw is not installed</);
});

test('agentThreadItems: keyed by message id, a pending line while the model answers', () => {
  const chat = { messages: [{ id: 1, role: 'user', content: 'hi' }, { id: 2, role: 'assistant', content: 'yo' }], chatting: true };
  const items = agentThreadItems(chat, status());
  assert.deepEqual([...items.map(i => i.key)], ['m1', 'm2', 'pending']);
  assert.equal(agentThreadItems({ messages: [], chatting: false }, status()).length, 0);
  assert.match(agentEmptyThreadHTML(status()), /Never paste a secret/);
  assert.match(agentEmptyThreadHTML({ enabled: true, reason: 'Ollama is not answering <x>' }), /Ollama is not answering &lt;x&gt;/);
});

test('agentPlanHTML: a plan that cannot run says why and its dispatch buttons are disabled', () => {
  const plan = { id: 4, title: XSS, harness: 'codex', mode: 'terminal', workdir: '/w', task: 't', steps: ['a'], skills: [], status: 'saved', source: 'agent', ready: false, reason: 'Codex is not installed <here>' };
  const html = agentPlanHTML(plan, status());
  assert.ok(!html.includes('<img'));
  assert.match(html, /agent-plan-reason">Codex is not installed &lt;here&gt;/);
  assert.equal((html.match(/data-action="agent-dispatch"[^>]* disabled title="Codex is not installed &lt;here&gt;"/g) || []).length, 2);
  assert.match(html, /data-action="agent-plan-delete" data-plan="4">Delete/);
  const ready = agentPlanHTML({ ...plan, ready: true, reason: '' }, status());
  assert.ok(!ready.includes('disabled'), ready);
  assert.match(ready, /data-mode="headless">Run headless/);
  assert.match(ready, /data-mode="terminal">Open in terminal/);
  const running = agentPlanHTML({ ...plan, ready: true, status: 'running' }, status());
  assert.match(running, /data-action="agent-plan-delete" data-plan="4" disabled/);
  assert.match(running, /badge badge-amber">running/);
});

test('agentRunHTML: status, escaped output, the command, and a copyable command for a manual terminal run', () => {
  const now = Date.parse('2026-09-25T12:10:00Z');
  const run = { id: 9, plan_id: 4, ts: '2026-09-25T12:00:00Z', title: 'Sign', harness: 'codex', mode: 'headless', model: 'qwen3-coder', workdir: '/w',
    status: 'failed', exit_code: 2, command: "env 'A=b' codex exec <task>", output: XSS, detail: 'exit status 2' };
  const html = agentRunHTML(run, status(), now);
  assert.ok(!html.includes('<img'));
  assert.match(html, /badge badge-rose">failed/);
  assert.match(html, /10m ago/);
  assert.match(html, /exit 2/);
  assert.match(html, /env &#39;A=b&#39;|env 'A=b'/);
  const manual = { ...run, mode: 'terminal', status: 'manual', output: '', detail: "Run it in a terminal: sh '/Users/x/.config/secure-agent/sysagent/terminal-4-1.sh'" };
  assert.equal(agentRunCommand(manual), "sh '/Users/x/.config/secure-agent/sysagent/terminal-4-1.sh'");
  assert.match(agentRunHTML(manual, status(), now), /data-action="agent-copy" data-text="sh '\/Users\/x\/\.config\/secure-agent\/sysagent\/terminal-4-1\.sh'"/);
  assert.equal(agentRunCommand({ ...manual, status: 'opened' }), '');
});

test('agentHarnessesHTML and agentSkillsHTML: readiness, models, skills', () => {
  const html = agentHarnessesHTML(status());
  assert.match(html, /<b>Chat<\/b> qwen3:latest/);
  assert.match(html, /<b>Harness<\/b> qwen3-coder/);
  assert.equal((html.match(/badge badge-ok">ready/g) || []).length, 2);
  assert.match(html, /Codex is not installed where the daemon can find it/);
  const skills = agentSkillsHTML(status());
  assert.match(skills, /data-action="agent-skill" data-skill="ssh" title="Create keys"/);
  assert.match(skills, /title="Sign &quot;commits&quot;"/);
  assert.equal(agentSkillsHTML({}), '');
});

test('agentHarnessOptionsHTML: every harness, unavailable ones marked, the pick selected', () => {
  const html = agentHarnessOptionsHTML(status(), 'hermes');
  assert.equal((html.match(/<option /g) || []).length, 4);
  assert.match(html, /<option value="codex">Codex \(plan for later\)<\/option>/);
  assert.match(html, /<option value="hermes" selected>Hermes Agent<\/option>/);
});

test('agentDispatchMessage: names the harness, folder and local model; terminal says the operator approves', () => {
  const plan = { harness: 'claude', workdir: '/repo', model: '' };
  assert.match(agentDispatchMessage(plan, 'headless', status()), /^Run Claude Code headless in \/repo, on qwen3-coder from your local Ollama\?/);
  assert.match(agentDispatchMessage({ ...plan, model: 'glm' }, 'terminal', status()), /^Open Claude Code in a terminal in \/repo, on glm .*You approve each step there\.$/);
});
