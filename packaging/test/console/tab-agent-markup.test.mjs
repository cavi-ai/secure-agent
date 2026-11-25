import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact tab-agent.js markup for hostile served values: each value renders
// escaped once in text and attribute positions, and nested fragments render as markup.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const NOW = Date.parse('2026-01-01T02:00:00Z');

const assets = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const ctx = { window: {} };
vm.createContext(ctx);
for (const f of ['lib.js', 'tab-agent.js']) vm.runInContext(readFileSync(new URL(f, assets), 'utf8'), ctx, { filename: f });

const status = { enabled: true, reachable: true, model: H, harness_model: H, ollama_version: H, endpoint: H,
  harnesses: [{ id: 'claude', label: H, ready: false, reason: H }, { id: 'codex', label: 'Codex', ready: true }, { id: 'unlabeled', ready: true }],
  skills: [{ id: H, summary: H, title: H }] };

const cases = {
  'chat off': () => ctx.agentOffHTML(),
  'note turn': () => ctx.agentMessageHTML({ role: 'note', content: H }, status),
  'user turn': () => ctx.agentMessageHTML({ role: 'user', content: H, harness: 'claude', workdir: H }, status),
  'worktree turn': () => ctx.agentMessageHTML({ role: 'user', origin: 'worktree', content: `${H}?\nbranch: ${H}\n${H}` }, status),
  'assistant turn with a run and a saved plan': () => ctx.agentMessageHTML({ role: 'assistant', id: 7, content: `${H}\n\n**${H}**`, skills: [H, 'b'],
    usage: { model: H, prompt_tokens: 10, completion_tokens: 5, prompt_tokens_per_second: 2.5, output_tokens_per_second: 3, elapsed_ms: 1500, read_tool_calls: 2 },
    local_command: { mode: 'terminal', workdir: H, command: H }, local_run_id: 9, plan_id: 3,
    proposal: { harness: 'claude', mode: 'headless', title: H, workdir: H, task: H, steps: [H, 'two'] } }, status,
    [{ id: 9, status: 'done', exit_code: 0, detail: H, output: H }]),
  'assistant turn awaiting review': () => ctx.agentMessageHTML({ role: 'assistant', id: 8, content: H, usage: { tool_calls: 2 },
    local_command: { mode: 'headless', workdir: H, command: H },
    proposal: { harness: 'codex', mode: H, title: H, workdir: H, task: H } }, status, [], { actionRequests: new Set([8]) }),
  'pending turn': () => Array.from(ctx.agentThreadItems({ messages: [], chatting: true }, status, [], { sending: true }), item => item.html),
  'recommendations': () => [
    ctx.agentRecommendationHTML({ id: 4, ts: H, content: H, flag_ids: [H, 'flag-2'], local_command: { mode: H, command: H, workdir: H } }, status),
    ctx.agentRecommendationHTML({ id: 5, ts: H, content: H, review_state: 'saved', local_run_id: 6, plan_id: 7 }, status),
  ],
  'empty thread': () => [ctx.agentEmptyThreadHTML({ enabled: true }), ctx.agentEmptyThreadHTML({ enabled: true, reason: H }), ctx.agentEmptyThreadHTML(null)],
  'plans': () => [
    ctx.agentPlanHTML({ id: 1, harness: 'pi', title: H, status: 'saved', mode: H, workdir: H, model: H, steps: [H, H], source: H, task: H, ready: true }, status),
    ctx.agentPlanHTML({ id: 2, harness: 'claude', title: H, status: H, mode: H, workdir: H, source: H, task: H, ready: false, reason: H }, status),
    ctx.agentPlanHTML({ id: 3, harness: 'codex', title: H, status: 'running', mode: H, workdir: H, source: H, task: H, ready: true }, status),
  ],
  'runs': () => [
    ctx.agentRunHTML({ id: 1, harness: 'claude', plan_id: 2, title: H, status: 'manual', ts: '2026-01-01T00:00:00Z', mode: H, model: H, workdir: H, command: H, detail: `${H} sh 'run.sh'` }, status, NOW),
    ctx.agentRunHTML({ id: 3, harness: 'local', title: H, status: 'failed', exit_code: 2, ts: H, mode: H, model: H, workdir: H, command: H, output: H }, status, NOW),
    ctx.agentRunHTML({ id: 4, harness: 'unlabeled', plan_id: 5, title: H, status: 'done', ts: H, mode: H, model: H, workdir: H, command: H }, status, NOW),
  ],
  'harnesses': () => [ctx.agentHarnessesHTML(status), ctx.agentHarnessesHTML({ enabled: false, harnesses: [] }), ctx.agentHarnessesHTML(null)],
  'skills': () => [ctx.agentSkillsHTML(status), ctx.agentSkillsHTML({})],
  'harness options': () => ctx.agentHarnessOptionsHTML(status, 'codex'),
  'memory': () => [
    ctx.agentMemoryHTML({ facts: [{ summary: H, at: H, references: [H, null, 'r'] }],
      sessions: [{ id: 3, closed_at: H, scope: H, summary: [H, H] }, { id: 4, closed_at: 'c', summary: [] }, { id: 5 }] }),
    ctx.agentMemoryHTML({}),
    ctx.agentMemoryHTML(null),
  ],
};

const spinner = '<svg class="agent-spinner" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="7"/></svg>';
const logoChip = (key, title) => `<span class="harness-chip" title="${title}"><span class="harness-tile hk-${key}" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-${key}"/></svg></span></span>`;
const claudeChip = logoChip('claude', 'Claude Code');
const codexChip = logoChip('codex', 'Codex');
const markdown = body => `<div class="agent-bubble agent-bubble-markdown"><div class="markdown-view">${body}</div></div>`;
const copy = text => `<button type="button" class="btn btn-ghost btn-sm" data-action="agent-copy" data-text="${text}"><svg class="icon"><use href="#i-copy"/></svg><span>Copy</span></button>`;
const command = `<details class="agent-task"><summary>Command</summary><pre>${E}</pre>\n      ${copy(E)}</details>\n  </div>`;
const options = selected => `<option value="claude">${E} (plan for later)</option><option value="codex"${selected}>Codex</option><option value="unlabeled"></option>`;
const welcome = (title, text) => `<div class="agent-welcome"><svg class="icon"><use href="#i-chat"/></svg>\n    <h3>${title}</h3>\n    <p>${text}</p>\n    <span>Private chat on this machine. Never paste a secret.</span></div>`;
const dispatch = (plan, mode, attrs, label) => `<button type="button" class="btn btn-ghost btn-sm" data-action="agent-dispatch" data-plan="${plan}" data-mode="${mode}"${attrs}>${label}</button>`;
const memoryHead = n => `<p class="agent-history-empty">Recorded facts for this project. Historical checks must be repeated before removal. Showing ${n} of ${n} matching facts.</p>`;

const expected = {
  'chat off': `<div class="agent-off">\n    <h3>Secure Agent chat is off</h3>\n    <p>Chat directly with your local Ollama agent. It can propose an exact local command for your review; nothing runs until you confirm it. Harness handoff is a separate, optional section.</p>\n    <p>Open the Secure Agent menu bar app, then Settings → Secure Agent → Chat and turn on Enable chat. Return here to start a conversation.</p>\n    <p>For a headless install, add this to <code>~/.config/secure-agent/config.yaml</code>; the daemon applies it within seconds:</p>\n    <pre class="agent-snippet">system_agent:\n  enabled: true</pre>\n    <div>${copy('system_agent:\n  enabled: true')}</div>\n  </div>`,
  'note turn': `<div class="agent-msg note"><span>${E}</span></div>`,
  'user turn': `<div class="agent-msg user"><div class="agent-bubble">${E}</div><div class="agent-msg-meta">legacy harness selection (chat stayed on Ollama) · ${E}</div></div>`,
  'worktree turn': `<div class="agent-msg user"><div class="agent-proposal agent-worktree-card">\n    <div class="agent-proposal-head"><svg class="icon"><use href="#i-branch"/></svg><b>${E}?</b></div>\n    <div class="agent-msg-meta">branch ${E}</div>\n    <details class="agent-task"><summary>Facts sent</summary><pre>${E}?\nbranch: ${E}\n${E}</pre></details>\n  </div></div>`,
  'assistant turn with a run and a saved plan': `<div class="agent-msg assistant">${markdown(`<p>${E}</p><p><strong>${E}</strong></p>`)}`
    + `<div class="agent-msg-meta">${E} · 10 input tokens · 5 output tokens · 2.5 input tokens/s · 3.0 output tokens/s · 1.5s reply · 2 read tool calls</div>`
    + `<div class="agent-msg-meta">skills: <button type="button" class="link-btn" data-action="agent-skill" data-skill="${E}">${E}</button>, <button type="button" class="link-btn" data-action="agent-skill" data-skill="b">b</button></div>`
    + `<div class="agent-proposal agent-local-action" data-local-run="9">\n    <div class="agent-proposal-head"><svg class="icon"><use href="#i-terminal"/></svg><b>Shell command · Terminal</b><span class="badge badge-ok">Completed · exit 0</span></div>\n    <div class="agent-plan-meta">${E} · runs on this machine</div>\n    <pre class="agent-run-output">${E}</pre>\n    <div class="agent-run-detail">${E}</div>\n    <details class="agent-task agent-inline-output" open><summary>Output</summary><pre class="agent-run-output">${E}</pre></details>\n    <div class="agent-actions"><span class="agent-saved">Started as run #9</span></div>\n  </div>`
    + `<div class="agent-proposal">\n    <div class="agent-proposal-head">${claudeChip}<b>${E}</b><span class="badge">Headless</span></div>\n    <div class="agent-plan-meta">${E} · <code>${E}</code></div>\n    <div class="agent-plan-reason">${E}</div>\n    <ol class="agent-steps"><li>${E}</li><li>two</li></ol>\n    <details class="agent-task"><summary>Task the harness receives</summary><pre>${E}</pre></details>\n    <div class="agent-actions"><span class="agent-saved">Saved as plan #3</span>\n      <button type="button" class="btn btn-primary btn-sm" data-action="agent-dispatch" data-plan="3" data-mode="headless" disabled title="${E}">Run headless</button></div>\n  </div></div>`,
  'assistant turn awaiting review': `<div class="agent-msg assistant">${markdown(`<p>${E}</p>`)}<div class="agent-msg-meta">2 tool requests (not executed)</div>`
    + `<div class="agent-proposal agent-local-action">\n    <div class="agent-proposal-head"><svg class="icon"><use href="#i-terminal"/></svg><b>Shell command · Headless</b><span class="badge ">${spinner}Confirming command</span></div>\n    <div class="agent-plan-meta">${E} · runs on this machine</div>\n    <pre class="agent-run-output">${E}</pre>\n    \n    \n    <div class="agent-actions"><button type="button" class="btn btn-primary btn-sm" data-action="agent-run-local" data-message="8" disabled>Review and run</button><span class="agent-approval-note">Nothing runs until you confirm.</span></div>\n  </div>`
    + `<div class="agent-proposal">\n    <div class="agent-proposal-head">${codexChip}<b>${E}</b><span class="badge">Terminal</span></div>\n    <div class="agent-plan-meta">Codex · <code>${E}</code></div>\n    \n    \n    <details class="agent-task"><summary>Task the harness receives</summary><pre>${E}</pre></details>\n    <div class="agent-actions"><button type="button" class="btn btn-ghost btn-sm" data-action="agent-save-proposal" data-message="8">Save plan</button>\n      <button type="button" class="btn btn-primary btn-sm" data-action="agent-dispatch-proposal" data-message="8" data-mode="${E}">Open in terminal</button></div>\n  </div></div>`,
  'pending turn': [`<div class="agent-msg agent-pending" role="status" aria-live="polite">${spinner}<span class="agent-pending-label"></span><span class="agent-working-dots" aria-hidden="true"><span class="agent-activity-dot"></span><span class="agent-activity-dot"></span><span class="agent-activity-dot"></span></span></div>`],
  'recommendations': [
    `<article class="agent-recommendation" data-message="4">\n    <div class="agent-plan-head"><b>Activity analysis</b><span class="badge ">pending</span></div>\n    <div class="agent-plan-meta">Invalid Date · Flags: <button type="button" class="link-btn" data-action="open-flag" data-id="${E}">&lt;img src=x o</button>, <button type="button" class="link-btn" data-action="open-flag" data-id="flag-2">flag-2</button></div>\n    ${markdown(`<p>${E}</p>`)}\n    <div class="agent-proposal agent-local-action"><b>Proposed local command · ${E}</b><pre class="agent-run-output">${E}</pre><div class="agent-plan-meta">${E}</div></div>\n    <div class="agent-actions">\n      <button type="button" class="btn btn-primary btn-sm" data-action="agent-run-local" data-message="4">Review and run locally</button>\n      \n      \n      <label>Save for later delegation <select class="select select-sm agent-recommendation-harness">${options('')}</select></label>\n        <input class="input agent-workdir agent-recommendation-workdir" type="text" aria-label="Folder for a future harness plan" placeholder="Folder (default: home)">\n        <button type="button" class="btn btn-ghost btn-sm" data-action="agent-save-recommendation" data-message="4">Save plan</button>\n        <button type="button" class="btn btn-ghost btn-sm" data-action="agent-dismiss-recommendation" data-message="4">Dismiss</button>\n    </div>\n  </article>`,
    `<article class="agent-recommendation" data-message="5">\n    <div class="agent-plan-head"><b>Activity analysis</b><span class="badge badge-ok">saved</span></div>\n    <div class="agent-plan-meta">Invalid Date</div>\n    ${markdown(`<p>${E}</p>`)}\n    <p class="agent-plan-reason">No executable command proposed. Review the suggested steps or save them for later delegation.</p>\n    <div class="agent-actions">\n      \n      <span class="agent-saved">Started as run #6</span>\n      <span class="agent-saved">Saved as plan #7</span>\n      \n    </div>\n  </article>`,
  ],
  'empty thread': [
    welcome('What would you like to take care of?', 'Ask about your machine, check your setup, or choose a quick command below.'),
    welcome('Your local agent', E),
    welcome('Your local agent', 'Connecting to local Ollama…'),
  ],
  'plans': [
    `<div class="agent-plan" data-plan="1">\n    <div class="agent-plan-head"><span class="harness-chip" title="Pi"><span class="harness-glyph hk-pi" aria-hidden="true">π</span></span><b>${E}</b>\n      <span class="badge ">saved</span></div>\n    <div class="agent-plan-meta">#1 · Pi · ${E} · <code>${E}</code> · ${E} · 2 steps · ${E}</div>\n    \n    <details class="agent-task"><summary>Task</summary><pre>${E}</pre></details>\n    <div class="agent-actions">\n      ${dispatch(1, 'headless', ' disabled title="Pi has no built-in sandbox; use Terminal"', 'Run headless')}\n      ${dispatch(1, 'terminal', '', 'Open in terminal')}\n      <button type="button" class="btn btn-ghost btn-sm" data-action="agent-plan-delete" data-plan="1">Delete</button>\n    </div>\n  </div>`,
    `<div class="agent-plan" data-plan="2">\n    <div class="agent-plan-head">${claudeChip}<b>${E}</b>\n      <span class="badge ">${E}</span></div>\n    <div class="agent-plan-meta">#2 · ${E} · ${E} · <code>${E}</code> · ${E}</div>\n    <div class="agent-plan-reason">${E}</div>\n    <details class="agent-task"><summary>Task</summary><pre>${E}</pre></details>\n    <div class="agent-actions">\n      ${dispatch(2, 'headless', ` disabled title="${E}"`, 'Run headless')}\n      ${dispatch(2, 'terminal', ` disabled title="${E}"`, 'Open in terminal')}\n      <button type="button" class="btn btn-ghost btn-sm" data-action="agent-plan-delete" data-plan="2">Delete</button>\n    </div>\n  </div>`,
    `<div class="agent-plan" data-plan="3">\n    <div class="agent-plan-head">${codexChip}<b>${E}</b>\n      <span class="badge badge-amber">running</span></div>\n    <div class="agent-plan-meta">#3 · Codex · ${E} · <code>${E}</code> · ${E}</div>\n    \n    <details class="agent-task"><summary>Task</summary><pre>${E}</pre></details>\n    <div class="agent-actions">\n      ${dispatch(3, 'headless', ' disabled title="This plan is running"', 'Run headless')}\n      ${dispatch(3, 'terminal', ' disabled title="This plan is running"', 'Open in terminal')}\n      <button type="button" class="btn btn-ghost btn-sm" data-action="agent-plan-delete" data-plan="3" disabled>Delete</button>\n    </div>\n  </div>`,
  ],
  'runs': [
    `<div class="agent-run" data-run="1">\n    <div class="agent-plan-head">${claudeChip}<b>${E}</b>\n      <span class="badge badge-amber">manual</span><span class="agent-age">2h ago</span></div>\n    <div class="agent-plan-meta">plan #2 · ${E} · ${E} · ${E} · <code>${E}</code></div>\n    <div class="agent-run-detail">${E} sh &#39;run.sh&#39; ${copy('sh &#39;run.sh&#39;')}</div>\n    \n    ${command}`,
    `<div class="agent-run" data-run="3">\n    <div class="agent-plan-head"><span class="harness-chip" title="local"><span class="harness-glyph" data-harness-color="hsl(64 62% 62%)" aria-hidden="true">L</span></span><b>${E}</b>\n      <span class="badge badge-rose">failed</span></div>\n    <div class="agent-plan-meta">Direct Ollama action · ${E} · ${E} · <code>${E}</code> · exit 2</div>\n    \n    <details class="agent-task"><summary>Output</summary><pre class="agent-run-output">${E}</pre></details>\n    ${command}`,
    `<div class="agent-run" data-run="4">\n    <div class="agent-plan-head"><span class="harness-chip" title="unlabeled"><span class="harness-glyph" data-harness-color="hsl(73 62% 62%)" aria-hidden="true">U</span></span><b>${E}</b>\n      <span class="badge badge-ok">done</span></div>\n    <div class="agent-plan-meta">plan #5 ·  · ${E} · ${E} · <code>${E}</code></div>\n    \n    \n    ${command}`,
  ],
  'harnesses': [
    `<div class="agent-models">\n        <span><b>Chat</b> ${E}</span>\n        <span><b>Harness</b> ${E}</span>\n        <span><b>Ollama</b> ${E} · <code>${E}</code></span>\n      </div>`
      + '<div class="agent-harness">\n      <span class="harness-chip" title="Claude Code"><span class="harness-tile hk-claude" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-claude"/></svg></span><span class="harness-label">Claude Code</span></span>\n'
      + `      <span class="agent-harness-reason">${E}</span>\n    </div>`
      + '<div class="agent-harness">\n      <span class="harness-chip" title="Codex"><span class="harness-tile hk-codex" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-codex"/></svg></span><span class="harness-label">Codex</span></span>\n      <span class="badge badge-ok">ready</span>\n    </div>'
      + '<div class="agent-harness">\n      <span class="harness-chip" title="unlabeled"><span class="harness-glyph" data-harness-color="hsl(73 62% 62%)" aria-hidden="true">U</span><span class="harness-label">unlabeled</span></span>\n      <span class="badge badge-ok">ready</span>\n    </div>',
    '',
    '<div class="loading">Loading…</div>',
  ],
  'skills': [`<div class="agent-skills"><button type="button" class="agent-skill" data-action="agent-skill" data-skill="${E}" title="${E}"><b>${E}</b><span>${E}</span></button></div>`, ''],
  'harness options': options(' selected'),
  'memory': [
    `${memoryHead(1)}<article class="agent-memory-item"><p>${E}</p><small>${E} · ${E} ·  · r</small></article><h4>Recent closed sessions</h4>`
      + `<article class="agent-memory-item"><strong>Session 3</strong><small>${E} · ${E}</small><p>${E}<br>${E}</p></article>`
      + '<article class="agent-memory-item"><strong>Session 4</strong><small> · c</small><p>No recorded outcomes retained.</p></article>',
    `${memoryHead(0)}<p class="agent-history-empty">No retained facts match.</p><h4>Recent closed sessions</h4><p class="agent-history-empty">No closed sessions.</p>`,
    '<p class="agent-history-empty">Open History to load retained facts.</p>',
  ],
};

for (const [name, run] of Object.entries(cases)) {
  test(`agent markup: ${name}`, () => assert.deepEqual(run(), expected[name]));
}
