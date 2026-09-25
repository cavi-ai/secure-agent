// Agent tab: chat with the system agent — a model on the local Ollama —
// its proposals and saved plans, the dispatches that ran them, and the
// harnesses it routes to. State, fetches and actions live in app.js; the
// builders here are pure (data in, escaped HTML out) and unit-tested.

const AGENT_RUN_BADGE = { running: 'badge-amber', done: 'badge-ok', failed: 'badge-rose', timeout: 'badge-rose', opened: 'badge-ok', manual: 'badge-amber' };
const AGENT_PLAN_BADGE = { saved: '', running: 'badge-amber', opened: 'badge-ok', manual: 'badge-amber', done: 'badge-ok', failed: 'badge-rose' };

// The config the off state offers to copy.
const AGENT_CONFIG_SNIPPET = 'system_agent:\n  enabled: true\n  model: qwen3                # chat model: ollama pull qwen3\n  harness_model: qwen3-coder  # what dispatched harnesses run';

// agentHarnessLabel: the harness's display name from /agent/status, else
// the console's harness table.
function agentHarnessLabel(status, id) {
  const h = ((status && status.harnesses) || []).find(x => x.id === id);
  return h ? h.label : harnessMeta(id).label || id || '';
}

// agentStateText: the one-line state beside the chat title.
function agentStateText(status) {
  if (!status) return 'Loading…';
  if (!status.enabled) return 'Off';
  if (!status.reachable) return `Ollama is not answering at ${status.endpoint}`;
  if (status.reason) return status.reason;
  return `${status.model} on Ollama ${status.ollama_version || ''}`.trim() + ' · stays on this machine';
}

// agentOffHTML: what the tab shows while system_agent.enabled is false.
function agentOffHTML() {
  return `<div class="agent-off">
    <h3>The system agent is off</h3>
    <p>It chats with a model on your own Ollama, drafts work for Claude Code, Codex, OpenClaw or Hermes Agent, and runs that work against the same local model — keys, sign-ins and harness config never reach a vendor model.</p>
    <p>Turn it on in <code>~/.config/secure-agent/config.yaml</code>; the daemon applies it within seconds:</p>
    <pre class="agent-snippet">${escapeHTML(AGENT_CONFIG_SNIPPET)}</pre>
    <div><button type="button" class="btn btn-ghost btn-sm" data-action="agent-copy" data-text="${escapeHTML(AGENT_CONFIG_SNIPPET)}"><svg class="icon"><use href="#i-copy"/></svg><span>Copy</span></button></div>
  </div>`;
}

// agentTextHTML: message text, escaped; line breaks survive through CSS.
function agentTextHTML(text) {
  return `<div class="agent-bubble">${escapeHTML(text || '')}</div>`;
}

// agentHarnessBlock: why a harness cannot be dispatched now ('' when it
// can), from /agent/status.
function agentHarnessBlock(status, id) {
  const h = ((status && status.harnesses) || []).find(x => x.id === id);
  if (!h) return 'Unknown harness';
  return h.ready ? '' : (h.reason || 'Not available now');
}

// agentProposalHTML: work a reply hands to a harness. Saved → the plan id
// and its dispatch button; not saved → Save plan and a dispatch in the
// proposed mode (app.js saves it first). A harness that cannot run now
// keeps its dispatch disabled with the reason.
function agentProposalHTML(m, status) {
  const p = m.proposal;
  if (!p) return '';
  const steps = (p.steps || []).length
    ? `<ol class="agent-steps">${p.steps.map(s => `<li>${escapeHTML(s)}</li>`).join('')}</ol>` : '';
  const mode = p.mode === 'headless' ? 'Headless' : 'Terminal';
  const verb = p.mode === 'headless' ? 'Run headless' : 'Open in terminal';
  const block = agentHarnessBlock(status, p.harness);
  const dis = block ? ` disabled title="${escapeHTML(block)}"` : '';
  let actions;
  if (m.plan_id) {
    actions = `<span class="agent-saved">Saved as plan #${Number(m.plan_id)}</span>
      <button type="button" class="btn btn-primary btn-sm" data-action="agent-dispatch" data-plan="${Number(m.plan_id)}" data-mode="${escapeHTML(p.mode)}"${dis}>${verb}</button>`;
  } else {
    actions = `<button type="button" class="btn btn-ghost btn-sm" data-action="agent-save-proposal" data-message="${Number(m.id)}">Save plan</button>
      <button type="button" class="btn btn-primary btn-sm" data-action="agent-dispatch-proposal" data-message="${Number(m.id)}" data-mode="${escapeHTML(p.mode)}"${dis}>${verb}</button>`;
  }
  return `<div class="agent-proposal">
    <div class="agent-proposal-head">${harnessChipHTML(p.harness, { label: false })}<b>${escapeHTML(p.title)}</b><span class="badge">${mode}</span></div>
    <div class="agent-plan-meta">${escapeHTML(agentHarnessLabel(status, p.harness))} · <code>${escapeHTML(p.workdir)}</code></div>
    ${block ? `<div class="agent-plan-reason">${escapeHTML(block)}</div>` : ''}
    ${steps}
    <details class="agent-task"><summary>Task the harness receives</summary><pre>${escapeHTML(p.task)}</pre></details>
    <div class="agent-actions">${actions}</div>
  </div>`;
}

// agentMessageHTML: one chat turn. The operator's turns show where they
// were routed; notes come from the daemon, not the model.
function agentMessageHTML(m, status) {
  if (m.role === 'note') {
    return `<div class="agent-msg note"><span>${escapeHTML(m.content)}</span></div>`;
  }
  if (m.role === 'user') {
    const route = [m.harness ? '→ ' + agentHarnessLabel(status, m.harness) : '', m.workdir || ''].filter(Boolean).join(' · ');
    return `<div class="agent-msg user">${agentTextHTML(m.content)}${route ? `<div class="agent-msg-meta">${escapeHTML(route)}</div>` : ''}</div>`;
  }
  const skills = (m.skills || []).length
    ? `<div class="agent-msg-meta">skills: ${m.skills.map(s => `<button type="button" class="link-btn" data-action="agent-skill" data-skill="${escapeHTML(s)}">${escapeHTML(s)}</button>`).join(', ')}</div>` : '';
  return `<div class="agent-msg assistant">${agentTextHTML(m.content)}${skills}${agentProposalHTML(m, status)}</div>`;
}

// agentThreadItems: the chat as patchList items, with a pending line while
// the model answers.
function agentThreadItems(chat, status) {
  const items = ((chat && chat.messages) || []).map(m => ({ key: 'm' + m.id, html: agentMessageHTML(m, status) }));
  if (chat && chat.chatting) {
    items.push({ key: 'pending', html: `<div class="agent-msg note agent-pending"><span>The local model is answering…</span></div>` });
  }
  return items;
}

// agentEmptyThreadHTML: an enabled agent before the first message.
function agentEmptyThreadHTML(status) {
  const ready = status && status.enabled && !status.reason;
  return `<div class="empty"><svg class="icon"><use href="#i-chat"/></svg>
    <span>${ready
      ? 'Ask about SSH keys, Git credentials, commit signing or a harness’s sign-in and config — or describe work to hand to a harness. Never paste a secret: commands that need one prompt for it.'
      : escapeHTML((status && status.reason) || 'Loading…')}</span></div>`;
}

// agentPlanHTML: one saved plan, whether its harness can run now, and
// its dispatch buttons.
function agentPlanHTML(p, status) {
  const running = p.status === 'running';
  const blocked = !p.ready || running;
  const why = running ? 'This plan is running' : (p.reason || '');
  const dis = blocked ? ` disabled title="${escapeHTML(why)}"` : '';
  const reason = !p.ready && p.reason ? `<div class="agent-plan-reason">${escapeHTML(p.reason)}</div>` : '';
  const steps = (p.steps || []).length ? ` · ${p.steps.length} step${p.steps.length === 1 ? '' : 's'}` : '';
  return `<div class="agent-plan" data-plan="${Number(p.id)}">
    <div class="agent-plan-head">${harnessChipHTML(p.harness, { label: false })}<b>${escapeHTML(p.title)}</b>
      <span class="badge ${AGENT_PLAN_BADGE[p.status] || ''}">${escapeHTML(p.status)}</span></div>
    <div class="agent-plan-meta">#${Number(p.id)} · ${escapeHTML(agentHarnessLabel(status, p.harness))} · ${escapeHTML(p.mode)} · <code>${escapeHTML(p.workdir)}</code>${p.model ? ' · ' + escapeHTML(p.model) : ''}${steps} · ${escapeHTML(p.source)}</div>
    ${reason}
    <details class="agent-task"><summary>Task</summary><pre>${escapeHTML(p.task)}</pre></details>
    <div class="agent-actions">
      <button type="button" class="btn btn-ghost btn-sm" data-action="agent-dispatch" data-plan="${Number(p.id)}" data-mode="headless"${dis}>Run headless</button>
      <button type="button" class="btn btn-ghost btn-sm" data-action="agent-dispatch" data-plan="${Number(p.id)}" data-mode="terminal"${dis}>Open in terminal</button>
      <button type="button" class="btn btn-ghost btn-sm" data-action="agent-plan-delete" data-plan="${Number(p.id)}"${running ? ' disabled' : ''}>Delete</button>
    </div>
  </div>`;
}

// agentRunCommand: the shell command a manual terminal dispatch leaves for
// the operator ("sh '<script>'"), or ''.
function agentRunCommand(r) {
  const m = /(sh '[^']+'|sh \S+)$/.exec((r && r.detail) || '');
  return r && r.status === 'manual' && m ? m[1] : '';
}

// agentRunHTML: one dispatch — status, what it printed, and the command
// that ran.
function agentRunHTML(r, status, nowMs) {
  const age = fmtAge(r.ts, nowMs);
  const exit = r.status === 'failed' && r.exit_code ? ` · exit ${Number(r.exit_code)}` : '';
  const manual = agentRunCommand(r);
  const detail = r.detail ? `<div class="agent-run-detail">${escapeHTML(r.detail)}${manual
    ? ` <button type="button" class="btn btn-ghost btn-sm" data-action="agent-copy" data-text="${escapeHTML(manual)}"><svg class="icon"><use href="#i-copy"/></svg><span>Copy</span></button>` : ''}</div>` : '';
  return `<div class="agent-run" data-run="${Number(r.id)}">
    <div class="agent-plan-head">${harnessChipHTML(r.harness, { label: false })}<b>${escapeHTML(r.title)}</b>
      <span class="badge ${AGENT_RUN_BADGE[r.status] || ''}">${escapeHTML(r.status)}</span>${age ? `<span class="agent-age">${escapeHTML(age)} ago</span>` : ''}</div>
    <div class="agent-plan-meta">plan #${Number(r.plan_id)} · ${escapeHTML(agentHarnessLabel(status, r.harness))} · ${escapeHTML(r.mode)} · ${escapeHTML(r.model)} · <code>${escapeHTML(r.workdir)}</code>${exit}</div>
    ${detail}
    ${r.output ? `<pre class="agent-run-output">${escapeHTML(r.output)}</pre>` : ''}
    <details class="agent-task"><summary>Command</summary><pre>${escapeHTML(r.command)}</pre>
      <button type="button" class="btn btn-ghost btn-sm" data-action="agent-copy" data-text="${escapeHTML(r.command)}"><svg class="icon"><use href="#i-copy"/></svg><span>Copy</span></button></details>
  </div>`;
}

// agentHarnessesHTML: the models in use and each harness's readiness.
function agentHarnessesHTML(status) {
  if (!status) return '<div class="loading">Loading…</div>';
  const rows = (status.harnesses || []).map(h => `<div class="agent-harness">
      ${harnessChipHTML(h.id, { label: true })}
      ${h.ready ? '<span class="badge badge-ok">ready</span>' : `<span class="agent-harness-reason">${escapeHTML(h.reason || '')}</span>`}
    </div>`).join('');
  const models = status.enabled
    ? `<div class="agent-models">
        <span><b>Chat</b> ${escapeHTML(status.model || '—')}</span>
        <span><b>Harness</b> ${escapeHTML(status.harness_model || '—')}</span>
        <span><b>Ollama</b> ${escapeHTML(status.reachable ? (status.ollama_version || 'up') : 'down')} · <code>${escapeHTML(status.endpoint)}</code></span>
      </div>` : '';
  return models + rows;
}

// agentSkillsHTML: the procedures the agent follows; each opens in the
// drawer.
function agentSkillsHTML(status) {
  const skills = (status && status.skills) || [];
  if (!skills.length) return '';
  return `<div class="agent-skills">${skills.map(s => `<button type="button" class="agent-skill" data-action="agent-skill" data-skill="${escapeHTML(s.id)}" title="${escapeHTML(s.summary)}"><b>${escapeHTML(s.id)}</b><span>${escapeHTML(s.title)}</span></button>`).join('')}</div>`;
}

// agentHarnessOptionsHTML: the composer's route-to dropdown.
function agentHarnessOptionsHTML(status, selected) {
  return ((status && status.harnesses) || []).map(h => `<option value="${escapeHTML(h.id)}"${h.id === selected ? ' selected' : ''}>${escapeHTML(h.label)}${h.ready ? '' : ' (plan for later)'}</option>`).join('');
}

// agentDispatchMessage: the confirmation before a dispatch.
function agentDispatchMessage(plan, mode, status) {
  const label = agentHarnessLabel(status, plan.harness);
  const model = plan.model || (status && status.harness_model) || 'the harness model';
  if (mode === 'terminal') {
    return `Open ${label} in a terminal in ${plan.workdir}, on ${model} from your local Ollama, with this plan's task as its first message? You approve each step there.`;
  }
  return `Run ${label} headless in ${plan.workdir}, on ${model} from your local Ollama? It works with its own sandbox and approvals on and your secure-agent hooks active; it can edit files in that folder. The answer shows under Runs.`;
}
