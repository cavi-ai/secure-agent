import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact console markup for hostile served values: each value renders escaped
// once in text and attribute positions, and nested fragments render as markup.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const SEEN = '2026-10-20T16:00:00Z';
const LOCAL = new Date(SEEN).toLocaleString();
const NOW = Date.parse('2026-10-10T10:00:00Z');
class FixedDate extends Date { static now() { return NOW; } }

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const source = name => readFileSync(new URL(name, web), 'utf8');
const app = source('app.js');
const node = (extra = {}) => ({ innerHTML: '', textContent: '', hidden: false, dataset: {}, style: {},
  contains: () => false, querySelectorAll: () => [], focus() {}, ...extra });

// Evaluates the files as classic scripts, then installs the collaborators.
function context(files, globals) {
  const ctx = vm.createContext({ URLSearchParams, Date: FixedDate, window: {}, document: { activeElement: null } });
  for (const file of files) vm.runInContext(source(file), ctx, { filename: file });
  return Object.assign(ctx, globals);
}
// Evaluates one app.js block, from its declaration up to the next marker.
function appBlock(ctx, start, end) {
  const from = app.indexOf(start), to = app.indexOf(end, from);
  assert.ok(from >= 0 && to > from, start);
  vm.runInContext(app.slice(from, to), ctx, { filename: 'app.js' });
  return ctx;
}

const items = [{ kind: 'flag', id: 'a', title: H, detail: H }, { kind: 'flag', id: 'b', title: H, detail: H }];
const agents = [
  { pid: 101, ppid: 1, name: 'codex', cwd: H, started_at: H, last_seen_at: '2026-10-10T09:58:00Z', rss_bytes: 1048576, cpu_percent: 12.5, is_orphan: true },
  { pid: 102, ppid: 101, name: 'codex', cwd: H, rss_bytes: 2048 },
  { pid: 201, ppid: 1, name: 'ollama', cwd: H, last_seen_at: '2026-10-10T09:00:00Z' },
];
const path = state => ({ state, supported: true, detail: H, last_seen: SEEN });
const coverageRow = (session_id, root_pid) => ({ session_id, root_pid, workspace: H, harness: 'codex', identity_basis: H,
  guard: path('observed'), trace: path('not-observed'), payload: path('off') });
const coverage = { status: { coverage: { sessions: [coverageRow(H, 41), coverageRow('', 42)] } }, sessions: [{ id: H, repo: H, branch: H }],
  posture: { coverage_items: [{ kind: H, title: H, detail: H }, { kind: 'uninspected_egress', title: H, detail: H }] } };
const monitoring = () => context(['lib.js', 'telemetry-validation.js', 'tab-monitoring.js'], {});

const cases = {
  'attention inspector': () => {
    const opened = [];
    const ctx = appBlock(context(['lib.js'], {
      attentionGeneration: 0, reviewDrafts: new Map(), attentionItems: () => items, hookRepairScope: () => null,
      homeContext: () => ({ flags: new Map(), patterns: new Map(), routine: new Map(), incidents: new Map() }),
      needView: item => ({ word: H, agent: H, what: H, why: H, items: [], ...(item.id === 'b' ? { body: () => '<b>recorded</b>' } : {}) }),
      actionBarHTML: () => '', renderAttention() {}, btnDrawerClose: null,
      detailDrawer: { setMode() {}, setCopyVisible() {}, open: o => opened.push(o.body), mode: () => 'attention', selection: () => ({ signature: '' }) },
      drawer: node(), drawerBody: node(), drawerFoot: node(), drawerTitle: node(),
    }), '  function selectAttention(', '  function reconcileAttention(');
    ctx.selectAttention('flag:a');
    ctx.selectAttention('flag:b');
    ctx.refreshAttentionInspector(items[0]);
    return [...opened, ctx.drawerBody.innerHTML];
  },
  'hook delivery': async () => {
    let opened;
    const ctx = appBlock(context(['lib.js'], {
      sessionEnded: false, hookDiagnostic: null, handoffGeneration: 0, drawer: node(), drawerBody: node(),
      detailDrawer: { setMode() {}, setCopyVisible() {}, open: o => { opened = o; return true; }, seq: () => 1 },
      apiFetch: async () => ({ ok: true, json: async () => ({ hook_ingestion: { forwarders: [{ report: { forwarder_id: H, harness: H } }] } }) }),
      validHookForwarder: () => true, hookForwardersHTML: () => '<ul>forwarders</ul>', hookDiagnosticSummary: () => '',
    }), '  async function openHookInspector(', '  function openHookSetup(');
    await ctx.openHookInspector('delivery', { session: H, harness: H, event: H, handler: H, config: H, script: H, id: H });
    return [opened.foot, ctx.drawerBody.innerHTML];
  },
  'saved views': () => {
    const list = node();
    const ctx = appBlock(context(['lib.js'], { document: { getElementById: () => list }, loadViews: () => [{ name: H, tab: H }, { name: 'b' }] }),
      '  function renderViews(', '  function syncFilterControls(');
    ctx.renderViews();
    return list.innerHTML;
  },
  'agent skill': async () => {
    let body;
    const ctx = appBlock(context(['lib.js'], { agentState: { skills: [{ id: 's', title: H, summary: H, body: H }] }, detailDrawer: { open: o => { body = o.body; } } }),
      '  window.showAgentSkill = async function(id) {', '  if (agentComposer)');
    await ctx.window.showAgentSkill('s');
    return body;
  },
  'playbook error': async () => {
    const slot = node();
    const ctx = appBlock(context(['lib.js'], { sessionEnded: false, handoffGeneration: 0,
      fetchPlan: async () => { throw new Error(H); }, planSlots: () => [slot], paintPlanSlots() {}, pollPlan() {} }),
      '  async function loadPlanSlot(', '  window.askAdvisorPlan');
    await ctx.loadPlanSlot(H);
    return slot.innerHTML;
  },
  'resource policy': () => {
    const body = node();
    const ctx = appBlock(context(['lib.js'], { drawerBody: body, resourcePolicyDraft: {
      default: { mode: 'prompt', max_rss_mb: 2048, max_cpu_percent: 90, sustain_seconds: 30, cooldown_seconds: 300,
        interventions: [{ action: 'notify', after_seconds: 5 }, { action: 'lower_priority', after_seconds: 40, nice: 7 }] },
      overrides: [{ cwd_prefix: H, mode: 'terminate', interventions: [] }] } }),
    '  function resourcePolicyFields(', '  function readResourcePolicyEditor(');
    ctx.renderResourcePolicyEditor();
    return body.innerHTML;
  },
  'notification rules': () => {
    let added;
    const rules = node(), scopes = node({ parentNode: { insertBefore: form => { added = form; } } });
    const ctx = appBlock(context(['lib.js'], {
      NOTIFY_RULES: [[H, H], ['sensitive-read', 'Sensitive reads']],
      telemetryData: { notifyCfg: { overrides: { [H]: false }, scopes: [{ rule: H, workspace: H, notify: true }, { rule: 'sensitive-read', workspace: '/work', notify: false }] } },
      patchList: (list, rows, opts) => { list.innerHTML = rows.length ? rows.map(opts.html).join('') : opts.empty; },
      document: { getElementById: id => ({ 'notify-rules-list': rules, 'notify-scopes-list': scopes }[id] || null), createElement: () => node() },
    }), '  function renderNotifyRules(', '  window.addNotifyScope');
    ctx.renderNotifyRules();
    return [rules.innerHTML, scopes.innerHTML, added.innerHTML];
  },
  'agent groups': () => {
    let parts;
    const els = { 'agents-container': node(), 'badge-agents-count': node() };
    const ctx = context(['lib.js', 'tab-agents.js'], {
      window: { SA: { t: { status: { agents, trees: [] } }, harnessFilter: { harnesses: {} }, agentGroupOpen: {}, agentTreeOpen: { 101: true }, expanded: new Set(), setTabBadge() {} } },
      document: { getElementById: id => els[id] || null }, patchList: (container, rows) => { parts = Array.from(rows, p => [p.key, p.html]); },
    });
    ctx.renderAgents();
    return parts;
  },
  'fleet nodes': () => {
    const els = { 'fleet-col': node(), 'fleet-panel': node(), 'fleet-container': node(), 'badge-fleet-count': node() };
    const ctx = context(['lib.js', 'tab-agents.js'], {
      window: { SA: { t: { status: { fleet_configured: true }, audit: [], fleet: [{ hostname: H, online: true, os: H, arch: H, ip: H, version: H, active_agents: 2, recent_flags: 3 }, { id: H }] } } },
      document: { getElementById: id => els[id] || null },
    });
    ctx.renderFleet();
    return els['fleet-container'].innerHTML;
  },
  'monitoring controller': () => {
    const els = new Map();
    const el = id => { if (!els.has(id)) els.set(id, node({ id, querySelector: () => node() })); return els.get(id); };
    const ctx = monitoring();
    ctx.createMonitoringController({ root: { querySelector: selector => el(selector.slice(1)), addEventListener() {} }, data: () => coverage,
      health: () => ({}), openSession() {}, retry() {}, openTraffic() {}, openDiagnostics() {} }).render();
    return ['monitoring-notice', 'monitoring-issue-list', 'monitoring-note-list', 'monitoring-sessions', 'monitoring-other-list', 'monitoring-detail'].map(id => el(id).innerHTML);
  },
  'monitoring process detail': () => {
    const ctx = monitoring();
    const model = ctx.monitoringModel(coverage, '', {});
    return ctx.monitoringDetailHTML(model.unlinked[0], model);
  },
};

const attention = last => `<div class="panel-body attention-inspector"><p class="finding-why">${E}</p><h3>${E}</h3><p>${E}</p>${last}</div>`;
const viewRow = (name, tab) => `<div class="view-row">
          <button class="view-load" data-action="apply-view" data-name="${name}" title="Apply ${name}">${name}</button>
          <span class="view-tab">${tab}</span>
          <button class="source-remove" data-action="remove-view" data-name="${name}" title="Delete view"><svg class="icon"><use href="#i-close"/></svg></button>
        </div>`;
const chip = '<span class="harness-chip" title="Codex"><span class="harness-tile hk-codex" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-codex"/></svg></span></span>';
const seen = `<time datetime="${SEEN}">Last observed ${LOCAL}</time>`;
const inspectionOff = `<article class="monitoring-path" data-monitoring-path="payload"><svg class="icon" aria-hidden="true"><use href="#i-globe"/></svg><h3>Traffic inspection</h3><div><span class="monitoring-state neutral"><span aria-hidden="true"></span>Inspection off</span><p>Traffic inspection is off. Historical observations do not establish current inspection.</p>${seen}</div></article>`;
const caveat = '<p class="monitoring-caveat">An observation does not prove every tool call is guarded. Machine-wide traffic does not establish this session’s inspection.</p>';
const unlinked = '<span class="monitoring-state neutral"><span aria-hidden="true"></span>Session not linked</span><p>No durable session matches this process and its start time.</p>';
const identity = ([session, workspace, pid, basis, branch]) => `<details class="monitoring-identity" id="monitoring-identity"><summary id="monitoring-identity-summary">Identity and technical details</summary><dl>\n      <div><dt>Session</dt><dd>${session}</dd></div><div><dt>Harness</dt><dd>codex</dd></div><div><dt>Workspace</dt><dd>${workspace}</dd></div><div><dt>Root process</dt><dd>${pid}</dd></div><div><dt>Attribution</dt><dd>${basis}</dd></div><div><dt>Branch</dt><dd>${branch}</dd></div>\n      </dl><details id="monitoring-source"><summary id="monitoring-source-summary">Source observation details</summary><p><strong>File guard</strong> ${E}</p><p><strong>Recorded activity</strong> ${E}</p><p><strong>Traffic inspection</strong> ${E}</p></details></details>`;

const expected = {
  'attention inspector': [attention(`<p>${E}</p>`), attention('<b>recorded</b>'), attention(`<p>${E}</p>`)],
  'hook delivery': [`<button type="button" class="btn btn-ghost btn-sm" data-action="hook-delivery-inspect" data-session="${E}" data-harness="${E}" data-event="${E}" data-event_scope="group" data-handler="${E}" data-config="${E}" data-script="${E}" data-id="${E}">Refresh delivery</button><button type="button" class="btn btn-ghost btn-sm" data-action="hook-diagnostic-copy" disabled>Copy diagnostic summary</button>`,
    `<ul>forwarders</ul><button type="button" class="link-btn" data-action="hook-setup" data-harness="${E}">Hook setup and verification</button>`],
  'saved views': viewRow(E, E) + viewRow('b', 'overview'),
  'agent skill': `<div class="panel-body"><p>${E}</p><pre class="agent-skill-body">${E}</pre></div>`,
  'playbook error': `<p class="plan-status">No playbook: ${E}</p>`,
  'resource policy': `<p class="resource-policy-intro">Set machine-wide budgets, then add complete policies for specific workspace trees. The most specific matching path wins.</p>\n      <section class="resource-policy-section"><div class="resource-policy-section-head"><h4>Machine default</h4></div><div class="resource-policy-editor-row default" data-policy-row data-policy-index="-1" data-policy-default="true">\n      \n      <label class="resource-policy-field">Action<select class="select" data-policy-field="mode"><option value="observe">Observe</option><option value="prompt" selected>Ask first</option><option value="terminate">Terminate</option></select></label>\n      <label class="resource-policy-field">Memory (MiB)<input class="input" type="number" min="0" step="1" data-policy-field="max_rss_mb" value="2048"></label>\n      <label class="resource-policy-field">CPU (%)<input class="input" type="number" min="0" step="1" data-policy-field="max_cpu_percent" value="90"></label>\n      <label class="resource-policy-field">Grace (sec)<input class="input" type="number" min="0" step="1" data-policy-field="sustain_seconds" value="30"></label>\n      <label class="resource-policy-field">Cooldown (sec)<input class="input" type="number" min="0" step="1" data-policy-field="cooldown_seconds" value="300"></label>\n\t  <div class="resource-policy-ladder"><span class="resource-policy-ladder-title">Intervention ladder <small>seconds after grace</small></span>\n\t\t<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="notify" checked><span>Notify</span><input class="input" type="number" min="0" step="1" data-step-after value="5" aria-label="Notify delay in seconds"></label>\n\t\t<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="lower_priority" checked><span>Lower priority</span><input class="input" type="number" min="0" step="1" data-step-after value="40" aria-label="Lower priority delay in seconds"><input class="input resource-policy-nice" type="number" min="1" max="19" step="1" data-step-nice value="7" aria-label="Nice value"></label>\n\t\t<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="pause"><span>Pause</span><input class="input" type="number" min="0" step="1" data-step-after value="60" aria-label="Pause delay in seconds"></label>\n\t\t<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="terminate"><span>Terminate</span><input class="input" type="number" min="0" step="1" data-step-after value="120" aria-label="Terminate delay in seconds"></label>\n\t  </div>\n      \n    </div></section>\n      <section class="resource-policy-section"><div class="resource-policy-section-head"><h4>Workspace overrides</h4><span><button type="button" class="btn btn-ghost btn-sm" data-action="add-resource-override" data-source="current">Add current workspace</button><button type="button" class="btn btn-ghost btn-sm" data-action="add-resource-override" data-source="manual">Add path</button></span></div>\n      <div id="resource-policy-overrides"><div class="resource-policy-editor-row" data-policy-row data-policy-index="0" data-policy-default="false">\n      <label class="resource-policy-field resource-policy-path">Workspace path<input class="input" data-policy-field="cwd_prefix" value="${E}" placeholder="Absolute project path" spellcheck="false"></label>\n      <label class="resource-policy-field">Action<select class="select" data-policy-field="mode"><option value="observe">Observe</option><option value="prompt">Ask first</option><option value="terminate" selected>Terminate</option></select></label>\n      <label class="resource-policy-field">Memory (MiB)<input class="input" type="number" min="0" step="1" data-policy-field="max_rss_mb" value="0"></label>\n      <label class="resource-policy-field">CPU (%)<input class="input" type="number" min="0" step="1" data-policy-field="max_cpu_percent" value="0"></label>\n      <label class="resource-policy-field">Grace (sec)<input class="input" type="number" min="0" step="1" data-policy-field="sustain_seconds" value="0"></label>\n      <label class="resource-policy-field">Cooldown (sec)<input class="input" type="number" min="0" step="1" data-policy-field="cooldown_seconds" value="0"></label>\n\t  <div class="resource-policy-ladder"><span class="resource-policy-ladder-title">Intervention ladder <small>seconds after grace</small></span>\n\t\t<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="notify"><span>Notify</span><input class="input" type="number" min="0" step="1" data-step-after value="0" aria-label="Notify delay in seconds"></label>\n\t\t<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="lower_priority"><span>Lower priority</span><input class="input" type="number" min="0" step="1" data-step-after value="30" aria-label="Lower priority delay in seconds"><input class="input resource-policy-nice" type="number" min="1" max="19" step="1" data-step-nice value="10" aria-label="Nice value"></label>\n\t\t<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="pause"><span>Pause</span><input class="input" type="number" min="0" step="1" data-step-after value="60" aria-label="Pause delay in seconds"></label>\n\t\t<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="terminate"><span>Terminate</span><input class="input" type="number" min="0" step="1" data-step-after value="120" aria-label="Terminate delay in seconds"></label>\n\t  </div>\n      <button type="button" class="btn btn-ghost btn-sm" data-action="remove-resource-override" data-index="0">Remove</button>\n    </div></div></section>\n\t  <p class="resource-policy-danger">Terminate mode applies every enabled intervention automatically. Pause stops the full attributed session until resumed; terminate ends it.</p>`,
  'notification rules': [
    `<div class="notify-rule-row">\n        <span class="notify-rule-name" title="${E}">${E}</span>\n        <select class="select select-sm" data-notify-rule="${E}" aria-label="Notifications for ${E}">\n          <option value="default">Default</option>\n          <option value="always">Always</option>\n          <option value="never" selected>Never</option>\n        </select>\n      </div><div class="notify-rule-row">\n        <span class="notify-rule-name" title="sensitive-read">Sensitive reads</span>\n        <select class="select select-sm" data-notify-rule="sensitive-read" aria-label="Notifications for Sensitive reads">\n          <option value="default" selected>Default</option>\n          <option value="always">Always</option>\n          <option value="never">Never</option>\n        </select>\n      </div>`,
    `<div class="notify-rule-row">\n        <span class="notify-rule-name" title="${E}">${E} <span class="notify-scope-path">${E}</span></span>\n        <span class="notify-scope-mode on">page</span>\n        <button class="source-remove" title="Remove this scope" data-action="notify-scope-remove" data-rule="${E}" data-workspace="${E}"><svg class="icon"><use href="#i-close"/></svg></button>\n      </div><div class="notify-rule-row">\n        <span class="notify-rule-name" title="/work">sensitive-read <span class="notify-scope-path">/work</span></span>\n        <span class="notify-scope-mode off">quiet</span>\n        <button class="source-remove" title="Remove this scope" data-action="notify-scope-remove" data-rule="sensitive-read" data-workspace="/work"><svg class="icon"><use href="#i-close"/></svg></button>\n      </div>`,
    `\n        <select class="select select-sm" id="notify-scope-rule" aria-label="Rule for the workspace scope">\n          <option value="${E}">${E}</option><option value="sensitive-read">Sensitive reads</option>\n        </select>\n        <input class="input input-sm" id="notify-scope-path" aria-label="Workspace path for notification scope" placeholder="repo path, e.g. ~/work/prod" autocomplete="off" spellcheck="false">\n        <select class="select select-sm" id="notify-scope-mode" aria-label="Scope action">\n          <option value="always">Page</option>\n          <option value="never">Quiet</option>\n        </select>\n        <button class="btn btn-ghost btn-sm" data-action="notify-scope-add" title="Add this workspace scope"><svg class="icon"><use href="#i-arrow"/></svg><span>Add</span></button>`],
  'agent groups': [
    ['group:codex', `\n    <details class="agent-group" data-harness="codex" open>\n      <summary class="agent-group-head">\n        <span class="agent-group-title"><span class="harness-chip" title="Codex"><span class="harness-tile hk-codex" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-codex"/></svg></span><span class="harness-label">Codex</span></span></span>\n        <span class="agent-group-meta">\n          <span class="agent-meta-item">1 instance · 2 processes · 1.0 MB · 12.5% CPU · <span class="agent-lastseen" title="2026-10-10T09:58:00Z">seen 2m ago</span></span>\n          <span class="agent-orphan-count">1 leftover</span>\n          <button type="button" class="btn btn-danger btn-sm" data-action="kill-orphans" data-family="codex"><svg class="icon"><use href="#i-power"/></svg><span>Terminate orphans (1)</span></button>\n        </span>\n      </summary>\n      <div class="agent-instances">\n        \n      <div class="agent-instance agent-row has-tree orphan">\n        <div class="agent-row-main" title="${E}">\n          <span class="agent-row-title">${E}</span>\n          <div class="agent-row-meta">\n          <span class="agent-pid">PID 101</span>\n          <span class="agent-status orphan">leftover</span>\n          <span class="agent-meta-item agent-lastseen" title="last event 2026-10-10T09:58:00Z">active 2m ago</span>\n          <span class="agent-meta-item">1.0 MB</span>\n          </div>\n        </div>\n        <button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="101" data-started="${E}" data-family="codex"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>\n        <details class="session-helpers agent-tree" data-pid="101" open><summary class="session-helpers-sum">1 helper process</summary>\n      <div class="agent-instance nested stale">\n        <div class="agent-info">\n          <div class="agent-name">\n            <span class="agent-pid">PID 102</span>\n            <span class="agent-status live">live</span>\n            \n            <span class="agent-meta-item agent-lastseen">no activity</span>\n            <span class="agent-meta-item">2 KB</span>\n          </div>\n          <div class="agent-cwd">${E}</div>\n        </div>\n        <button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="102" data-started="" data-family="codex"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>\n      </div></details>\n      </div>\n      </div>\n    </details>`],
    ['infra', `<section class="agent-infra" aria-label="Infrastructure"><h3 class="agent-infra-head">Infrastructure <span>IDEs and model servers — not counted as agents</span></h3>\n    <details class="agent-group infra" data-harness="ollama">\n      <summary class="agent-group-head">\n        <span class="agent-group-title"><span class="harness-chip" title="Ollama"><span class="harness-tile hk-ollama" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-ollama"/></svg></span><span class="harness-label">Ollama</span></span></span>\n        <span class="agent-group-meta">\n          <span class="agent-meta-item">1 instance · 1 process · <span class="agent-lastseen" title="2026-10-10T09:00:00Z">seen 1h ago</span></span>\n          \n          \n        </span>\n      </summary>\n      <div class="agent-instances">\n        \n      <div class="agent-instance agent-row stale">\n        <div class="agent-row-main" title="${E}">\n          <span class="agent-row-title">${E}</span>\n          <div class="agent-row-meta">\n          <span class="agent-pid">PID 201</span>\n          \n          <span class="agent-meta-item agent-lastseen" title="last event 2026-10-10T09:00:00Z">active 1h ago</span>\n          \n          </div>\n        </div>\n        <button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="201" data-started="" data-family="ollama"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>\n        \n      </div>\n      </div>\n    </details></section>`]],
  'fleet nodes': `\n    <div class="fleet-node-card">\n      <div class="fleet-node-header">\n        <span class="fleet-node-name"><svg class="icon"><use href="#i-server"/></svg>${E}</span>\n        <span class="status-badge online">ONLINE</span>\n      </div>\n      <div class="fleet-node-meta">\n        <span>${E}/${E}</span>\n        <span>IP ${E}</span>\n        <span>${E}</span>\n        <span>2 agents</span>\n        <span>3 flags</span>\n      </div>\n    </div>\n  \n    <div class="fleet-node-card">\n      <div class="fleet-node-header">\n        <span class="fleet-node-name"><svg class="icon"><use href="#i-server"/></svg>${E}</span>\n        <span class="status-badge offline">OFFLINE</span>\n      </div>\n      <div class="fleet-node-meta">\n        \n        \n        <span>v1.0</span>\n        \n        \n      </div>\n    </div>\n  `,
  'monitoring controller': [
    `<div class="monitoring-notice warning" role="status"><svg class="icon" aria-hidden="true"><use href="#i-alert"/></svg><div><strong>Monitoring needs attention</strong><p>${E}</p></div><button type="button" class="link-btn" data-monitoring-action="issues">Review issues</button></div>`,
    `<li><strong>${E}</strong><p>${E}</p><button type="button" class="link-btn" data-monitoring-action="diagnostics">Inspect monitoring</button></li>`,
    `<li><strong>${E}</strong><p>${E}</p><button type="button" class="link-btn" data-action="open-uninspected">Review endpoints</button></li>`,
    `<button type="button" class="monitoring-row" data-monitoring-key="session:${E}" aria-pressed="true" aria-controls="monitoring-detail">\n    ${chip}<span class="monitoring-row-name"><strong title="${E}">${E}</strong><span>Codex</span></span>\n    <span class="monitoring-state neutral"><span aria-hidden="true"></span>No recent activity</span></button>`,
    `<button type="button" class="monitoring-row" data-monitoring-key="process:42" aria-pressed="false" aria-controls="monitoring-detail">\n    ${chip}<span class="monitoring-row-name"><strong title="${E}">${E}</strong><span>Codex · Process 42</span></span>\n    <span class="monitoring-state neutral"><span aria-hidden="true"></span>Not linked</span></button>`,
    `<header class="monitoring-detail-heading">${chip}<div><h2>${E}</h2><p>Codex<span class="monitoring-identity-state">Session linked</span></p></div></header>\n    \n    <div class="monitoring-paths"><article class="monitoring-path" data-monitoring-path="guard"><svg class="icon" aria-hidden="true"><use href="#i-shield"/></svg><h3>File guard</h3><div><span class="monitoring-state observed"><span aria-hidden="true"></span>Observed</span><p>A guard hook outcome or decision was recorded for this session.</p>${seen}</div></article><article class="monitoring-path" data-monitoring-path="trace"><svg class="icon" aria-hidden="true"><use href="#i-activity"/></svg><h3>Recorded activity</h3><div><span class="monitoring-state neutral"><span aria-hidden="true"></span>No recent activity</span><p>No recent activity was recorded. An idle session can be quiet.</p>${seen}</div></article>${inspectionOff}</div>\n    ${caveat}\n    <button type="button" id="monitoring-open" class="btn btn-primary monitoring-open" data-monitoring-action="open">Open session evidence<svg class="icon" aria-hidden="true"><use href="#i-arrow"/></svg></button>\n    ${identity([E, E, '41', E, E])}`],
  'monitoring process detail': `<header class="monitoring-detail-heading">${chip}<div><h2>${E}</h2><p>Codex<span class="monitoring-identity-state">Session not linked</span></p></div></header>\n    <p class="monitoring-unlinked-note">This is a detected process, not an identified session. Its working directory may belong to a plugin or helper. Session-specific evidence cannot be credited until identity is resolved.</p>\n    <div class="monitoring-paths"><article class="monitoring-path" data-monitoring-path="guard"><svg class="icon" aria-hidden="true"><use href="#i-shield"/></svg><h3>File guard</h3><div>${unlinked}</div></article><article class="monitoring-path" data-monitoring-path="trace"><svg class="icon" aria-hidden="true"><use href="#i-activity"/></svg><h3>Recorded activity</h3><div>${unlinked}</div></article>${inspectionOff}</div>\n    ${caveat}\n    \n    ${identity(['Not identified', E, '42', E, 'Not recorded'])}`,
};

for (const [name, render] of Object.entries(cases)) {
  test(`console markup: ${name}`, async () => {
    const actual = await render();
    assert.deepEqual(actual, expected[name]);
    assert.ok(![actual].flat(2).some(out => out.includes('<img')), 'hostile value rendered as markup');
  });
}
