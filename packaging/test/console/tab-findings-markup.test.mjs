import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact findings tab markup for hostile served values: each value renders
// escaped once in text and attribute positions, and nested fragments render
// as markup. Collaborators outside tab-findings.js return fixed markup.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
// H with every character outside [A-Za-z0-9_-] replaced by _.
const D = '_img_src_x_onerror_1____amp_';
const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);

function load(SA = {}, ids = []) {
  const nodes = new Map(ids.map(id => [id, { hidden: false, innerHTML: '', textContent: '', dataset: {}, children: [], querySelectorAll: () => [] }]));
  const ctx = vm.createContext({ window: { SA }, document: { getElementById: id => nodes.get(id) || null } });
  for (const file of ['lib.js', 'tab-findings.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), ctx, { filename: file });
  const parts = [];
  Object.assign(ctx, {
    monitoringItemActive: () => true,
    hookMonitoringModel: () => ({ available: true, rows: [{ reports: [{ report: { forwarder_id: H } }] }] }),
    hookMonitoringHTML: () => '<i>hooks</i>',
    buildEvidenceChain: () => [{ icon: 'i-one', cls: 'cn-one', label: H, sub: H }, { icon: 'i-two', cls: '', label: H, sub: '' }],
    explainLines: f => (f.explain ? { what: H, verdict: H, who: H } : null),
    explainActionItems: (_f, extra) => extra,
    factChipsHTML: () => '<i>chips</i>',
    assessmentHTML: () => '<i>assessment</i>',
    labelsLineHTML: () => '<i>labels</i>',
    markButtonsHTML: () => '<i>marks</i>',
    assessmentActions: actions => actions || [],
    actionItems: (acts, _extra, attrs, label) => acts.map(a => ({ label: label(a), attrs: attrs(a) })),
    assessmentDisplay: (a, legacy) => (a ? { state: 'warning', text: 'Assessed' } : { state: 'warning', ...legacy }),
    actionBarHTML: items => items.filter(Boolean).map(i => `<a ${i.attrs}>${ctx.escapeHTML(i.label)}</a>`).join(''),
    patternProcessesText: () => H,
    sessionShort: s => s,
    payloadOutcomeHTML: () => '<i>payload</i>',
    incidentRemediationHTML: () => '',
    harnessChipHTML: () => '<i>chip</i>',
    hookFindingBodyHTML: () => '<i>hook</i>',
    validHookForwarder: () => true,
    hookForwardersHTML: () => '<i>forwarders</i>',
    reviewHTML: () => '<i>review</i>',
    validReviewRevision: () => true,
    reviewPermissionItems: () => [],
    guardChoiceLabel: s => 'Allow for ' + s.kind,
    advisorAdviceHTML: () => '<i>advice</i>',
    ruleTitle: rule => rule,
    harnessMeta: agent => ({ label: agent }),
    capFirst: s => s,
    validAttentionSummary: () => true,
    inspectionVisible: () => ({ audit: true, advisor: false }),
    patchList: (_node, items, opts) => parts.push(...items.map(opts.html)),
  });
  return { ctx, nodes, parts };
}

const inner = (h, id) => h.nodes.get(id).innerHTML;
const bars = (...heights) => heights.concat(Array(24 - heights.length).fill(0)).map(n => `<i class="h${n}"></i>`).join('');
const chain = `<div class="chain"><div class="chain-node cn-one"><span class="cn-icon"><svg class="icon"><use href="#i-one"/></svg></span><span class="cn-body"><span class="cn-label">${E}</span><span class="cn-sub">${E}</span></span></div>`
  + `<span class="chain-link" aria-hidden="true"></span><div class="chain-node "><span class="cn-icon"><svg class="icon"><use href="#i-two"/></svg></span><span class="cn-body"><span class="cn-label">${E}</span><span class="cn-sub"></span></span></div></div>`;

test('findings markup: monitoring coverage', () => {
  const status = { proxy_enabled: false, coverage: {
    sessions_truncated: true,
    sessions: [{ session_id: H, harness: H, workspace: H, trace: { state: 'observed', last_seen: H, detail: H }, guard: { state: 'off' }, payload: null }, { harness: H }],
    probes: [{ harness: H, state: H, hook_path: H, checked_at: H, detail: H }],
    harnesses: [{ name: H, trace_supported: true, trace_last_seen: H, guard_supported: false }],
  } };
  const posture = { coverage_count: 5, coverage_items: [
    { kind: 'hook_evidence_gap', id: 'hook-gap:' + H, title: H, detail: H },
    { kind: 'hook_delivery_unknown', id: 'x', title: H },
    { kind: 'uninspected_egress', title: H, detail: H },
    { kind: 'storage_loss', title: H },
    { kind: 'other', title: H },
  ] };
  const h = load({ t: { status, posture } }, ['coverage-center', 'coverage-list', 'monitoring-diagnostic-list']);
  h.ctx.renderCoverage();
  const btn = (attrs, label) => `<button type="button" class="btn btn-ghost btn-sm" ${attrs}>${label}</button>`;
  const row = (detail, action) => `<div class="coverage-row"><span><strong>${E}</strong><span>${detail}</span></span>${action}</div>`;
  assert.equal(inner(h,'coverage-list'), row(E, btn(`data-action="hook-delivery-inspect" data-id="${E}"`, 'Inspect delivery'))
    + row('', btn('data-action="hook-setup"', 'Hook setup and verification'))
    + row(E, btn('data-action="open-uninspected"', 'Review endpoints'))
    + row('', btn('data-action="monitoring-diagnostics"', 'Inspect monitoring'))
    + row('', '<span class="coverage-guidance">Check Setup &amp; Permissions in the menu bar</span>'));
  const path = (name, label, guidance) => `<span>${name}: ${label}</span><span class="coverage-guidance">${guidance}</span>`;
  assert.equal(inner(h,'monitoring-diagnostic-list'), '<details class="coverage-diagnostics" data-hook-disclosure="monitoring"><summary>Hook monitoring details</summary><i>hooks</i></details>'
    + '<button type="button" class="link-btn" data-action="hook-setup">Hook setup and verification</button>'
    + '<details class="coverage-harness" data-coverage-disclosure="sessions"><summary>Per-session coverage · 2</summary>'
    + `<details class="coverage-session" data-coverage-disclosure="[&quot;session&quot;,&quot;&lt;img src=x onerror=1&gt;\\&quot;&#39;&amp;amp;&quot;]" data-session-id="${E}"><summary>${E} · Guard: proxy off</summary><div class="coverage-row"><span><strong>${E}</strong>`
    + path('Trace', `activity observed · ${E}`, E) + path('Guard', 'proxy off', '') + path('Payload inspection', 'unknown', '') + '</span></div></details>'
    + `<details class="coverage-session" data-coverage-disclosure="[&quot;unresolved&quot;,&quot;&lt;img src=x onerror=1&gt;\\&quot;&#39;&amp;amp;&quot;,&quot;&quot;]" data-session-id=""><summary>${E} · Guard: unknown</summary><div class="coverage-row"><span><strong>${E} · session identity unresolved</strong>`
    + path('Trace', 'unknown', '') + path('Guard', 'unknown', '') + path('Payload inspection', 'unknown', '') + '</span></div></details>'
    + '<p class="coverage-guidance">Observations belong to each session. An installed-hook check and activity in another session do not prove this session is protected.</p>'
    + '<p class="coverage-guidance">More sessions are running than this list can show. Coverage for the remaining sessions is not shown.</p></details>'
    + `<details class="coverage-harness" data-coverage-disclosure="probes"><summary>Installed hook checks</summary><div class="coverage-row"><span><strong>${E} · ${E}</strong><span>${E}</span><span>Checked ${E}</span><span>${E}</span></span></div></details>`
    + `<details class="coverage-harness" data-coverage-disclosure="agents"><summary>Per-agent coverage</summary><div class="coverage-row"><span><strong>${E}</strong><span>Trace: activity observed in 24h · Guard: not supported</span></span></div>`
    + '<p class="coverage-guidance">Payload inspection is off (proxy disabled). Recent harness activity does not prove every current session is guarded.</p></details>');
});

test('findings markup: unexplained flag body', () => {
  const h = load();
  const f = { id: H, rule: 'keychain-access', agent: H, pid: 7, session_id: H, evidence: [H, { text: H }, { label: H, sub: H }, { label: H }], advisor: { assessment: H, rationale: H } };
  assert.equal(h.ctx.flagBodyHTML(f, { now: 0, advisor: { offline: false, error: '' }, SA: {} }),
    `<div class="row-body" data-flag-id="${E}"><p class="body-lead">Apps read the keychain to load their own credentials; this is usually routine.</p>`
    + `<p class="body-note"><span class="advisor-chip adv-${E}" title="${E}">advisor: ${E}</span></p>`
    + `<div class="body-actions"><a data-action="dismiss-flag" data-id="${E}">Dismiss</a><a data-action="retriage" data-id="${E}">Re-run advisor</a>`
    + `<a data-action="filter-session" data-session="${E}">View session in timeline</a><a data-action="mute-rule" data-rule="keychain-access" data-agent="${E}">Dismiss this flag class</a>`
    + `<a data-action="kill" data-pid="7">Kill ${E}</a></div>`
    + `<details class="body-evidence"><summary>Evidence</summary>${chain}<div class="flag-evidence"><div>${E}</div><div>${E}</div><div>${E} (${E})</div><div>${E}</div></div></details></div>`);
});

test('findings markup: explained flag body and facts', () => {
  const h = load();
  const f = { id: H, rule: H, agent: H, pid: 7, ts: H, session_id: H, explain: { subject: { rule: H, path: H }, context: { tool: H, tool_at: H, model: H },
    egress: [{ host: H, port: 443, org: H }, { host: '::1', port: 80 }, { host: H }] } };
  const facts = `<dl class="finding-facts"><dt>Rule</dt><dd>${E}</dd><dt>Matched rule</dt><dd>${E}</dd>`
    + `<dt>File</dt><dd><button type="button" class="file-link" data-action="open-file" data-path="${E}">${E}</button></dd>`
    + `<dt>Destinations</dt><dd>${E}:443 (${E}), [::1]:80, ${E}</dd><dt>PID</dt><dd>7</dd><dt>Session</dt><dd>${E}</dd><dt>Raised</dt><dd>${E}</dd>`
    + `<dt>Tool</dt><dd>${E} at ${E}</dd><dt>Model</dt><dd>${E}</dd></dl>`;
  assert.equal(h.ctx.flagBodyHTML(f, { now: 0, advisor: null, SA: {} }),
    `<div class="row-body" data-flag-id="${E}"><p class="body-lead">${E}</p><i>chips</i><p class="body-verdict">${E}</p><i>labels</i>`
    + `<div class="body-actions"><a data-action="open-plan" data-subject="flag:${E}">What to do</a><a data-action="filter-session" data-session="${E}">View session in timeline</a></div>`
    + `<details class="body-evidence"><summary>Evidence</summary>${chain}${facts}<div class="body-marks"><i>marks</i></div></details></div>`);
});

test('findings markup: pattern body', () => {
  const h = load();
  const p = { key: H, agent: H, title: H, summary: H, count: 2, unacked: 1, flags: 2, cadence: H, hourly: [2, 1], flag_ids: [H],
    disposition: { text: H, why: H }, actions: [{ id: 'allow-host', label: H, body: { host: H } }, { id: 'kill' }, { id: 'unknown-action' }] };
  const ctx = { now: 0, SA: { t: { flags: [{ id: H, ts: H, pid: 9, session_id: H }] }, expanded: new Set() } };
  assert.equal(h.ctx.patternBodyHTML(p, ctx),
    `<div class="row-body" data-pattern-key="${E}"><p class="body-lead">${E}</p><p class="body-note pattern-processes">${E}</p>`
    + `<div class="pattern-cadence"><span class="pattern-bars" role="img" aria-label="Flags per bucket over the window, oldest first">${bars(8, 4)}</span>`
    + `<span class="pattern-cadence-text">2× · ${E} · <b class="pattern-open">1 open</b></span></div><p class="body-verdict">${E}: ${E}</p>`
    + `<div class="body-actions"><a data-action="explain-act" data-pattern-key="${E}" data-action-id="allow-host" data-host="${E}">${E}</a>`
    + `<a data-action="explain-act" data-pattern-key="${E}" data-action-id="kill">Kill ${E}</a></div>`
    + `<details class="body-evidence"><summary>Individual flags (2)</summary><ul class="pattern-flag-list"><li><button type="button" class="pattern-flag-link" data-action="open-flag" data-id="${E}" aria-label="View security flag ${E}">`
    + `<span>${E}</span><span>pid 9</span><span>session ${E}</span><code>${E}</code><span aria-hidden="true">↗</span></button></li></ul></details></div>`);
});

test('findings markup: routine body', () => {
  const h = load();
  const rg = { key: H, reader: H, area: H, files: 3, agents: [H, 'codex'], destinations: [{ host: H, count: 1, org: H }, { host: H, count: 2 }], destination_count: 4,
    summary: H, assessment: {}, actions: [{ id: 'expect-all', label: H }, { id: 'dismiss-all' }] };
  assert.equal(h.ctx.routineBodyHTML(rg),
    `<div class="row-body" data-routine-key="${E}"><p class="body-lead">${E}</p><div class="facts">`
    + `<span class="fact"><svg class="icon"><use href="#i-terminal"/></svg>${E}</span>`
    + `<span class="fact fact-file"><svg class="icon"><use href="#i-doc"/></svg>${E} · 3 files</span>`
    + `<span class="fact"><svg class="icon"><use href="#i-agent"/></svg>${E}, codex</span>`
    + `<span class="fact fact-dest" title="${E} · cited by 1 flag"><svg class="icon"><use href="#i-globe"/></svg>${E}</span>`
    + `<span class="fact fact-dest" title="${E} · cited by 2 flags"><svg class="icon"><use href="#i-globe"/></svg>${E}</span>`
    + `<span class="fact">+2 more</span></div><i>assessment</i>`
    + `<div class="body-actions"><a data-action="routine-act" data-routine-key="${E}" data-action-id="expect-all">${E}</a>`
    + `<a data-action="routine-act" data-routine-key="${E}" data-action-id="dismiss-all">dismiss-all</a></div></div>`);
});

test('findings markup: incident body', () => {
  const h = load();
  const inc = { id: H, summary: H, advisor_narrative: H, workflow: { status: 'open', resolution_note: H }, rotate_list: [{ name: H, category: H }] };
  assert.equal(h.ctx.incidentBodyHTML(inc, { advisor: {} }),
    `<div class="row-body" data-incident-id="${E}"><p class="body-lead">${E}</p><i>payload</i><p class="body-note">${E}</p><p class="body-note">Reported resolution: ${E}</p>`
    + `<div class="body-actions"><a data-action="open-incident" data-id="${E}">View report</a>`
    + `<a data-action="incident-status" data-id="${E}" data-status="acknowledged" title="Remove from Needs you; keep the report and monitoring">Dismiss</a>`
    + `<a data-action="incident-status" data-id="${E}" data-status="resolved">Report resolved</a></div>`
    + `<details class="body-evidence"><summary>Secrets to rotate</summary><div class="rotate-item-row"><span class="rk"><svg class="icon"><use href="#i-key"/></svg><strong>${E}</strong> (${E})</span></div></details></div>`);
});

const needCtx = () => ({ now: 0, SA: {}, flags: new Map(), patterns: new Map(), routine: new Map(), incidents: new Map(), advisor: null });
const chev = '<svg class="icon need-chev" aria-hidden="true"><use href="#i-arrow"/></svg>';
const head = (kind, what, why, meta) => `<button type="button" class="need-head" data-action="select-attention" data-need-kind="${kind}" data-need-id="${E}" aria-pressed="false">`
  + `<i>chip</i><span class="need-what" title="${what}">${what}</span><span class="need-why">${why}</span><span class="need-meta">${meta}</span></button>`;
const li = (cls, kind) => `<li class="need need-row ${cls}" data-kind="${kind}" data-need-key="${kind}:${E}">`;
const guardFacts = `<dl class="finding-facts guard-request-facts"><dt>Operation</dt><dd>${E}</dd><dt>Resource</dt><dd>${E}</dd><dt>Workspace</dt><dd>${E}</dd><dt>Matched rule</dt><dd>${E}</dd><dt>Executable path</dt><dd>${E}</dd></dl>`;
const guardItem = { kind: 'guard', id: H, title: H, tool: H, path: H, workspace: H, rule: H, reader_exe: H, session_id: H, scopeText: H, advisor: {},
  available_scopes: [{ kind: 'once' }, { kind: 'session', expiry: H, category: true }], group: { agent: H } };

const needs = {
  guard: [guardItem, li('sev-warn', 'guard') + head('guard', E, `${E} is paused until you answer · Future access requires a chosen limit · ${E}`, 'access request' + chev)
    + `<div class="guard-request-summary">${guardFacts}<p>Once answers only this request. Inspection leaves it unanswered; its timeout continues.</p></div>`
    + `<div class="need-actions"><a data-action="guard-resolve" data-id="${E}" data-verdict="allow" data-scope="once">Allow once</a><a data-action="guard-resolve" data-id="${E}" data-verdict="deny" data-scope="once">Deny</a>`
    + `<a data-action="guard-inspect" data-id="${E}">Inspect session</a><a data-action="guard-resolve" data-id="${E}" data-verdict="allow" data-scope="session" data-expiry="${E}" data-category="kind">Allow for session</a></div></li>`],
  resource: [{ kind: 'resource', id: H, title: H, action: H, group: { label: H, processCount: 1 } }, li('sev-warn', 'resource') + head('resource', E, `${E} · 1 process`, 'resource')
    + `<div class="need-actions"><a data-action="resource-control" data-id="${E}" data-decision="dismiss">Keep running</a><a data-action="resource-control" data-id="${E}" data-decision="apply" data-intervention="${E}">Apply ${E}</a></div></li>`],
  review: [{ kind: 'review', id: H, review: { id: H, revision: 3, agent: H, last_seen: H, evidence_available: true, context: { resources: [H, H] }, assessment: { reason: H } } },
    li('sev-bad need-assessed', 'review') + head('review', `${E}, ${E}`, E, 'Assessed' + chev) + '<div class="need-assessment"><i>assessment</i></div>'
    + '<p class="need-consequence">Records this evidence revision as reviewed; risk and control outcomes stay unchanged.</p>'
    + `<div class="need-actions"><a data-action="review-decision" data-id="${E}" data-revision="3" data-decision="acknowledge">Mark reviewed</a><a data-action="review-decision" data-id="${E}" data-revision="3" data-decision="close_reported">Report closure</a></div></li>`],
  hook: [{ kind: 'hook', id: H, title: H, session_id: H, hook_finding: { detail: H, last_at: H } }, li('sev-warn', 'hook') + head('hook', E, E, 'hook repair' + chev)
    + `<div class="need-actions"><a data-action="session-current" data-session="${E}">Inspect session hooks</a></div></li>`],
  hook_delivery: [{ kind: 'hook_delivery', id: H, title: H, detail: H, hook_delivery: { received_at: H, report: { forwarder_id: H } } }, li('sev-warn', 'hook_delivery') + head('hook_delivery', E, E, 'hook delivery' + chev)
    + `<div class="need-actions"><a data-action="hook-delivery-inspect" data-id="${E}">Inspect delivery</a></div></li>`],
  incident: [{ kind: 'incident', id: H, rule: H, status: 'open' }, li('sev-bad', 'incident') + head('incident', E, 'open', 'Incident')
    + `<div class="need-actions"><a data-action="open-incident" data-id="${E}">View report</a><a data-action="incident-status" data-id="${E}" data-status="acknowledged" title="Remove from Needs you; keep the report and monitoring">Dismiss</a>`
    + `<a data-action="incident-status" data-id="${E}" data-status="resolved">Report resolved</a></div></li>`],
  flag: [{ kind: 'flag', id: H, disposition: { text: H } }, li('sev-bad', 'flag') + head('flag', '', 'Evidence is outside the current event view. Dismiss marks this flag reviewed; the rule keeps watching.', E)
    + `<div class="need-actions"><a data-action="open-flag" data-id="${E}">View evidence</a><a data-action="dismiss-flag" data-id="${E}">Dismiss</a></div></li>`],
};

for (const [kind, [item, expected]] of Object.entries(needs)) {
  test(`findings markup: ${kind} need row`, () => {
    const h = load();
    assert.equal(h.ctx.needRowHTML(h.ctx.needView(item, needCtx()), false, 0), expected);
  });
}

test('findings markup: guard request body', () => {
  const h = load();
  assert.equal(h.ctx.needView(guardItem, needCtx()).body(), guardFacts + '<p>Once answers only this request. Future access requires a separate confirmation.</p>'
    + `<p>${E}</p><p>Advisor interpretation; not proof of intent or safety.</p><i>advice</i>`);
});

test('findings markup: guard scope from the served item is escaped', () => {
  const h = load();
  const v = h.ctx.needView({ kind: 'guard', id: 'g1', available_scopes: [{ kind: H }] }, needCtx());
  assert.deepEqual(Array.from(v.items, i => i.attrs), [
    'data-action="guard-resolve" data-id="g1" data-verdict="allow" data-scope="once"',
    'data-action="guard-resolve" data-id="g1" data-verdict="deny" data-scope="once"',
    `data-action="guard-resolve" data-id="g1" data-verdict="allow" data-scope="${E}"`,
  ]);
});

test('findings markup: attention summary', () => {
  const h = load();
  const first = { kind: H, id: H, title: H };
  const posture = { attention_summary: { buckets: [{ kind: 'decisions', count: 1, coverage_count: 0, first }, { kind: 'security', count: 2, coverage_count: 0, first },
    { kind: 'monitoring', count: 0, coverage_count: 1, first: null }, { kind: 'other', count: 1, coverage_count: 0, first }] } };
  const inspect = label => `<button type="button" class="link-btn" data-action="select-attention" data-need-kind="${E}" data-need-id="${E}">${label}</button>`;
  const card = (title, count, rest) => `<article class="attention-summary-card"><h3>${title}</h3><p>${count}</p>${rest}</article>`;
  const grid = cards => `<div class="attention-summary-grid">${cards}</div><p>Zero queued items is not a safety verdict.</p>`;
  assert.equal(h.ctx.attentionSummaryHTML(posture, false), grid(card('Waiting for your decision', '1 queued item', `<p>${E}</p>` + inspect('Review request'))
    + card('Security review', '2 queued items', `<p>${E}</p>` + inspect('Review evidence'))
    + card('Monitoring problems', '1 current problem', '<button type="button" class="link-btn" data-action="view-monitoring">View monitoring</button>')
    + card('Other attention', '1 queued item', `<p>${E}</p>` + inspect('Inspect issue'))));
  assert.equal(h.ctx.attentionSummaryHTML(posture, true), '<p role="status">Last known attention breakdown; current counts and requests may have changed. Refresh telemetry before relying on these observations.</p>'
    + grid(card('Waiting for your decision', '1 queued item', `<p>${E}</p>`) + card('Security review', '2 queued items', `<p>${E}</p>`)
    + card('Monitoring problems', '1 current problem', '') + card('Other attention', '1 queued item', `<p>${E}</p>`)));
});

test('findings markup: history rows', () => {
  const h = load();
  const open = { kind: 'flag', key: H, at: H, agent: H, title: H, sub: H, count: 3, hourly: [1], risk: { cls: 'disp-critical', text: H, critical: true }, reviewed: false, body: () => '<i>body</i>' };
  assert.equal(h.ctx.logRowHTML(open, true, 0), `<li class="log-row crit open" data-row-key="flag:${E}"><div class="log-line">`
    + `<input type="checkbox" class="log-check" data-action="history-select" data-row-key="flag:${E}" aria-label="Select: ${E}">`
    + `<button type="button" class="log-head" data-action="toggle-row" data-key="log:flag:${E}" aria-expanded="true" aria-controls="log-flag_${D}">`
    + `<span class="c-when"></span><span class="c-agent"><i>chip</i><span>${E}</span></span>`
    + `<span class="c-finding"><span class="c-title" title="${E} · ${E}">${E} <span class="c-sub-text">· ${E}</span></span><span class="c-sub">${E} · 3× · ${E}</span></span>`
    + `<span class="c-count">3×</span><span class="c-bars"><span class="pattern-bars log-bars crit" aria-hidden="true">${bars(8)}</span></span>`
    + `<span class="c-verdict"><i class="vdot disp-critical" aria-hidden="true"></i><span class="c-verdict-text">${E}</span></span>`
    + `<svg class="icon log-chev" aria-hidden="true"><use href="#i-arrow"/></svg></button></div><div class="log-detail" id="log-flag_${D}"><i>body</i></div></li>`);
  const closed = { kind: 'review', key: H, at: '', agent: '', title: H, count: 1, hourly: null, risk: { cls: 'disp-warning', text: H, critical: false }, reviewed: true, body: () => '<i>body</i>' };
  assert.equal(h.ctx.logRowHTML(closed, false, 0), `<li class="log-row" data-row-key="review:${E}"><div class="log-line">`
    + `<input type="checkbox" class="log-check" data-action="history-select" data-row-key="review:${E}" aria-label="Select: ${E}" disabled>`
    + `<button type="button" class="log-head" data-action="toggle-row" data-key="log:review:${E}" aria-expanded="false" aria-controls="log-review_${D}">`
    + `<span class="c-when"></span><span class="c-agent"><i>chip</i><span></span></span><span class="c-finding"><span class="c-title" title="${E}">${E}</span><span class="c-sub">${E}</span></span>`
    + `<span class="c-count">1</span><span class="c-bars"></span><span class="c-verdict"><i class="vdot disp-warning" aria-hidden="true"></i><span class="c-verdict-text">${E}</span></span>`
    + `<svg class="icon log-chev" aria-hidden="true"><use href="#i-arrow"/></svg></button></div><div class="log-detail" id="log-review_${D}" hidden></div></li>`);
});

test('findings markup: capped history list', () => {
  const h = load();
  const rows = Array.from({ length: 51 }, (_, i) => ({ kind: 'flag', key: 'k' + i, at: '', agent: '', title: 't', count: 1, risk: { cls: 'disp-warning', text: '', critical: false }, reviewed: true }));
  h.ctx.patchLog({}, rows, H, { expanded: new Set() }, 0);
  assert.equal(h.parts.length, 51);
  assert.equal(h.parts[50], `<li class="log-more"><button type="button" class="btn btn-ghost btn-sm show-more" data-action="show-more" data-key="${E}">Show 1 more</button></li>`);
});

const auditRow = (cls, action, label) => `\n      <div class="audit-item">\n        <div class="audit-head">\n          <span class="event-kind ${cls}">${action}</span>\n`
  + `          <span class="audit-t">Invalid Date</span>\n        </div>\n        <div class="audit-dtl">${label}</div>\n      </div>\n    `;

test('findings markup: policy audit', () => {
  const empty = load({ t: { audit: [] } }, ['audit-container', 'badge-audit-count']);
  empty.ctx.renderAudit();
  assert.equal(inner(empty, 'audit-container'), '<div class="empty"><svg class="icon"><use href="#i-history"/></svg><span>No policy changes yet — promotions and secret registrations are logged here</span></div>');
  const h = load({ t: { audit: [{ ts: H, action: 'rule-mode', rule: H, from_mode: H, to_mode: 'block' }, { ts: H, action: 'fingerprint-reload' }, { ts: H, action: 'secret-register', detail: H }] } },
    ['audit-container', 'badge-audit-count']);
  h.ctx.renderAudit();
  assert.deepEqual(h.parts, [auditRow('ok', 'RULE MODE', `${E}: ${E} → block`), auditRow('tool', 'FINGERPRINT RELOAD', 'fingerprints reloaded'), auditRow('', 'SECRET REGISTER', E)]);
});

test('findings markup: audit action from the served entry is escaped', () => {
  const h = load({ t: { audit: [{ ts: H, action: H, detail: H }] } }, ['audit-container', 'badge-audit-count']);
  h.ctx.renderAudit();
  assert.deepEqual(h.parts, [auditRow('', '&lt;IMG SRC=X ONERROR=1&gt;&quot;&#39;&amp;AMP;', E)]);
});

test('findings markup: empty incidents', () => {
  const h = load({ t: { incidents: [] } }, ['incidents-container', 'badge-incidents-count']);
  h.ctx.renderIncidents();
  assert.equal(inner(h,'incidents-container'), '<div class="empty"><svg class="icon"><use href="#i-incident"/></svg><span>No incidents — nothing to contain right now</span></div>');
});

const flagsSA = over => ({ t: { flags: [], patterns: [], flagsView: [], routine: [], reviews: { reviews: [] } }, seenAgents: new Set(), seenRules: new Set(), syncSelect() {},
  globalSearchTerm: () => '', sessionScopeOn: () => false, sessionScopeTag: () => H, isFlagsFiltered: () => false, paintSessionChip() {},
  historySelected: new Set(), reviewCursor: null, timelineSession: null, timelinePids: null, ...over });

test('findings markup: empty session-scoped history', () => {
  const h = load(flagsSA({ sessionScopeOn: () => true }), ['flags-list', 'badge-flags-count']);
  h.ctx.renderFlags();
  assert.equal(inner(h,'flags-list'), `<div class="empty"><svg class="icon"><use href="#i-alert"/></svg><span>No flags for ${E} in the loaded window</span></div>`);
});

test('findings markup: review paging rows', () => {
  const sa = flagsSA({ reviewCursor: 'c' });
  sa.t.reviews = { reviews: [], next: H, degraded: true };
  const h = load(sa, ['flags-list', 'badge-flags-count']);
  h.ctx.renderFlags();
  assert.deepEqual(h.parts, ['<li><p role="alert">Review storage is degraded. Original findings remain available.</p></li>',
    `<li><button class="btn btn-ghost" data-action="review-page" data-after="${E}">Next reviews</button></li>`,
    '<li><button class="btn btn-ghost" data-action="review-page">First reviews</button></li>']);
});

test('findings markup: history selection bar', () => {
  const h = load({}, ['flags-bulk']);
  h.ctx.paintHistoryBulk({ historySelected: new Set(['a', 'b']) });
  assert.equal(inner(h,'flags-bulk'), '<span>2 selected</span><button type="button" class="btn btn-ghost btn-sm" data-action="history-bulk-review">Mark reviewed</button>'
    + '<button type="button" class="btn btn-ghost btn-sm" data-action="history-bulk-clear">Clear</button>');
});

test('findings markup: muted rows', () => {
  const h = load();
  const row = (pair, host, agent) => `\n      <div class="mute-row">\n        <span class="mute-pair">${pair}</span>\n`
    + `        <button class="source-remove" title="Unmute" data-action="unmute" data-rule="${E}" data-host="${host}" data-agent="${agent}"><svg class="icon"><use href="#i-close"/></svg></button>\n      </div>`;
  assert.equal(h.ctx.muteRowHTML({ rule: H, host: H, agent: H }), row(`${E} · ${E} · ${E}`, E, E));
  assert.equal(h.ctx.muteRowHTML({ rule: H, host: '*' }), row(`${E} · all hosts`, '*', ''));
});
