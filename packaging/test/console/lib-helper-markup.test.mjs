import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact markup the lib.js action, chart, session, policy and review helpers
// return for hostile served values: each value renders escaped once.
const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
const ctx = vm.createContext({ window: {} });
for (const file of ['lib.js', 'decision-permissions.js']) vm.runInContext(readFileSync(new URL(file, web), 'utf8'), ctx);

const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const T0 = '2026-07-12T12:00:00Z';
const NOW = Date.parse('2026-07-12T12:05:00Z');
const lines = (...rows) => rows.join('\n');

function inUTC(render) {
  const original = process.env.TZ;
  try {
    process.env.TZ = 'UTC';
    return render();
  } finally {
    if (original === undefined) delete process.env.TZ;
    else process.env.TZ = original;
  }
}

const stampLabel = new Date(T0).toLocaleString(undefined, {
  year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short',
});
const stamp = recorded => `<time datetime="${recorded}" title="${recorded}">${stampLabel}</time>`;
const receiptAt = new Date(T0).toLocaleString(undefined, { timeZone: 'UTC' });

const menu = entries => `<details class="act-more"><summary class="btn btn-ghost btn-sm">More</summary><div class="act-menu">${entries}</div></details>`;

const hbarRow = (title, label, cls, w, val, sub) => lines('<div class="hbar-row">',
  `      <span class="hbar-label" title="${title}">${label}</span>`,
  `      <span class="hbar-track"><span class="hbar-fill ${cls}" data-w="${w}"></span></span>`,
  `      <span class="hbar-val">${val}</span>`, `      ${sub}`, '    </div>');

const moreButton = key => `<button type="button" class="btn btn-ghost btn-sm show-more" data-action="show-more" data-key="${key}">Show 2 more</button>`;

const waterfallEvents = [
  { kind: 12, tool: H, ts: T0, duration_ms: 1500, tool_status: 'error' },
  { kind: 12, ts: '2026-07-12T12:00:02Z' },
  { kind: 5, ts: '2026-07-12T12:00:01Z' }, { kind: 10, ts: T0 }, { kind: 2, ts: T0 }, { kind: 13, ts: T0 },
  { kind: 14, model: H, ts: '2026-07-12T12:00:03Z', tokens_in: 1200, tokens_out: 30, cost_usd: 0.5 },
  { kind: 14, ts: '2026-07-12T12:00:04Z' },
];

const stripRow = (label, rss, seen, need) => lines('<button type="button" class="session-strip-row" data-action="goto-tab" data-tab="sessions">',
  `      <span class="session-strip-label">${label}</span>`, `      ${rss}`, `      ${seen}`, `      ${need}`, '    </button>');

const live = '<span class="agent-status live">live</span>';
const noActivity = '<span class="agent-meta-item agent-lastseen">no activity</span>';
const killButton = (pid, started, family) => `<button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="${pid}" data-started="${started}" data-family="${family}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>`;
const procRow = (cls, pid, status, started, seen, rss, cwd, kill) => lines('', `      <div class="agent-instance${cls}">`,
  '        <div class="agent-info">', '          <div class="agent-name">', `            <span class="agent-pid">PID ${pid}</span>`,
  `            ${status}`, `            ${started}`, `            ${seen}`, `            ${rss}`, '          </div>', `          ${cwd}`, '        </div>',
  `        ${kill}`, '      </div>');
const bareProc = (pid, cls = ' stale') => procRow(cls, pid, live, '', noActivity, '', '', killButton(pid, '', ''));
const procInput = { pid: 7, started_at: T0, last_seen_at: '2026-07-12T12:04:00Z', rss_bytes: 4096, cwd: H, name: H, is_orphan: true };

const boardRow = (cls, pids, label, title, who, seen, rss, kill, helpers) => lines('', `      <div class="session-row${cls}">`,
  `        <button type="button" class="session-main" data-action="filter-pids" data-pids="${pids}" data-label="${label}" title="${title}">`,
  `          <span class="session-label">${label}</span>`, `          <span class="agent-pid">${who}</span>`, `          ${seen}`, `          ${rss}`,
  '        </button>', `        ${kill}`, `        ${helpers}`, '      </div>');
const helperBox = (open, pid, summary, rows) => `<details class="session-helpers"${open} data-pid="${pid}"><summary class="session-helpers-sum">${summary}</summary>${rows}</details>`;

const vendor = metric => lines('<div class="fw-promote-vendor">', '    <div class="fw-rule-main">', '      <span class="fw-rule-id">Catch secrets</span>',
  `      <div class="fw-metrics"><span class="fw-metric">${metric} still in monitor — they report leaks but do not stop them</span></div>`, '    </div>',
  '    <button class="btn btn-primary btn-sm" data-action="promote-vendor-keys"><svg class="icon"><use href="#i-arrow"/></svg><span>Promote vendor keys to block</span></button>',
  '  </div>');

const unknownChip = `<span class="harness-chip" title="${E}"><span class="harness-glyph" data-harness-color="hsl(264 62% 62%)" aria-hidden="true">&lt;</span><span class="harness-label">${E}</span></span>`;
const cursorChip = '<span class="harness-chip" title="Cursor"><span class="harness-tile hk-cursor light" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-cursor"/></svg></span><span class="harness-label">Cursor</span></span>';
const policyRow = (main, sub, meta) => `<div class="policy-row"><div class="policy-row-main">${main}</div><div class="policy-row-sub">${sub}</div>`
  + (meta === undefined ? '' : `<span class="policy-row-meta">${meta}</span>`) + '</div>';
const group = (title, rows) => `<section class="policy-harness-group"><div class="policy-harness-title">${title}</div>${rows}</section>`;
const policyList = (kind, groups) => `<div class="policy-list" data-policy="${kind}">${groups}</div>`;
const forget = key => `<button type="button" class="btn btn-ghost btn-sm" data-action="forget-expected" data-key="${key}" aria-label="Remove exception for ${E}: ${E}" disabled>Remove exception</button>`;
const scopeSub = (tail, id, feedback = '') => `Workspace not recorded · executable path Unknown (observed, not signature verified) · ${tail}<br>Saved ${stamp(T0)} · Permission ${id}${feedback}`;

const permission = (id, revision, scope, expiry = '') => `data-action="review-decision" data-id="${id}" data-revision="${revision}" data-decision="expect" data-scope="${scope}"${expiry}`;

const reviewResult = { receipt: { id: H, revision: 4, action: 'expect', at: T0, scope_ids: [H, 'p2'] },
  review: { agent: H, source_ids: [H, 'f2'], context: { resources: [H], session_id: H, workspace: H, destinations: [H, 'b'] }, assessment: { risk: H, reason: H } } };
const resultReceipt = revision => `<p>Decision for evidence revision ${revision} · <time datetime="${T0}">${receiptAt}</time></p>`;
const resultSummary = (label, target, revision, meaning) => `<div class="panel-head"><h2 id="review-result-title">${label}</h2><button type="button" class="btn btn-ghost btn-sm" data-action="dismiss-review-result">Dismiss</button></div>\n`
  + `    <div class="panel-body"><p class="review-result-target">${target}</p>${resultReceipt(revision)}<p>${meaning}</p><button type="button" class="btn btn-ghost btn-sm" data-action="open-review-result">View result</button></div>`;
const noAssessment = '<div class="finding-assessment"><p class="assessment-state">Review state unknown · Exposure unknown · Control outcome unknown</p></div>';
const scopedMeaning = '2 permission scopes recorded. Matching activity remains subject to firewall and payload checks.';

const reviewInput = { id: H, revision: 2, reviewed_revision: 1, count: 3, agent: H, review_state: 'unreviewed',
  context: { resources: [H, 'b'], destinations: [H], session_id: H, workspace: H }, assessment: { risk: 'critical', reason: H },
  evidence_available: true, evidence_flag_available: true, evidence_flag_id: H, source_ids: [H, 's2'], incident_ids: [H],
  available_scopes: [{ kind: 'once' }, { kind: 'session' }, { kind: 'exact', expiry: '24h' }], decision: { action: 'close_reported', revision: 1, at: H } };
const reviewNote = '<p>Expected once records this review only. Future permissions count matching observed activity as expected; they do not bypass firewall or payload checks. They use the recorded executable path, workspace, file and exact endpoint. Executable signatures are not verified. Revoke under Protection → Rules &amp; permissions.</p>';
const noFuture = '<p>Future permission is unavailable because session, workspace, executable or recipient identity is incomplete or the session has ended.</p>';
const sourceExpired = '<p>The source supporting this assessment has expired. The recorded risk remains in history.</p>';
const reviewCard = (cls, head, why, where, reason, future, evidence, conflict, decide, permit, history) => lines(
  `<article class="finding-item ${cls}">`, `    <div class="decision-head">${head}</div>`, `    <p class="finding-why">${why}</p>`,
  `    <p class="finding-why">${where}</p>`, `    <p>${reason}</p>`, `    ${noAssessment}`, `    ${reviewNote}`, `    ${future}`,
  `    ${evidence}`, `    ${conflict}`, `    ${decide}`, `    ${permit}`,
  `    <details><summary>Evidence and review history</summary>${history}</details>`, '  </article>');
const decide = (id, revision, decision, cls, label) => `<button class="btn ${cls} btn-sm" data-action="review-decision" data-id="${id}" data-revision="${revision}" data-decision="${decision}">${label}</button>`;
const reviewLinks = `<button class="btn btn-ghost btn-sm" data-action="open-flag" data-id="${E}">Recorded evidence 1</button>`
  + '<button class="btn btn-ghost btn-sm" data-action="open-flag" data-id="s2">Recorded evidence 2</button>'
  + `<button class="btn btn-ghost btn-sm" data-action="open-incident" data-id="${E}">View report</button>`;

const cases = {
  'actionBarHTML bar and menu': [() => ctx.actionBarHTML([
    { label: H, attrs: 'data-a="1"', title: H, kind: 'primary', bar: true },
    { label: H, attrs: 'data-b="2"', bar: true, disabled: true },
    { label: H, attrs: 'data-c="3"', title: H },
    { label: H, attrs: 'data-d="4"', kind: 'danger', disabled: true },
    null,
  ]), `<button class="btn btn-primary btn-sm" data-a="1" title="${E}">${E}</button><button class="btn btn-ghost btn-sm" data-b="2" disabled>${E}</button>`
    + menu(`<button class="act-menu-item" data-c="3" title="${E}">${E}</button><hr><button class="act-menu-item danger" data-d="4" disabled>${E}</button>`)],
  'actionBarHTML danger only': [() => ctx.actionBarHTML([{ label: 'Kill', attrs: 'data-k="1"', kind: 'danger' }]),
    menu('<button class="act-menu-item danger" data-k="1">Kill</button>')],
  'actionBarHTML none': [() => ctx.actionBarHTML(null), ''],
  'explainActionsHTML': [() => ctx.explainActionsHTML({ id: H, agent: H, explain: {
    actions: [{ id: 'allow-host', body: { host: '1.1.1.1' }, consequence: H, label: H }, { id: 'allow-host', body: { host: '2.2.2.2' } },
      { id: 'allow-host', body: { host: H }, consequence: H, label: H }, { id: 'kill', consequence: H }, { id: 'nope' }],
    egress: [{ org: H, host: '1.1.1.1' }, { org: H, host: '2.2.2.2' }, { org: 'Solo', host: H }],
    assessment: { recommendation_id: 'kill' } } }, [{ label: H, attrs: 'data-action="open-plan"' }]),
  `<button class="btn btn-danger btn-sm" data-action="explain-act" data-flag-id="${E}" data-action-id="kill" title="${E}">Kill ${E}</button>`
    + menu(`<button class="act-menu-item" data-action="open-plan">${E}</button>`
      + `<button class="act-menu-item" data-action="explain-allow-org" data-flag-id="${E}" data-org="${E}" title="Future connections from ${E} to these 2 ${E} addresses are trusted and stop being flagged: 1.1.1.1, 2.2.2.2. This finding is marked reviewed.">Allow ${E} for ${E} · 2 addresses</button>`
      + `<button class="act-menu-item" data-action="explain-act" data-flag-id="${E}" data-action-id="allow-host" data-host="${E}" title="${E}">${E}</button>`)],
  'explainActionsHTML none': [() => ctx.explainActionsHTML({}, []), ''],
  'hbarsHTML': [() => ctx.hbarsHTML([{ label: H, titleAttr: H, value: 5, sub: H, cls: 'crit' }, { label: H, value: 1 }], { format: v => H + v }),
    hbarRow(E, E, 'crit', '100.0', `${E}5`, `<span class="hbar-sub">${E}</span>`) + hbarRow(E, E, '', '20.0', `${E}1`, '')],
  'hbarRowHTML': [() => ctx.hbarRowHTML({ label: H, value: 1 }, 4), hbarRow(E, E, '', '25.0', '1', '')],
  'resourceDiagnosisText summary': [() => ctx.resourceDiagnosisText({ summary: H, code: 'heavy-cpu' }), E],
  'resourceDiagnosisText code': [() => ctx.resourceDiagnosisText({ code: 'heavy-cpu' }), 'High CPU use'],
  'resourceDiagnosisText default': [() => ctx.resourceDiagnosisText({}), 'Resource pressure detected'],
  'resourceDiagnosisText none': [() => ctx.resourceDiagnosisText(null), ''],
  'cappedList more': [() => { const c = ctx.cappedList([H, 'b', 'c'], 1, x => `<i>${x}</i>`, H, null); return [c.more, c.html, c.hidden].join('|'); },
    `${moreButton(E)}|<i>${H}</i>${moreButton(E)}|2`],
  'cappedList open': [() => { const c = ctx.cappedList([1, 2], 1, null, 'k', new Set(['k'])); return [c.more, c.html, c.hidden].join('|'); }, '||0'],
  'sessionWaterfallHTML': [() => ctx.sessionWaterfallHTML(waterfallEvents), lines('<div class="wf">',
    '    <div class="wf-axis"><span>12:00:00</span><span>12:00:04</span></div>',
    `    <div class="wf-row"><span class="wf-name">${E}<span class="wf-dur">1.5s</span></span><span class="wf-track"><span class="wf-bar error" data-left="0.00" data-w="37.50"></span></span></div>`
      + '<div class="wf-row"><span class="wf-name">tool<span class="wf-dur"></span></span><span class="wf-track"><span class="wf-bar" data-left="50.00" data-w="0.40"></span></span></div>'
      + '<div class="wf-row"><span class="wf-name">file · net · guard</span><span class="wf-track"><span class="wf-dot conn" data-left="25.00"></span><span class="wf-dot guard" data-left="0.00"></span><span class="wf-dot " data-left="0.00"></span></span></div>'
      + `<div class="wf-model"><span><b>${E}</b> · 12:00:03</span><span>1.2k in · 30 out · $0.5000</span></div>`
      + '<div class="wf-model"><span><b>model</b> · 12:00:04</span><span>0 in · 0 out</span></div>',
    '  </div>')],
  'sessionWaterfallHTML empty': [() => ctx.sessionWaterfallHTML([]), '<div class="empty"><span>No trace events for this session yet</span></div>'],
  'sessionStripHTML': [() => ctx.sessionStripHTML([{ label: H, rss: 2048, lastSeen: T0, pids: [7] }, { label: 'b', pids: [8] }], 5, NOW, [{ pid: 7 }, { pid: 7, acknowledged: true }]),
    '<div class="session-strip">'
      + stripRow(E, '<span class="session-strip-meta">2 KB</span>', '<span class="session-strip-meta">5m</span>', '<span class="session-strip-need">1</span>')
      + stripRow('b', '', '', '') + '<button type="button" class="session-strip-more" data-action="goto-tab" data-tab="sessions">View all 5</button></div>'],
  'sessionStripHTML none': [() => ctx.sessionStripHTML([], 0, NOW, []), ''],
  'renderProcessRow full': [() => ctx.renderProcessRow(procInput, NOW, true), procRow(' nested orphan', 7, '<span class="agent-status orphan">leftover</span>',
    `<span class="agent-meta-item" title="started ${T0}">12:00:00 · 5m</span>`,
    '<span class="agent-meta-item agent-lastseen" title="last event 2026-07-12T12:04:00Z">active 1m ago</span>',
    '<span class="agent-meta-item">4 KB</span>', `<div class="agent-cwd">${E}</div>`, killButton(7, T0, E))],
  'renderProcessRow bare': [() => ctx.renderProcessRow({ pid: 8 }, NOW), bareProc(8)],
  'sessionBoardHTML': [() => ctx.sessionBoardHTML([
    { root: { pid: 7, cwd: H, name: H, started_at: H, is_orphan: true }, rss: 4096, lastSeen: '2026-07-12T12:04:00Z', label: H, pids: [7, 9], children: [{ pid: 9 }] },
    { root: { pid: 8 }, label: 'b', pids: [8], children: [{ pid: 10 }, { pid: 11 }] },
    { root: { pid: 12, name: 'n' }, label: 'c', pids: [12], children: [] },
  ], NOW, { 7: true }),
  boardRow(' orphan', '7,9', E, E, `${E} · PID 7`, '<span class="agent-meta-item agent-lastseen">active 1m ago</span>', '<span class="agent-meta-item">4 KB</span>',
    killButton(7, E, E), helperBox(' open', 7, '1 helper', bareProc(9, ' nested stale')))
    + boardRow(' stale', '8', 'b', '', ' · PID 8', noActivity, '', killButton(8, '', ''), helperBox('', 8, '2 helpers', bareProc(10, ' nested stale') + bareProc(11, ' nested stale')))
    + boardRow(' stale', '12', 'c', '', 'n · PID 12', noActivity, '', killButton(12, '', 'n'), '')],
  'vendorKeyPromoteHTML one': [() => ctx.vendorKeyPromoteHTML(['a']), vendor('1 vendor-key rule')],
  'vendorKeyPromoteHTML two': [() => ctx.vendorKeyPromoteHTML(['a', 'b']), vendor('2 vendor-key rules')],
  'vendorKeyPromoteHTML none': [() => ctx.vendorKeyPromoteHTML([]), ''],
  'policyListHTML loading': [() => ctx.policyListHTML('guard', null, {}), '<div class="loading">Loading…</div>'],
  'policyListHTML unavailable': [() => ctx.policyListHTML('mute', null, { error: H, label: H, loading: true }),
    `<div class="policy-read-status" role="status"><p>${E}: Unavailable. No successful read yet. ${E}</p><button type="button" class="btn btn-ghost btn-sm" data-action="policy-refresh-report" data-kind="mute" disabled>Refresh ${E}</button></div>`],
  'policyListHTML empty': [() => ctx.policyListHTML('path', [], {}), '<div class="empty"><span>No file exceptions yet. Always allow this file, on a finding, adds one here.</span></div>'],
  'policyListHTML guard': [() => ctx.policyListHTML('guard', [{ decision: 'deny', rule_id: H, agent: H, source: H, created_at: T0 }, { decision: H }], { error: H, lastSuccessAt: Date.parse(T0) }),
    `<div class="policy-read-status" role="status"><p>Guard decisions: Refresh failed. Showing last known records; current status is unavailable. Last successful refresh: ${stamp('2026-07-12T12:00:00.000Z')}. ${E}</p>`
      + '<button type="button" class="btn btn-ghost btn-sm" data-action="policy-refresh-report" data-kind="guard">Refresh guard decisions</button></div>'
      + policyList('guard', group(unknownChip, policyRow(`<span class="policy-decision deny">deny</span> <b>${E}</b> for ${E}`, `Legacy policy · no expiry · ${E}`, stamp(T0)))
        + group('All harnesses', policyRow(`<span class="policy-decision allow">${E}</span> <b></b> for `, 'Legacy policy · no expiry · ')))],
  'policyListHTML path': [() => ctx.policyListHTML('path', [{ path: H, rule_id: H, agent: 'cursor' }], { loading: true }),
    '<p class="policy-read-status" role="status">Refreshing file exceptions…</p>'
      + policyList('path', group(cursorChip, policyRow(`<code>${E}</code>`, `Legacy policy · includes descendants · no expiry · ${E} for cursor`)))],
  'policyListHTML mute': [() => ctx.policyListHTML('mute', [{ host: '*', title: H }, { host: H, agent: H, rule: H }], {}),
    policyList('mute', group(unknownChip, policyRow(`<b>${E}</b>`, `${E} · ${E}`)) + group('All harnesses', policyRow(`<b>${E}</b>`, 'all hosts · all agents')))],
  'policyListHTML expected': [() => ctx.policyListHTML('expected', [
    { key: H, agent: H, reader: 'tool', path: H, dest: 'Example.com', hits: 3 },
    { key: 'k2', agent: H, reader: H, path: H, dest: H, scope: 'file', hits: H },
    { key: 'k3', agent: H, reader: H, path: H, dest: 'a.example', hits: 2 },
    { key: 'k4', agent: H, reader: H, path: H, dest: 'b.example' },
  ], { expectedRemoval: { path: H, agent: H }, loading: true,
    expectedMutations: new Map([['k2', { status: 'unconfirmed' }], ['k3', { status: 'saving' }]]) }),
  `<p role="status">Exception removal saved for <code>${E}</code> (${E}). Remaining exceptions and policies still apply; past activity is unchanged.</p>`
    + '<p class="policy-read-status" role="status">Refreshing expected secret reads…</p>'
    + policyList('expected', group(unknownChip,
      policyRow(`<b>an agent tool</b> reads <code>${E}</code>, then reaches <b>Example.com</b>`, `${E} · legacy policy · no expiry · Legacy provider exception is inactive; review an exact host`, ` ${forget(E)}`)
      + policyRow(`<b>Non-secret file</b> <code>${E}</code>`, `${E} only · all readers and destinations · 0 matches<p role="status">Removal not confirmed. Refresh exceptions before trying again.</p><button type="button" class="link-btn" data-action="policy-refresh">Refresh exceptions</button>`, ' ')
      + policyRow(`<b>${E}</b> reads <code>${E}</code>, then reaches <b>a.example</b>`, `${E} · legacy policy · no expiry · 2 since the daemon started<p role="status">Saving exception removal…</p>`, ` ${forget('k3')}`)
      + policyRow(`<b>${E}</b> reads <code>${E}</code>, then reaches <b>b.example</b>`, `${E} · legacy policy · no expiry · 0 since the daemon started`, ` ${forget('k4')}`)))],
  'policyListHTML scope': [() => ctx.policyListHTML('scope', [
    { id: H, agent: H, operation: 'guard:' + H, resource_path: H, destination: H, workspace: H, reader_exe: H, kind: 'session', session_id: H,
      created_at: T0, applicability: { label: H, revoke: true } },
    { id: 'p2', agent: H, operation: 'read-connect', resource_path: H, expires_at: T0, created_at: T0, applicability: { label: 'Active', revoke: true } },
    { id: 'p3', agent: H, operation: 'other', resource_path: H, created_at: T0, applicability: { label: 'Active', revoke: true } },
    { id: 'p4', agent: H, operation: 'other', resource_path: H, created_at: T0 },
    { id: 'p5', agent: H, operation: 'other', resource_path: H, created_at: T0, applicability: { label: 'Active', revoke: true } },
  ], { loading: true, scopeMutations: new Map([['p2', { status: 'saved' }], ['p3', { status: 'unconfirmed' }], ['p5', { status: 'saving' }]]) }),
  '<p class="policy-read-status" role="status">Refreshing scoped permissions…</p>' + policyList('scope', group(unknownChip,
    policyRow(`<b>${E}</b> · Guarded ${E} access <code>${E}</code> → ${E}`,
      `${E} · executable path ${E} (observed, not signature verified) · ${E} · Session ${E}<br>Saved ${stamp(T0)} · Permission ${E}`,
      `<button type="button" class="btn btn-ghost btn-sm" data-action="permission-session" data-id="${E}">Inspect session</button><button type="button" class="btn btn-ghost btn-sm" data-action="revoke-scope" data-id="${E}" disabled>Revoke</button>`)
    + policyRow(`<b>${E}</b> · Expected read/connect activity <code>${E}</code>`, scopeSub(`Revoked · Expires ${stamp(T0)}`, 'p2', '<p role="status">Revocation saved. Other permissions may still apply; past access is unchanged.</p>'))
    + policyRow(`<b>${E}</b> · Operation unavailable <code>${E}</code>`, scopeSub('Active', 'p3', '<p role="status">Revocation not confirmed. Refresh permissions before trying again.</p><button type="button" class="link-btn" data-action="policy-refresh">Refresh permissions</button>'))
    + policyRow(`<b>${E}</b> · Operation unavailable <code>${E}</code>`, scopeSub('Applicability unknown', 'p4'))
    + policyRow(`<b>${E}</b> · Operation unavailable <code>${E}</code>`, scopeSub('Active', 'p5', '<p role="status">Saving revocation…</p>'),
      '<button type="button" class="btn btn-ghost btn-sm" data-action="revoke-scope" data-id="p5" disabled>Revoke</button>')))],
  'reviewPermissionItems': [() => JSON.stringify(ctx.reviewPermissionItems({ id: H, revision: 3, evidence_available: true,
    available_scopes: [{ kind: 'once' }, { kind: 'session' }, { kind: 'exact', expiry: '7d' }, { kind: 'exact', expiry: '24h' }, { kind: H }] })),
  JSON.stringify([{ label: 'Expected once', attrs: permission(E, 3, 'once') }, { label: 'Expected for this session', attrs: permission(E, 3, 'session') },
    { label: 'Expected for 7 days', attrs: permission(E, 3, 'exact', ' data-expiry="7d"') }, { label: 'Expected for 24 hours', attrs: permission(E, 3, 'exact', ' data-expiry="24h"') }])],
  'reviewPermissionItems default scope': [() => JSON.stringify(ctx.reviewPermissionItems({ id: 'r', revision: 1, evidence_available: true })),
    JSON.stringify([{ label: 'Expected once', attrs: permission('r', 1, 'once') }])],
  'reviewPermissionItems none': [() => JSON.stringify(ctx.reviewPermissionItems({ id: 'r', revision: 0 })), '[]'],
  'reviewResultHTML summary': [() => ctx.reviewResultHTML(reviewResult), resultSummary('Scoped permission recorded', E, 4, scopedMeaning)],
  'reviewResultHTML details': [() => ctx.reviewResultHTML(reviewResult, true), lines(
    `<div class="panel-body"><h3>Scoped permission recorded</h3><p>${E}</p>${resultReceipt(4)}<p>${scopedMeaning}</p>`,
    `    <p>Recorded permission IDs: ${E}, p2</p>`,
    '    <button type="button" class="btn btn-ghost btn-sm" data-action="open-review-result-permissions">View permissions</button>',
    `    <h4>Evidence before this decision</h4><p>${E} · ${E} · ${E}</p>`,
    `      <p>${E}, b</p><p>Recorded risk: ${E}</p><p>${E}</p>${noAssessment}`
      + `<button type="button" class="btn btn-ghost btn-sm" data-action="open-flag" data-id="${E}">Recorded evidence 1</button>`
      + '<button type="button" class="btn btn-ghost btn-sm" data-action="open-flag" data-id="f2">Recorded evidence 2</button></div>')],
  'reviewResultHTML without review': [() => ctx.reviewResultHTML({ receipt: { id: H, revision: 2, action: 'close_reported', at: T0 } }, true), lines(
    `<div class="panel-body"><h3>Closure reported</h3><p>${E}</p>${resultReceipt(2)}<p>Closure was reported; remediation has not been verified.</p>`,
    '    ', '    ', '    <p>The evidence shown before this decision is unavailable. The server receipt remains.</p></div>')],
  'reviewResultHTML review recorded': [() => ctx.reviewResultHTML({ receipt: { id: 'x', revision: 1, action: 'acknowledge', at: T0 }, review: { context: { rule: H } } }, true), lines(
    `<div class="panel-body"><h3>Review recorded</h3><p>${E}</p>${resultReceipt(1)}<p>This records your review of the evidence; it does not establish remediation.</p>`,
    '    ', '    ', '    <h4>Evidence before this decision</h4><p>Unknown agent · Session unknown</p>',
    `      <p>Destination unknown</p><p>Recorded risk: unknown</p><p></p>${noAssessment}</div>`)],
  'reviewHTML full': [() => ctx.reviewHTML(reviewInput, { conflict: true, action: 'close_reported' }), reviewCard('critical',
    `<strong>${E}, b</strong><span class="disp-badge">unreviewed</span>`, `${E} · 3 occurrences · evidence revision 2 · reviewed revision 1`, `${E} · ${E} · ${E}`, E, '',
    `<button class="btn btn-ghost btn-sm" data-action="open-flag" data-id="${E}">View supporting evidence</button>`,
    '<p role="alert">Evidence changed. Your close reported choice is retained. Review the new facts and choose again.</p>',
    `<div class="attention-actions">${decide(E, 2, 'acknowledge', 'btn-primary', 'Mark reviewed')}${decide(E, 2, 'close_reported', 'btn-ghost', 'Report closure')}</div>`,
    `<div class="attention-actions"><button class="btn btn-ghost btn-sm" ${permission(E, 2, 'once')}>Expected once</button>`
      + `<button class="btn btn-ghost btn-sm" ${permission(E, 2, 'session')}>Expected for this session</button>`
      + `<button class="btn btn-ghost btn-sm" ${permission(E, 2, 'exact', ' data-expiry="24h"')}>Expected for 24 hours</button></div>`,
    `<p>close reported · revision 1 · ${E}</p>${reviewLinks}`)],
  'reviewHTML closure reported without actions': [() => ctx.reviewHTML({ ...reviewInput, review_state: 'closed_reported', decision: null }, null, false), reviewCard('critical',
    `<strong>${E}, b</strong><span class="disp-badge">closed reported</span>`, `${E} · 3 occurrences · evidence revision 2 · reviewed revision 1`, `${E} · ${E} · ${E}`, E, '',
    `<button class="btn btn-ghost btn-sm" data-action="open-flag" data-id="${E}">View supporting evidence</button>`, '', '', '',
    `<p>No decision receipt recorded.</p>${reviewLinks}`)],
  'reviewHTML expired evidence': [() => ctx.reviewHTML({ id: 'x', revision: 0, context: { rule: H } }), reviewCard('',
    `<strong>${E}</strong><span class="disp-badge">unreviewed</span>`, 'Unknown agent · NaN occurrences · evidence revision 0',
    'Destination unknown · Session unknown; this source only', '', noFuture, sourceExpired, '',
    '<p>Source evidence has expired. Risk and review history remain; closure has not been verified.</p>', '', '<p>No decision receipt recorded.</p>')],
  'reviewHTML acknowledged': [() => ctx.reviewHTML({ id: 'x', revision: 5, count: 1, review_state: 'acknowledged', evidence_available: true, available_scopes: [{ kind: 'once' }] }),
    reviewCard('', '<strong></strong><span class="disp-badge">acknowledged</span>', 'Unknown agent · 1 occurrences · evidence revision 5',
      'Destination unknown · Session unknown; this source only', '', noFuture, sourceExpired, '',
      `<div class="attention-actions">${decide('x', 5, 'close_reported', 'btn-ghost', 'Report closure')}</div>`,
      `<div class="attention-actions"><button class="btn btn-ghost btn-sm" ${permission('x', 5, 'once')}>Expected once</button></div>`,
      '<p>No decision receipt recorded.</p>')],
};

for (const [name, [render, expected]] of Object.entries(cases)) {
  test(`lib markup: ${name}`, () => {
    assert.equal(inUTC(render), expected);
  });
}

test('lib markup: renderProcessRow escapes a served pid', () => {
  assert.equal(ctx.renderProcessRow({ pid: H }, NOW), bareProc(E));
});

test('lib markup: sessionBoardHTML escapes a served pid', () => {
  assert.equal(ctx.sessionBoardHTML([{ root: { pid: H }, label: 'x', pids: [], children: [{ pid: 1 }] }], NOW),
    boardRow(' stale', '', 'x', '', ` · PID ${E}`, noActivity, '', killButton(E, '', ''), helperBox('', E, '1 helper', bareProc(1, ' nested stale'))));
});

test('lib markup: reviewResultHTML escapes a served revision', () => {
  assert.equal(inUTC(() => ctx.reviewResultHTML({ receipt: { id: 'x', revision: H, action: 'expect', at: T0 } })),
    resultSummary('Expected once', 'x', E, 'This decision records expected activity once. No future permission was created.'));
});
