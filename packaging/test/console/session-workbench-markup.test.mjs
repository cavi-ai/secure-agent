import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact session workbench markup for hostile served values: each value renders
// escaped once in text and attribute positions, and nested fragments render as markup.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const J = '&quot;&lt;img src=x onerror=1&gt;\\&quot;&#39;&amp;amp;&quot;';

const NOW = Date.parse('2026-10-14T12:00:00Z');
class FixedDate extends Date { static now() { return NOW; } }

const ctx = { Date: FixedDate, window: { SA: {} } };
const load = (context, files) => { vm.createContext(context); for (const file of files) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + file, import.meta.url), 'utf8'), context); return context; };
load(ctx, ['lib.js', 'tab-findings.js', 'tab-overview.js', 'session-layout.js', 'session-workbench.js', 'decision-permissions.js']);

const health = { source_state: 'disconnected', capture_error: H, delivery_error: 'recorder-failed', outbox: { persisted: 1, recovered: 0, error: H }, report_error: true };
const live = { report: { harness: H, forwarder_id: H, sequence: 3, session_id: H, ts: H, state: 'error', pending: 2, delivery_failures: 1, dropped: 1, health }, received_at: H, freshness: 'recent' };
const stale = { report: { harness: H, forwarder_id: H, sequence: 1, ts: H, state: 'connected', pending: 1, delivery_failures: 0, dropped: 0 }, received_at: H, freshness: 'stale',
  assessment: { issues: [{ stage: H, code: H, next_action: H }] } };
const times = `<p>Host report time: <time>${E}</time> · Local receipt: <time>${E}</time></p>`;
const recheck = '<p>Check the reporting host, recorder and clocks, then obtain a new report.</p>';
const gap = '<p>The host reports dropped completions. Some evidence may be missing; inspect host diagnostics and retry retained deliveries. Dropped completions may not be recoverable.</p>';
const healthTail = '<p>1 persisted of 2 queued · 0 recovered after host restart. Persisted completions can survive host restart; recorder acceptance does not establish daemon storage.</p><p>A previous health report failed to reach the recorder. This received report shows reporting has resumed.</p>';
const errors = prefix => `<p>${prefix}Capture error: ${E}. Check the reporting host diagnostics.</p><p>${prefix}Delivery error: recorder-failed. Check the recorder and its output storage. Retry retained completions using their original delivery IDs.</p><p>${prefix}Persistence error: ${E}. Check the reporting host diagnostics.</p>`;
const liveHead = state => `<article class="sd-finding"><h5>${E} · ${state} (host reported)</h5><p>Forwarder: ${E} · Report 3 · Host-supplied session: ${E}</p><p>2 queued · 1 delivery failures · 1 dropped. Failure and drop counts are cumulative for this forwarder instance.</p>${times}`;
const staleRow = state => `<article class="sd-finding"><h5>${E} · ${state} (host reported)</h5><p>Forwarder: ${E} · Report 1 · Session ID not supplied</p><p>1 queued · 0 delivery failures · 0 dropped. Failure and drop counts are cumulative for this forwarder instance.</p>${times}<p>Detailed source, delivery and persistence diagnostics are unavailable from this host.</p><p>Last reported ${E} error: ${E}. ${E}</p>${recheck}</article>`;
const hostReports = rows => `<h5>Host reports</h5>${rows}<p>Host reports do not establish complete delivery or protection coverage.</p>`;

const monitorRow = { harness: 'hermes', receipt: { last_received_at: H, accepted: 4 }, reports: [{ report: { forwarder_id: H } }, { report: { forwarder_id: H } }],
  sessions: Array(6).fill({ id: H, repo: H, status: H }), errors: 1, unknown: 0, gaps: 1 };
const monitorHead = '<section class="hook-monitoring" aria-label="Hook monitoring"><h3>Hook monitoring</h3>';
const monitorTail = '<p>Receipt does not confirm durable storage or protection coverage. Retries can count again; silence does not establish a forwarding failure.</p></section>';
const refreshMonitoring = '<button type="button" class="link-btn" data-action="retry-posture">Refresh monitoring</button>';
const since = `<p>Receipts across all sessions since <time>${E}</time> in this daemon run.</p>`;

const ingestionHead = '<details class="sd-findings-head" data-session-part="hook-ingestion"><summary>Daemon hook ingestion · all sessions</summary>';
const counts = `<p>Counts since <time>${E}</time> in this daemon run, across all sessions.</p>`;
const receiptLimits = '<p>Receipt confirms collection, not durable storage or a unique execution. Retries can count again. Silence does not establish a forwarding failure. Errors before the recorder writes a shared record are visible only when the host reports them.</p>';

const ingestion = { available: true, since: '2026-10-14T09:00:00Z', rejected: 0, harnesses: [{ harness: 'hermes', accepted: 7, last_received_at: '2026-10-14T10:00:00Z' }] };
const setupSteps = '<ol><li>Confirm that this source is connected using the integration guide and check the installed recorder’s configuration.</li><li>Observe a real completion during normal use; do not infer execution from configured hooks.</li><li>Refresh this session’s Hooks view and inspect recorded runs, measurements, and delivery reports.</li></ol>';
const setupTail = '<p>These observations do not establish protection coverage. A configured integration or connected source alone does not establish complete hook delivery.</p></section><p><a href="https://github.com/cavi-ai/secure-agent/blob/main/docs/HOOKS.md" target="_blank" rel="noopener noreferrer">Hook integration guide</a></p>';

const evidencePage = { filter: { harness: H, event: H, handler_id: H, config_id: H }, since: H, until: H, truncated: true, rows: [
  { status: H, ts: H, id: H, duration_ms: 1500, chars: 12, evidence: { reason_code: H, action_outcome: H, control_role: H } }, { status: H, ts: H, id: H }] };
const emptyPage = { filter: { harness: H, event: H }, since: H, until: H, truncated: false, rows: [] };
const runHead = `<article class="sd-finding"><h4>${E} · <time>${E}</time></h4><p>Run: ${E}</p>`;
const evidenceTail = '<p>Only normalized metadata is shown. These records do not establish protection coverage.</p></section>';
const evidence = `<section class="sd-hook-evidence"><p>${E} · ${E} · Handler: ${E} · Configuration: ${E}</p><p>Retained completions from <time>${E}</time> to <time>${E}</time>. Evidence is limited to the latest 100 matching runs. Equal timestamps do not establish execution order.</p>${runHead}<p>Reason: ${E} · Duration: 1.5s · Returned characters: 12</p><p>Host-reported action outcome: ${E} · Control role: ${E}</p></article>${runHead}<p>Reason: not reported · Duration: unknown · Returned characters: unknown</p><p>Host-reported action outcome: unknown · Control role: unknown</p></article>${evidenceTail}`;
const emptyEvidence = `<section class="sd-hook-evidence"><p>${E} · ${E} · Handler: unattributed · Configuration: not supplied</p><p>Retained completions from <time>${E}</time> to <time>${E}</time>.  Equal timestamps do not establish execution order.</p><p>No matching retained completions in this window. This does not establish recovery or prove that no hooks ran.</p>${evidenceTail}`;

const scope = { problem: H, explanation: H, after: H, handler: H, config: H, guidance: H };
const baseline = `<section class="sd-hook-evidence"><section class="sd-finding"><h4>Original failure: ${E}</h4><p>${E}</p><p>Last observed failure: <time>${E}</time></p><details><summary>Original failure details</summary><p>Handler: ${E} · Configuration: ${E}</p><p>Original guidance: ${E}</p></details></section>`;
const result = `<section aria-label="Repair check result" role="status"><h4>${E}</h4><p>${E}</p><p>Newest observed completion: <time>${E}</time> · Configuration: `;
const recorded = page => `<details><summary>Recorded runs for the original configuration</summary>${page}</details></section>`;

const finding = { kind: 'execution-errors', harness: 'hermes', event: H, script: H, handler_id: H, config_id: H, title: H, detail: H, next_action: H, count: 4, first_at: H, last_at: H, limits: [H, H], needs_action: true };
const advisory = { kind: H, harness: H, event: H, handler_id: H, title: H, detail: H, next_action: H, count: 1, first_at: H, last_at: H, needs_action: false };
const evidenceButton = eventScope => `<button type="button" class="link-btn" data-action="hook-evidence" data-session="${E}" data-harness="hermes" data-event="${E}" data-event_scope="${eventScope}" data-script="${E}" data-handler="${E}" data-config="${E}">Inspect recorded runs</button>`;
const findingBody = `<p>${E}</p><p><strong>Next action:</strong> ${E}</p>\n    <p>${E} · ${E} · Handler: ${E} · Configuration: ${E}</p>\n    <p>4 observed runs · <time>${E}</time> to <time>${E}</time></p>\n    <p class="sd-context-limit">${E}</p><p class="sd-context-limit">${E}</p><button type="button" class="link-btn" data-action="hook-repair-check" data-session="${E}" data-harness="hermes" data-event="${E}" data-event_scope="exact" data-handler="${E}" data-config="${E}" data-script="${E}" data-after="${E}" data-problem="${E}" data-explanation="${E}" data-guidance="${E}">Check repair</button>${evidenceButton('exact')}`;
const advisoryBody = `<p>${E}</p><p><strong>Next action:</strong> ${E}</p>\n    <p>${E} · Handler: ${E}</p>\n    <p>1 observed runs · <time>${E}</time> to <time>${E}</time></p>\n    `;
const healthHead = '<section data-session-part="hook-health" class="sd-findings-head"><h4>Hook findings</h4>';
const healthUnavailable = healthHead + '<p role="status">Hook assessment unavailable. Refresh current session status to retry.</p></section>';

const hookRow = { harness: 'hermes', event: H, script: H, handler_id: H, config_id: H, runs: 4, errors: 1, blocks: 0, cancelled: 1, chars: 1500, total_ms: 2500, duration_samples: 2, char_samples: 4, last_at: H };
const plainRow = { event: H, script: '', runs: 1, errors: 0, blocks: 1, chars: 0, total_ms: 0, last_at: H };
const retryHooks = '<button type="button" class="link-btn" data-action="session-hooks-retry">Retry hooks</button>';
const hooksHead = notice => healthUnavailable + ingestionHead + '<p>Ingestion diagnostics unavailable.</p></details><header data-session-part="hooks-head"><h4>Hook history</h4><button type="button" class="link-btn" data-action="hook-setup">Hook setup and verification</button><p>Recorded completions from session transcripts and connected hosts. Errors and cancellations are separate. Blocks can be expected protection or validation decisions. Cumulative runtime can include overlapping callbacks. Outcome counts are historical; current repair findings are assessed separately. Measurement sorts use reported totals; unknown values sort last.</p>' + `<p role="status">${notice}</p></header>`;
const hookControls = `<div class="sd-hook-controls" data-session-part="hooks-controls" role="group" aria-label="Filter hook history">
    <label>Search hook history<input type="search" maxlength="256" data-hook-history="query" placeholder="Event, script or handler ID"></label>
    <label>Outcome<select data-hook-history="outcome"><option value="all">All outcomes</option><option value="errors">Execution errors</option><option value="blocks">Blocks</option><option value="cancelled">Cancellations</option></select></label>
    <label>Sort by<select data-hook-history="sort"><option value="runs">Most runs</option><option value="total_ms">Cumulative runtime</option><option value="chars">Returned characters</option></select></label>
    <button type="button" class="link-btn" data-action="hook-history-clear">Clear filters</button></div>`;
const td = (label, value) => `<td role="cell" data-label="${label}">${value}</td>`;
const hookRows = `<tr class="sd-hook-failed" role="row" data-row-id="[&quot;hermes&quot;,${J},${J},${J},${J}]">
      ${td('Event', E)}${td('Handler', `${E}<details><summary>Handler details</summary><p>Handler: ${E}<br>Configuration: ${E}</p></details>${evidenceButton('group')}`)}
      ${td('Runs', 4)}${td('Errors', 1)}${td('Blocked', 0)}${td('Cancelled', 1)}
      ${td('Chars returned', '1.5k')}${td('Cumulative runtime', '2.5s (2/4 measured)')}</tr><tr role="row" data-row-id="[&quot;&quot;,${J},&quot;&quot;,&quot;&quot;,&quot;&quot;]">
      ${td('Event', E)}${td('Handler', 'not recorded<details><summary>Handler details</summary><p>Handler: identity unavailable<br>Configuration: not supplied</p></details>')}
      ${td('Runs', 1)}${td('Errors', 0)}${td('Blocked', 1)}${td('Cancelled', 0)}
      ${td('Chars returned', 'unknown')}${td('Cumulative runtime', 'unknown')}</tr>`;
const hookTable = `<div class="sd-hooks-scroll" data-session-part="hooks-table" role="region" aria-label="Hook history" tabindex="0"><table class="sd-hooks" role="table"><thead role="rowgroup"><tr role="row">
      <th scope="col" role="columnheader">Event</th><th scope="col" role="columnheader">Handler</th><th scope="col" role="columnheader">Runs</th><th scope="col" role="columnheader">Errors</th>
      <th scope="col" role="columnheader">Blocked</th><th scope="col" role="columnheader">Cancelled</th><th scope="col" role="columnheader">Chars returned</th><th scope="col" role="columnheader">Cumulative runtime</th>
    </tr></thead><tbody role="rowgroup">${hookRows}</tbody></table></div>`;

const recentSession = { id: H, repo: H, branch: H, harness: 'codex', status: H };
const recentRow = status => `<div class="session-daily-row"><button type="button" class="session-daily-card" data-action="session-current" data-session="${E}" title="Session ${E}">
    <span class="session-daily-workspace"><strong>${E}</strong><small title="${E}">${E}</small></span>
    <span class="session-daily-identity"><span class="harness-chip" title="Codex"><span class="harness-tile hk-codex" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-codex"/></svg></span></span><span>Codex</span></span>
    <span class="session-daily-status" data-status="${status}">${status}</span>
    <time datetime="" title="Activity time unavailable">—</time>
  </button><button type="button" class="btn btn-ghost btn-sm session-daily-results" data-action="recent-session-results" data-session="${E}" aria-label="Review results for ${E} · ${E}">Results<svg class="icon" aria-hidden="true"><use href="#i-arrow"/></svg></button></div>`;

const coverageHead = '<header class="sd-coverage-head"><h5>Observed paths</h5><button type="button" class="link-btn" data-action="session-overview-retry">Refresh observations</button></header>';
const guardIntro = '<p>Guard observations record invocations attributed to this session. No invocation observed does not by itself establish a broken installation.</p>';
const guardTail = '<p>An installed-hook check establishes its manual monitor round trip. It does not prove that a running session invokes the guard or that traffic is inspected. Hook-completion reporting is a separate integration.</p>';

const ago = ms => new Date(NOW - ms).toISOString();
const chip = (key, name, label) => `<span class="harness-chip" title="${name}"><span class="harness-tile hk-${key}" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-${key}"/></svg></span>${label ? `<span class="harness-label">${name}</span>` : ''}</span>`;
const EID = `${E}@${E} · ${E}`;
const railCard = ({ cls, id, pressed = false, title, aria = title, label, branch, status, seen, kill = '' }) => `<div class="session-card ${cls}">
    <button type="button" class="sc-main" data-action="select-session" data-id="${id}" aria-pressed="${pressed}" title="${title}" aria-label="${aria}">
      <span class="sc-pulse ${status}" aria-hidden="true"></span><span class="sc-identity"><span class="sc-label">${label}</span>${branch ? `<span class="sc-branch">${branch}</span>` : ''}</span>
      <span class="sc-meta"><span class="sr-only">${status}</span>${seen ? `<span>${seen}</span>` : ''}</span>
    </button>${kill}
  </div>`;
const railSession = { id: H, status: H, repo: H, branch: H, origin: H, harness: H, root_pid: 7, last_seen_at: ago(9000e3) };
const killMenu = `<details class="sc-actions"><summary aria-label="Actions for ${EID}">Actions</summary><div><button type="button" class="btn btn-danger btn-sm sc-kill" data-action="kill" data-pid="7" data-started="${E}" data-family="${E}">Terminate session</button></div></details>`;
const dupLater = { id: 'b', status: 'ended', repo: H, branch: H, origin: H, started_at: '2026-10-14T10:30:00' };
const dupEarlier = { id: H, status: 'idle', repo: H, branch: H, origin: H, started_at: '2026-10-14T09:05:00' };
const dupRow = (cls, key, expanded, bucket, pulse, title, label, count, secondary, members) => `<div class="session-dup ${cls}">
    <button type="button" class="session-dup-toggle" data-action="toggle-session-dup" data-key="${key}" aria-expanded="${expanded}"${bucket}>
      <span class="sc-head"><span class="sc-pulse ${pulse}" aria-hidden="true"></span><span class="sc-label" title="${title}">${label}</span><span class="session-dup-count">×${count}</span><svg class="icon"><use href="#i-arrow"/></svg></span>
      <span class="sc-meta"><span class="sc-branch">${secondary}</span></span>
    </button>${members}
  </div>`;
const dupMembers = railCard({ cls: 'ended selected nested', id: 'b', pressed: true, title: EID, aria: `${EID}, 10:30`, label: '10:30', branch: E, status: 'ended' })
  + railCard({ cls: 'idle nested', id: E, title: EID, aria: `${EID}, 09:05`, label: '09:05', branch: E, status: 'idle' });
const familyRow = '<div class="session-family">' + railCard({ cls: 'active', id: 'p', title: 'api', label: 'api', status: 'active' })
  + railCard({ cls: 'ended nested', id: E, title: E, label: E, status: 'ended' }) + '</div>';
const groupShell = (key, open, summary, ended) => `<details class="session-group" data-harness="${key}"${open}>
    <summary class="session-group-head">${summary}<svg class="icon session-group-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></summary>
    <div class="session-group-body"><div class="session-rows"></div>${ended}</div>
  </details>`;
const endedTail = `<div class="session-ended open">
        <button type="button" class="session-ended-toggle" data-action="toggle-ended-sessions" data-harness="${E}" aria-expanded="true">Ended (2) <svg class="icon"><use href="#i-arrow"/></svg></button>
        <div class="session-ended-body"></div>
      </div>`;
const emptyHead = '<div class="empty session-empty"><svg class="icon"><use href="#i-agent"/></svg><div>';

const memRow = (day, id, at, full, time, source, strong, rest) => `${day}<article class="sm-row" data-row-id="${id}">
      <div class="sm-marker"><time datetime="${at}" title="${full}" aria-label="${full}">${time}</time><span class="sm-source">${source}</span></div>
      <div class="sm-content"><strong>${strong}</strong>${rest}</div>
    </article>`;
const memoryRows = [{ kind: 'flag', source_id: 'f-1', title: H, id: H, at: H, detail: H, severity: H, status: H }, { kind: H, title: H, at: '2026-10-14T09:05:07' },
  { kind: 'incident', source_id: 'i-1', title: H, id: 'r3', at: '2026-10-14T09:06:00' }];
const memoryList = memRow('<div class="sm-day">Date unavailable</div>', E, E, 'Time unavailable', 'Time unavailable', 'Flag',
  `<button type="button" class="link-btn sm-source-link" data-action="open-flag" data-id="f-1" aria-label="View finding evidence: ${E}" title="View finding evidence">${E}</button>`,
  `<p>${E}</p><div class="sm-chips"><span class="sm-chip">${E}</span><span class="sm-chip">${E}</span></div>`)
  + memRow('<div class="sm-day">2026-10-14</div>', '', '2026-10-14T09:05:07', '2026-10-14 09:05:07', '09:05:07', 'Activity', E, '<div class="sm-chips"></div>')
  + memRow('', 'r3', '2026-10-14T09:06:00', '2026-10-14 09:06:00', '09:06:00', 'Incident',
    `<button type="button" class="link-btn sm-source-link" data-action="open-incident" data-id="i-1" aria-label="View incident report: ${E}" title="View incident report">${E}</button>`, '<div class="sm-chips"></div>');

const traceHealth = text => `<div class="sm-state" data-session-part="trace-health" role="status"${text ? '' : ' hidden'}>${text}</div>`;
const traceEmpty = traceHealth('') + '<div class="empty"><span>No trace events for this session yet</span></div>';
const waterfall = `<div class="wf">
    <div class="wf-axis"><span>09:00:00</span><span>09:00:00</span></div>
    <div class="wf-row"><span class="wf-name">${E}<span class="wf-dur">10ms</span></span><span class="wf-track"><span class="wf-bar error" data-left="0.00" data-w="100.00"></span></span></div>
  </div>`;

const overviewHead = status => `<div class="sd-current-head" data-session-part="current-head"><h4 tabindex="-1">Current session status</h4>${status ? `<p class="sd-current-status" role="status">${status}</p>` : ''}</div>`;
const ingestionUnavailable = ingestionHead + '<p>Ingestion diagnostics unavailable.</p></details>';
const noCoverage = '<p>No current coverage is attributed to this session. Retained events do not establish live protection.</p>';
const findingsHead = (text, id) => `<div class="sd-findings-head" data-session-part="findings-head"><h4>Retained findings</h4><p>${text}
      <button type="button" class="link-btn" data-action="session-findings" data-id="${id}">View session findings history</button></p></div>`;
const overviewData = { session_id: H, requests: [{ kind: 'guard', id: H, detail: H, scopeText: H }],
  resources: { key: H, process_count: 3, control: { state: H, last_error: H }, diagnoses: [{ summary: H }, {}] },
  findings: [{ id: H, title: H, assessment: { risk: H, reason: H, review_state: 'reviewed', residual_risk: H, control: 'blocked', evidence_basis: ['os-read', H], limits: [H], advice: { assessment: H, confidence: 0.5, rationale: H } } }] };
const overviewFull = overviewHead(`Last known session status. Refresh failed; requests and measurements may have changed. <button type="button" class="link-btn" data-action="session-overview-retry" disabled>Retrying current status…</button>`)
  + `<fieldset class="sd-request" data-session-part="request:${E}" disabled>
      <legend>Access request</legend><p>${E}</p>
      <p class="sd-context-limit">${E}</p><button class="btn btn-ghost btn-sm" data-action="guard-resolve" data-id="${E}" data-verdict="allow" data-scope="once">Allow once</button><button class="btn btn-danger btn-sm" data-action="guard-resolve" data-id="${E}" data-verdict="deny" data-scope="once">Deny</button>
    </fieldset>` + healthUnavailable + ingestionUnavailable
  + `<section class="sd-coverage" data-session-part="coverage" aria-label="Observed session coverage"><header class="sd-coverage-head"><h5>Observed paths</h5><button type="button" class="link-btn" data-action="session-overview-retry" disabled>Refreshing observations…</button></header>${noCoverage}</section>`
  + `<fieldset class="sd-impact" data-session-part="impact" disabled><legend>Machine impact</legend><p>— memory · — CPU · 3 processes</p>
    <p>Control: ${E} · ${E}</p>
    <p>${E}</p><p></p>
    <button type="button" class="link-btn" data-action="view-family" data-key="${E}">Inspect session resources</button></fieldset>`
  + findingsHead('Review and remaining risk are shown separately.', E)
  + `<article class="sd-finding" data-session-part="finding:${E}"><h5>${E}</h5><p>Risk: ${E} · ${E}</p><div class="finding-assessment"><p class="assessment-state">Reviewed · Exposure unknown · Blocked</p><details class="assessment-limits"><summary>Evidence and limits</summary><ul><li>OS file read</li><li>${E}</li><li>${E}</li></ul></details><p class="assessment-advice">Advisor opinion: ${E} (50%) · ${E}</p></div>
    <button type="button" class="link-btn" data-action="open-flag" data-id="${E}">View evidence</button></article>`;

const sourcesOK = { available: true, at_limit: false, limit: 50 };
const followData = { session_id: H, observed_at: H, history: {
  reviews: [{ id: H, revision: 3, decision: { action: 'expect', revision: 2, scope_ids: [H] }, context: { rule: H }, evidence_available: true, evidence_flag_available: true, evidence_flag_id: H }],
  interventions: [{ id: H, status: 'failed', kind: H, verification: H, error: H, limits: [H] }],
  incidents: [{ id: H, remediation: { steps: [{ id: H, status: 'reported', item: { name: H, action: H }, newer_evidence: true }] } }],
  guards: [{ id: H, session_id: H, verdict: 'allow', scope: 'exact', scope_ids: [H, 'missing'], rule_id: H, at: H }],
  evidence: { reviews: sourcesOK, interventions: sourcesOK, incidents: { ...sourcesOK, at_limit: true }, guards: sourcesOK } } };
const followPermissions = { records: [{ id: H, resource_path: H, expires_at: H, revoked_at: H, applicability: { label: H, revoke: true } }], readAt: H };
const unknownPermission = '<li>Current status unknown. The record is missing or unavailable; expiry or revocation cannot be established.</li>';
const permissionRecord = `<li><strong>${E}</strong> · <code>${E}</code><p>Expires Time unavailable</p><p>Revoked Time unavailable</p></li>`;
const refreshResults = '<button type="button" class="link-btn" data-action="session-outcomes-retry">Refresh results</button>';
const retryResults = '<button type="button" class="link-btn" data-action="session-outcomes-retry">Retry results</button>';
const partialNote = '<p>Follow-up uses missing or bounded history. Other work may be absent.</p>';
const followGroup = (key, title, rows, n) => `<div data-row-id="follow-up:group:${key}"><details data-session-details data-follow-up-group="${key}"><summary>${title}<span>${n}</span></summary><ul>${rows}</ul></details></div>`;
const followSection = (button, status, partial, empty, groups, permission) => `<section class="sd-follow-up" data-session-part="follow-up" aria-label="Session follow-up">
    <div class="sd-follow-up-head"><h4>Needs follow-up</h4>${button}</div>
    ${status}
    ${partial}
    ${empty}
    ${groups}
    ${permission}
  </section>`;
const followFull = followSection(refreshResults, '<p>Results read at Time unavailable</p>', partialNote, '',
  followGroup('evidence', 'New evidence', `<li data-row-id="follow-up:review:${E}"><strong>${E}</strong><p>Decision for revision 2 · now revision 3. The saved decision does not cover this evidence.</p><button type="button" class="link-btn" data-action="open-flag" data-id="${E}">Review newer evidence</button></li>`, 1)
  + followGroup('actions', 'Actions to check', `<li data-row-id="follow-up:control:${E}" data-follow-up-id="${E}"><strong>Check process result</strong><details class="resource-action-result"><summary>${E} · Failed · Verification unknown</summary><p>${E}</p><ul><li>${E}</li></ul></details><p>Inspect the recorded result before deciding whether another action is needed.</p></li>`
    + `<li data-row-id="follow-up:incident:${E}:${E}"><strong>${E} · ${E}</strong><p>Action reported, not technically verified. Newer evidence exists; this report does not cover it.</p><button type="button" class="link-btn" data-action="open-incident" data-id="${E}">Review incident report</button></li>`, 2)
  + followGroup('permissions', 'Permissions from decisions', `<li data-row-id="follow-up:permission:review:${E}"><strong>${E}</strong><ul>${permissionRecord}</ul><button type="button" class="link-btn" data-action="session-permissions" data-review="${E}" data-session="${E}">Inspect permissions</button></li>`
    + `<li data-row-id="follow-up:permission:guard:${E}"><strong>${E}</strong><ul>${permissionRecord}${unknownPermission}</ul><button type="button" class="link-btn" data-action="session-guard-permissions" data-id="${E}" data-session="${E}">Inspect permissions</button></li>`, 2),
  '<p>Permissions read at Time unavailable. Applicability can change; inspect before relying on access.</p>');
const followLoadingData = { session_id: H, history: { reviews: [{ id: 'r', revision: 1, decision: { revision: 1, scope_ids: ['p'] }, context: {} }], interventions: [], incidents: [], guards: [],
  evidence: { reviews: sourcesOK, interventions: sourcesOK, incidents: sourcesOK, guards: sourcesOK } } };

const outcomeData = { session_id: H, history: {
  reviews: [{ id: H, revision: 2, decision: { action: 'expect', revision: 2, scope_ids: [H], at: H }, context: { rule: H }, assessment: { residual_risk: H }, evidence_available: false, evidence_flag_available: false },
    { id: 'r2', revision: 5, decision: { action: H, revision: 4, at: H }, evidence_available: true, evidence_flag_available: true, evidence_flag_id: H }],
  interventions: [{ id: H, status: 'cancelled', kind: 'stop', verification: 'pending', requested_at: H }],
  incidents: [{ id: H, remediation: { steps: [{ id: 's1', status: 'reported', reported_at: H, item: { name: H, action: H }, verification: H, newer_evidence: true }, { id: 's2', status: 'open', item: {} }] } }],
  guards: [{ id: H, session_id: H, verdict: 'allow', scope: 'exact', scope_ids: [H], rule_id: H, reason: H, at: H }, { id: 'g2', verdict: 'deny', scope: H, rule_id: H, at: H }],
  evidence: { reviews: { ...sourcesOK, available: false }, interventions: { available: true, at_limit: true, limit: 25 }, incidents: sourcesOK, guards: { ...sourcesOK, limit: 10 } } } };
const outcomesHead = notice => `<header data-session-part="outcomes-head"><h4>Decisions and results</h4><p>Saved decisions and action receipts. They do not prove task completion or tool access. Review payload outcomes in Evidence.</p><p role="status">${notice}</p></header>`;
const outcome = (key, title, body) => `<article class="sd-outcome" data-session-part="${key}" data-row-id="${key}"><h5>${title}</h5>Time unavailable${body}</article>`;
const outcomesStale = followSection(refreshResults, '<p role="status">Last known follow-up. Refresh must succeed before relying on these records.</p>', partialNote, '',
  followGroup('evidence', 'New evidence', '<li data-row-id="follow-up:review:r2"><strong>Finding review</strong><p>Decision for revision 4 · now revision 5. The saved decision does not cover this evidence.</p><p>Refresh results before reviewing newer evidence.</p></li>', 1)
  + followGroup('actions', 'Actions to check', `<li data-row-id="follow-up:incident:${E}:s1"><strong>${E} · ${E}</strong><p>Action reported, not technically verified. Newer evidence exists; this report does not cover it.</p></li>`, 1)
  + followGroup('permissions', 'Permissions from decisions', `<li data-row-id="follow-up:permission:review:${E}"><strong>${E}</strong><ul>${unknownPermission}</ul></li><li data-row-id="follow-up:permission:guard:${E}"><strong>${E}</strong><ul>${unknownPermission}</ul></li>`, 2),
  '<p>Permission status unavailable. Inspect permissions to retry the current scope and expiry.</p>')
  + outcomesHead(`Last known results. Refresh failed; later decisions or observations may be missing. ${retryResults}`)
  + `<div data-session-part="outcomes-limits"><p role="status">Review decisions unavailable. Showing last known receipts; later changes may be missing.</p><p>Process results: bounded to 25 retained records; earlier history may be omitted.</p>${retryResults}</div>`
  + outcome(`decision:${E}`, 'Scoped permission recorded', `<p>${E} · decision for revision 2</p><p>1 permission scope recorded. Inspect current expiry or revocation for this decision. <button type="button" class="link-btn" data-action="session-permissions" data-review="${E}" data-session="${E}">View permissions</button></p><p>Remaining risk: ${E}</p><p>Source evidence unavailable; the saved receipt remains.</p>`)
  + outcome('decision:r2', 'Saved decision', `<p>Finding · decision for revision 4</p><p>This decision does not cover newer evidence.</p><p>Remaining risk: unknown</p><button type="button" class="link-btn" data-action="open-flag" data-id="${E}">View finding evidence</button>`)
  + outcome(`guard:${E}`, 'Guard allowed', `<p>${E} · exact · ${E}</p><p>Recorded request outcome; tool receipt and completed access are not verified.</p><button type="button" class="link-btn" data-action="session-guard-permissions" data-id="${E}" data-session="${E}">View permissions</button>`)
  + outcome('guard:g2', 'Guard denied', `<p>${E} · ${E}</p><p>Recorded request outcome; tool receipt and completed access are not verified.</p><p>No future permission IDs recorded with this outcome. Other permissions may still apply.</p>`)
  + outcome(`incident:${E}:s1`, 'External action reported', `<p>${E} · ${E}</p><p>Credential verification: ${E}</p><p>Newer evidence exists; this report does not establish its remediation.</p><button type="button" class="link-btn" data-action="open-incident" data-id="${E}">View incident report</button>`)
  + outcome(`intervention:${E}`, 'Process control', '<details class="resource-action-result"><summary>stop · Cancelled · Observing up to 3 samples / 15 seconds</summary><ul></ul></details>');

const detailSession = { id: H, harness: 'codex', repo: H, branch: H, workspace: H, confidence: H, started_at: ago(9000e3), ended_at: ago(90e3) };
const detailContext = (id, harness, rest) => `<section class="session-context" data-session-part="session-context" aria-label="Session context">
      <button type="button" class="btn btn-sm btn-ghost" data-action="session-events" data-id="${id}" title="Inspect retained file, connection, and tool events attributed to this session">View session events</button>
      <details class="session-metadata" data-session-details>
        <summary>Details</summary>
        <div class="sd-metadata-body">
          <span class="sd-harness">${harness}</span>
          ${rest}
        </div>
      </details>
    </section>`;
const noDetails = '\n          \n          ';
const viewButton = (view, label, active) => `<button type="button" class="sd-view${active ? ' active' : ''}" data-action="session-view" data-view="${view}" aria-pressed="${active}">${label}</button>`;
const detailFrame = (home, id, workspace, chipHTML, title, view, body) => `<div class="session-detail-chrome">
    <div class="session-detail-actions">
      ${home}
      <button type="button" class="btn btn-sm btn-ghost sd-back" data-action="session-list">Back to sessions</button>
      <button type="button" class="btn btn-sm btn-ghost sd-status" data-action="session-status">Current status</button>
      <button type="button" class="btn btn-sm btn-ghost sd-export" data-action="copy-report" data-id="${id}" title="Copy this session's report as markdown"><svg class="icon"><use href="#i-copy"/></svg>Copy report</button>
      ${workspace}
    </div>
    <div class="session-detail-head">
      ${chipHTML}
      <h3 tabindex="-1">${title}</h3>
    </div>
    <div class="sd-detail-controls">
      <div class="sd-view-switch" role="group" aria-label="Session detail view">
        ${viewButton('memory', 'Evidence', view === 'memory')}
        ${viewButton('results', 'Results', view === 'results')}
        ${viewButton('trace', 'Trace', view === 'trace')}
        ${viewButton('hooks', 'Hooks', view === 'hooks')}
      </div>
      <button type="button" class="btn btn-sm btn-ghost sd-latest" data-action="session-latest" hidden>Jump to latest</button>
    </div>
    </div>
    <div class="session-detail-body" tabindex="-1">${body}</div>`;
const workspacePermissions = id => `<button type="button" class="btn btn-sm btn-ghost" data-action="workspace-permissions" data-session="${id}">Workspace permissions</button>`;
const withRecentWork = render => () => { ctx.window.SA.recentWorkReturn = true; try { return render(); } finally { delete ctx.window.SA.recentWorkReturn; } };

// The legacy process-tree board's empty states, written by the workbench's render.
function legacyBoard(harnessFilter) {
  const board = {};
  const context = load({ Date: FixedDate, window: { SA: { t: {}, harnessFilter, setTabBadge() {} }, addEventListener() {}, matchMedia: () => ({ matches: false }) },
    document: { getElementById: id => id === 'session-rail' ? { dataset: {} } : id === 'session-board' ? board : null, querySelectorAll: () => [] } },
  ['lib.js', 'session-layout.js', 'session-workbench.js']);
  context.createSessionWorkbench({ apiFetch() {}, renderNow() {} }).render();
  return board.innerHTML;
}

const cases = {
  'forwarders with limit': [() => ctx.hookForwardersHTML([live, stale], true, false), hostReports('<p>Only the 128 most recently received forwarder instances are retained; other reports may be omitted.</p>'
    + liveHead('Forwarding error') + '<p>Source disconnected (host reported). Check the host subscription and restore the source connection.</p>' + errors('') + healthTail + gap + '</article>'
    + staleRow('Report stale; current connection state unknown'))],
  'forwarders read failed': [() => ctx.hookForwardersHTML([live], false, true), hostReports(liveHead('Report freshness unverified; current connection state unknown')
    + '<p>Last reported diagnostics follow; their current state is unknown.</p>' + errors('Last reported ') + healthTail + recheck + gap + '</article>')],
  'monitoring row': [() => ctx.hookMonitoringHTML({ available: true, stale: false, since: H, rejected: 2, truncated: true, rows: [monitorRow] }), monitorHead + since
    + `<article class="hook-monitoring-row" data-hook-runtime="hermes"><h4>Hermes</h4><p>Last completion receipt: <time>${E}</time> · 4 accepted deliveries.</p><p>1 host with active errors · 1 host reporting no active error.</p><p>Evidence gap: 1 host instance reported drops. Missing evidence may be unrecoverable.</p><div class="hook-monitoring-actions"><details data-hook-disclosure="hosts:hermes"><summary>Inspect 2 forwarding hosts</summary>`
    + `<button type="button" class="link-btn" data-action="hook-delivery-inspect" data-id="${E}">Inspect delivery · ${E}</button>`.repeat(2)
    + '</details><details data-hook-disclosure="sessions:hermes"><summary>6 retained sessions</summary>' + `<button type="button" class="link-btn" data-action="hook-session-open" data-session="${E}">Open session hooks · ${E} · ${E}</button>`.repeat(5)
    + '<button type="button" class="link-btn" data-action="goto-tab" data-tab="sessions">View all sessions</button></details><button type="button" class="link-btn" data-action="hook-setup" data-harness="hermes">Setup and verification</button></div></article>'
    + '<p>2 rejected shared records; rejections cannot be attributed to a runtime or session. Review the reporting host diagnostics.</p><p>Other forwarding instances may be omitted from the retained reports.</p>' + monitorTail],
  'monitoring unavailable': [() => ctx.hookMonitoringHTML({ available: false, stale: false, rejected: 0, truncated: false, rows: [{ harness: 'codex', receipt: null, reports: [], sessions: [], errors: 0, unknown: 0, gaps: 0 }] }),
    monitorHead + '<p role="status">Ingestion diagnostics unavailable. Current receipt and forwarding states are unknown.</p>' + refreshMonitoring
    + '<article class="hook-monitoring-row" data-hook-runtime="codex"><h4>Codex</h4><p>Completion receipt unavailable.</p><p>Forwarding state unknown; no host report received.</p><div class="hook-monitoring-actions"><button type="button" class="link-btn" data-action="hook-setup" data-harness="codex">Setup and verification</button></div></article>' + monitorTail],
  'monitoring stale empty': [() => ctx.hookMonitoringHTML({ available: true, stale: true, since: H, rejected: 0, truncated: false, rows: [] }), monitorHead
    + '<p role="status">Last loaded observations; current receipt and forwarding states are unknown. Refresh telemetry to retry.</p>' + refreshMonitoring + since + '<p>No supported runtimes observed in retained sessions or hook diagnostics.</p>' + monitorTail],
  'ingestion stale': [() => ctx.hookIngestionHTML({ available: true, since: H, rejected: 3, last_rejected_at: H, harnesses: [{ harness: H, accepted: 5, last_received_at: H }], forwarders: [] }, { error: true }),
    ingestionHead + '<p role="status">Showing the last loaded ingestion diagnostics; they may be out of date.</p>' + counts + `<p>${E}: 5 accepted deliveries · Last local receipt: <time>${E}</time></p><p>3 rejected shared hook records · Last rejection: <time>${E}</time></p>`
    + '<p>Check the forwarding host and recorder diagnostics, validate the shared record format, then retry retained completions with their original delivery IDs. Rejected records cannot be attributed to a session or harness.</p>' + receiptLimits + '<p>No host health reports received. Host connectivity is unknown.</p></details>'],
  'ingestion with host report': [() => ctx.hookIngestionHTML({ available: true, since: H, rejected: 0, harnesses: [], forwarders: [stale] }), ingestionHead + counts
    + '<p>No hook deliveries observed in this daemon run.</p><p>No recognized shared hook records rejected.</p>' + receiptLimits + hostReports(staleRow('Report stale; current connection state unknown')) + '</details>'],
  'ingestion unavailable': [() => ctx.hookIngestionHTML(null), ingestionHead + '<p>Ingestion diagnostics unavailable.</p></details>'],
  'setup with receipt': [() => ctx.hookSetupHTML('hermes', ingestion), '<section class="sd-finding"><h4>Hermes</h4><p>Your Hermes host must forward individual plugin handler completions after native response normalization. Gateway hook dispatchers are outside this adapter’s scope.</p>'
    + setupSteps + '<p>Last daemon receipt: 2026-10-14T10:00:00Z · 7 accepted deliveries in this daemon run. Receipt does not confirm durable storage.</p>' + setupTail],
  'setup without receipt': [() => ctx.hookSetupHTML('claude', null), '<section class="sd-finding"><h4>Claude Code</h4><p>Secure Agent reads retained hook completions from Claude Code transcripts. Check that the daemon can read this session’s transcript. Stable registered-handler identity is unavailable in these records.</p>'
    + setupSteps + '<p>No daemon receipt is available for this source. Connection and delivery remain unknown.</p>' + setupTail],
  'setup unknown runtime': [() => ctx.hookSetupHTML(H, null), '<p>Hook integration guidance is unavailable for this runtime.</p>'],
  'evidence rows': [() => ctx.hookEvidenceHTML(evidencePage), evidence],
  'evidence empty': [() => ctx.hookEvidenceHTML(emptyPage), emptyEvidence],
  'diagnostic preview': [() => ctx.hookDiagnosticPreviewHTML(H), `<details class="hook-diagnostic-preview"><summary>Preview diagnostic summary</summary><label>Diagnostic summary<textarea readonly rows="10" spellcheck="false">${E}</textarea></label><p>Only normalized metadata is included. Review this snapshot before sharing it.</p></details><p id="hook-diagnostic-status" role="status"></p>`],
  'repair loading': [() => ctx.hookRepairHTML(scope, null, H), `${baseline}<p role="status">${E}</p></section>`],
  'repair changed configuration': [() => ctx.hookRepairHTML(scope, { ...evidencePage, verification: { title: H, detail: H, observed_at: H, config_id: H + 'x', run_ids: [H, H], reason_code: H, limits: [H, H] } }),
    `${baseline}${result}${E}x</p><details><summary>Completion identifiers</summary><p>Run IDs: ${E}, ${E}</p></details><p>Reported reason: ${E}</p><p>${E}</p><p>${E}</p></section>${recorded(evidence)}`],
  'repair same configuration': [() => ctx.hookRepairHTML(scope, { ...emptyPage, verification: { title: H, detail: H, observed_at: H, config_id: H, run_ids: [H], limits: [] } }),
    `${baseline}${result}Matches the original reported revision</p><details><summary>Completion identifiers</summary><p>Run IDs: ${E}</p></details></section>${recorded(emptyEvidence)}`],
  'finding with repair check': [() => ctx.hookFindingBodyHTML(finding, H), findingBody],
  'finding without actions': [() => ctx.hookFindingBodyHTML(advisory, H), advisoryBody],
  'hook health stale': [() => ctx.sessionHookHealthHTML({ available: true, since: H, until: H, observed_runs: 9, unattributed_runs: 1, truncated: true, findings: [finding, advisory] }, { error: true }, H),
    healthHead + '<p role="status">Showing the last loaded hook assessment; it may be out of date.</p>' + `<p>9 recorded completions assessed from ${E} to ${E}. This does not establish protection coverage.</p><p>Analysis is limited to recent samples and up to 20 findings.</p><p>1 recorded run lacks handler identity and cannot support handler-specific findings.</p>`
    + `<article class="sd-finding"><h5>${E} · Needs repair</h5>${findingBody}</article><article class="sd-finding"><h5>${E} · Advisory</h5>${advisoryBody}</article></section>`],
  'hook health empty': [() => ctx.sessionHookHealthHTML({ available: true, since: H, until: H, observed_runs: 0, unattributed_runs: 2, truncated: false, findings: [] }),
    healthHead + `<p>0 recorded completions assessed from ${E} to ${E}. This does not establish protection coverage.</p><p>2 recorded runs lack handler identity and cannot support handler-specific findings.</p><p>No repair or advisory pattern was found in the assessed records.</p></section>`],
  'hook health unavailable': [() => ctx.sessionHookHealthHTML(null), healthUnavailable],
  'hooks loading': [() => ctx.sessionHooksHTML(null, {}), hooksHead('Loading hook runs…')],
  'hooks failed': [() => ctx.sessionHooksHTML(null, { error: true }), hooksHead(`Hook runs unavailable. ${retryHooks}`)],
  'hooks table': [() => ctx.sessionHooksHTML([hookRow, plainRow], { error: true }, null, null, null, H, {}),
    hooksHead(`Hook runs unavailable. Showing the last loaded totals; they may be out of date. ${retryHooks}`) + hookControls + '<p data-session-part="hooks-count" role="status">2 of 2 recorded hook groups.</p>' + hookTable],
  'recent work row': [() => ctx.recentWorkRowHTML(recentSession), recentRow(E)],
  'recent work frame': [() => ctx.sessionDailyHTML([{ ...recentSession, status: 'active' }], null, ''), '<div class="session-daily-grid"><div class="session-daily-labels" aria-hidden="true"><span>Workspace</span><span>Agent</span><span>Status</span><span>Last activity</span></div>'
    + `<div class="session-daily-rows">${recentRow('active')}</div></div><p class="recent-work-count">Showing 1 of 1 loaded sessions</p>`],
  'coverage paths': [() => ctx.sessionCoverageHTML({ session_id: H, coverage: { guard: { state: 'observed', detail: H, last_seen: H }, trace: { state: 'not-observed', detail: H }, payload: { state: 'off', detail: H } } }), coverageHead
    + `<article data-coverage-path="guard"><b>Guard: activity observed</b><p>${E}</p><time datetime="${E}">Last observed: ${E}</time><p class="sd-coverage-next">This observation does not establish coverage of every operation.</p><button data-coverage-origin="guard" type="button" class="link-btn" data-action="session-events" data-id="${E}">View recorded session events</button></article>`
    + `<article data-coverage-path="trace"><b>Recorded activity: not observed</b><p>${E}</p><p class="sd-coverage-next">Run a small supported task, then refresh. Missing activity alone does not mean setup is broken.</p><button data-coverage-origin="trace" type="button" class="link-btn" data-action="session-coverage-guide" data-id="${E}" data-path="trace">Review activity sources</button></article>`
    + `<article data-coverage-path="payload"><b>Payload inspection: proxy off</b><p>${E}</p><p class="sd-coverage-next">Machine-wide traffic does not establish this session’s payload coverage. Routing and inspection are separate opt-ins.</p><button data-coverage-origin="payload" type="button" class="link-btn" data-action="session-coverage-traffic" data-id="${E}">Review Traffic settings</button></article>`],
  'coverage other states': [() => ctx.sessionCoverageHTML({ session_id: H, coverage: { guard: { state: 'unsupported', detail: H }, trace: { state: 'stale', detail: H }, payload: { state: H, detail: H } } }, {}), coverageHead
    + `<article data-coverage-path="guard"><b>Guard: not supported</b><p>${E}</p><p class="sd-coverage-next">This path is not supported by this source. Other observation paths may still be available.</p><button data-coverage-origin="guard" type="button" class="link-btn" data-action="session-coverage-guide" data-id="${E}" data-path="guard">Review available paths</button></article>`
    + `<article data-coverage-path="trace"><b>Recorded activity: last-known data; refresh failed</b><p>${E}</p><p class="sd-coverage-next">Refresh observations before relying on this result.</p></article>`
    + `<article data-coverage-path="payload"><b>Payload inspection: unknown</b><p>${E}</p><p class="sd-coverage-next">The current state is unknown. Refresh observations before choosing a setup change.</p></article>`],
  'coverage missing': [() => ctx.sessionCoverageHTML({ session_id: H }, { loading: true }), '<header class="sd-coverage-head"><h5>Observed paths</h5><button type="button" class="link-btn" data-action="session-overview-retry" disabled>Refreshing observations…</button></header>'
    + `<p>No current coverage is attributed to this session. Retained events do not establish live protection.</p><button type="button" class="link-btn" data-action="session-events" data-id="${E}">View recorded session events</button>`],
  'coverage guide unsupported': [() => ctx.sessionCoverageGuideHTML({ harness: H }, 'guard', { state: 'unsupported' }), `<p>This source does not support this observation path. An unsupported path is not a failed setup check.</p><p>Review the other observed paths for ${E}; each has its own limits.</p><p><a href="https://github.com/cavi-ai/secure-agent/blob/main/docs/ARCHITECTURE.md#collectors" target="_blank" rel="noopener noreferrer">Harness observation sources</a></p>`],
  'coverage guide guard steps': [() => ctx.sessionCoverageGuideHTML({ harness: 'claude' }, 'guard', { state: 'not-observed' }), guardIntro
    + '<ol><li>Open Secure Agent’s Setup &amp; Permissions and select Claude Code.</li><li>Review the selected harness’s installed guard hooks and run its installed-hook check if needed.</li><li>Run a small ordinary task in the same workspace, then return here and refresh observations.</li></ol>' + guardTail],
  'coverage guide guard review': [() => ctx.sessionCoverageGuideHTML({ harness: H }, 'guard', { state: 'off' }), guardIntro + `<p>Review ${E} in Setup &amp; Permissions and check its supported guarding path before changing configuration.</p>` + guardTail],
  'coverage guide activity': [() => ctx.sessionCoverageGuideHTML({ harness: H }, 'trace', {}), `<p>Recorded activity depends on the supported process, transcript, or tool sources for ${E}. Missing activity may reflect a quiet task, an unavailable source, or unresolved session identity.</p>`
    + '<ol><li>In the same harness and workspace, ask for a file listing and README summary without changing files or reading secrets.</li><li>Refresh observations and inspect recorded session events.</li><li>If activity is still missing, review this harness’s observation sources in Setup &amp; Permissions.</li></ol><p>Hook-completion reporting alone does not establish trace or guard coverage.</p><p><a href="https://github.com/cavi-ai/secure-agent/blob/main/docs/FIRST_SESSION.md" target="_blank" rel="noopener noreferrer">First observed session guide</a></p>'],
  'empty with hidden ended sessions': [() => ctx.sessionEmptyHTML([{ key: 'codex', live: [], ended: [{ session: { id: 'e', status: 'ended' }, children: [] }] }], { liveOnly: true, harnesses: {} }),
    emptyHead + '<span>No live sessions.</span>\n    <p>Matching ended sessions are available.</p><button type="button" class="btn btn-sm" data-action="show-ended-sessions">Show ended sessions</button>\n    </div></div>'],
  'empty with filter': [() => ctx.sessionEmptyHTML([], { text: H, harnesses: {} }),
    emptyHead + '<span>No sessions match these filters.</span>\n    \n    <button type="button" class="link-btn" data-action="clear-harness-filter">clear the filter</button></div></div>'],
  'rail card selected with actions': [() => ctx.sessionRailCardHTML(railSession, [{ root: { pid: 7, cwd: H, started_at: H } }], H, false),
    railCard({ cls: `${E} selected`, id: E, pressed: true, title: EID, label: E, branch: `${E} · ${E}`, status: E, seen: '2h30m ago', kill: killMenu })],
  'rail rows workspace view': [() => ctx.sessionRailRows([{ session: { id: H, status: 'idle', branch: H, harness: H }, children: [] }], H, [], '', null, 'live', true).map(r => `${r.key}=${r.html}`).join('\n'),
    `${H}=` + railCard({ cls: 'idle nested', id: E, title: '&lt;img src', label: E, branch: E, status: 'idle' })],
  'rail rows family and fold': [() => ctx.sessionRailRows([{ session: { id: 'p', status: 'active', repo: 'api' }, children: [{ id: H, status: 'ended', repo: H }] },
    { session: dupEarlier, children: [] }, { session: dupLater, children: [] }], 'codex', [], 'b', null, 'live').map(r => `${r.key}=${r.html}`).join('\n'),
    `p=${familyRow}\ngroup:codex|${H}@${H} · ${H}=` + dupRow('idle open', `group:codex|${EID}`, true, ' data-bucket="live"', 'idle', EID, E, 2, `${E} · ${E}`, `<div class="session-dup-body">${dupMembers}</div>`)],
  'folded row closed': [() => ctx.sessionDupRowHTML({ key: H, status: H, title: H, sessions: [{ id: 'c' }] }, [], '', false),
    dupRow(E, E, false, '', E, E, E, 1, E, '')],
  'group workspace with ended tail': [() => ctx.sessionGroupHTML({ key: H, workspaceView: true, workspace: H, label: H, live: [{ session: { id: 'a' }, children: [] }], ended: [{ session: { id: 'b' }, children: [{ id: 'c' }] }] }, true, true),
    groupShell(E, ' open', `<svg class="icon session-workspace-icon" aria-hidden="true"><use href="#i-folder"/></svg><span class="session-workspace-name" title="${E}">${E}</span><span class="session-group-counts">3 sessions</span>`, endedTail)],
  'group harness': [() => ctx.sessionGroupHTML({ key: 'codex', live: [{ session: { id: 'a', status: 'idle' }, children: [{ id: 'x' }] }], ended: [] }, false, false),
    groupShell('codex', '', chip('codex', 'Codex', true) + '<span class="session-group-counts">1 active · 1 idle</span>', '')],
  'infra group': [() => ctx.sessionInfraGroupHTML({ rss: 3145728, items: [{ key: 'ollama', rss: 2048 }, { key: 'lm-studio' }] }, true),
    '<details class="session-group infra" data-harness="infra" open>\n    <summary class="session-group-head"><span class="session-group-title">Infrastructure</span><span class="session-group-counts">3.0 MB</span><svg class="icon session-group-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></summary>\n    <div class="session-group-body">'
    + `<div class="infra-row">${chip('ollama', 'Ollama', true)}<span class="agent-meta-item">2 KB</span></div><div class="infra-row">${chip('lm-studio', 'LM Studio', true)}<span class="agent-meta-item">—</span></div></div>\n  </details>`],
  'memory rows with refresh error': [() => ctx.sessionMemoryHTML({ rows: memoryRows, has_earlier: true, next_cursor: 'c' }, { error: true, loadingEarlier: true }),
    '<div class="session-memory"><button type="button" class="btn btn-sm btn-ghost sm-earlier" data-action="memory-earlier" disabled>Loading earlier…</button><div class="sm-state" role="alert">Could not refresh memory. <button type="button" class="link-btn" data-action="memory-retry">Retry</button></div>'
    + `<div class="sm-list">${memoryList}</div></div>`],
  'memory loading': [() => ctx.sessionMemoryHTML({ rows: [] }, { loading: true }), '<div class="session-memory"><div class="sm-state" role="status">Loading memory…</div><div class="sm-list"></div></div>'],
  'trace loading': [() => ctx.sessionTraceHTML([], { loading: true }), traceHealth('Loading trace…')],
  'trace stale': [() => ctx.sessionTraceHTML([{ kind: 12, tool: H, tool_status: 'error', ts: '2026-10-14T09:00:00', duration_ms: 10 }], { error: H, loading: true }),
    traceHealth('Trace unavailable. Showing the last successfully loaded history; it may be out of date. <button type="button" class="link-btn" data-action="trace-retry" disabled>Retry trace</button>') + waterfall],
  'trace loaded empty': [() => ctx.sessionTraceHTML([], { loaded: true }), traceEmpty],
  'overview unavailable': [() => ctx.sessionOverviewHTML(null, { error: true }, '<p>context</p>'),
    overviewHead('Current session status unavailable. <button type="button" class="link-btn" data-action="session-overview-retry">Retry current status</button>') + '<p>context</p>'],
  'overview stale with request and resources': [() => ctx.sessionOverviewHTML(overviewData, { error: true, loading: true }), overviewFull],
  'overview without resources': [() => ctx.sessionOverviewHTML({ session_id: H, requests: [], findings: [], findings_truncated: true }, {}),
    overviewHead('') + healthUnavailable + ingestionUnavailable
    + `<section class="sd-coverage" data-session-part="coverage" aria-label="Observed session coverage">${coverageHead}${noCoverage}<button type="button" class="link-btn" data-action="session-events" data-id="${E}">View recorded session events</button></section>`
    + '<fieldset class="sd-impact" data-session-part="impact"><legend>Machine impact</legend><p>No live resource family is attributed to this session.</p></fieldset>'
    + findingsHead('More findings exist than the 20 most recent shown here.', E)],
  'follow-up with permissions': [() => ctx.sessionFollowUpHTML(followData, { permissions: followPermissions }), followFull],
  'follow-up loading': [() => ctx.sessionFollowUpHTML(followLoadingData, { loading: true, permissions: { loading: true } }),
    followSection('<button type="button" class="link-btn" data-action="session-outcomes-retry" disabled>Refreshing…</button>', '<p role="status">Refreshing follow-up. Refresh must succeed before relying on these records.</p>', '', '',
      followGroup('permissions', 'Permissions from decisions', `<li data-row-id="follow-up:permission:review:r"><strong>Review decision</strong><ul>${unknownPermission}</ul><button type="button" class="link-btn" data-action="session-permissions" data-review="r" data-session="${E}">Inspect permissions</button></li>`, 1),
      '<p>Loading permission status…</p>')],
  'outcomes unavailable': [() => ctx.sessionOutcomesHTML(null, {}), outcomesHead(`Results unavailable. ${retryResults}`)],
  'outcomes stale history': [() => ctx.sessionOutcomesHTML(outcomeData, { error: true }), outcomesStale],
  'detail without session': [() => ctx.sessionDetailHTML(null), '<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>Select a session to inspect its evidence</span></div>'],
  'detail hooks view': [withRecentWork(() => ctx.sessionDetailHTML(detailSession, [], [], { sessionView: 'hooks', sessionHooks: null, sessionHooksState: {}, sessionOverview: null, selectedSessionId: H, sessionHookHistory: {} })),
    detailFrame('<button type="button" class="btn btn-sm btn-ghost" data-action="recent-work-home">Back to Home</button>', E, workspacePermissions(E), chip('codex', 'Codex'), `${E}@${E}`, 'hooks',
      detailContext(E, 'Codex', `<span class="ss-chip sd-conf" title="How this session was identified">${E}</span>\n          <button type="button" class="sd-path" data-action="copy-path" data-path="${E}" title="${E} — click to copy">${E}</button>\n          <span class="sd-meta">started 2h30m ago · ended 1m ago</span>`)
      + hooksHead('Loading hook runs…'))],
  'detail results view': [() => ctx.sessionDetailHTML({ id: 's2', harness: 'claude', workspace: '/' }, [], [], { sessionView: 'results', sessionOutcomes: null }),
    detailFrame('', 's2', workspacePermissions('s2'), chip('claude', 'Claude Code'), 's2', 'results', detailContext('s2', 'Claude Code', noDetails) + outcomesHead(`Results unavailable. ${retryResults}`))],
  'detail trace view': [() => ctx.sessionDetailHTML({ id: 's3', harness: 'claude' }, [], [], { sessionView: 'trace', sessionOverview: null, sessionOverviewState: { loading: true }, sessionTimelineState: { loaded: true } }),
    detailFrame('', 's3', '', chip('claude', 'Claude Code'), 's3', 'trace', overviewHead('Loading current session status…') + detailContext('s3', 'Claude Code', noDetails) + traceEmpty)],
  'legacy board quiet': [() => legacyBoard({ harnesses: {} }), '<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>All quiet. Nothing is running.</span></div>'],
  'legacy board without matches': [() => legacyBoard({ text: H, harnesses: {} }),
    '<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No sessions match — <button type="button" class="link-btn" data-action="clear-harness-filter">clear the filter</button></span></div>'],
};

for (const [name, [render, expected]] of Object.entries(cases)) {
  test(`session workbench markup: ${name}`, () => {
    assert.equal(render(), expected);
  });
}
