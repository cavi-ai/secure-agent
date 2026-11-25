import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact session workbench markup for hostile served values: each value renders
// escaped once in text and attribute positions, and nested fragments render as markup.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const J = '&quot;&lt;img src=x onerror=1&gt;\\&quot;&#39;&amp;amp;&quot;';

const ctx = { Date, window: { SA: {} } };
vm.createContext(ctx);
for (const file of ['lib.js', 'tab-findings.js', 'session-layout.js', 'session-workbench.js']) vm.runInContext(readFileSync(new URL('../../../daemon/internal/api/web_dist/' + file, import.meta.url), 'utf8'), ctx);

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
};

for (const [name, [render, expected]] of Object.entries(cases)) {
  test(`session workbench markup: ${name}`, () => {
    assert.equal(render(), expected);
  });
}
