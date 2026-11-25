// Sessions tab: durable sessions grouped by harness or workspace on the left;
// the selected session's memory or trace on
// the right. renderSessionBoard (app.js's panel registry) delegates here when
// durable sessions exist; the legacy process-tree board remains the fallback.

// The hosts whose hook completions the daemon records (model.HookHarnesses,
// pinned by a drift test in daemon/internal/wiregen).
const HOOK_HARNESSES = ['claude', 'codex', 'openclaw', 'hermes', 'opencode'];

// Empty recovery considers ended sessions hidden only by Live only.
function sessionEmptyHTML(groups, filter) {
  const filtered = !!String(filter.text || filter.search || '').trim() || Object.values(filter.harnesses || {}).some(value => value === false);
  const visible = new Set(visibleSessionMembers(applySessionFilters(groups, filter)).map(session => session.id));
  const hiddenEnded = filter.liveOnly && visibleSessionMembers(applySessionFilters(groups, {...filter, liveOnly: false}))
    .some(session => session.status === 'ended' && !visible.has(session.id));
  const message = filter.liveOnly ? (filtered ? 'No live sessions match these filters.' : 'No live sessions.')
    : filtered ? 'No sessions match these filters.' : 'All quiet. Nothing is running.';
  return html`<div class="empty session-empty"><svg class="icon"><use href="#i-agent"/></svg><div><span>${message}</span>
    ${raw(hiddenEnded ? '<p>Matching ended sessions are available.</p><button type="button" class="btn btn-sm" data-action="show-ended-sessions">Show ended sessions</button>' : '')}
    ${raw(filtered ? '<button type="button" class="link-btn" data-action="clear-harness-filter">clear the filter</button>' : '')}</div></div>`;
}

function sessionEmptyDetailHTML(emptyHTML) {
  return emptyHTML.includes('data-action="session-list"') ? emptyHTML
    : '<button type="button" class="btn btn-sm btn-ghost sd-back" data-action="session-list">Back to sessions</button>' + emptyHTML;
}

// liveTreeFor: the live process tree rooted at a session's root pid, if up.
function liveTreeFor(s, trees) {
  if (!s.root_pid) return null;
  return (trees || []).find(t => t.root && Number(t.root.pid) === Number(s.root_pid)) || null;
}

// One rail row per session: repository and branch, one activity marker,
// and last activity. Destructive controls belong to selected-row actions.
// nested indents a sub-session
// under its parent; label, when set, replaces the title (a collapsed row's
// member reads by its start time).
function sessionRailCardHTML(s, trees, selectedId, nested, label, workspaceView = false) {
  const tree = liveTreeFor(s, trees);
  const status = s.status || 'active';
  const pulse = html`<span class="sc-pulse ${status}" aria-hidden="true"></span>`;
  const seen = s.last_seen_at ? fmtAge(s.last_seen_at, Date.now()) + ' ago' : '';
  const selected = s.id === selectedId;
  const identity = sessionTitle(s, tree && tree.root.cwd);
  const title = label || (workspaceView ? s.branch || 'Branch not recorded' : s.repo || cwdLabel(s.workspace) || cwdLabel(tree && tree.root.cwd) || sessionShort(s.id));
  const secondary = workspaceView ? harnessMeta(s.harness).label : label ? originAgent(s) : [s.branch, originAgent(s)].filter(Boolean).join(' · ');
  const kill = selected && tree && status !== 'ended'
    ? html`<details class="sc-actions"><summary aria-label="Actions for ${identity}">Actions</summary><div><button type="button" class="btn btn-danger btn-sm sc-kill" data-action="kill" data-pid="${tree.root.pid}" data-started="${tree.root.started_at || ''}" data-family="${s.harness || ''}">Terminate session</button></div></details>`
    : '';
  return html`<div class="session-card ${status}${selected ? ' selected' : ''}${nested ? ' nested' : ''}">
    <button type="button" class="sc-main" data-action="select-session" data-id="${s.id}" aria-pressed="${selected}" title="${identity}" aria-label="${label ? identity + ', ' + title : identity}">
      ${raw(pulse)}<span class="sc-identity"><span class="sc-label">${title}</span>${secondary ? raw(html`<span class="sc-branch">${secondary}</span>`) : ''}</span>
      <span class="sc-meta"><span class="sr-only">${status}</span>${seen ? raw(html`<span>${seen}</span>`) : ''}</span>
    </button>${raw(kill)}
  </div>`;
}

// Workspace paths are identities; equal repository names alone never merge
// unrelated checkouts. Sessions without a path retain their own identity.
function groupSessionWorkspaces(groups) {
  const workspaces = new Map();
  for (const s of visibleSessionMembers(groups)) {
    const path = String(s.workspace || '').replace(/\/+$/, '');
    const key = path ? 'workspace:' + path : 'session:' + s.id;
    if (!workspaces.has(key)) workspaces.set(key, {key, workspaceView: true,
      label: s.repo || cwdLabel(path) || 'Workspace not recorded', workspace: path, live: [], ended: []});
    workspaces.get(key)[s.status === 'ended' ? 'ended' : 'live'].push({session: s, children: []});
  }
  return [...workspaces.values(), ...(groups || []).filter(g => g.infra)];
}

function sessionNavigationCounts(g) {
  const count = familySize(g.live) + familySize(g.ended);
  return g.workspaceView ? `${count} session${count === 1 ? '' : 's'}` : sessionGroupCounts(g);
}

// One harness group's shell: mark + display name + counts in a collapsible
// head, an empty live row list, then the collapsed ended tail's toggle and
// empty row list. sessionRailRows fills both lists through patchList;
// syncSessionGroupShell keeps the counts current on a kept shell.
function sessionGroupHTML(g, open, endedOpen) {
  const ended = g.ended.length
    ? html`<div class="session-ended${endedOpen ? ' open' : ''}">
        <button type="button" class="session-ended-toggle" data-action="toggle-ended-sessions" data-harness="${g.key}" aria-expanded="${endedOpen}">Ended (${familySize(g.ended)}) <svg class="icon"><use href="#i-arrow"/></svg></button>
        <div class="session-ended-body"></div>
      </div>`
    : '';
  return html`<details class="session-group" data-harness="${g.key}"${raw(open ? ' open' : '')}>
    <summary class="session-group-head">${raw(g.workspaceView ? html`<svg class="icon session-workspace-icon" aria-hidden="true"><use href="#i-folder"/></svg><span class="session-workspace-name" title="${g.workspace || ''}">${g.label}</span>` : harnessChipHTML(g.key, { label: true }))}<span class="session-group-counts">${sessionNavigationCounts(g)}</span><svg class="icon session-group-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></summary>
    <div class="session-group-body"><div class="session-rows"></div>${raw(ended)}</div>
  </details>`;
}

// syncSessionGroupShell: a kept group shell's volatile text — the head's
// counts, the ended toggle's count and open state — written in place, so a
// status change never rebuilds the group or its rows.
function syncSessionGroupShell(node, g, endedOpen) {
  const counts = node.querySelector('.session-group-counts');
  const text = sessionNavigationCounts(g);
  if (counts && counts.textContent !== text) counts.textContent = text;
  const ended = node.querySelector('.session-ended');
  if (!ended) return;
  ended.classList.toggle('open', endedOpen);
  const toggle = ended.querySelector('.session-ended-toggle');
  if (!toggle) return;
  toggle.setAttribute('aria-expanded', String(endedOpen));
  const label = toggle.firstChild;
  const want = `Ended (${familySize(g.ended)}) `;
  if (label && label.nodeType === 3 && label.nodeValue !== want) label.nodeValue = want;
}

// sessionRailRows: one half (bucket: 'live' or 'ended') of a harness group as
// patchList items, keyed by session id, or by group:<harness>|<title> for
// sessions folded by collapseSessionFamilies. dupOpen maps '<bucket>|<key>'
// to a folded row's expanded state, so a live and an ended fold with one
// title open apart; unset, a row is open while it holds the selected session.
function sessionRailRows(fams, harness, trees, selectedId, dupOpen, bucket, workspaceView = false) {
  if (workspaceView) return fams.map(f => ({key: f.session.id, html: sessionRailCardHTML(f.session, trees, selectedId, true, null, true)}));
  const titleOf = s => { const t = liveTreeFor(s, trees); return sessionTitle(s, t && t.root.cwd); };
  return collapseSessionFamilies(fams, harness, titleOf).map(r => {
    if (!r.dup) {
      const f = r.family;
      const cards = sessionRailCardHTML(f.session, trees, selectedId, false)
        + f.children.map(c => sessionRailCardHTML(c, trees, selectedId, true)).join('');
      return { key: r.key, html: f.children.length ? html`<div class="session-family">${raw(cards)}</div>` : cards };
    }
    const state = bucket ? `${bucket}|${r.key}` : r.key;
    const set = dupOpen && Object.prototype.hasOwnProperty.call(dupOpen, state);
    const open = set ? !!dupOpen[state] : r.sessions.some(s => s.id === selectedId);
    return { key: r.key, html: sessionDupRowHTML(r, trees, selectedId, open, bucket) };
  });
}

// A folded row: "title ×N" with the most active member's status; open, it
// lists each member by start time (HH:MM) and status, selectable as a card.
function sessionDupRowHTML(r, trees, selectedId, open, bucket) {
  const status = r.status;
  const pulse = html`<span class="sc-pulse ${status}" aria-hidden="true"></span>`;
  const first = r.sessions[0] || {};
  const title = first.repo || cwdLabel(first.workspace) || r.title;
  const secondary = [first.branch, originAgent(first)].filter(Boolean).join(' · ');
  const members = open
    ? html`<div class="session-dup-body">${r.sessions.map(s => raw(sessionRailCardHTML(s, trees, selectedId, true, fmtHHMM(s.started_at) || sessionShort(s.id))))}</div>`
    : '';
  return html`<div class="session-dup ${status}${open ? ' open' : ''}">
    <button type="button" class="session-dup-toggle" data-action="toggle-session-dup" data-key="${r.key}" aria-expanded="${open}"${bucket ? raw(html` data-bucket="${bucket}"`) : ''}>
      <span class="sc-head">${raw(pulse)}<span class="sc-label" title="${r.title}">${title}</span><span class="session-dup-count">×${r.sessions.length}</span><svg class="icon"><use href="#i-arrow"/></svg></span>
      <span class="sc-meta"><span class="sc-branch">${secondary || status}</span></span>
    </button>${raw(members)}
  </div>`;
}

// The trailing infra group: IDEs and model servers, RSS totals only.
function sessionInfraGroupHTML(g, open) {
  const rows = g.items.map(it => raw(html`<div class="infra-row">${raw(harnessChipHTML(it.key, { label: true }))}<span class="agent-meta-item">${fmtRSS(it.rss) || '—'}</span></div>`));
  return html`<details class="session-group infra" data-harness="infra"${raw(open ? ' open' : '')}>
    <summary class="session-group-head"><span class="session-group-title">Infrastructure</span><span class="session-group-counts">${fmtRSS(g.rss) || '—'}</span><svg class="icon session-group-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></summary>
    <div class="session-group-body">${rows}</div>
  </details>`;
}

// Memory rows contain only server-redacted labels, but every field is still
// escaped at this final DOM boundary. Unknown source types use a generic name.
function sessionMemoryHTML(page, state) {
  const rows = Array.isArray(page && page.rows) ? page.rows : [];
  const sourceNames = { activity: 'Activity', 'guard-audit': 'Guard', flag: 'Flag', incident: 'Incident', guard: 'Guard', resource: 'Resource' };
  const loading = !!(state && state.loading);
  const error = !!(state && state.error);
  let lastDay = null;
  const rowHTML = rows.map(row => {
    const source = Object.prototype.hasOwnProperty.call(sourceNames, row.kind) ? sourceNames[row.kind] : 'Activity';
    const date = new Date(row.at);
    const pad = n => String(n).padStart(2, '0');
    const validTime = !Number.isNaN(date.getTime());
    const day = validTime ? `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` : 'Date unavailable';
    const time = validTime ? fmtTime(date) : 'Time unavailable';
    const fullTime = validTime ? `${day} ${time}` : time;
    const dayHTML = day !== lastDay ? html`<div class="sm-day">${day}</div>` : '';
    lastDay = day;
    const severity = row.severity ? html`<span class="sm-chip">${row.severity}</span>` : '';
    const status = row.status ? html`<span class="sm-chip">${row.status}</span>` : '';
    const sourceID = typeof row.source_id === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(row.source_id) ? row.source_id : '';
    const action = row.kind === 'flag' ? 'open-flag' : row.kind === 'incident' ? 'open-incident' : '';
    const label = row.kind === 'flag' ? 'View finding evidence' : 'View incident report';
    const title = sourceID && action
      ? html`<button type="button" class="link-btn sm-source-link" data-action="${action}" data-id="${sourceID}" aria-label="${label}: ${row.title}" title="${label}">${row.title}</button>`
      : html`${row.title}`;
    return raw(html`${raw(dayHTML)}<article class="sm-row" data-row-id="${row.id || ''}">
      <div class="sm-marker"><time datetime="${row.at}" title="${fullTime}" aria-label="${fullTime}">${time}</time><span class="sm-source">${source}</span></div>
      <div class="sm-content"><strong>${raw(title)}</strong>${row.detail ? raw(html`<p>${row.detail}</p>`) : ''}<div class="sm-chips">${raw(severity)}${raw(status)}</div></div>
    </article>`);
  });
  const earlier = page && page.has_earlier && page.next_cursor
    ? html`<button type="button" class="btn btn-sm btn-ghost sm-earlier" data-action="memory-earlier"${raw(state && state.loadingEarlier ? ' disabled' : '')}>${state && state.loadingEarlier ? 'Loading earlier…' : 'Load earlier'}</button>` : '';
  const message = error && !rows.length ? '<div class="sm-state" role="alert">Memory unavailable. <button type="button" class="link-btn" data-action="memory-retry">Retry</button></div>'
    : error && state.error === 'earlier' && page && page.has_earlier && page.next_cursor
      ? '<div class="sm-state" role="alert">Could not load earlier. Use Load earlier to retry.</div>'
    : error ? html`<div class="sm-state" role="alert">${state.error === 'earlier' ? 'Could not load earlier.' : 'Could not refresh memory.'} <button type="button" class="link-btn" data-action="memory-retry">Retry</button></div>`
    : loading && !rows.length ? '<div class="sm-state" role="status">Loading memory…</div>'
    : !rows.length ? '<div class="sm-state">No retained memory for this session. Older activity may have expired.</div>' : '';
  return html`<div class="session-memory">${raw(earlier)}${raw(message)}<div class="sm-list">${rowHTML}</div></div>`;
}

// The selected session's head and detail: mark, repo@branch, harness name,
// identity confidence, workspace path (click copies), Export (copies the
// markdown report from GET /sessions/{id}/report), then Memory by default.
// Trace keeps the existing waterfall and timeline endpoint.
function validSessionTrace(rows, id) {
  return Array.isArray(rows) && rows.length <= 500 && rows.every(row => row && typeof row === 'object'
    && !Array.isArray(row) && row.session_id === id && Number.isInteger(row.kind) && row.kind >= 0
    && typeof row.ts === 'string' && Number.isFinite(Date.parse(row.ts))
    && ['duration_ms', 'tokens_in', 'tokens_out', 'cost_usd'].every(key => row[key] === undefined
      || (typeof row[key] === 'number' && Number.isFinite(row[key]))));
}

function sessionTraceHTML(events, state) {
  const loaded = state?.loaded || events.length > 0;
  const retry = html`<button type="button" class="link-btn" data-action="trace-retry"${raw(state?.loading ? ' disabled' : '')}>Retry trace</button>`;
  const message = state?.error ? html`Trace unavailable.${loaded ? ' Showing the last successfully loaded history; it may be out of date.' : ''} ${raw(retry)}`
    : state?.loading && !loaded ? 'Loading trace…' : '';
  const text = message || (!loaded ? 'Loading trace…' : '');
  const notice = html`<div class="sm-state" data-session-part="trace-health" role="status"${raw(text ? '' : ' hidden')}>${raw(text)}</div>`;
  if (!loaded) return notice;
  const limit = events.length === 500 ? '<p class="sm-state" data-session-part="trace-limit">This view contains the latest 500 retained event records; earlier history may be omitted. Use View session events to browse retained records.</p>' : '';
  return notice + limit + sessionWaterfallHTML(events);
}

function validHookForwarder(row) {
  const r = row && row.report;
  if (!r || typeof r !== 'object' || Array.isArray(r)) return false;
  const id = v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(v);
  const time = v => typeof v === 'string' && Number.isFinite(Date.parse(v));
  const count = v => Number.isSafeInteger(v) && v >= 0;
  const codes = (v, allowed) => v === undefined || v === '' || (typeof v === 'string' && allowed.includes(v));
  const h = r && r.health;
  let healthValid = r && r.version === 1 && h == null;
  if (r && r.version === 2 && h && typeof h === 'object' && !Array.isArray(h)) {
    const box = h.outbox;
    const boxValid = box == null || (box && typeof box === 'object' && !Array.isArray(box)
      && count(box.persisted) && box.persisted <= r.pending && count(box.recovered)
      && codes(box.error, ['outbox-failed', 'outbox-full']));
    const state = h.capture_error || h.delivery_error || (box && box.error) ? 'error' : h.source_state;
    healthValid = ['connected', 'disconnected', 'error'].includes(h.source_state) && typeof h.report_error === 'boolean'
      && codes(h.capture_error, ['invalid-input', 'unsupported-protocol', 'scope-mismatch', 'delivery-conflict', 'queue-full'])
      && codes(h.delivery_error, ['recorder-unavailable', 'recorder-failed']) && boxValid && r.state === state;
  }
  const a = row && row.assessment;
  const expected = row && row.freshness !== 'recent' ? 'unknown' : r && r.state === 'error' ? 'needs-action' : 'no-active-error';
  const assessmentValid = a === undefined || (a && typeof a === 'object' && a.state === expected
    && typeof a.title === 'string' && a.title.length > 0 && a.title.length <= 256 && a.evidence_gap === (r.dropped > 0)
    && Array.isArray(a.issues) && a.issues.length <= 4 && (a.state === 'needs-action' ? a.issues.length > 0 : a.issues.length === 0)
    && a.issues.every(v => v && ['source','capture','delivery','persistence','forwarding'].includes(v.stage)
      && typeof v.code === 'string' && v.code.length > 0 && v.code.length <= 64 && typeof v.next_action === 'string' && v.next_action.length > 0 && v.next_action.length <= 1024)
    && Array.isArray(a.limits) && a.limits.length <= 5 && a.limits.every(v => typeof v === 'string' && v.length <= 1024));
  return !!r && r.type === 'hook_forwarder' && healthValid && assessmentValid && id(r.forwarder_id)
    && (r.session_id === undefined || id(r.session_id))
    && HOOK_HARNESSES.includes(r.harness)
    && ['connected', 'disconnected', 'error'].includes(r.state)
    && ['recent', 'stale', 'unverified'].includes(row.freshness)
    && ['sequence', 'pending', 'delivery_failures', 'dropped'].every(k => count(r[k])) && r.sequence > 0
    && time(r.ts) && time(row.received_at);
}

function hookDeliveryIssuesHTML(a, stale) {
  return (a.issues || []).map(v => html`<p>${stale ? 'Last reported ' : ''}${v.stage} error: ${v.code}. ${v.next_action}</p>`).join('');
}

function hookForwarderHealthHTML(r, freshness, assessment) {
  const h = r.health;
  if (!h) return '<p>Detailed source, delivery and persistence diagnostics are unavailable from this host.</p>' + (assessment ? hookDeliveryIssuesHTML(assessment, freshness !== 'recent') : '');
  const stale = freshness !== 'recent';
  const source = stale ? '<p>Last reported diagnostics follow; their current state is unknown.</p>'
    : html`<p>${({ connected: 'Source connected', disconnected: 'Source disconnected', error: 'Source error' })[h.source_state]} (host reported).${h.source_state === 'connected' ? '' : ' Check the host subscription and restore the source connection.'}</p>`;
  const actions = {
    'invalid-input': 'Validate the completion metadata against the shared contract, then submit the corrected completion.',
    'unsupported-protocol': 'Use the supported native hook protocol and required snapshots, then submit the corrected completion.',
    'scope-mismatch': 'Route the completion to the forwarder for its harness and session.',
    'delivery-conflict': 'Keep one execution ID for identical retry metadata; use a new ID for a different execution.',
    'queue-full': 'Restore delivery and allow the queue to drain. Some rejected completions may be unrecoverable.',
    'recorder-unavailable': 'Restore the installed recorder executable and its permissions. Retry retained completions using their original delivery IDs.',
    'recorder-failed': 'Check the recorder and its output storage. Retry retained completions using their original delivery IDs.',
    'outbox-full': 'Free outbox storage or increase its configured budget. Keep the existing outbox to preserve pending evidence.',
    'outbox-failed': 'Check outbox storage availability and permissions. Keep the existing outbox to preserve pending evidence.'
  };
  const errors = [['Capture', h.capture_error], ['Delivery', h.delivery_error], ['Persistence', h.outbox && h.outbox.error]]
    .filter(([, code]) => code).map(([stage, code]) => html`<p>${stale ? 'Last reported ' : ''}${stage} error: ${code}. ${actions[code] || 'Check the reporting host diagnostics.'}</p>`).join('');
  const persistence = h.outbox
    ? html`<p>${Number(h.outbox.persisted)} persisted of ${Number(r.pending)} queued · ${Number(h.outbox.recovered)} recovered after host restart. Persisted completions can survive host restart; recorder acceptance does not establish daemon storage.</p>`
    : '<p>Host outbox persistence is disabled. Queued completions are held in memory and may be lost if the host exits.</p>';
  const reporting = h.report_error ? '<p>A previous health report failed to reach the recorder. This received report shows reporting has resumed.</p>' : '';
  return source + (assessment ? hookDeliveryIssuesHTML(assessment, stale) : errors) + persistence + reporting;
}

function hookForwardersHTML(rows, truncated, readFailed) {
  if (!rows || !rows.length) return '<p>No host health reports received. Host connectivity is unknown.</p>';
  const limit = truncated ? '<p>Only the 128 most recently received forwarder instances are retained; other reports may be omitted.</p>' : '';
  return html`<h5>Host reports</h5>${raw(limit)}${rows.map(row => {
    const r = row.report;
    const freshness = readFailed ? 'unverified' : row.freshness;
    const state = freshness === 'stale' ? 'Report stale; current connection state unknown'
      : freshness === 'unverified' ? 'Report freshness unverified; current connection state unknown'
      : ({ connected: 'Source connected', disconnected: 'Source disconnected', error: 'Forwarding error' })[r.state];
    let action = '';
    if (freshness !== 'recent') action = '<p>Check the reporting host, recorder and clocks, then obtain a new report.</p>';
    else if (!r.health && (r.state !== 'connected' || r.pending > 0)) action = '<p>Check the source connection and recorder. Retry retained completions using their original delivery IDs.</p>';
    const gap = r.dropped > 0 ? '<p>The host reports dropped completions. Some evidence may be missing; inspect host diagnostics and retry retained deliveries. Dropped completions may not be recoverable.</p>' : '';
    return raw(html`<article class="sd-finding"><h5>${r.harness} · ${state} (host reported)</h5><p>Forwarder: ${r.forwarder_id} · Report ${Number(r.sequence)}${r.session_id ? ' · Host-supplied session: ' + r.session_id : ' · Session ID not supplied'}</p><p>${Number(r.pending)} queued · ${Number(r.delivery_failures)} delivery failures · ${Number(r.dropped)} dropped. Failure and drop counts are cumulative for this forwarder instance.</p><p>Host report time: <time>${r.ts}</time> · Local receipt: <time>${row.received_at}</time></p>${raw(hookForwarderHealthHTML(r, freshness, row.assessment))}${raw(action)}${raw(gap)}</article>`);
  })}<p>Host reports do not establish complete delivery or protection coverage.</p>`;
}

function validHookIngestion(h) {
  const time = v => typeof v === 'string' && Number.isFinite(Date.parse(v));
  const count = v => Number.isSafeInteger(v) && v >= 0;
  if (!h || typeof h !== 'object' || Array.isArray(h) || typeof h.available !== 'boolean'
    || !count(h.rejected) || !Array.isArray(h.harnesses) || h.harnesses.length > 5) return false;
  if (h.forwarders !== undefined && (!Array.isArray(h.forwarders) || h.forwarders.length > 128 || !h.forwarders.every(validHookForwarder)
    || new Set(h.forwarders.map(r => r.report.forwarder_id)).size !== h.forwarders.length)) return false;
  if (h.forwarders_truncated !== undefined && typeof h.forwarders_truncated !== 'boolean') return false;
  if (!h.available) return h.rejected === 0 && h.harnesses.length === 0 && !(h.forwarders || []).length;
  return time(h.since) && (h.rejected === 0 ? h.last_rejected_at == null : time(h.last_rejected_at))
    && new Set(h.harnesses.map(r => r && r.harness)).size === h.harnesses.length
    && h.harnesses.every(r => r && HOOK_HARNESSES.includes(r.harness)
      && count(r.accepted) && r.accepted > 0 && time(r.last_received_at));
}

// Summarize observations without merging independent forwarding instances or
// borrowing one session's evidence to describe another session's coverage.
function hookMonitoringModel(h, sessions = [], health = {}, now = Date.now()) {
  const supported=HOOK_HARNESSES;
  const available=validHookIngestion(h) && h.available;
  const stale=!!health.error || !(health.lastSnapshotAt>0) || now-health.lastSnapshotAt>120000 || now<health.lastSnapshotAt;
  const rows=new Map();
  const get=name=>{
    if (!supported.includes(name)) return null;
    if (!rows.has(name)) rows.set(name,{harness:name,receipt:null,reports:[],sessions:[],errors:0,unknown:0,gaps:0});
    return rows.get(name);
  };
  for(const s of Array.isArray(sessions)?sessions:[]) {
    if (!s || typeof s.id!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(s.id)) continue;
    const row=get(s.harness);
    if (row && !row.sessions.some(other=>other.id===s.id)) row.sessions.push(s);
  }
  if (available) {
    for(const receipt of h.harnesses) get(receipt.harness).receipt=receipt;
    for(const report of h.forwarders || []) get(report.report.harness).reports.push(report);
  }
  for(const row of rows.values()) {
    row.errors=stale?0:row.reports.filter(r=>r.freshness==='recent' && r.report.state==='error').length;
    row.unknown=row.reports.filter(r=>stale || r.freshness!=='recent').length;
    row.gaps=row.reports.filter(r=>r.report.dropped>0).length;
    row.sessions.sort((a,b)=>Number(!['active','idle'].includes(a.status))-Number(!['active','idle'].includes(b.status)) || (Date.parse(b.last_seen_at)||0)-(Date.parse(a.last_seen_at)||0) || a.id.localeCompare(b.id));
  }
  return {available,stale,since:available?h.since:'',rejected:available?h.rejected:0,truncated:available && !!h.forwarders_truncated,
    rows:[...rows.values()].sort((a,b)=>b.errors-a.errors || b.gaps-a.gaps || a.harness.localeCompare(b.harness))};
}

function hookMonitoringHTML(m) {
  const plural=(n,single,many)=>`${n} ${n===1?single:many}`;
  const labels={claude:'Claude Code',codex:'Codex',openclaw:'OpenClaw',hermes:'Hermes',opencode:'OpenCode'};
  const rows=m.rows.map(row=>{
    const receipt=!m.available ? 'Completion receipt unavailable.' : row.receipt
      ? html`${m.stale?'Last known completion receipt':'Last completion receipt'}: <time>${row.receipt.last_received_at}</time> · ${Number(row.receipt.accepted)} accepted deliveries.`
      : 'No completion received in this daemon run. Delivery is unknown.';
    const forwarding=!row.reports.length ? 'Forwarding state unknown; no host report received.'
      : [row.errors?plural(row.errors,'host with active errors','hosts with active errors'):'',row.unknown?plural(row.unknown,'host with unknown current state','hosts with unknown current state'):'',
        row.reports.length-row.errors-row.unknown?plural(row.reports.length-row.errors-row.unknown,'host reporting no active error','hosts reporting no active error'):''].filter(Boolean).join(' · ')+'.';
    const hosts=row.reports.map(r=>raw(html`<button type="button" class="link-btn" data-action="hook-delivery-inspect" data-id="${r.report.forwarder_id}">Inspect delivery${row.reports.length>1?' · '+r.report.forwarder_id:''}</button>`));
    const sessions=row.sessions.slice(0,5).map(s=>raw(html`<button type="button" class="link-btn" data-action="hook-session-open" data-session="${s.id}">Open session hooks · ${sessionTitle(s)}${s.status?' · '+s.status:''}</button>`));
    return html`<article class="hook-monitoring-row" data-hook-runtime="${row.harness}"><h4>${labels[row.harness]}</h4><p>${raw(receipt)}</p><p>${forwarding}</p>${row.gaps?raw(html`<p>Evidence gap: ${plural(row.gaps,'host instance reported drops','host instances reported drops')}. Missing evidence may be unrecoverable.</p>`):''}<div class="hook-monitoring-actions">${row.reports.length>1?raw(html`<details data-hook-disclosure="hosts:${row.harness}"><summary>Inspect ${row.reports.length} forwarding hosts</summary>${hosts}</details>`):hosts}${row.sessions.length?raw(html`<details data-hook-disclosure="sessions:${row.harness}"><summary>${plural(row.sessions.length,'retained session','retained sessions')}</summary>${sessions}${raw(row.sessions.length>5?'<button type="button" class="link-btn" data-action="goto-tab" data-tab="sessions">View all sessions</button>':'')}</details>`):''}<button type="button" class="link-btn" data-action="hook-setup" data-harness="${row.harness}">Setup and verification</button></div></article>`;
  }).join('');
  return html`<section class="hook-monitoring" aria-label="Hook monitoring"><h3>Hook monitoring</h3>${raw(!m.available?'<p role="status">Ingestion diagnostics unavailable. Current receipt and forwarding states are unknown.</p><button type="button" class="link-btn" data-action="retry-posture">Refresh monitoring</button>':m.stale?'<p role="status">Last loaded observations; current receipt and forwarding states are unknown. Refresh telemetry to retry.</p><button type="button" class="link-btn" data-action="retry-posture">Refresh monitoring</button>':'')}${m.available?raw(html`<p>Receipts across all sessions since <time>${m.since}</time> in this daemon run.</p>`):''}${raw(rows || '<p>No supported runtimes observed in retained sessions or hook diagnostics.</p>')}${m.rejected?raw(html`<p>${Number(m.rejected)} rejected shared records; rejections cannot be attributed to a runtime or session. Review the reporting host diagnostics.</p>`):''}${raw(m.truncated?'<p>Other forwarding instances may be omitted from the retained reports.</p>':'')}<p>Receipt does not confirm durable storage or protection coverage. Retries can count again; silence does not establish a forwarding failure.</p></section>`;
}

function hookIngestionHTML(h, state) {
  const head = '<summary>Daemon hook ingestion · all sessions</summary>';
  if (!h || !h.available) return html`<details class="sd-findings-head" data-session-part="hook-ingestion">${raw(head)}<p>Ingestion diagnostics unavailable.</p></details>`;
  const stale = state && state.error ? '<p role="status">Showing the last loaded ingestion diagnostics; they may be out of date.</p>' : '';
  const rows = h.harnesses.map(r => html`<p>${r.harness}: ${Number(r.accepted)} accepted deliveries · Last local receipt: <time>${r.last_received_at}</time></p>`).join('');
  const rejected = h.rejected ? html`<p>${Number(h.rejected)} rejected shared hook records · Last rejection: <time>${h.last_rejected_at}</time></p><p>Check the forwarding host and recorder diagnostics, validate the shared record format, then retry retained completions with their original delivery IDs. Rejected records cannot be attributed to a session or harness.</p>` : '<p>No recognized shared hook records rejected.</p>';
  return html`<details class="sd-findings-head" data-session-part="hook-ingestion">${raw(head)}${raw(stale)}<p>Counts since <time>${h.since}</time> in this daemon run, across all sessions.</p>${raw(rows || '<p>No hook deliveries observed in this daemon run.</p>')}${raw(rejected)}<p>Receipt confirms collection, not durable storage or a unique execution. Retries can count again. Silence does not establish a forwarding failure. Errors before the recorder writes a shared record are visible only when the host reports them.</p>${raw(hookForwardersHTML(h.forwarders, h.forwarders_truncated, state && state.error))}</details>`;
}

function validHookHealth(h) {
  const record = v => v && typeof v === 'object' && !Array.isArray(v);
  const count = v => Number.isSafeInteger(v) && v >= 0;
  const time = v => typeof v === 'string' && Number.isFinite(Date.parse(v));
  if (!record(h) || typeof h.available !== 'boolean' || !Array.isArray(h.findings) || h.findings.length > 20) return false;
  if (!h.available) return h.findings.length === 0;
  return time(h.since) && time(h.until) && count(h.observed_runs) && count(h.unattributed_runs)
    && h.unattributed_runs <= h.observed_runs && typeof h.truncated === 'boolean'
    && h.findings.every(f => record(f) && ['id', 'kind', 'harness', 'event', 'handler_id', 'title', 'detail', 'next_action'].every(k => typeof f[k] === 'string' && f[k].length > 0)
      && ['script', 'config_id', 'operation_id'].every(k => f[k] === undefined || typeof f[k] === 'string')
      && count(f.count) && typeof f.needs_action === 'boolean' && time(f.first_at) && time(f.last_at)
      && Array.isArray(f.limits) && f.limits.every(v => typeof v === 'string'));
}

function hookSetupHTML(harness, ingestion) {
  if (!validHookIngestion(ingestion)) ingestion=null;
  const sources = {
    claude: ['Claude Code', 'Secure Agent reads retained hook completions from Claude Code transcripts. Check that the daemon can read this session’s transcript. Stable registered-handler identity is unavailable in these records.'],
    codex: ['Codex', 'Your existing Codex host must forward app-server hook completion notifications. Installing Secure Agent alone does not connect another host or recover hook completions from rollouts.'],
    openclaw: ['OpenClaw', 'Your OpenClaw host must forward each observed plugin handler completion. An aggregate dispatcher result or observer hook cannot establish that every handler executed.'],
    hermes: ['Hermes', 'Your Hermes host must forward individual plugin handler completions after native response normalization. Gateway hook dispatchers are outside this adapter’s scope.'],
    opencode: ['OpenCode', 'Your host needs the supported OpenCode v2 integration, including before and after snapshots for mutable results. OpenCode v1 hook protocols are unsupported.']
  };
  const selected = harness ? (Object.hasOwn(sources,harness) ? [harness] : []) : Object.keys(sources);
  if (!selected.length) return '<p>Hook integration guidance is unavailable for this runtime.</p>';
  return selected.map(name => {
    const [title, detail] = sources[name];
    const receipt = ingestion?.available && ingestion.harnesses?.find(r => r.harness === name);
    const observed = receipt ? `Last daemon receipt: ${receipt.last_received_at} · ${Number(receipt.accepted)} accepted deliveries in this daemon run. Receipt does not confirm durable storage.` : 'No daemon receipt is available for this source. Connection and delivery remain unknown.';
    return html`<section class="sd-finding"><h4>${title}</h4><p>${detail}</p><ol><li>Confirm that this source is connected using the integration guide and check the installed recorder’s configuration.</li><li>Observe a real completion during normal use; do not infer execution from configured hooks.</li><li>Refresh this session’s Hooks view and inspect recorded runs, measurements, and delivery reports.</li></ol><p>${observed}</p><p>These observations do not establish protection coverage. A configured integration or connected source alone does not establish complete hook delivery.</p></section>`;
  }).join('') + '<p><a href="https://github.com/cavi-ai/secure-agent/blob/main/docs/HOOKS.md" target="_blank" rel="noopener noreferrer">Hook integration guide</a></p>';
}

function validHookEvidence(page, scope) {
  const object = v => v && typeof v === 'object' && !Array.isArray(v);
  const time = v => typeof v === 'string' && Number.isFinite(Date.parse(v));
  const count = v => Number.isSafeInteger(v) && v >= 0;
  const id = v => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(v);
  if (!object(page) || page.session_id !== scope.session || !object(page.filter)
    || ![['harness','harness'],['event','event'],['handler_id','handler'],['config_id','config'],['script','script']].every(([key,attr]) => page.filter[key] === (scope[attr] || ''))
    || !['group','exact'].includes(page.filter.event_scope || 'group') || (page.filter.event_scope || 'group') !== (scope.event_scope || 'group')
    || !time(page.since) || !time(page.until) || Date.parse(page.until) < Date.parse(page.since) || Date.parse(page.until)-Date.parse(page.since) > 1800000
    || typeof page.truncated !== 'boolean' || !Array.isArray(page.rows) || page.rows.length > 100) return false;
  return new Set(page.rows.map(r => r?.id)).size === page.rows.length && page.rows.every(r => object(r) && id(r.id) && time(r.ts)
    && Date.parse(r.ts) >= Date.parse(page.since) && Date.parse(r.ts) <= Date.parse(page.until)
    && ['ok','inject','block','deny','error','cancelled'].includes(r.status)
    && ['duration_ms','chars'].every(k => r[k] === undefined || count(r[k]))
    && (r.evidence === undefined || (object(r.evidence) && (r.evidence.handler_id || '') === scope.handler && (r.evidence.config_id || '') === scope.config
      && typeof r.evidence.duration_known === 'boolean' && typeof r.evidence.chars_known === 'boolean'
      && r.evidence.duration_known === (r.duration_ms !== undefined) && r.evidence.chars_known === (r.chars !== undefined)
      && (r.evidence.reason_code === undefined || ['timeout','dependency-unavailable','invalid-output','permission-denied','execution-failed','policy-block'].includes(r.evidence.reason_code))
      && (r.evidence.action_outcome === undefined || ['stopped','proceeded'].includes(r.evidence.action_outcome))
      && (r.evidence.control_role === undefined || ['security','other'].includes(r.evidence.control_role)))));
}

function hookEvidenceHTML(page) {
  const rows = page.rows.map(r => html`<article class="sd-finding"><h4>${r.status} · <time>${r.ts}</time></h4><p>Run: ${r.id}</p><p>Reason: ${r.evidence?.reason_code || 'not reported'} · Duration: ${r.duration_ms === undefined ? 'unknown' : fmtDurationMs(r.duration_ms)} · Returned characters: ${r.chars === undefined ? 'unknown' : Number(r.chars)}</p><p>Host-reported action outcome: ${r.evidence?.action_outcome || 'unknown'} · Control role: ${r.evidence?.control_role || 'unknown'}</p></article>`).join('');
  return html`<section class="sd-hook-evidence"><p>${page.filter.harness} · ${page.filter.event} · Handler: ${page.filter.handler_id || 'unattributed'} · Configuration: ${page.filter.config_id || 'not supplied'}</p><p>Retained completions from <time>${page.since}</time> to <time>${page.until}</time>. ${page.truncated ? 'Evidence is limited to the latest 100 matching runs.' : ''} Equal timestamps do not establish execution order.</p>${raw(rows || '<p>No matching retained completions in this window. This does not establish recovery or prove that no hooks ran.</p>')}<p>Only normalized metadata is shown. These records do not establish protection coverage.</p></section>`;
}

// Build an allowlisted handoff from the same validated snapshot as the inspector.
// Do not serialize the payload: it may gain fields unsuitable for sharing.
function hookDiagnosticSummary(kind, scope, payload) {
  const clean = value => String(value ?? 'unknown').replace(/[\u0000-\u001f\u007f]/g, ' ');
  const lines = ['Hook diagnostic summary', 'Snapshot of loaded evidence; refresh before assessing current state.'];
  const add = (label, value) => lines.push(label + ': ' + clean(value));
  const limits = values => { for (const value of values || []) add('Limit', value); };
  if (kind === 'delivery') {
    const ingestion = payload?.hook_ingestion;
    if (!validHookIngestion(ingestion) || !ingestion.available) return null;
    const row = ingestion.forwarders?.find(r => r.report.forwarder_id === scope.id);
    if (!row) return null;
    const r = row.report, health = r.health;
    add('Type', 'Forwarding delivery');
    add('Runtime', r.harness); add('Forwarder', r.forwarder_id); add('Session', r.session_id || 'not supplied');
    add('Host report time', r.ts); add('Local receipt', row.received_at); add('Report sequence', r.sequence);
    add('Freshness at load', row.freshness);
    add('Host-reported state', r.state);
    add('Assessment', row.freshness === 'recent' ? row.assessment?.title || 'Assessment unavailable' : 'current state unknown');
    add('Queued completions', r.pending); add('Delivery failures (cumulative)', r.delivery_failures); add('Dropped completions (cumulative)', r.dropped);
    if (r.dropped) lines.push('Evidence gap: dropped completions may be unrecoverable.');
    add('Host-reported source state', health?.source_state || 'unknown');
    add('Persisted queued completions', health?.outbox?.persisted);
    add('Recovered after host restart', health?.outbox?.recovered);
    if (row.freshness !== 'recent') lines.push('Next action: Check the reporting host, recorder and clocks, then obtain a new report.');
    else for (const issue of row.assessment?.issues || []) {
      add('Issue', issue.stage + ' / ' + issue.code); add('Next action', issue.next_action);
    }
    if (row.freshness === 'recent' && !row.assessment?.issues?.length) lines.push('Next action: Inspect the reporting host diagnostics and refresh its report before assessing recovery.');
    limits(row.assessment?.limits);
    if (ingestion.forwarders_truncated) lines.push('Limit: Other forwarding instances may be omitted.');
    lines.push('Host reports do not establish complete delivery, durable daemon storage or protection coverage.');
  } else if (kind === 'evidence' || kind === 'repair') {
    const repair = kind === 'repair';
    if (!(repair ? validHookRepair(payload, scope) : validHookEvidence(payload, scope))) return null;
    const p = payload, f = p.filter;
    add('Type', repair ? 'Repair verification' : 'Recorded completions');
    add('Runtime', f.harness); add('Session', p.session_id); add('Event', f.event);
    add('Event scope', f.event_scope || 'group'); add('Handler', f.handler_id || 'unattributed'); add('Original configuration', f.config_id || 'not supplied');
    add('Observation window', p.since + ' to ' + p.until);
    if (repair) {
      add('Original failure', scope.problem || 'Hook repeatedly failed'); add('Original observation', scope.explanation || 'not supplied');
      add('Last original failure', scope.after); add('Original guidance', scope.guidance || 'not supplied');
      const v = p.verification;
      add('Verification state', v.state); add('Verification result', v.title); add('Observation', v.detail);
      add('Newest observed completion', v.observed_at); add('Observed configuration', v.config_id || 'not supplied');
      add('Verification run IDs', v.run_ids.slice(0, 20).join(', ') || 'none reported');
      if (v.run_ids.length > 20) add('Verification sample', '20 of ' + v.run_ids.length + ' returned run IDs');
      if (v.reason_code) add('Reported reason', v.reason_code);
      if (v.truncated) lines.push('Limit: Verification evidence is truncated; repair remains unconfirmed.');
      limits(v.limits);
      lines.push('Original-configuration completions follow; they are separate from the newer verification result.');
    }
    add('Completion sample', Math.min(20, p.rows.length) + ' of ' + p.rows.length + ' returned rows');
    if (p.truncated) lines.push('Limit: Evidence is limited to the latest 100 matching runs.');
    if (p.rows.length > 20) lines.push('Limit: This summary includes only the first 20 returned rows; inspect the remaining rows in Secure Agent.');
    if (!p.rows.length) lines.push('No matching retained completions; recovery and whether hooks ran remain unknown.');
    for (const r of p.rows.slice(0, 20)) {
      lines.push(''); add('Run', r.id); add('Time', r.ts); add('Outcome', r.status);
      add('Reported reason', r.evidence?.reason_code || 'not reported');
      add('Duration', r.duration_ms === undefined ? 'unknown' : fmtDurationMs(r.duration_ms));
      add('Returned characters', r.chars === undefined ? 'unknown' : r.chars);
      add('Host-reported action outcome', r.evidence?.action_outcome || 'unknown');
      add('Host-reported control role', r.evidence?.control_role || 'unknown');
    }
    lines.push('Equal timestamps do not establish execution order.');
    if (!repair) lines.push('Next action: Compare these outcomes with the handler configuration, then refresh evidence after a real completion.');
    lines.push('Recorded completions do not establish lasting repair, total task delay, token cost or protection coverage.');
  } else return null;
  return lines.join('\n');
}

function hookDiagnosticPreviewHTML(summary) {
  return html`<details class="hook-diagnostic-preview"><summary>Preview diagnostic summary</summary><label>Diagnostic summary<textarea readonly rows="10" spellcheck="false">${summary}</textarea></label><p>Only normalized metadata is included. Review this snapshot before sharing it.</p></details><p id="hook-diagnostic-status" role="status"></p>`;
}

function hookEvidenceButtonHTML(f, sessionId, exact = false) {
  if (!sessionId || !HOOK_HARNESSES.includes(f.harness)) return '';
  return html`<button type="button" class="link-btn" data-action="hook-evidence" data-session="${sessionId}" data-harness="${f.harness}" data-event="${f.event}" data-event_scope="${exact ? 'exact' : 'group'}" data-script="${f.script || ''}" data-handler="${f.handler_id || ''}" data-config="${f.config_id || ''}">Inspect recorded runs</button>`;
}

function hookRepairScope(f, session) {
  if (!session || f?.kind !== 'execution-errors' || !f.handler_id) return null;
  return {session,harness:f.harness,event:f.event,event_scope:'exact',handler:f.handler_id,config:f.config_id || '',script:f.script || '',after:f.last_at,
    problem:f.title,explanation:f.detail,guidance:f.next_action};
}

function hookInstant(value) {
  const m=typeof value==='string' && value.match(/^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/);
  if (!m || !Number.isFinite(Date.parse(m[1]+m[3]))) return null;
  return BigInt(Date.parse(m[1]+m[3]))*1000000n + BigInt((m[2] || '').padEnd(9,'0'));
}

function validHookRepair(page, scope) {
  if (!validHookEvidence(page,scope) || page.filter.event_scope !== 'exact' || !scope.handler
    || !page.filter.verify_after || page.filter.verify_after !== scope.after) return false;
  const v=page.verification, time=s=>typeof s==='string' && Number.isFinite(Date.parse(s));
  const id=s=>typeof s==='string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(s);
  return !!v && typeof v==='object' && !Array.isArray(v)
    && ['awaiting-completion','successful-completion','still-failing','decision-observed','configuration-changed','unconfirmed'].includes(v.state)
    && ['title','detail'].every(k=>typeof v[k]==='string' && v[k].length>0 && v[k].length<=2048)
    && typeof v.config_id==='string' && (v.config_id==='' || id(v.config_id))
    && typeof v.truncated==='boolean' && (!v.truncated || v.state==='unconfirmed')
    && Array.isArray(v.run_ids) && v.run_ids.length<=1000 && v.run_ids.every(id) && new Set(v.run_ids).size===v.run_ids.length
    && Array.isArray(v.limits) && v.limits.length>0 && v.limits.length<=5 && v.limits.every(s=>typeof s==='string' && s.length<=2048)
    && (v.reason_code===undefined || ['timeout','dependency-unavailable','invalid-output','permission-denied','execution-failed','policy-block'].includes(v.reason_code))
    && (v.observed_at===undefined ? v.run_ids.length===0 && ['unconfirmed','awaiting-completion'].includes(v.state)
      : time(v.observed_at) && hookInstant(v.observed_at)!==null && hookInstant(scope.after)!==null && hookInstant(v.observed_at)>hookInstant(scope.after) && Date.parse(v.observed_at)<=Date.parse(page.until) && v.run_ids.length>0)
    && (v.state!=='configuration-changed' || v.config_id!=='' && v.config_id!==scope.config)
    && (!['successful-completion','still-failing','decision-observed'].includes(v.state) || v.config_id===scope.config);
}

function hookRepairHTML(scope, page, message) {
  const baseline=html`<section class="sd-finding"><h4>Original failure: ${scope.problem || 'Hook repeatedly failed'}</h4><p>${scope.explanation || ''}</p><p>Last observed failure: <time>${scope.after}</time></p><details><summary>Original failure details</summary><p>Handler: ${scope.handler} · Configuration: ${scope.config || 'not supplied'}</p><p>Original guidance: ${scope.guidance || ''}</p></details></section>`;
  const v=page?.verification;
  if (!v) return html`<section class="sd-hook-evidence">${raw(baseline)}<p role="status">${message || 'Loading verification evidence…'}</p></section>`;
  return html`<section class="sd-hook-evidence">${raw(baseline)}<section aria-label="Repair check result" role="status"><h4>${v.title}</h4><p>${v.detail}</p>${v.observed_at ? raw(html`<p>Newest observed completion: <time>${v.observed_at}</time> · Configuration: ${v.config_id && v.config_id===scope.config ? 'Matches the original reported revision' : v.config_id || 'not supplied'}</p><details><summary>Completion identifiers</summary><p>Run IDs: ${v.run_ids.join(', ')}</p></details>`) : ''}${v.reason_code ? raw(html`<p>Reported reason: ${v.reason_code}</p>`) : ''}${v.limits.map(s=>raw(html`<p>${s}</p>`))}</section><details><summary>Recorded runs for the original configuration</summary>${raw(hookEvidenceHTML(page))}</details></section>`;
}

function hookFindingBodyHTML(f, sessionId) {
  const repair=hookRepairScope(f,sessionId);
  const check=repair ? html`<button type="button" class="link-btn" data-action="hook-repair-check" ${raw(Object.entries(repair).map(([k,v])=>html`data-${k}="${v}"`).join(' '))}>Check repair</button>` : '';
  return html`<p>${f.detail}</p><p><strong>Next action:</strong> ${f.next_action}</p>
    <p>${f.event}${f.script ? ' · ' + f.script : ''} · Handler: ${f.handler_id}${f.config_id ? ' · Configuration: ' + f.config_id : ''}</p>
    <p>${Number(f.count)} observed runs · <time>${f.first_at}</time> to <time>${f.last_at}</time></p>
    ${(f.limits || []).map(limit => raw(html`<p class="sd-context-limit">${limit}</p>`))}${raw(check)}${raw(hookEvidenceButtonHTML(f, sessionId, true))}`;
}

function sessionHookHealthHTML(health, state, sessionId) {
  const head = '<h4>Hook findings</h4>';
  if (!health || !health.available) return html`<section data-session-part="hook-health" class="sd-findings-head">${raw(head)}<p role="status">Hook assessment unavailable. Refresh current session status to retry.</p></section>`;
  const stale = state && state.error ? '<p role="status">Showing the last loaded hook assessment; it may be out of date.</p>' : '';
  const limits = html`${raw(health.truncated ? '<p>Analysis is limited to recent samples and up to 20 findings.</p>' : '')}${health.unattributed_runs ? raw(html`<p>${Number(health.unattributed_runs)} recorded ${health.unattributed_runs === 1 ? 'run lacks' : 'runs lack'} handler identity and cannot support handler-specific findings.</p>`) : ''}`;
  const rows = health.findings.map(f => html`<article class="sd-finding"><h5>${f.title} · ${f.needs_action ? 'Needs repair' : 'Advisory'}</h5>${raw(hookFindingBodyHTML(f, sessionId))}</article>`).join('');
  return html`<section data-session-part="hook-health" class="sd-findings-head">${raw(head)}${raw(stale)}<p>${Number(health.observed_runs)} recorded completions assessed from ${health.since} to ${health.until}. This does not establish protection coverage.</p>${raw(limits)}${raw(rows || '<p>No repair or advisory pattern was found in the assessed records.</p>')}</section>`;
}

// Identified handlers stay separate; legacy rows remain event/script totals.
function validSessionHooks(rows) {
  const count = v => Number.isInteger(v) && v >= 0;
  return Array.isArray(rows) && rows.every(r => r && typeof r === 'object' && !Array.isArray(r)
    && typeof r.event === 'string' && typeof r.script === 'string' && typeof r.last_at === 'string'
    && ['runs', 'errors', 'blocks', 'chars', 'total_ms'].every(k => count(r[k]))
    && ['cancelled', 'duration_samples', 'char_samples'].every(k => r[k] === undefined || (count(r[k]) && r[k] <= r.runs))
    && ['harness', 'handler_id', 'config_id'].every(k => r[k] === undefined || typeof r[k] === 'string'));
}

// Group totals remain scoped to the selected session; these controls only
// narrow the retained response and never change the current diagnosis.
function hookMeasurementKnown(row, key, samples) {
  return row[samples] === undefined ? row[key] > 0 : row[samples] > 0;
}

function selectHookHistory(rows, controls = {}) {
  const query = String(controls.query || '').trim().toLowerCase();
  const outcome = ['errors', 'blocks', 'cancelled'].includes(controls.outcome) ? controls.outcome : 'all';
  const sort = ['runs', 'total_ms', 'chars'].includes(controls.sort) ? controls.sort : 'runs';
  const samples = sort === 'total_ms' ? 'duration_samples' : 'char_samples';
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  const identity = r => JSON.stringify([r.harness || '', r.event, r.script || '', r.handler_id || '', r.config_id || '']);
  return rows.filter(r => (outcome === 'all' || r[outcome] > 0)
    && (!query || [r.event, r.script, r.handler_id].some(v => String(v || '').toLowerCase().includes(query))))
    .sort((a, b) => {
      if (sort !== 'runs') {
        const knownA = hookMeasurementKnown(a, sort, samples), knownB = hookMeasurementKnown(b, sort, samples);
        if (knownA !== knownB) return knownA ? -1 : 1;
        if (!knownA) return compare(identity(a), identity(b));
      }
      return b[sort] - a[sort] || compare(identity(a), identity(b));
    });
}

function sessionHooksHTML(rows, state, health, healthState, ingestion, sessionId, controls = {}) {
  state = state || {};
  const retry = '<button type="button" class="link-btn" data-action="session-hooks-retry">Retry hooks</button>';
  const notice = state.error ? html`Hook runs unavailable.${rows ? ' Showing the last loaded totals; they may be out of date.' : ''} ${raw(retry)}`
    : !rows ? 'Loading hook runs…' : '';
  const head = sessionHookHealthHTML(health, healthState, sessionId) + hookIngestionHTML(ingestion, healthState) + html`<header data-session-part="hooks-head"><h4>Hook history</h4><button type="button" class="link-btn" data-action="hook-setup">Hook setup and verification</button><p>Recorded completions from session transcripts and connected hosts. Errors and cancellations are separate. Blocks can be expected protection or validation decisions. Cumulative runtime can include overlapping callbacks. Outcome counts are historical; current repair findings are assessed separately. Measurement sorts use reported totals; unknown values sort last.</p>${notice ? raw(html`<p role="status">${raw(notice)}</p>`) : ''}</header>`;
  // Static markup keeps native inputs and their caret stable during refreshes.
  const tools = html`<div class="sd-hook-controls" data-session-part="hooks-controls" role="group" aria-label="Filter hook history">
    <label>Search hook history<input type="search" maxlength="256" data-hook-history="query" placeholder="Event, script or handler ID"></label>
    <label>Outcome<select data-hook-history="outcome"><option value="all">All outcomes</option><option value="errors">Execution errors</option><option value="blocks">Blocks</option><option value="cancelled">Cancellations</option></select></label>
    <label>Sort by<select data-hook-history="sort"><option value="runs">Most runs</option><option value="total_ms">Cumulative runtime</option><option value="chars">Returned characters</option></select></label>
    <button type="button" class="link-btn" data-action="hook-history-clear">Clear filters</button></div>`;
  if (!rows) return head;
  const selected = selectHookHistory(rows, controls);
  const count = html`<p data-session-part="hooks-count" role="status">${selected.length} of ${rows.length} recorded hook groups.</p>`;
  if (!rows.length) return head + tools + count + '<p data-session-part="hooks-empty">No hook runs recorded for this session.</p>';
  if (!selected.length) return head + tools + count + '<p data-session-part="hooks-empty">No hook groups match these filters. Clear filters to see retained history.</p>';
  const metric = (r, key, samples, format) => {
    if (!hookMeasurementKnown(r, key, samples)) return 'unknown';
    return html`${format(r[key])}${r[samples] !== undefined && r[samples] < r.runs ? ` (${r[samples]}/${r.runs} measured)` : ''}`;
  };
  const cell = (label, value) => raw(html`<td role="cell" data-label="${label}">${value}</td>`);
  const body = selected.map(r => raw(html`<tr${raw(r.errors > 0 ? ' class="sd-hook-failed"' : '')} role="row" data-row-id="${JSON.stringify([r.harness || '',r.event,r.script || '',r.handler_id || '',r.config_id || ''])}">
      ${cell('Event',r.event)}${cell('Handler',raw(html`${r.script || 'not recorded'}<details><summary>Handler details</summary><p>Handler: ${r.handler_id || 'identity unavailable'}<br>Configuration: ${r.config_id || 'not supplied'}</p></details>${raw(hookEvidenceButtonHTML(r, sessionId))}`))}
      ${cell('Runs',r.runs)}${cell('Errors',r.errors)}${cell('Blocked',r.blocks)}${cell('Cancelled',r.cancelled || 0)}
      ${cell('Chars returned',raw(metric(r, 'chars', 'char_samples', fmtCompact)))}${cell('Cumulative runtime',raw(metric(r, 'total_ms', 'duration_samples', fmtDurationMs)))}</tr>`));
  return head + tools + count + html`<div class="sd-hooks-scroll" data-session-part="hooks-table" role="region" aria-label="Hook history" tabindex="0"><table class="sd-hooks" role="table"><thead role="rowgroup"><tr role="row">
      <th scope="col" role="columnheader">Event</th><th scope="col" role="columnheader">Handler</th><th scope="col" role="columnheader">Runs</th><th scope="col" role="columnheader">Errors</th>
      <th scope="col" role="columnheader">Blocked</th><th scope="col" role="columnheader">Cancelled</th><th scope="col" role="columnheader">Chars returned</th><th scope="col" role="columnheader">Cumulative runtime</th>
    </tr></thead><tbody role="rowgroup">${body}</tbody></table></div>`;
}

// Durable IDs are the entry point; live process counts and setup checks do
// not substitute for a session's own record.
function recentWorkActivity(s) {
  for (const [at, label] of [[s.ended_at, 'Ended'], [s.last_seen_at, 'Last observed'], [s.started_at, 'Started']]) {
    if (at && Number.isFinite(Date.parse(at))) return {at, label, ms:Date.parse(at)};
  }
  return {ms:0};
}

function recentWorkSessions(sessions, search, order = []) {
  const rank = new Map(order.map((id, i) => [id, i]));
  return sessions.filter(s => ['active', 'idle', 'ended'].includes(s.status) && sessionMatchesText(s, search))
    .sort((a, b) => (rank.get(a.id) ?? Infinity) - (rank.get(b.id) ?? Infinity)
      || recentWorkActivity(b).ms - recentWorkActivity(a).ms || a.id.localeCompare(b.id));
}

function recentWorkRowHTML(s) {
  const seen = recentWorkActivity(s);
  const name = s.repo || sessionTitle(s);
  return html`<div class="session-daily-row"><button type="button" class="session-daily-card" data-action="session-current" data-session="${s.id}" title="Session ${s.id}">
    <span class="session-daily-workspace"><strong>${name}</strong><small title="${s.branch || ''}">${s.branch || 'Branch not recorded'}</small></span>
    <span class="session-daily-identity">${raw(harnessChipHTML(s.harness))}<span>${harnessMeta(s.harness).label}</span></span>
    <span class="session-daily-status" data-status="${s.status}">${s.status}</span>
    <time datetime="${seen.at || ''}" title="${seen.at ? seen.label + ': ' + new Date(seen.at).toLocaleString() : 'Activity time unavailable'}">${seen.at ? eventTime(new Date(seen.at)) : '—'}</time>
  </button><button type="button" class="btn btn-ghost btn-sm session-daily-results" data-action="recent-session-results" data-session="${s.id}" aria-label="Review results for ${name} · ${s.id}">Results<svg class="icon" aria-hidden="true"><use href="#i-arrow"/></svg></button></div>`;
}

function recentWorkFrameHTML(rows, total) {
  return html`<div class="session-daily-grid"><div class="session-daily-labels" aria-hidden="true"><span>Workspace</span><span>Agent</span><span>Status</span><span>Last activity</span></div><div class="session-daily-rows">${raw(rows)}</div></div><p class="recent-work-count">Showing ${Math.min(6,total)} of ${total} loaded sessions</p>`;
}

function sessionDailyHTML(sessions, coverage, search, order = []) {
  if (!Array.isArray(sessions)) return '<p role="status">Session data unavailable.</p>';
  const recent = recentWorkSessions(sessions, search, order);
  if (!recent.length && String(search || '').trim()) return '<p role="status">No sessions match your search. <button type="button" class="link-btn" data-action="clear-global-search">Clear search</button></p>';
  if (!recent.length) return '<p>No sessions recorded in the loaded history.</p>';
  return recentWorkFrameHTML(recent.slice(0,6).map(recentWorkRowHTML).join(''), recent.length);
}

function renderSessionDaily() {
  const el = document.getElementById('session-daily');
  if (!el) return;
  const SA = window.SA;
  const search = window.globalSearchTerm?.() || '';
  if (el._recentSearch !== search) el._recentOrder = null;
  el._recentSearch = search;
  const latest = Array.isArray(SA.t.sessions) ? recentWorkSessions(SA.t.sessions, search) : [];
  const ordered = Array.isArray(SA.t.sessions) ? recentWorkSessions(SA.t.sessions, search, el._recentOrder || []) : [];
  const shown = ordered.slice(0,6);
  el._recentOrder = shown.map(s=>s.id);
  const refresh = document.querySelector('[data-action="recent-work-refresh"]');
  if (refresh) {
    const changed = latest.slice(0,6).some((s,i)=>s.id !== shown[i]?.id);
    refresh.classList.toggle('has-updates', changed);
    refresh.title = changed ? 'New activity available — update list order' : 'Reorder by latest activity';
    refresh.setAttribute('aria-label', refresh.title);
  }
  if (!shown.length) {
    const markup = sessionDailyHTML(SA.t.sessions, null, search);
    if (el._saHTML !== markup) el.innerHTML = markup;
    el._saHTML = markup;
    return;
  }
  const focused = el.contains(document.activeElement) ? document.activeElement : null;
  const target = focused?.dataset;
  if (!el.querySelector('.session-daily-rows')) el.innerHTML = recentWorkFrameHTML('',ordered.length);
  el._saHTML = null;
  patchList(el.querySelector('.session-daily-rows'), shown, {key:s=>s.id, html:recentWorkRowHTML,
    hash:s=>JSON.stringify([s.id,s.repo,s.branch,s.harness])});
  for (const [i,row] of Array.from(el.querySelector('.session-daily-rows').children).entries()) {
    const s = shown[i], seen = recentWorkActivity(s);
    const status = row.querySelector('.session-daily-status');
    status.textContent = s.status; status.dataset.status = s.status;
    const time = row.querySelector('time');
    time.dateTime = seen.at || '';
    time.textContent = seen.at ? eventTime(new Date(seen.at)) : '—';
    time.title = seen.at ? seen.label + ': ' + new Date(seen.at).toLocaleString() : 'Activity time unavailable';
  }
  el.querySelector('.recent-work-count').textContent = `Showing ${shown.length} of ${ordered.length} loaded sessions`;
  if (focused && !focused.isConnected && target?.action && target.session) Array.from(el.querySelectorAll('[data-action]'))
    .find(node=>node.dataset.action===target.action && node.dataset.session===target.session)?.focus({preventScroll:true});
}

// Validate the fields consumed by the current-status view before replacing
// its last successful response. Unknown assessment values remain unknown.
function validSessionOverview(data, id) {
  const record = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  const text = (v, names) => names.every(k => v[k] === undefined || typeof v[k] === 'string');
  const number = (v, names) => names.every(k => v[k] === undefined || (typeof v[k] === 'number' && Number.isFinite(v[k]) && v[k] >= 0));
  const rows = (v, test) => v == null || (Array.isArray(v) && v.every(test));
  const strings = v => rows(v, s => typeof s === 'string');
  const time = v => v === undefined || (typeof v === 'string' && Number.isFinite(Date.parse(v)));
  const assessment = a => record(a) && text(a, ['risk', 'review_state', 'control', 'residual_risk', 'reason'])
    && strings(a.evidence_basis) && strings(a.limits)
    && (a.advice == null || (record(a.advice) && text(a.advice, ['assessment', 'rationale']) && number(a.advice, ['confidence'])));
  if (!record(data) || data.session_id !== id || !time(data.observed_at)
    || !Array.isArray(data.requests) || !Array.isArray(data.findings) || data.findings.length > 20
    || (data.findings_truncated !== undefined && typeof data.findings_truncated !== 'boolean')) return false;
  if (data.hook_health != null && !validHookHealth(data.hook_health)) return false;
  if (data.hook_ingestion != null && !validHookIngestion(data.hook_ingestion)) return false;
  if (!data.requests.every(r => record(r) && r.kind === 'guard' && typeof r.id === 'string' && r.id.length > 0
    && text(r, ['title', 'detail', 'path', 'rule', 'scopeText', 'reader_exe'])
    && rows(r.available_scopes, c => record(c) && typeof c.kind === 'string' && text(c, ['expiry'])))) return false;
  if (!data.findings.every(f => record(f) && typeof f.id === 'string' && f.id.length > 0
    && text(f, ['title']) && time(f.at) && assessment(f.assessment))) return false;
  if (data.coverage != null && (!record(data.coverage) || data.coverage.session_id !== id
    || !['guard', 'trace', 'payload'].every(k => record(data.coverage[k]) && typeof data.coverage[k].state === 'string'
      && typeof data.coverage[k].detail === 'string' && text(data.coverage[k], ['last_seen'])
      && (data.coverage[k].supported === undefined || typeof data.coverage[k].supported === 'boolean')))) return false;
  const r = data.resources;
  return r == null || (record(r) && typeof r.key === 'string' && r.key.length > 0 && time(r.observed_at)
    && number(r, ['rss_bytes', 'cpu_percent', 'process_count'])
    && rows(r.diagnoses, d => record(d) && text(d, ['summary']))
    && (r.control == null || (record(r.control) && text(r.control, ['state', 'last_error']))));
}

// Coverage states describe observations, not a diagnosis that setup is broken.
function sessionCoverageHTML(data, state = {}) {
  const id = data.session_id;
  const refresh = html`<button type="button" class="link-btn" data-action="session-overview-retry"${raw(state.loading ? ' disabled' : '')}>${state.loading ? 'Refreshing observations…' : 'Refresh observations'}</button>`;
  const head = html`<header class="sd-coverage-head"><h5>Observed paths</h5>${raw(refresh)}</header>`;
  const events = html`<button type="button" class="link-btn" data-action="session-events" data-id="${id}">View recorded session events</button>`;
  if (!data.coverage) return head + '<p>No current coverage is attributed to this session. Retained events do not establish live protection.</p>' + (state.error ? '' : events);
  return head + (state.error ? '<p class="sd-coverage-notice" role="status">Last known observations. Refresh before relying on current coverage.</p>' : '')
    + [['guard','Guard'],['trace','Recorded activity'],['payload','Payload inspection']].map(([key,label]) => {
      const path = data.coverage[key] || {};
      const stale = !!state.error || path.state === 'stale';
      const guide = html`<button type="button" class="link-btn" data-action="session-coverage-guide" data-id="${id}" data-path="${key}">${path.state === 'unsupported' || path.supported === false ? 'Review available paths' : key === 'guard' ? 'Review guard setup' : 'Review activity sources'}</button>`;
      const traffic = html`<button type="button" class="link-btn" data-action="session-coverage-traffic" data-id="${id}">Review Traffic settings</button>`;
      let next = '', action = '';
      if (stale) next = 'Refresh observations before relying on this result.';
      else if (path.state === 'unsupported' || path.supported === false) { next = 'This path is not supported by this source. Other observation paths may still be available.'; action = guide; }
      else if (path.state === 'observed') { next = 'This observation does not establish coverage of every operation.'; action = key === 'payload' ? traffic : events; }
      else if (key === 'payload' && ['off','unattributed','not-observed'].includes(path.state)) {
        next = 'Machine-wide traffic does not establish this session’s payload coverage. Routing and inspection are separate opt-ins.'; action = traffic;
      } else if (path.state === 'not-observed') { next = 'Run a small supported task, then refresh. Missing activity alone does not mean setup is broken.'; action = guide; }
      else if (path.state === 'unattributed') { next = 'Session identity is unresolved. Compare the harness and workspace before relying on attribution.'; action = guide; }
      else if (path.state === 'off') { next = 'Review this capability’s configuration if you need it. Nothing is enabled automatically.'; action = guide; }
      else next = 'The current state is unknown. Refresh observations before choosing a setup change.';
      return html`<article data-coverage-path="${key}"><b>${label}: ${coveragePathLabel(path)}</b><p>${path.detail || ''}</p>${path.last_seen ? raw(html`<time datetime="${path.last_seen}">Last observed: ${path.last_seen}</time>`) : ''}<p class="sd-coverage-next">${next}</p>${action ? raw(action.replace('<button ', html`<button data-coverage-origin="${key}" `)) : ''}</article>`;
    }).join('');
}

function sessionCoverageGuideHTML(session, key, path) {
  const name = harnessMeta(session?.harness).label;
  if (path.state === 'unsupported' || path.supported === false) return html`<p>This source does not support this observation path. An unsupported path is not a failed setup check.</p><p>Review the other observed paths for ${name}; each has its own limits.</p><p><a href="https://github.com/cavi-ai/secure-agent/blob/main/docs/ARCHITECTURE.md#collectors" target="_blank" rel="noopener noreferrer">Harness observation sources</a></p>`;
  if (key === 'guard') return html`<p>Guard observations record invocations attributed to this session. No invocation observed does not by itself establish a broken installation.</p>${['claude','cursor'].includes(session?.harness) ? raw(html`<ol><li>Open Secure Agent’s Setup &amp; Permissions and select ${name}.</li><li>Review the selected harness’s installed guard hooks and run its installed-hook check if needed.</li><li>Run a small ordinary task in the same workspace, then return here and refresh observations.</li></ol>`) : raw(html`<p>Review ${name} in Setup &amp; Permissions and check its supported guarding path before changing configuration.</p>`)}<p>An installed-hook check establishes its manual monitor round trip. It does not prove that a running session invokes the guard or that traffic is inspected. Hook-completion reporting is a separate integration.</p>`;
  return html`<p>Recorded activity depends on the supported process, transcript, or tool sources for ${name}. Missing activity may reflect a quiet task, an unavailable source, or unresolved session identity.</p><ol><li>In the same harness and workspace, ask for a file listing and README summary without changing files or reading secrets.</li><li>Refresh observations and inspect recorded session events.</li><li>If activity is still missing, review this harness’s observation sources in Setup &amp; Permissions.</li></ol><p>Hook-completion reporting alone does not establish trace or guard coverage.</p><p><a href="https://github.com/cavi-ai/secure-agent/blob/main/docs/FIRST_SESSION.md" target="_blank" rel="noopener noreferrer">First observed session guide</a></p>`;
}

function sessionOverviewHTML(data, state, contextHTML = '') {
  state = state || {};
  const retry = html`<button type="button" class="link-btn" data-action="session-overview-retry"${raw(state.loading ? ' disabled' : '')}>${state.loading ? 'Retrying current status…' : 'Retry current status'}</button>`;
  const status = !data ? state.loading && !state.error ? 'Loading current session status…' : html`Current session status unavailable. ${raw(retry)}`
    : state.error ? html`Last known session status. Refresh failed; requests and measurements may have changed. ${raw(retry)}` : '';
  const head = html`<div class="sd-current-head" data-session-part="current-head"><h4 tabindex="-1">Current session status</h4>${status ? raw(html`<p class="sd-current-status" role="status">${raw(status)}</p>`) : ''}</div>` + contextHTML;
  if (!data) return head;
  const disabled = raw(state.error ? ' disabled' : '');
  const requests = (data.requests || []).map(r => {
    const actions = needView({ ...r, kind: 'guard' }, { SA: window.SA }).items;
    return html`<fieldset class="sd-request" data-session-part="request:${r.id}"${disabled}>
      <legend>Access request</legend><p>${r.detail || r.title || 'Waiting for a decision'}</p>
      <p class="sd-context-limit">${r.scopeText || 'This request does not grant future access.'}</p>${raw(actionBarHTML(actions))}
    </fieldset>`;
  }).join('');
  const paths = sessionCoverageHTML(data, state);
  const resources = data.resources;
  const control = resources && resources.control;
  const impact = resources ? html`<p>${fmtRSS(resources.rss_bytes) || '—'} memory · ${fmtCPU(resources.cpu_percent) || '—'} CPU · ${Number(resources.process_count) || 0} processes</p>
    ${control ? raw(html`<p>Control: ${control.state || 'unknown'}${control.last_error ? ` · ${control.last_error}` : ''}</p>`) : ''}
    ${(resources.diagnoses || []).map(d => raw(html`<p>${d.summary || ''}</p>`))}
    <button type="button" class="link-btn" data-action="view-family" data-key="${resources.key}">Inspect session resources</button>`
    : '<p>No live resource family is attributed to this session.</p>';
  const findings = (data.findings || []).map(f => html`<article class="sd-finding" data-session-part="finding:${f.id}"><h5>${f.title || 'Finding'}</h5><p>Risk: ${(f.assessment || {}).risk || 'unknown'} · ${(f.assessment || {}).reason || 'Evidence interpretation unavailable'}</p>${raw(assessmentHTML(f.assessment))}
    <button type="button" class="link-btn" data-action="open-flag" data-id="${f.id}">View evidence</button></article>`).join('');
  return head + requests
    + sessionHookHealthHTML(data.hook_health, state, data.session_id)
    + hookIngestionHTML(data.hook_ingestion, state)
    + html`<section class="sd-coverage" data-session-part="coverage" aria-label="Observed session coverage">${raw(paths)}</section>`
    + html`<fieldset class="sd-impact" data-session-part="impact"${disabled}><legend>Machine impact</legend>${raw(impact)}</fieldset>`
    + html`<div class="sd-findings-head" data-session-part="findings-head"><h4>Retained findings</h4><p>${data.findings_truncated ? 'More findings exist than the 20 most recent shown here.' : (data.findings || []).length ? 'Review and remaining risk are shown separately.' : 'No retained findings are attributed to this session. This is not a safety verdict.'}
      <button type="button" class="link-btn" data-action="session-findings" data-id="${data.session_id}">View session findings history</button></p></div>` + findings;
}

// Reconcile each request/finding independently. A new finding must not replace
// a focused approval button, an open disclosure, or the history view switch.
function patchSessionDetail(el, sessionID, markup) {
  const template = document.createElement('template');
  template.innerHTML = markup;
  const body = template.content.querySelector('.session-detail-body');
  const content = body && body.innerHTML;
  if (body) body.innerHTML = '';
  const parts = Array.from(template.content.children).map((node, i) => ({
    key: sessionID + ':' + (node.dataset.sessionPart || node.className || i), html: node.outerHTML,
  }));
  patchList(el, parts, { key: p => p.key, html: p => p.html });
  if (body) patchSessionDetail(el.querySelector('.session-detail-body'), sessionID + ':body', content);
}

// Latest durable receipts per context/operation, ordered by their recorded
// action time. Refreshes never turn a saved receipt into current authority.
function validSessionOutcomes(data, id) {
  const h = data && data.history;
  const record = r => !!r && typeof r === 'object' && typeof r.id === 'string' && !!r.id;
  const optionalArray = value => value == null || Array.isArray(value);
  return !!h && data.session_id === id && ['reviews', 'incidents', 'interventions'].every(key =>
    Array.isArray(h[key]) && h[key].every(record) && h.evidence &&
    typeof h.evidence[key]?.available === 'boolean' && typeof h.evidence[key]?.at_limit === 'boolean' && Number.isInteger(h.evidence[key]?.limit) && h.evidence[key].limit > 0) &&
    h.reviews.every(r => !r.decision || (typeof r.decision.action === 'string' && Number.isInteger(r.decision.revision))) &&
    (h.guards == null || (Array.isArray(h.guards) && h.guards.every(r => record(r) && r.session_id === id && typeof r.rule_id === 'string' && ['allow','deny'].includes(r.verdict) && typeof r.scope === 'string' && typeof r.at === 'string' && Number.isFinite(Date.parse(r.at)) && (r.scope_ids == null || (Array.isArray(r.scope_ids) && r.scope_ids.every(s => typeof s === 'string' && !!s)))) && h.evidence.guards && typeof h.evidence.guards.available === 'boolean' && Number.isInteger(h.evidence.guards.limit) && h.evidence.guards.limit > 0)) &&
    h.interventions.every(r => optionalArray(r.after) && optionalArray(r.limits)) &&
    h.incidents.every(inc => !inc.remediation || (Array.isArray(inc.remediation.steps) && inc.remediation.steps.every(step => record(step) && step.item && typeof step.item === 'object'))) &&
    validSessionFollowUp(data, id);
}

function validSessionFollowUp(data, id) {
  if (!Object.prototype.hasOwnProperty.call(data, 'follow_up')) return true;
  const f = data.follow_up, h = data.history;
  const keys = ['reviews', 'incidents', 'interventions', 'guards'];
  if (!f || f.schema_version !== 1 || f.session_id !== id || f.observed_at !== data.observed_at ||
      !Number.isFinite(Date.parse(f.observed_at)) || typeof f.partial !== 'boolean' ||
      !keys.every(key => {
        const source = f.sources?.[key], expected = h.evidence[key];
        return source && expected && typeof source.available === 'boolean' && typeof source.at_limit === 'boolean' &&
          Number.isSafeInteger(source.limit) && source.limit > 0 && source.available === expected.available &&
          source.at_limit === expected.at_limit && source.limit === expected.limit;
      }) || f.partial !== keys.some(key => !f.sources[key].available || f.sources[key].at_limit) ||
      !['newer_evidence', 'process_actions', 'reported_actions', 'permissions'].every(key => Array.isArray(f[key]))) return false;
  const string = value => typeof value === 'string';
  const unique = (rows, key) => new Set(rows.map(key)).size === rows.length;
  if (!f.newer_evidence.every(row => row && string(row.id) && row.id && string(row.title) &&
      Number.isSafeInteger(row.revision) && Number.isSafeInteger(row.decision_revision) &&
      typeof row.evidence_available === 'boolean' && string(row.evidence_flag_id) &&
      h.reviews.some(r => r.id === row.id && r.revision === row.revision && r.decision?.revision === row.decision_revision)) ||
      !unique(f.newer_evidence, row => row.id)) return false;
  if (!f.process_actions.every(row => row && string(row.id) && row.id && string(row.kind) && string(row.status) && string(row.verification) &&
      Array.isArray(row.limits) && row.limits.every(string) && h.interventions.some(r => r.id === row.id)) ||
      !unique(f.process_actions, row => row.id)) return false;
  if (!f.reported_actions.every(row => row && string(row.incident_id) && string(row.step_id) && string(row.title) && string(row.action) &&
      typeof row.newer_evidence === 'boolean' && row.verification === 'not_verified' &&
      h.incidents.some(inc => inc.id === row.incident_id && inc.remediation?.steps.some(step => step.id === row.step_id))) ||
      !unique(f.reported_actions, row => JSON.stringify([row.incident_id, row.step_id]))) return false;
  const allowed = new Map(legacySessionOutcomePermissionLinks(data).map(link => [link.kind + ':' + link.id, new Set(link.ids)]));
  return f.permissions.every(row => row && string(row.id) && string(row.title) && row.status === 'unknown' &&
    ['review', 'guard'].includes(row.kind) && Array.isArray(row.ids) && row.ids.length > 0 && row.ids.length <= 128 &&
    row.ids.every(value => string(value) && value && allowed.get(row.kind + ':' + row.id)?.has(value)) &&
    new Set(row.ids).size === row.ids.length) && unique(f.permissions, row => row.kind + ':' + row.id);
}

// Only IDs saved with this session's decisions can contribute permission rows.
// A receipt alone never establishes current applicability.
function legacySessionOutcomePermissionLinks(data) {
  const validIDs = ids => Array.isArray(ids) && ids.length > 0 && ids.length <= 128 && ids.every(id => typeof id === 'string' && !!id);
  const links = [];
  for (const r of data.history.reviews) {
    if (r.decision && Number.isSafeInteger(r.decision.revision) && r.decision.revision > 0 && validIDs(r.decision.scope_ids)) {
      links.push({ id: r.id, kind: 'review', ids: [...new Set(r.decision.scope_ids)], title: r.context?.rule || 'Review decision' });
    }
  }
  for (const g of data.history.guards || []) {
    if (g.session_id === data.session_id && g.verdict === 'allow' && ['session', 'exact'].includes(g.scope) && validIDs(g.scope_ids)) {
      links.push({ id: g.id, kind: 'guard', ids: [...new Set(g.scope_ids)], title: g.rule_id });
    }
  }
  return links;
}

function sessionOutcomePermissionLinks(data) {
  const legacy = legacySessionOutcomePermissionLinks(data);
  if (!data.follow_up) return legacy;
  return ['review', 'guard'].flatMap(kind => data.history.evidence[kind === 'review' ? 'reviews' : 'guards']?.available === true
    ? data.follow_up.permissions.filter(link => link.kind === kind)
    : legacy.filter(link => link.kind === kind));
}

function sessionFollowUpHTML(data, state = {}) {
  if (!data) return '';
  const h = data.history, stale = !!state.error || !!state.loading;
  // Read-only drill-downs re-read their own evidence. Keep them stable during
  // refresh so keyboard focus survives; suppress them after a failed read.
  const current = key => !state.error && h.evidence[key]?.available === true;
  const canonicalIDs = (key, source, identify = row => row.id) => data.follow_up && h.evidence[source]?.available === true
    ? new Set(data.follow_up[key].map(identify)) : null;
  const evidenceIDs = canonicalIDs('newer_evidence', 'reviews');
  const processIDs = canonicalIDs('process_actions', 'interventions');
  const reportedIDs = canonicalIDs('reported_actions', 'incidents', row => JSON.stringify([row.incident_id, row.step_id]));
  const evidenceRows = h.reviews.filter(r => evidenceIDs ? evidenceIDs.has(r.id) : r.decision && Number.isInteger(r.revision) && r.revision > r.decision.revision).map(r => {
    const link = current('reviews') && r.evidence_available && r.evidence_flag_available && r.evidence_flag_id
      ? html`<button type="button" class="link-btn" data-action="open-flag" data-id="${r.evidence_flag_id}">Review newer evidence</button>` : html`<p>${stale ? 'Refresh results before reviewing newer evidence.' : 'Source evidence unavailable. Refresh results before reviewing.'}</p>`;
    return html`<li data-row-id="follow-up:review:${r.id}"><strong>${r.context?.rule || 'Finding review'}</strong><p>Decision for revision ${Number(r.decision.revision)} · now revision ${Number(r.revision)}. The saved decision does not cover this evidence.</p>${raw(link)}</li>`;
  });
  const actionRows = h.interventions.filter(r => processIDs ? processIDs.has(r.id) : r.status !== 'cancelled' && !(r.status === 'applied' && (r.verification === 'observed' || (r.verification === 'verified' && r.verified_by === 'captured-family-absent')))).map(r =>
    html`<li data-row-id="follow-up:control:${r.id}" data-follow-up-id="${r.id}"><strong>Check process result</strong>${raw(resourceOutcomeHTML(r))}<p>Inspect the recorded result before deciding whether another action is needed.</p></li>`);
  for (const inc of h.incidents) {
    for (const step of inc.remediation?.steps || []) {
      if (reportedIDs ? !reportedIDs.has(JSON.stringify([inc.id, step.id])) : step.status !== 'reported') continue;
      actionRows.push(html`<li data-row-id="follow-up:incident:${inc.id}:${step.id}"><strong>${step.item.name} · ${step.item.action}</strong><p>Action reported, not technically verified.${step.newer_evidence ? ' Newer evidence exists; this report does not cover it.' : ''}</p>${current('incidents') ? raw(html`<button type="button" class="link-btn" data-action="open-incident" data-id="${inc.id}">Review incident report</button>`) : ''}</li>`);
    }
  }
  const permissions = state.permissions;
  const records = !stale && permissions?.records ? new Map(permissions.records.map(r => [r.id, r])) : null;
  const permissionRows = sessionOutcomePermissionLinks(data).map(link => {
    const rows = link.ids.map(id => {
      const r = records?.get(id);
      return raw(r ? html`<li><strong>${decisionScopeApplicability(r).label}</strong> · <code>${r.resource_path}</code>${r.expires_at ? raw(html`<p>Expires ${raw(localTimestampHTML(r.expires_at))}</p>`) : ''}${r.revoked_at ? raw(html`<p>Revoked ${raw(localTimestampHTML(r.revoked_at))}</p>`) : ''}</li>` : '<li>Current status unknown. The record is missing or unavailable; expiry or revocation cannot be established.</li>');
    });
    const action = !state.error ? html`<button type="button" class="link-btn" data-action="${link.kind === 'guard' ? 'session-guard-permissions' : 'session-permissions'}" ${raw(link.kind === 'guard' ? 'data-id' : 'data-review')}="${link.id}" data-session="${data.session_id}">Inspect permissions</button>` : '';
    return html`<li data-row-id="follow-up:permission:${link.kind}:${link.id}"><strong>${link.title}</strong><ul>${rows}</ul>${raw(action)}</li>`;
  });
  const group = (key, title, rows) => rows.length ? html`<div data-row-id="follow-up:group:${key}"><details data-session-details data-follow-up-group="${key}"><summary>${title}<span>${rows.length}</span></summary><ul>${raw(rows.join(''))}</ul></details></div>` : '';
  const partial = ['reviews', 'interventions', 'incidents', 'guards'].some(key => !h.evidence[key]?.available || h.evidence[key]?.at_limit);
  const count = evidenceRows.length + actionRows.length + permissionRows.length;
  return html`<section class="sd-follow-up" data-session-part="follow-up" aria-label="Session follow-up">
    <div class="sd-follow-up-head"><h4>Needs follow-up</h4><button type="button" class="link-btn" data-action="session-outcomes-retry"${raw(state.loading ? ' disabled' : '')}>${state.loading ? 'Refreshing…' : 'Refresh results'}</button></div>
    ${raw(stale ? html`<p role="status">${state.loading ? 'Refreshing follow-up' : 'Last known follow-up'}. Refresh must succeed before relying on these records.</p>` : data.observed_at ? html`<p>Results read at ${raw(localTimestampHTML(data.observed_at))}</p>` : '')}
    ${raw(partial ? '<p>Follow-up uses missing or bounded history. Other work may be absent.</p>' : '')}
    ${raw(!count ? '<p>No follow-up identified in the loaded records. This is not a safety verdict.</p>' : '')}
    ${raw(group('evidence', 'New evidence', evidenceRows))}${raw(group('actions', 'Actions to check', actionRows))}${raw(group('permissions', 'Permissions from decisions', permissionRows))}
    ${permissionRows.length ? raw(html`<p>${permissions?.loading ? 'Loading permission status…' : records ? raw(html`Permissions read at ${raw(localTimestampHTML(permissions.readAt))}. Applicability can change; inspect before relying on access.`) : 'Permission status unavailable. Inspect permissions to retry the current scope and expiry.'}</p>`) : ''}
  </section>`;
}

function sessionOutcomesHTML(data, state) {
  state = state || {};
  const retry = '<button type="button" class="link-btn" data-action="session-outcomes-retry">Retry results</button>';
  const notice = state.error ? html`Last known results. Refresh failed; later decisions or observations may be missing. ${raw(retry)}`
    : !data ? state.loading ? 'Loading decisions and results…' : html`Results unavailable. ${raw(retry)}` : '';
  const head = html`<header data-session-part="outcomes-head"><h4>Decisions and results</h4><p>Saved decisions and action receipts. They do not prove task completion or tool access. Review payload outcomes in Evidence.</p>${notice ? raw(html`<p role="status">${raw(notice)}</p>`) : ''}</header>`;
  if (!data) return head;
  const h = data.history;
  const limits = [['reviews', 'Review decisions'], ['interventions', 'Process results'], ['incidents', 'Incident reports'], ['guards','Guard decisions']].map(([key, label]) => {
    const source = h.evidence[key];
    if(!source) return key === 'guards' ? '<p>Guard decision history unavailable from this daemon.</p>' : '';
    return !source.available ? html`<p role="status">${label} unavailable.${h[key].length ? ' Showing last known receipts; later changes may be missing.' : ''}</p>`
      : source.at_limit ? html`<p>${label}: bounded to ${Number(source.limit) || 0} retained records; earlier history may be omitted.</p>` : '';
  }).join('');
  const rows = [];
  for(const g of h.guards || []) {
    const linked = Array.isArray(g.scope_ids) && g.scope_ids.length && g.verdict === 'allow' && ['session','exact'].includes(g.scope);
    const permission = linked ? html`<button type="button" class="link-btn" data-action="session-guard-permissions" data-id="${g.id}" data-session="${data.session_id || ''}">View permissions</button>`
      : ['always','scoped','session','exact'].includes(g.scope) ? '<p>Permission linkage unavailable. Inspect Rules &amp; permissions; this record does not establish current access.</p>' : '<p>No future permission IDs recorded with this outcome. Other permissions may still apply.</p>';
    rows.push({key:'guard:'+g.id,at:g.at,title:g.verdict === 'allow' ? 'Guard allowed' : 'Guard denied',html:html`<p>${g.rule_id} · ${g.scope}${g.reason ? ` · ${g.reason}` : ''}</p><p>Recorded request outcome; tool receipt and completed access are not verified.</p>${raw(permission)}`});
  }
  for (const r of h.reviews) {
    if (!r.decision) continue;
    const d = r.decision;
    const scopes = Array.isArray(d.scope_ids) ? d.scope_ids : [];
    const label = { acknowledge: 'Reviewed', close_reported: 'Closure reported', expect: scopes.length ? 'Scoped permission recorded' : 'Expected once' }[d.action] || 'Saved decision';
    const permission = scopes.length ? html`<p>${scopes.length} permission scope${scopes.length === 1 ? '' : 's'} recorded. Inspect current expiry or revocation for this decision. <button type="button" class="link-btn" data-action="session-permissions" data-review="${r.id}" data-session="${data.session_id || ''}">View permissions</button></p>` : '';
    const changed = d.revision !== r.revision ? '<p>This decision does not cover newer evidence.</p>' : '';
    const source = !r.evidence_available ? '<p>Source evidence unavailable; the saved receipt remains.</p>' : !r.evidence_flag_available ? '<p>Assessment source evidence unavailable; other linked evidence may remain.</p>' : '';
    const link = r.evidence_flag_available && r.evidence_flag_id ? html`<button type="button" class="link-btn" data-action="open-flag" data-id="${r.evidence_flag_id}">View finding evidence</button>` : '';
    rows.push({ key: 'decision:' + r.id, at: d.at, title: label, html: html`<p>${(r.context || {}).rule || 'Finding'} · decision for revision ${d.revision}</p>${raw(changed)}${raw(permission)}<p>Remaining risk: ${(r.assessment || {}).residual_risk || 'unknown'}</p>${raw(source)}${raw(link)}` });
  }
  for (const r of h.interventions) {
    rows.push({ key: 'intervention:' + r.id, at: r.requested_at, title: 'Process control', html: resourceOutcomeHTML(r) });
  }
  for (const inc of h.incidents) {
    for (const step of ((inc.remediation || {}).steps || [])) {
      if (step.status !== 'reported') continue;
      rows.push({ key: 'incident:' + inc.id + ':' + step.id, at: step.reported_at, title: 'External action reported', html: html`<p>${step.item.name} · ${step.item.action}</p><p>Credential verification: ${step.verification || 'unverified'}</p>${raw(step.newer_evidence ? '<p>Newer evidence exists; this report does not establish its remediation.</p>' : '')}<button type="button" class="link-btn" data-action="open-incident" data-id="${inc.id}">View incident report</button>` });
    }
  }
  rows.sort((a, b) => (Date.parse(a.at) || 0) - (Date.parse(b.at) || 0) || a.key.localeCompare(b.key));
  const history = rows.map(row => {
    return html`<article class="sd-outcome" data-session-part="${row.key}" data-row-id="${row.key}"><h5>${row.title}</h5>${raw(localTimestampHTML(row.at))}${raw(row.html)}</article>`;
  }).join('');
  return sessionFollowUpHTML(data, state) + head + html`<div data-session-part="outcomes-limits">${raw(limits)}${raw(Object.values(h.evidence).some(source => !source.available) ? retry : '')}${raw(!rows.length && !limits ? '<p>No saved decisions or results in the retained history. This is not a safety verdict.</p>' : '')}</div>` + history;
}

function sessionDetailHTML(sess, events, trees, state = window.SA) {
  if (!sess) {
    return html`<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>Select a session to inspect its evidence</span></div>`;
  }
  const tree = liveTreeFor(sess, trees);
  const title = sessionTitle(sess, tree && tree.root.cwd);
  const path = sess.workspace && sess.workspace !== '/' ? sess.workspace : '';
  const meta = [
    sess.started_at ? 'started ' + fmtAge(sess.started_at, Date.now()) + ' ago' : '',
    sess.ended_at ? 'ended ' + fmtAge(sess.ended_at, Date.now()) + ' ago' : '',
  ].filter(Boolean).join(' · ');
  const contextHTML = html`<section class="session-context" data-session-part="session-context" aria-label="Session context">
      <button type="button" class="btn btn-sm btn-ghost" data-action="session-events" data-id="${sess.id}" title="Inspect retained file, connection, and tool events attributed to this session">View session events</button>
      <details class="session-metadata" data-session-details>
        <summary>Details</summary>
        <div class="sd-metadata-body">
          <span class="sd-harness">${harnessMeta(sess.harness).label}</span>
          ${sess.confidence ? raw(html`<span class="ss-chip sd-conf" title="How this session was identified">${sess.confidence}</span>`) : ''}
          ${path ? raw(html`<button type="button" class="sd-path" data-action="copy-path" data-path="${path}" title="${path} — click to copy">${path}</button>`) : ''}
          ${meta ? raw(html`<span class="sd-meta">${meta}</span>`) : ''}
        </div>
      </details>
    </section>`;
  return html`<div class="session-detail-chrome">
    <div class="session-detail-actions">
      ${raw(window.SA.recentWorkReturn ? '<button type="button" class="btn btn-sm btn-ghost" data-action="recent-work-home">Back to Home</button>' : '')}
      <button type="button" class="btn btn-sm btn-ghost sd-back" data-action="session-list">Back to sessions</button>
      <button type="button" class="btn btn-sm btn-ghost sd-status" data-action="session-status">Current status</button>
      <button type="button" class="btn btn-sm btn-ghost sd-export" data-action="copy-report" data-id="${sess.id}" title="Copy this session's report as markdown"><svg class="icon"><use href="#i-copy"/></svg>Copy report</button>
      ${sess.workspace ? raw(html`<button type="button" class="btn btn-sm btn-ghost" data-action="workspace-permissions" data-session="${sess.id}">Workspace permissions</button>`) : ''}
    </div>
    <div class="session-detail-head">
      ${raw(harnessChipHTML(sess.harness))}
      <h3 tabindex="-1">${title}</h3>
    </div>
    <div class="sd-detail-controls">
      <div class="sd-view-switch" role="group" aria-label="Session detail view">
        <button type="button" class="sd-view${state.sessionView === 'memory' ? ' active' : ''}" data-action="session-view" data-view="memory" aria-pressed="${state.sessionView === 'memory'}">Evidence</button>
        <button type="button" class="sd-view${state.sessionView === 'results' ? ' active' : ''}" data-action="session-view" data-view="results" aria-pressed="${state.sessionView === 'results'}">Results</button>
        <button type="button" class="sd-view${state.sessionView === 'trace' ? ' active' : ''}" data-action="session-view" data-view="trace" aria-pressed="${state.sessionView === 'trace'}">Trace</button>
        <button type="button" class="sd-view${state.sessionView === 'hooks' ? ' active' : ''}" data-action="session-view" data-view="hooks" aria-pressed="${state.sessionView === 'hooks'}">Hooks</button>
      </div>
      <button type="button" class="btn btn-sm btn-ghost sd-latest" data-action="session-latest" hidden>Jump to latest</button>
    </div>
    </div>
    <div class="session-detail-body" tabindex="-1">${raw(state.sessionView === 'hooks' ? contextHTML + sessionHooksHTML(state.sessionHooks, state.sessionHooksState, state.sessionOverview && state.sessionOverview.hook_health, state.sessionOverviewState, state.sessionOverview && state.sessionOverview.hook_ingestion, state.selectedSessionId, state.sessionHookHistory) : state.sessionView === 'results' ? contextHTML + sessionOutcomesHTML(state.sessionOutcomes, state.sessionOutcomesState) : sessionOverviewHTML(state.sessionOverview, state.sessionOverviewState, contextHTML) + (state.sessionView === 'trace' ? sessionTraceHTML(events, state.sessionTimelineState) : sessionMemoryHTML(state.sessionMemoryPage, state.sessionMemoryState)))}</div>`;
}

// One workbench owns selection, retained reads, rendering and reading position.
// createSessionWorkbench builds one state object; the sessionWorkbench*
// functions below read and write it.
const SESSION_WORKBENCH_SELECTION_KEY = 'sa.selected-session';

function createSessionWorkbench({ apiFetch, renderNow, onSelect = () => {} }) {
  // The generation invalidates late responses when selection changes; it
  // also protects an earlier-page request from writing into another session.
  const s = {
    apiFetch, renderNow, onSelect,
    selectedSessionId: '',
    sessionListView: 'harness',
    sessionSelectionInitialized: false,
    sessionFilterTransition: false,
    sessionReveal: false,
    sessionPane: 'detail',
    sessionListCollapsed: false,
    sessionView: 'memory',
    sessionMemoryPage: { rows: [], has_earlier: false, next_cursor: '' },
    sessionMemoryState: { loading: false, loadingEarlier: false, error: '' },
    sessionMemoryGeneration: 0,
    sessionMemoryAt: 0,
    sessionMemoryHistoryLoaded: false,
    sessionTimeline: [],
    sessionTimelineState: { loading: false, loaded: false, error: '' },
    sessionTimelineAt: 0,
    sessionTimelineRequest: 0,
    sessionOverview: null,
    sessionOverviewState: { loading: false, error: '' },
    sessionOverviewGeneration: 0,
    sessionOverviewAt: 0,
    sessionOverviewRefreshAgain: false,
    sessionOutcomes: null,
    sessionOutcomesState: { loading: false, error: '' },
    sessionOutcomesGeneration: 0,
    sessionOutcomesAt: 0,
    sessionHooks: null,
    sessionHooksState: { loading: false, error: '' },
    sessionHooksAt: 0,
    sessionHookHistory: { query: '', outcome: 'all', sort: 'runs' },
    // Reading state belongs to a session and a mode, not to a telemetry render.
    sessionReadingState: new Map(),
    sessionLayout: null
  };
  try { if (localStorage.getItem('sa.session-list-view') === 'sessions') s.sessionListView = 'sessions'; } catch { /* memory only */ }
  try { s.selectedSessionId = sessionStorage.getItem(SESSION_WORKBENCH_SELECTION_KEY) || ''; } catch { /* memory only */ }
  s.sessionLayout = createSessionLayout({getView: () => s.sessionView});
  return {
    setListView(view) {
      if (!['harness', 'sessions'].includes(view) || view === s.sessionListView) return;
      s.sessionListView = view;
      s.sessionReveal = true;
      try { localStorage.setItem('sa.session-list-view', view); } catch { /* memory only */ }
      s.renderNow(['sessions']);
    },
    get sessionListView() { return s.sessionListView; },
    setHookHistory: update => sessionWorkbenchSetHookHistory(s, update),
    get sessionHookHistory() { return { ...s.sessionHookHistory }; },
    selectSession: id => sessionWorkbenchSelect(s, id),
    setView: view => sessionWorkbenchSetView(s, view),
    render: () => sessionWorkbenchRenderBoard(s),
    refresh: (kind, options) => sessionWorkbenchRefresh(s, kind, options),
    refreshCurrent: force => sessionWorkbenchRefreshCurrent(s, force),
    activity: event => sessionWorkbenchActivity(s, event),
    invalidate: () => sessionWorkbenchInvalidate(s),
    restoreView: view => sessionWorkbenchRestoreView(s, view),
    showList: () => sessionWorkbenchShowList(s),
    jumpToLatest: () => sessionWorkbenchJumpToLatest(),
    showCurrentStatus: () => sessionWorkbenchShowCurrentStatus(s),
    toggleList: () => sessionWorkbenchToggleList(s),
    get sessionListCollapsed() { return s.sessionListCollapsed; },
    loadEarlier: () => sessionWorkbenchLoadEarlier(s),
    retryTrace: () => sessionWorkbenchRetryTrace(s),
    reconcileSelection: groups => sessionWorkbenchReconcileSelection(s, groups),
    takeReveal: () => sessionWorkbenchTakeReveal(s),
    filterChanged() { s.sessionFilterTransition = true; },
    readingHistory: (sessionId, mode) => sessionWorkbenchReadingHistory(s, sessionId, mode),
    get selectedSessionId() { return s.selectedSessionId; },
    get sessionTimeline() { return s.sessionTimeline; },
    get sessionTimelineState() { return s.sessionTimelineState; },
    get sessionView() { return s.sessionView; },
    get sessionMemoryPage() { return s.sessionMemoryPage; },
    get sessionMemoryState() { return s.sessionMemoryState; },
    get sessionOverview() { return s.sessionOverview; },
    get sessionOverviewState() { return s.sessionOverviewState; },
    get sessionOutcomes() { return s.sessionOutcomes; },
    get sessionOutcomesState() { return s.sessionOutcomesState; },
    get sessionHooks() { return s.sessionHooks; },
    get sessionHooksState() { return s.sessionHooksState; },
  };
}

function sessionWorkbenchRefreshCurrent(s, force) {
  if (s.selectedSessionId) {
    sessionWorkbenchLoadOverview(s, s.selectedSessionId, force);
    if (s.sessionView === 'results') sessionWorkbenchLoadOutcomes(s, s.selectedSessionId, force);
    if (s.sessionView === 'hooks') sessionWorkbenchLoadHooks(s, s.selectedSessionId, force);
  }
}

async function sessionWorkbenchLoadOutcomes(s, id, force = true) {
  if (!id || id !== s.selectedSessionId || s.sessionOutcomesState.loading) return;
  if (!force && Date.now() - s.sessionOutcomesAt < 5000) return;
  s.sessionOutcomesAt = Date.now();
  const generation = ++s.sessionOutcomesGeneration;
  s.sessionOutcomesState = { loading: true, error: s.sessionOutcomesState.error };
  s.renderNow(['sessions']);
  try {
    const response = await s.apiFetch('/sessions/' + encodeURIComponent(id) + '/outcomes');
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const data = await response.json();
    if (generation !== s.sessionOutcomesGeneration || id !== s.selectedSessionId) return;
    if (!validSessionOutcomes(data, id)) throw new Error('Invalid response');
    if (s.sessionOutcomes) for (const key of ['reviews', 'incidents', 'interventions', 'guards']) {
      if (data.history.evidence[key] && !data.history.evidence[key].available) data.history[key] = s.sessionOutcomes.history[key] || [];
    }
    let permissions;
    if (sessionOutcomePermissionLinks(data).length) {
      s.sessionOutcomes = data;
      s.sessionOutcomesState = { loading: false, error: '', permissions: { loading: true, records: null } };
      s.renderNow(['sessions']);
      try {
        const response = await s.apiFetch('/decision-scopes');
        if (!response.ok) throw new Error('Permissions unavailable');
        const records = await response.json();
        if (!validDecisionScopeRecords(records)) throw new Error('Invalid permissions');
        const ids = new Set(sessionOutcomePermissionLinks(data).flatMap(link => link.ids));
        permissions = { records: records.filter(r => ids.has(r.id)), readAt: new Date().toISOString(), error: '' };
      } catch {
        permissions = { records: null, error: 'unavailable' };
      }
      if (generation !== s.sessionOutcomesGeneration || id !== s.selectedSessionId) return;
    }
    s.sessionOutcomes = data;
    s.sessionOutcomesState = { loading: false, error: '', ...(permissions ? { permissions } : {}) };
  } catch {
    if (generation !== s.sessionOutcomesGeneration || id !== s.selectedSessionId) return;
    s.sessionOutcomesState = { loading: false, error: 'unavailable' };
  }
  s.renderNow(['sessions']);
}

async function sessionWorkbenchLoadHooks(s, id, force = true) {
  if (!id || id !== s.selectedSessionId || s.sessionHooksState.loading) return;
  if (!force && Date.now() - s.sessionHooksAt < 5000) return;
  s.sessionHooksAt = Date.now();
  const generation = s.sessionMemoryGeneration;
  const current = () => id === s.selectedSessionId && generation === s.sessionMemoryGeneration;
  s.sessionHooksState = { loading: true, error: s.sessionHooksState.error };
  s.renderNow(['sessions']);
  try {
    const response = await s.apiFetch('/sessions/' + encodeURIComponent(id) + '/hooks');
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const rows = await response.json();
    if (!current()) return;
    if (!validSessionHooks(rows)) throw new Error('Invalid response');
    s.sessionHooks = rows;
    s.sessionHooksState = { loading: false, error: '' };
  } catch {
    if (!current()) return;
    s.sessionHooksState = { loading: false, error: 'unavailable' };
  }
  s.renderNow(['sessions']);
}

async function sessionWorkbenchLoadOverview(s, id, force = true) {
  if (!id || id !== s.selectedSessionId) return;
  if (s.sessionOverviewState.loading) { if (force) s.sessionOverviewRefreshAgain = true; return; }
  if (!force && Date.now() - s.sessionOverviewAt < 5000) return;
  s.sessionOverviewAt = Date.now();
  const generation = s.sessionOverviewGeneration;
  s.sessionOverviewState = { loading: true, error: s.sessionOverviewState.error };
  s.renderNow(['sessions']);
  try {
    const response = await s.apiFetch('/sessions/' + encodeURIComponent(id) + '/overview');
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const overview = await response.json();
    if (generation !== s.sessionOverviewGeneration || id !== s.selectedSessionId) return;
    if (!validSessionOverview(overview, id)) throw new Error('Invalid response');
    s.sessionOverview = overview;
    s.sessionOverviewState = { loading: false, error: '' };
  } catch {
    if (generation !== s.sessionOverviewGeneration || id !== s.selectedSessionId) return;
    s.sessionOverviewState = { loading: false, error: 'unavailable' };
  }
  s.renderNow(['sessions']);
  if (s.sessionOverviewRefreshAgain) { s.sessionOverviewRefreshAgain = false; sessionWorkbenchLoadOverview(s, id); }
}

function sessionWorkbenchResetMemory(s) {
  s.sessionMemoryGeneration++;
  s.sessionMemoryHistoryLoaded = false;
  s.sessionMemoryAt = 0;
  s.sessionMemoryPage = { rows: [], has_earlier: false, next_cursor: '' };
  s.sessionMemoryState = { loading: false, loadingEarlier: false, error: '' };
  s.sessionTimelineAt = 0;
  s.sessionTimelineState = { loading: false, loaded: false, error: '' };
  s.sessionOverviewGeneration++;
  s.sessionOverview = null;
  s.sessionOverviewState = { loading: false, error: '' };
  s.sessionOverviewAt = 0;
  s.sessionOverviewRefreshAgain = false;
  s.sessionOutcomesGeneration++;
  s.sessionOutcomes = null;
  s.sessionOutcomesState = { loading: false, error: '' };
  s.sessionOutcomesAt = 0;
  s.sessionHooks = null;
  s.sessionHooksState = { loading: false, error: '' };
  s.sessionHooksAt = 0;
  s.sessionHookHistory = { query: '', outcome: 'all', sort: 'runs' };
}

function sessionWorkbenchTakeReveal(s) {
  const reveal = s.sessionReveal;
  s.sessionReveal = false;
  return reveal;
}

function sessionWorkbenchReconcileSelection(s, groups) {
  const visible = visibleSessionMembers(groups);
  const transition = s.sessionFilterTransition;
  s.sessionFilterTransition = false;
  if (!s.sessionSelectionInitialized || transition) {
    if (visible.length || transition) s.sessionSelectionInitialized = true;
    const id = initialSessionId(visible, s.selectedSessionId);
    if (id !== s.selectedSessionId) {
      window.SA.closeSessionPermissions?.();
      window.SA.clearSessionInvestigation?.();
      s.selectedSessionId = id;
      sessionWorkbenchResetMemory(s);
      s.sessionTimeline = [];
      try { id ? sessionStorage.setItem(SESSION_WORKBENCH_SELECTION_KEY, id) : sessionStorage.removeItem(SESSION_WORKBENCH_SELECTION_KEY); } catch { /* memory only */ }
      if (id) queueMicrotask(() => sessionWorkbenchLoadSelected(s, id));
    } else if (id && !s.sessionMemoryState.loading && !s.sessionMemoryPage.rows.length && !s.sessionTimeline.length) {
      queueMicrotask(() => sessionWorkbenchLoadSelected(s, id));
    }
    s.sessionReveal = !!id;
  }
  const panel = document.getElementById('session-board-panel');
  if (panel) panel.dataset.pane = s.sessionPane;
}

async function sessionWorkbenchLoadSelected(s, id) {
  const history = s.sessionView === 'trace' ? sessionWorkbenchLoadTimeline(s, id, true).catch(() => {})
    : s.sessionView === 'results' ? sessionWorkbenchLoadOutcomes(s, id)
      : s.sessionView === 'hooks' ? sessionWorkbenchLoadHooks(s, id) : sessionWorkbenchLoadMemory(s, id);
  await Promise.all([history, sessionWorkbenchLoadOverview(s, id)]);
  s.renderNow(['sessions']);
}

async function sessionWorkbenchLoadMemory(s, sessionID, before) {
  if (!sessionID || sessionID !== s.selectedSessionId) return;
  if (s.sessionMemoryState.loadingEarlier || (!before && s.sessionMemoryState.loading)) return;
  const generation = ++s.sessionMemoryGeneration;
  s.sessionMemoryAt = Date.now();
  s.sessionMemoryState = { ...s.sessionMemoryState, loading: !before, loadingEarlier: !!before, error: '' };
  s.renderNow(['sessions']);
  try {
    const query = before ? '?before=' + encodeURIComponent(before) : '';
    const response = await s.apiFetch('/sessions/' + encodeURIComponent(sessionID) + '/memory' + query);
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const page = await response.json();
    if (generation !== s.sessionMemoryGeneration || sessionID !== s.selectedSessionId) return;
    const incoming = Array.isArray(page.rows) ? page.rows : [];
    if (before) {
      s.sessionMemoryHistoryLoaded = true;
      const seen = new Set((s.sessionMemoryPage.rows || []).map(row => row.id));
      const older = incoming.filter(row => {
        if (seen.has(row.id)) return false;
        seen.add(row.id);
        return true;
      });
      s.sessionMemoryPage = { rows: [...older, ...s.sessionMemoryPage.rows], has_earlier: !!page.has_earlier, next_cursor: page.next_cursor || '' };
    } else if (s.sessionMemoryHistoryLoaded || sessionWorkbenchReadingHistory(s, sessionID, 'memory')) {
      const merged = new Map(s.sessionMemoryPage.rows.map(row => [row.id, row]));
      for (const row of incoming) merged.set(row.id, row);
      s.sessionMemoryPage = { ...s.sessionMemoryPage, rows: [...merged.values()].sort((a, b) => String(a.at).localeCompare(String(b.at)) || String(a.id).localeCompare(String(b.id))) };
    } else {
      s.sessionMemoryPage = { rows: incoming, has_earlier: !!page.has_earlier, next_cursor: page.next_cursor || '' };
    }
    s.sessionMemoryState = { loading: false, loadingEarlier: false, error: '' };
  } catch {
    if (generation !== s.sessionMemoryGeneration || sessionID !== s.selectedSessionId) return;
    s.sessionMemoryState = { loading: false, loadingEarlier: false, error: before ? 'earlier' : 'latest' };
  }
  s.renderNow(['sessions']);
}

async function sessionWorkbenchLoadTimeline(s, id, force) {
  if (!id || id !== s.selectedSessionId) return;
  const generation = s.sessionMemoryGeneration;
  // Throttle refetches: deltas for the selected session arrive per event.
  if (!force && Date.now() - s.sessionTimelineAt < 2000) return;
  s.sessionTimelineAt = Date.now();
  const request = ++s.sessionTimelineRequest;
  const current = () => id === s.selectedSessionId && generation === s.sessionMemoryGeneration
    && request === s.sessionTimelineRequest && s.sessionView === 'trace';
  s.sessionTimelineState = { ...s.sessionTimelineState, loading: true };
  s.renderNow(['sessions']);
  try {
    const r = await s.apiFetch('/sessions/' + encodeURIComponent(id) + '/timeline?limit=500');
    if (!r.ok) throw new Error('Trace unavailable');
    const rows = await r.json();
    if (!validSessionTrace(rows, id)) throw new Error('Invalid session trace');
    if (!current()) return;
    s.sessionTimeline = rows;
    s.sessionTimelineState = { loading: false, loaded: true, error: '' };
  } catch {
    if (!current()) return;
    s.sessionTimelineState = { ...s.sessionTimelineState, loading: false, error: 'unavailable' };
  }
  if (current()) s.renderNow(['sessions']);
}

function sessionWorkbenchRetryTrace(s) {
  if (s.selectedSessionId && s.sessionView === 'trace' && !s.sessionTimelineState.loading) {
    return sessionWorkbenchLoadTimeline(s, s.selectedSessionId, true);
  }
}

async function sessionWorkbenchSelect(s, id) {
  if (!id) return;
  const changed = s.selectedSessionId !== id;
  if (changed) window.SA.closeSessionPermissions?.();
  if (changed) window.SA.clearSessionInvestigation?.();
  if (changed) window.SA.clearRecentWorkReturn?.(id);
  s.selectedSessionId = id;
  s.sessionSelectionInitialized = true;
  s.sessionReveal = true;
  s.sessionPane = 'detail';
  try { sessionStorage.setItem(SESSION_WORKBENCH_SELECTION_KEY, id); } catch { /* memory only */ }
  s.onSelect(id);
  if (changed) { sessionWorkbenchResetMemory(s); s.sessionTimeline = []; }
  s.renderNow(['sessions']);
  if (window.matchMedia('(max-width: 900px)').matches) {
    document.querySelector('#session-detail h3')?.focus({ preventScroll: true });
  }
  if (changed || (!s.sessionMemoryPage.rows.length && !s.sessionTimeline.length)) await sessionWorkbenchLoadSelected(s, id);
}

function sessionWorkbenchShowList(s) {
  // Capture the current reading position before narrow CSS hides detail.
  s.renderNow(['sessions']);
  s.sessionPane = 'list';
  const panel = document.getElementById('session-board-panel');
  if (panel) panel.dataset.pane = s.sessionPane;
  const detail = document.getElementById('session-detail');
  if (detail) detail._sessionReadingVisible = false;
  const rail = document.getElementById('session-rail');
  const scroll = rail?.scrollTop || 0;
  const selected = Array.from(rail?.querySelectorAll('[data-action="select-session"]') || []).find(el => el.dataset.id === s.selectedSessionId);
  const search = document.getElementById('session-cwd-filter');
  const target = selected?.getClientRects().length ? selected : search?.getClientRects().length ? search : rail;
  target?.focus({ preventScroll: true });
  if (rail) rail.scrollTop = scroll;
}

function sessionWorkbenchToggleList(s) {
  // Save the reading anchor before changing the available width.
  s.renderNow(['sessions']);
  const detail = document.getElementById('session-detail');
  if (detail) detail._sessionReadingVisible = false;
  s.sessionListCollapsed = !s.sessionListCollapsed;
  s.renderNow(['sessions']);
}

function sessionWorkbenchJumpToLatest() {
  const latest = document.querySelector('#session-detail [data-action="session-latest"]');
  const ownsFocus = !!latest && document.activeElement === latest;
  const body = document.querySelector('#session-detail .session-detail-body');
  if (body) body.scrollTop = body.scrollHeight;
  if (ownsFocus && body?.isConnected && body.getClientRects().length) {
    body.focus({ preventScroll: true });
    if (document.activeElement === body && typeof window.saAnnounce === 'function') window.saAnnounce('Moved to latest session content.');
  }
  if (latest) latest.hidden = true;
}

function sessionWorkbenchShowCurrentStatus(s) {
  if (s.sessionView === 'results' || s.sessionView === 'hooks') { sessionWorkbenchSetView(s, 'memory').then(() => sessionWorkbenchShowCurrentStatus(s)); return; }
  const body = document.querySelector('#session-detail .session-detail-body');
  if (body) body.scrollTop = 0;
  document.querySelector('#session-detail .sd-current-head h4')?.focus({ preventScroll: true });
}

async function sessionWorkbenchSetView(s, view) {
  if (!['memory', 'trace', 'results', 'hooks'].includes(view)) return;
  s.sessionView = view;
  s.renderNow(['sessions']);
  if (view === 'results' && s.selectedSessionId) {
    await sessionWorkbenchLoadOutcomes(s, s.selectedSessionId);
  } else if (view === 'hooks' && s.selectedSessionId) {
    await sessionWorkbenchLoadHooks(s, s.selectedSessionId);
  } else if (view === 'trace' && s.selectedSessionId) {
    try { await sessionWorkbenchLoadTimeline(s, s.selectedSessionId, true); } catch { /* trace retries on next activation */ }
    s.renderNow(['sessions']);
  } else if (view === 'memory' && s.selectedSessionId && !s.sessionMemoryPage.rows.length) {
    await sessionWorkbenchLoadMemory(s, s.selectedSessionId);
  }
}

function sessionWorkbenchLoadEarlier(s) {
  if (s.selectedSessionId && s.sessionMemoryPage.has_earlier && s.sessionMemoryPage.next_cursor) {
    return sessionWorkbenchLoadMemory(s, s.selectedSessionId, s.sessionMemoryPage.next_cursor);
  }
}

function sessionWorkbenchReadingHistory(s, sessionId, mode) {
  const key = sessionId + '|' + mode;
  const detail = document.getElementById('session-detail');
  const body = detail?._sessionReadingKey === key ? detail.querySelector('.session-detail-body') : null;
  if (body?.getClientRects().length) return body.scrollHeight - body.clientHeight - body.scrollTop >= 64;
  // Back hides the pane; zero geometry must not replace its saved reading state.
  return s.sessionReadingState.get(key)?.nearLatest === false;
}

function sessionWorkbenchRenderDetail(s, detail, selected, trees, emptyHTML) {
  const key = s.selectedSessionId + '|' + s.sessionView;
  const oldBody = detail.querySelector('.session-detail-body');
  const oldKey = detail._sessionReadingKey;
  const oldSession = detail._sessionSelectedId;
  const focused = detail.contains(document.activeElement) ? document.activeElement : null;
  const currentStatusFocus = !!focused && oldKey === key && focused === detail.querySelector('.sd-current-head h4');
  const focusedRow = focused?.closest('[data-row-id]');
  const focusWithinRow = focusedRow ? '[data-row-id="' + CSS.escape(focusedRow.dataset.rowId) + '"] ' : '';
  const focusTarget = focused && (focused.tagName === 'SUMMARY' ? 'summary'
    : focused.dataset.action ? '[data-action="' + focused.dataset.action + '"]' + (focused.dataset.view ? '[data-view="' + focused.dataset.view + '"]' : '') : focused.tagName === 'H3' ? 'h3' : currentStatusFocus ? '.sd-current-head h4' : null);
  const focusKey = focusTarget && focusWithinRow + focusTarget;
  if (oldBody && oldKey && oldBody.getClientRects().length && detail._sessionReadingVisible !== false) {
    const bounds = oldBody.getBoundingClientRect();
    const anchor = Array.from(oldBody.querySelectorAll('[data-row-id]')).find(row => row.getBoundingClientRect().bottom > bounds.top && row.getBoundingClientRect().top < bounds.bottom);
    const prev = s.sessionReadingState.get(oldKey) || {};
    s.sessionReadingState.set(oldKey, { ...prev, top: oldBody.scrollTop,
      nearLatest: oldBody.scrollHeight - oldBody.clientHeight - oldBody.scrollTop < 64,
      anchor: anchor?.dataset.rowId, offset: anchor ? anchor.getBoundingClientRect().top - bounds.top : 0,
      first: oldBody.querySelector('[data-row-id]')?.dataset.rowId,
      detailsOpen: !!detail.querySelector('details.session-metadata')?.open });
  }
  const markup = selected ? sessionDetailHTML(selected, s.sessionTimeline, trees, sessionWorkbenchSnapshot(s)) : sessionEmptyDetailHTML(emptyHTML);
  if (detail._sessionMarkup !== markup) {
    const disclosures = new Map(Array.from(detail.querySelectorAll('[data-row-id]')).map(row =>
      [row.dataset.rowId, Array.from(row.querySelectorAll('details'), d => d.open)]));
    if (selected) patchSessionDetail(detail, selected.id, markup);
    else detail.innerHTML = markup;
    if (oldSession === s.selectedSessionId) for (const row of detail.querySelectorAll('[data-row-id]')) {
      const saved = disclosures.get(row.dataset.rowId);
      if (saved) Array.from(row.querySelectorAll('details')).forEach((d, i) => { d.open = !!saved[i]; });
    }
    detail._sessionMarkup = markup;
    applyInlineMetrics(detail);
  }
  for (const input of detail.querySelectorAll('[data-hook-history]')) {
    const value = s.sessionHookHistory[input.dataset.hookHistory];
    if (input.value !== value) input.value = value;
  }
  detail._sessionReadingKey = key;
  detail._sessionSelectedId = s.selectedSessionId;
  const body = detail.querySelector('.session-detail-body');
  detail._sessionReadingVisible = !!body?.getClientRects().length;
  if (!body) return;
  const state = s.sessionReadingState.get(key) || {};
  const metadata = detail.querySelector('details.session-metadata');
  if (metadata) metadata.open = !!state.detailsOpen;
  const rows = Array.from(body.querySelectorAll('[data-row-id]'));
  const loaded = s.sessionView === 'trace' ? !!s.sessionTimeline?.length : s.sessionView === 'results' ? !!s.sessionOutcomes : s.sessionView === 'hooks' ? !!s.sessionHooks : !!s.sessionMemoryPage?.rows.length;
  const prepended = state.first && rows.length && rows[0].dataset.rowId !== state.first && rows.some(row => row.dataset.rowId === state.first);
  if (!detail._sessionReadingVisible) return;
  if (s.sessionView === 'results' && !state.loaded && loaded) body.scrollTop = 0;
  else if (s.sessionView !== 'hooks' && s.sessionView !== 'results' && ((!state.loaded && loaded) || (state.nearLatest && !prepended))) body.scrollTop = body.scrollHeight;
  else {
    body.scrollTop = state.top || 0;
    const anchor = state.anchor && rows.find(row => row.dataset.rowId === state.anchor);
    if (anchor) body.scrollTop += anchor.getBoundingClientRect().top - body.getBoundingClientRect().top - state.offset;
  }
  s.sessionReadingState.set(key, { ...state, loaded: state.loaded || loaded });
  const updateLatest = () => {
    const latest = detail.querySelector('[data-action="session-latest"]');
    if (latest) latest.hidden = s.sessionView === 'hooks' || body.scrollHeight - body.clientHeight - body.scrollTop < 64;
  };
  if (!body._sessionScrollBound) { body.addEventListener('scroll', updateLatest, { passive: true }); body._sessionScrollBound = true; }
  updateLatest();
  if (focusKey && oldSession === s.selectedSessionId && !focused.isConnected) {
    const target = detail.querySelector(focusKey);
    if (target && (!currentStatusFocus || target.getClientRects().length)) target.focus({ preventScroll: true });
  }
}

function sessionWorkbenchRenderBoard(s) {
  const SA = window.SA;

  const rail = document.getElementById('session-rail');
  const detail = document.getElementById('session-detail');
  const legacy = document.getElementById('session-board');
  const badge = document.getElementById('badge-session-count');
  const pills = document.getElementById('session-harness-pills');
  const strip = document.getElementById('session-count-strip');
  if (!rail) return;
  rail.dataset.view = s.sessionListView;
  for (const button of document.querySelectorAll('[data-action="session-list-view"]')) button.setAttribute('aria-pressed', String(button.dataset.view === s.sessionListView));
  const agents = (SA.t.status && SA.t.status.agents) ? SA.t.status.agents : [];
  const trees = SA.t.status && SA.t.status.trees;
  const filter = {...SA.harnessFilter, search: window.globalSearchTerm?.() || ''};
  const q = filter.text || '';
  const filtered = !!String(q || filter.search).trim() || Object.values(filter.harnesses).some(v => v === false);
  const noMatch = html`<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No sessions match — <button type="button" class="link-btn" data-action="clear-harness-filter">clear the filter</button></span></div>`;
  const quiet = html`<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>All quiet. Nothing is running.</span></div>`;
  // The durable session spine (/sessions) is the source of truth when the
  // daemon provides it; process-tree grouping is the fallback for older
  // daemons.
  const durable = SA.t.sessions;
  const useDurable = Array.isArray(durable);
  const panel = document.getElementById('session-board-panel');
  if (panel) panel.classList.toggle('session-workbench', useDurable);
  if (panel) panel.classList.toggle('session-list-collapsed', s.sessionListCollapsed && !!s.selectedSessionId);
  if (useDurable) s.sessionLayout.schedule();

  if (useDurable) {
    if (legacy) legacy.hidden = true;
    rail.hidden = false;
    if (detail) detail.hidden = false;
    // Rail: one group per harness, live work first; ended runs collapse
    // into a per-harness tail and infra sits in the last group.
    const groups = groupSessionsByHarness(durable, trees, agents);
    const liveCount = groups.reduce((n, g) => n + (g.infra ? 0 : familySize(g.live)), 0);
    if (badge) badge.textContent = liveCount;
    SA.setTabBadge('sessions', liveCount);
    if (strip) {
      strip.textContent = `${groups.filter(g => !g.infra && g.live.length).length} harnesses`;
      strip.title = sessionCountStrip(groups, SA.t.status && SA.t.status.coverage);
    }
    if (pills) {
      const present = applySessionFilters(groups, { liveOnly: filter.liveOnly }).filter(g => !g.infra).map(g => g.key);
      renderFilterPills(pills, harnessPillsHTML(present, filter.harnesses));
      applyInlineMetrics(pills);
    }
    const shown = applySessionFilters(groups, filter);
    const emptyHTML = sessionEmptyHTML(groups, filter);
    sessionWorkbenchReconcileSelection(s, shown);
    const reveal = sessionWorkbenchTakeReveal(s);
    const navigationGroups = s.sessionListView === 'sessions' ? groupSessionWorkspaces(shown).filter(g => g.infra || !filter.liveOnly || g.live.length) : shown;
    const orders = rail._sessionGroupOrders || (rail._sessionGroupOrders = {});
    const sessionGroups = stableSessionOrder(navigationGroups.filter(g => !g.infra), orders[s.sessionListView], g => g.key);
    orders[s.sessionListView] = sessionGroups.map(g => g.key);
    const infra = shown.find(g => g.infra);
    // A group's open state is DOM state: patchList keeps an unchanged group's
    // node and carries open across a rebuilt one.
    // Rows patch inside each group's shell, keyed by session id or folded
    // title, so a selected or expanded row survives a reconcile. The shell
    // hashes by key and whether it has an ended tail: its counts change in
    // place (syncSessionGroupShell), never by rebuilding the group.
    const parts = sessionGroups.length
      ? sessionGroups.map(g => ({ key: 'group:' + g.key, group: g, shell: `group:${g.key}|${g.ended.length ? 'ended' : ''}`, html: sessionGroupHTML(g, visibleSessionMembers([g]).some(member => member.id === s.selectedSessionId), !!SA.endedSessionsOpen[g.key]) }))
      : [{ key: filtered ? 'empty:nomatch' : 'empty:quiet', html: emptyHTML }];
    if (infra) parts.push({ key: 'infra', html: sessionInfraGroupHTML(infra, false) });
    const railTop = rail.scrollTop;
    const railFocus = rail.contains(document.activeElement) ? document.activeElement : null;
    const railFocusId = railFocus?.dataset.id;
    patchList(rail, parts, { key: p => p.key, html: p => p.html, hash: p => p.shell || p.html });
    const rowOpts = { key: r => r.key, html: r => r.html };
    const rowOrders = rail._sessionRowOrders || (rail._sessionRowOrders = new Map());
    const childOrders = rail._sessionChildOrders || (rail._sessionChildOrders = new Map());
    for (const p of parts) {
      if (!p.group) continue;
      const node = Array.from(rail.children).find(n => n._saKey === p.key);
      if (!node) continue;
      if (reveal && visibleSessionMembers([p.group]).some(member => member.id === s.selectedSessionId)) {
        node.open = true;
        if (visibleSessionMembers([{ ...p.group, live: [] }]).some(member => member.id === s.selectedSessionId)) SA.endedSessionsOpen[p.group.key] = true;
        for (const bucket of ['live', 'ended']) {
          const titleOf = member => { const t = liveTreeFor(member, trees); return sessionTitle(member, t && t.root.cwd); };
          for (const row of collapseSessionFamilies(p.group[bucket], p.group.key, titleOf)) {
            if (row.dup && row.sessions.some(member => member.id === s.selectedSessionId)) SA.sessionDupOpen[bucket + '|' + row.key] = true;
          }
        }
      }
      syncSessionGroupShell(node, p.group, !!SA.endedSessionsOpen[p.group.key]);
      const rows = (fams, bucket) => {
        for (const family of fams) {
          const familyKey = p.group.key + '|' + bucket + '|' + family.session.id;
          family.children = stableSessionOrder(family.children, childOrders.get(familyKey), child => child.id);
          childOrders.set(familyKey, family.children.map(child => child.id));
        }
        const list = sessionRailRows(fams, p.group.key, trees, s.selectedSessionId, SA.sessionDupOpen, bucket, p.group.workspaceView);
        const orderKey = p.group.key + '|' + bucket;
        const ordered = stableSessionOrder(list, rowOrders.get(orderKey), row => row.key);
        rowOrders.set(orderKey, ordered.map(row => row.key));
        return ordered;
      };
      patchList(node.querySelector('.session-rows'), rows(p.group.live, 'live'), rowOpts);
      patchList(node.querySelector('.session-ended-body'), rows(p.group.ended, 'ended'), rowOpts);
    }
    rail.scrollTop = railTop;
    if (railFocusId && !railFocus.isConnected) Array.from(rail.querySelectorAll('[data-action="select-session"]')).find(el => el.dataset.id === railFocusId)?.focus({ preventScroll: true });
    const selected = durable.find(member => member.id === s.selectedSessionId);
    const emptyDetail = s.selectedSessionId
      ? html`<div class="empty"><span>Session unavailable. It is no longer listed. <button type="button" class="link-btn" data-action="session-list">Back to sessions</button></span></div>`
      : filter.liveOnly || filtered ? emptyHTML : html`<div class="empty"><span>No sessions available. Start an agent session, then refresh.</span></div>`;
    if (detail) sessionWorkbenchRenderDetail(s, detail, selected, trees, emptyDetail);
    return;
  }

  // Legacy fallback: process-tree board, no rail, no harness grouping.
  const rows = filterSessionRows(filterSessionRows(sessionRows(agents, trees), q), filter.search);
  if (badge) badge.textContent = rows.length;
  SA.setTabBadge('sessions', rows.length);
  if (pills) pills.innerHTML = '';
  if (strip) strip.textContent = '';
  rail.hidden = true;
  if (detail) detail.hidden = true;
  if (legacy) legacy.hidden = false;
  if (rows.length === 0) {
    legacy.innerHTML = filtered ? noMatch : quiet;
    return;
  }
  const now = Date.now();
  legacy.innerHTML = sessionBoardHTML(rows, now, SA.sessionHelpOpen);
  legacy.querySelectorAll('details.session-helpers').forEach(el => {
    el.addEventListener('toggle', () => {
      SA.sessionHelpOpen[el.dataset.pid] = el.open;
    });
  });
}

function sessionWorkbenchInvalidate(s) {
  s.sessionMemoryGeneration++;
  s.sessionTimelineRequest++;
  s.sessionOverviewGeneration++;
  s.sessionOutcomesGeneration++;
  s.sessionMemoryState = { ...s.sessionMemoryState, loading: false, loadingEarlier: false };
  s.sessionTimelineState = { ...s.sessionTimelineState, loading: false, error: 'unavailable' };
  s.sessionOverviewState = { loading: false, error: 'unavailable' };
  s.sessionOverviewRefreshAgain = false;
  s.sessionOutcomesState = { loading: false, error: 'unavailable' };
  s.sessionHooksState = { loading: false, error: 'unavailable' };
}

function sessionWorkbenchRefresh(s, kind, { id = s.selectedSessionId, before, force = true } = {}) {
  if (kind === 'memory') return sessionWorkbenchLoadMemory(s, id, before);
  if (kind === 'trace') return sessionWorkbenchLoadTimeline(s, id, force);
  if (kind === 'results') return sessionWorkbenchLoadOutcomes(s, id, force);
  if (kind === 'hooks') return sessionWorkbenchLoadHooks(s, id, force);
  if (kind === 'overview') return sessionWorkbenchLoadOverview(s, id, force);
  return sessionWorkbenchLoadSelected(s, id);
}

function sessionWorkbenchActivity(s, event) {
  if (!s.selectedSessionId || event.session_id !== s.selectedSessionId) return;
  if (s.sessionView === 'trace') return sessionWorkbenchLoadTimeline(s, s.selectedSessionId);
  if (s.sessionView === 'hooks') return sessionWorkbenchLoadHooks(s, s.selectedSessionId, false);
  if (s.sessionView === 'memory' && Date.now() - s.sessionMemoryAt >= 2000) return sessionWorkbenchLoadMemory(s, s.selectedSessionId);
}

function sessionWorkbenchRestoreView(s, view) {
  if (['memory', 'trace', 'results', 'hooks'].includes(view)) s.sessionView = view;
}

function sessionWorkbenchSetHookHistory(s, update = {}) {
  s.sessionHookHistory = {
    query: typeof update.query === 'string' ? update.query.slice(0, 256) : s.sessionHookHistory.query,
    outcome: ['all', 'errors', 'blocks', 'cancelled'].includes(update.outcome) ? update.outcome : s.sessionHookHistory.outcome,
    sort: ['runs', 'total_ms', 'chars'].includes(update.sort) ? update.sort : s.sessionHookHistory.sort,
  };
  s.renderNow(['sessions']);
}

function sessionWorkbenchSnapshot(s) {
  const { sessionListCollapsed, sessionHookHistory, selectedSessionId, sessionTimeline, sessionTimelineState, sessionView, sessionMemoryPage, sessionMemoryState, sessionOverview, sessionOverviewState, sessionOutcomes, sessionOutcomesState, sessionHooks, sessionHooksState } = s;
  return { sessionListCollapsed, sessionHookHistory, selectedSessionId, sessionTimeline, sessionTimelineState, sessionView, sessionMemoryPage, sessionMemoryState, sessionOverview, sessionOverviewState, sessionOutcomes, sessionOutcomesState, sessionHooks, sessionHooksState };
}
