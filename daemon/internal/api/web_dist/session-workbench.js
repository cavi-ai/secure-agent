// Sessions tab: session-first. A rail of durable sessions (the P1 spine)
// grouped by harness on the left; the selected session's memory or trace on
// the right. renderSessionBoard (app.js's panel registry) delegates here when
// durable sessions exist; the legacy process-tree board remains the fallback.

// Empty recovery considers ended sessions hidden only by Live only.
function sessionEmptyHTML(groups, filter) {
  const filtered = !!String(filter.text || '').trim() || Object.values(filter.harnesses || {}).some(value => value === false);
  const visible = new Set(visibleSessionMembers(applySessionFilters(groups, filter)).map(session => session.id));
  const hiddenEnded = filter.liveOnly && visibleSessionMembers(applySessionFilters(groups, {...filter, liveOnly: false}))
    .some(session => session.status === 'ended' && !visible.has(session.id));
  const message = filter.liveOnly ? (filtered ? 'No live sessions match these filters.' : 'No live sessions.')
    : filtered ? 'No sessions match these filters.' : 'All quiet. Nothing is running.';
  return `<div class="empty session-empty"><svg class="icon"><use href="#i-agent"/></svg><div><span>${message}</span>
    ${hiddenEnded ? '<p>Matching ended sessions are available.</p><button type="button" class="btn btn-sm" data-action="show-ended-sessions">Show ended sessions</button>' : ''}
    ${filtered ? '<button type="button" class="link-btn" data-action="clear-harness-filter">clear the filter</button>' : ''}</div></div>`;
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

// One rail card per session: title (the group head already names the
// harness), state chip, last activity, live RSS when the tree is up, a pulse
// while active. Kill stays on live cards only. nested indents a sub-session
// under its parent; label, when set, replaces the title (a collapsed row's
// member reads by its start time).
function sessionRailCardHTML(s, trees, selectedId, nested, label) {
  const tree = liveTreeFor(s, trees);
  const rss = tree ? fmtRSS(tree.rss_bytes) : '';
  const status = s.status || 'active';
  const pulse = status === 'active' ? '<span class="sc-pulse active" aria-hidden="true"></span>' : '';
  const seen = s.last_seen_at ? fmtAge(s.last_seen_at, Date.now()) + ' ago' : '';
  const selected = s.id === selectedId;
  const identity = sessionTitle(s, tree && tree.root.cwd);
  const title = label || identity;
  const kill = tree && status !== 'ended'
    ? `<button type="button" class="btn btn-danger btn-sm sc-kill" data-action="kill" data-pid="${escapeHTML(tree.root.pid)}" data-started="${escapeHTML(tree.root.started_at || '')}" data-family="${escapeHTML(s.harness || '')}" title="Terminate" aria-label="Terminate ${escapeHTML(title)}"><svg class="icon"><use href="#i-power"/></svg></button>`
    : '';
  return `<div class="session-card ${escapeHTML(status)}${selected ? ' selected' : ''}${nested ? ' nested' : ''}">
    <button type="button" class="sc-main" data-action="select-session" data-id="${escapeHTML(s.id)}" aria-pressed="${selected}" title="${escapeHTML(identity)}" aria-label="${escapeHTML(label ? identity + ', ' + title : identity)}">
      <span class="sc-head">${pulse}<span class="sc-label">${escapeHTML(title)}</span></span>
      <span class="sc-meta"><span class="sc-state ${escapeHTML(status)}">${escapeHTML(status)}</span>${seen ? `<span>${escapeHTML(seen)}</span>` : ''}${rss ? `<span>${escapeHTML(rss)}</span>` : ''}</span>
    </button>${kill}
  </div>`;
}

// One harness group's shell: mark + display name + counts in a collapsible
// head, an empty live row list, then the collapsed ended tail's toggle and
// empty row list. sessionRailRows fills both lists through patchList;
// syncSessionGroupShell keeps the counts current on a kept shell.
function sessionGroupHTML(g, open, endedOpen) {
  const ended = g.ended.length
    ? `<div class="session-ended${endedOpen ? ' open' : ''}">
        <button type="button" class="session-ended-toggle" data-action="toggle-ended-sessions" data-harness="${escapeHTML(g.key)}" aria-expanded="${endedOpen}">Ended (${familySize(g.ended)}) <svg class="icon"><use href="#i-arrow"/></svg></button>
        <div class="session-ended-body"></div>
      </div>`
    : '';
  return `<details class="session-group" data-harness="${escapeHTML(g.key)}"${open ? ' open' : ''}>
    <summary class="session-group-head">${harnessChipHTML(g.key, { label: true })}<span class="session-group-counts">${escapeHTML(sessionGroupCounts(g))}</span><svg class="icon session-group-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></summary>
    <div class="session-group-body"><div class="session-rows"></div>${ended}</div>
  </details>`;
}

// syncSessionGroupShell: a kept group shell's volatile text — the head's
// counts, the ended toggle's count and open state — written in place, so a
// status change never rebuilds the group or its rows.
function syncSessionGroupShell(node, g, endedOpen) {
  const counts = node.querySelector('.session-group-counts');
  const text = sessionGroupCounts(g);
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
function sessionRailRows(fams, harness, trees, selectedId, dupOpen, bucket) {
  const titleOf = s => { const t = liveTreeFor(s, trees); return sessionTitle(s, t && t.root.cwd); };
  return collapseSessionFamilies(fams, harness, titleOf).map(r => {
    if (!r.dup) {
      const f = r.family;
      const cards = sessionRailCardHTML(f.session, trees, selectedId, false)
        + f.children.map(c => sessionRailCardHTML(c, trees, selectedId, true)).join('');
      return { key: r.key, html: f.children.length ? `<div class="session-family">${cards}</div>` : cards };
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
  const pulse = status === 'active' ? '<span class="sc-pulse active" aria-hidden="true"></span>' : '';
  const members = open
    ? `<div class="session-dup-body">${r.sessions.map(s => sessionRailCardHTML(s, trees, selectedId, true, fmtHHMM(s.started_at) || sessionShort(s.id))).join('')}</div>`
    : '';
  return `<div class="session-dup ${escapeHTML(status)}${open ? ' open' : ''}">
    <button type="button" class="session-dup-toggle" data-action="toggle-session-dup" data-key="${escapeHTML(r.key)}" aria-expanded="${open}"${bucket ? ` data-bucket="${escapeHTML(bucket)}"` : ''}>
      <span class="sc-head">${pulse}<span class="sc-label">${escapeHTML(r.title)}</span><span class="session-dup-count">×${r.sessions.length}</span><svg class="icon"><use href="#i-arrow"/></svg></span>
      <span class="sc-meta"><span class="sc-state ${escapeHTML(status)}">${escapeHTML(status)}</span></span>
    </button>${members}
  </div>`;
}

// The trailing infra group: IDEs and model servers, RSS totals only.
function sessionInfraGroupHTML(g, open) {
  const rows = g.items.map(it => `<div class="infra-row">${harnessChipHTML(it.key, { label: true })}<span class="agent-meta-item">${escapeHTML(fmtRSS(it.rss) || '—')}</span></div>`).join('');
  return `<details class="session-group infra" data-harness="infra"${open ? ' open' : ''}>
    <summary class="session-group-head"><span class="session-group-title">Infrastructure</span><span class="session-group-counts">${escapeHTML(fmtRSS(g.rss) || '—')}</span><svg class="icon session-group-disclosure" aria-hidden="true"><use href="#i-arrow"/></svg></summary>
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
    const dayHTML = day !== lastDay ? `<div class="sm-day">${escapeHTML(day)}</div>` : '';
    lastDay = day;
    const severity = row.severity ? `<span class="sm-chip">${escapeHTML(row.severity)}</span>` : '';
    const status = row.status ? `<span class="sm-chip">${escapeHTML(row.status)}</span>` : '';
    const sourceID = typeof row.source_id === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(row.source_id) ? row.source_id : '';
    const action = row.kind === 'flag' ? 'open-flag' : row.kind === 'incident' ? 'open-incident' : '';
    const label = row.kind === 'flag' ? 'View finding evidence' : 'View incident report';
    const title = sourceID && action
      ? `<button type="button" class="link-btn sm-source-link" data-action="${action}" data-id="${escapeHTML(sourceID)}" aria-label="${label}: ${escapeHTML(row.title)}" title="${label}">${escapeHTML(row.title)}</button>`
      : escapeHTML(row.title);
    return `${dayHTML}<article class="sm-row" data-row-id="${escapeHTML(row.id || '')}">
      <div class="sm-marker"><time datetime="${escapeHTML(row.at)}" title="${escapeHTML(fullTime)}" aria-label="${escapeHTML(fullTime)}">${escapeHTML(time)}</time><span class="sm-source">${source}</span></div>
      <div class="sm-content"><strong>${title}</strong>${row.detail ? `<p>${escapeHTML(row.detail)}</p>` : ''}<div class="sm-chips">${severity}${status}</div></div>
    </article>`;
  }).join('');
  const earlier = page && page.has_earlier && page.next_cursor
    ? `<button type="button" class="btn btn-sm btn-ghost sm-earlier" data-action="memory-earlier"${state && state.loadingEarlier ? ' disabled' : ''}>${state && state.loadingEarlier ? 'Loading earlier…' : 'Load earlier'}</button>` : '';
  const message = error && !rows.length ? '<div class="sm-state" role="alert">Memory unavailable. <button type="button" class="link-btn" data-action="memory-retry">Retry</button></div>'
    : error && state.error === 'earlier' && page && page.has_earlier && page.next_cursor
      ? '<div class="sm-state" role="alert">Could not load earlier. Use Load earlier to retry.</div>'
    : error ? `<div class="sm-state" role="alert">${state.error === 'earlier' ? 'Could not load earlier.' : 'Could not refresh memory.'} <button type="button" class="link-btn" data-action="memory-retry">Retry</button></div>`
    : loading && !rows.length ? '<div class="sm-state" role="status">Loading memory…</div>'
    : !rows.length ? '<div class="sm-state">No retained memory for this session. Older activity may have expired.</div>' : '';
  return `<div class="session-memory">${earlier}${message}<div class="sm-list">${rowHTML}</div></div>`;
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
  const retry = `<button type="button" class="link-btn" data-action="trace-retry"${state?.loading ? ' disabled' : ''}>Retry trace</button>`;
  const message = state?.error ? `Trace unavailable.${loaded ? ' Showing the last successfully loaded history; it may be out of date.' : ''} ${retry}`
    : state?.loading && !loaded ? 'Loading trace…' : '';
  const text = message || (!loaded ? 'Loading trace…' : '');
  const notice = `<div class="sm-state" data-session-part="trace-health" role="status"${text ? '' : ' hidden'}>${text}</div>`;
  if (!loaded) return notice;
  const limit = events.length === 500 ? '<p class="sm-state" data-session-part="trace-limit">This view contains the latest 500 retained event records; earlier history may be omitted. Use View session events to browse retained records.</p>' : '';
  return notice + limit + sessionWaterfallHTML(events);
}

// Hook totals for one session, one row per hook event and script.
function validSessionHooks(rows) {
  const count = v => Number.isInteger(v) && v >= 0;
  return Array.isArray(rows) && rows.every(r => r && typeof r === 'object' && !Array.isArray(r)
    && typeof r.event === 'string' && typeof r.script === 'string' && typeof r.last_at === 'string'
    && ['runs', 'errors', 'blocks', 'chars', 'total_ms'].every(k => count(r[k])));
}

function sessionHooksHTML(rows, state) {
  state = state || {};
  const retry = `<button type="button" class="link-btn" data-action="session-hooks-retry"${state.loading ? ' disabled' : ''}>Retry hooks</button>`;
  const notice = state.error ? `Hook runs unavailable.${rows ? ' Showing the last loaded totals; they may be out of date.' : ''} ${retry}`
    : !rows ? 'Loading hook runs…' : '';
  const head = `<header data-session-part="hooks-head"><h4>Hooks</h4><p>Every harness hook that ran in this session, read from its transcript. Failed counts errors and cancelled runs; blocked counts denied tool calls and blocked turns.</p>${notice ? `<p role="status">${notice}</p>` : ''}</header>`;
  if (!rows) return head;
  if (!rows.length) return head + '<p data-session-part="hooks-empty">No hook runs recorded for this session.</p>';
  const body = rows.map(r => `<tr${r.errors > 0 ? ' class="sd-hook-failed"' : ''}>
      <td>${escapeHTML(r.event)}</td><td>${escapeHTML(r.script || 'not recorded')}</td>
      <td>${r.runs}</td><td>${r.errors}</td><td>${r.blocks}</td>
      <td>${escapeHTML(fmtCompact(r.chars))}</td><td>${escapeHTML(fmtDurationMs(r.total_ms))}</td></tr>`).join('');
  return head + `<table class="sd-hooks" data-session-part="hooks-table"><thead><tr>
      <th scope="col">Event</th><th scope="col">Script</th><th scope="col">Runs</th><th scope="col">Failed</th>
      <th scope="col">Blocked</th><th scope="col">Chars returned</th><th scope="col">Time</th>
    </tr></thead><tbody>${body}</tbody></table>`;
}

// Durable IDs are the entry point; live process counts and setup checks do
// not substitute for a session's own record.
function sessionDailyHTML(sessions, coverage) {
  if (!Array.isArray(sessions)) return '<p role="status">Session data unavailable.</p>';
  const live = sessions.filter(s => s.status === 'active' || s.status === 'idle');
  if (!live.length) return '<p>No live sessions recorded. Active processes may not yet have an attributed session.</p>';
  const rows = live.slice(0, 6).map(s => {
    const observed = ((coverage && coverage.sessions) || []).find(c => c.session_id === s.id);
    return `<button type="button" class="session-daily-card" data-action="session-current" data-session="${escapeHTML(s.id)}">
      <span>${harnessChipHTML(s.harness)}<strong>${escapeHTML(sessionTitle(s))}</strong></span>
      <span>${escapeHTML(s.status)} · ${escapeHTML(sessionShort(s.id))}</span>
      <span>Guard: ${observed ? escapeHTML(coveragePathLabel(observed.guard)) : 'session coverage unavailable'}</span>
    </button>`;
  }).join('');
  return `<div class="session-daily-grid">${rows}</div>${live.length > 6 ? `<p>${live.length - 6} more live sessions. <button type="button" class="link-btn" data-action="goto-tab" data-tab="sessions">View all sessions</button></p>` : ''}`;
}

function renderSessionDaily() {
  const el = document.getElementById('session-daily');
  if (!el) return;
  const SA = window.SA;
  const html = sessionDailyHTML(SA.t.sessions, SA.t.status && SA.t.status.coverage);
  if (el._saHTML !== html) { el.innerHTML = html; el._saHTML = html; }
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

function sessionOverviewHTML(data, state, contextHTML = '') {
  state = state || {};
  const retry = `<button type="button" class="link-btn" data-action="session-overview-retry"${state.loading ? ' disabled' : ''}>${state.loading ? 'Retrying current status…' : 'Retry current status'}</button>`;
  const status = !data ? state.loading && !state.error ? 'Loading current session status…' : `Current session status unavailable. ${retry}`
    : state.error ? `Last known session status. Refresh failed; requests and measurements may have changed. ${retry}` : '';
  const head = `<div class="sd-current-head" data-session-part="current-head"><h4 tabindex="-1">Current session status</h4>${status ? `<p class="sd-current-status" role="status">${status}</p>` : ''}</div>` + contextHTML;
  if (!data) return head;
  const disabled = state.error ? ' disabled' : '';
  const requests = (data.requests || []).map(r => {
    const actions = needView({ ...r, kind: 'guard' }, { SA: window.SA }).items;
    return `<fieldset class="sd-request" data-session-part="request:${escapeHTML(r.id)}"${disabled}>
      <legend>Access request</legend><p>${escapeHTML(r.detail || r.title || 'Waiting for a decision')}</p>
      <p class="sd-context-limit">${escapeHTML(r.scopeText || 'This request does not grant future access.')}</p>${actionBarHTML(actions)}
    </fieldset>`;
  }).join('');
  const coverage = data.coverage;
  const paths = coverage ? [['Guard', coverage.guard], ['Trace', coverage.trace], ['Payload inspection', coverage.payload]].map(([label, p]) =>
    `<div><b>${label}: ${escapeHTML(coveragePathLabel(p))}</b><p>${escapeHTML((p || {}).detail || '')}</p>${p && p.last_seen ? `<time>${escapeHTML(p.last_seen)}</time>` : ''}</div>`).join('') : '<p>No current coverage is attributed to this session. Ended sessions retain their evidence without claiming live protection.</p>';
  const resources = data.resources;
  const control = resources && resources.control;
  const impact = resources ? `<p>${escapeHTML(fmtRSS(resources.rss_bytes) || '—')} memory · ${escapeHTML(fmtCPU(resources.cpu_percent) || '—')} CPU · ${Number(resources.process_count) || 0} processes</p>
    ${control ? `<p>Control: ${escapeHTML(control.state || 'unknown')}${control.last_error ? ` · ${escapeHTML(control.last_error)}` : ''}</p>` : ''}
    ${(resources.diagnoses || []).map(d => `<p>${escapeHTML(d.summary || '')}</p>`).join('')}
    <button type="button" class="link-btn" data-action="view-family" data-key="${escapeHTML(resources.key)}">Inspect session resources</button>`
    : '<p>No live resource family is attributed to this session.</p>';
  const findings = (data.findings || []).map(f => `<article class="sd-finding" data-session-part="finding:${escapeHTML(f.id)}"><h5>${escapeHTML(f.title || 'Finding')}</h5><p>Risk: ${escapeHTML((f.assessment || {}).risk || 'unknown')} · ${escapeHTML((f.assessment || {}).reason || 'Evidence interpretation unavailable')}</p>${assessmentHTML(f.assessment)}
    <button type="button" class="link-btn" data-action="open-flag" data-id="${escapeHTML(f.id)}">View evidence</button></article>`).join('');
  return head + requests
    + `<section class="sd-coverage" data-session-part="coverage" aria-label="Observed session coverage">${paths}</section>`
    + `<fieldset class="sd-impact" data-session-part="impact"${disabled}><legend>Machine impact</legend>${impact}</fieldset>`
    + `<div class="sd-findings-head" data-session-part="findings-head"><h4>Retained findings</h4><p>${data.findings_truncated ? 'More findings exist than the 20 most recent shown here.' : (data.findings || []).length ? 'Review and remaining risk are shown separately.' : 'No retained findings are attributed to this session. This is not a safety verdict.'}
      <button type="button" class="link-btn" data-action="session-findings" data-id="${escapeHTML(data.session_id)}">View session findings history</button></p></div>` + findings;
}

// Reconcile each request/finding independently. A new finding must not replace
// a focused approval button, an open disclosure, or the history view switch.
function patchSessionDetail(el, sessionID, html) {
  const template = document.createElement('template');
  template.innerHTML = html;
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
    h.interventions.every(r => optionalArray(r.after) && optionalArray(r.limits)) &&
    h.incidents.every(inc => !inc.remediation || (Array.isArray(inc.remediation.steps) && inc.remediation.steps.every(step => record(step) && step.item && typeof step.item === 'object')));
}

function sessionOutcomesHTML(data, state) {
  state = state || {};
  const retry = '<button type="button" class="link-btn" data-action="session-outcomes-retry">Retry results</button>';
  const notice = state.error ? `Last known results. Refresh failed; later decisions or observations may be missing. ${retry}`
    : !data ? state.loading ? 'Loading decisions and results…' : `Results unavailable. ${retry}` : '';
  const head = `<header data-session-part="outcomes-head"><h4>Decisions and results</h4><p>Latest saved decision per finding context and latest result per operation. These receipts do not establish task completion. Guard and payload outcomes remain in Memory.</p>${notice ? `<p role="status">${notice}</p>` : ''}</header>`;
  if (!data) return head;
  const h = data.history;
  const limits = [['reviews', 'Review decisions'], ['interventions', 'Process results'], ['incidents', 'Incident reports']].map(([key, label]) => {
    const source = h.evidence[key];
    return !source.available ? `<p role="status">${label} unavailable.${h[key].length ? ' Showing last known receipts; later changes may be missing.' : ''}</p>`
      : source.at_limit ? `<p>${label}: bounded to ${Number(source.limit) || 0} retained records; earlier history may be omitted.</p>` : '';
  }).join('');
  const rows = [];
  for (const r of h.reviews) {
    if (!r.decision) continue;
    const d = r.decision;
    const scopes = Array.isArray(d.scope_ids) ? d.scope_ids : [];
    const label = { acknowledge: 'Reviewed', close_reported: 'Closure reported', expect: scopes.length ? 'Scoped permission recorded' : 'Expected once' }[d.action] || 'Saved decision';
    const permission = scopes.length ? `<p>${scopes.length} permission scope${scopes.length === 1 ? '' : 's'} recorded. Inspect current expiry or revocation for this decision. <button type="button" class="link-btn" data-action="session-permissions" data-review="${escapeHTML(r.id)}" data-session="${escapeHTML(data.session_id || '')}">View permissions</button></p>` : '';
    const changed = d.revision !== r.revision ? '<p>This decision does not cover newer evidence.</p>' : '';
    const source = !r.evidence_available ? '<p>Source evidence unavailable; the saved receipt remains.</p>' : !r.evidence_flag_available ? '<p>Assessment source evidence unavailable; other linked evidence may remain.</p>' : '';
    const link = r.evidence_flag_available && r.evidence_flag_id ? `<button type="button" class="link-btn" data-action="open-flag" data-id="${escapeHTML(r.evidence_flag_id)}">View finding evidence</button>` : '';
    rows.push({ key: 'decision:' + r.id, at: d.at, title: label, html: `<p>${escapeHTML((r.context || {}).rule || 'Finding')} · decision for revision ${escapeHTML(d.revision)}</p>${changed}${permission}<p>Remaining risk: ${escapeHTML((r.assessment || {}).residual_risk || 'unknown')}</p>${source}${link}` });
  }
  for (const r of h.interventions) {
    rows.push({ key: 'intervention:' + r.id, at: r.requested_at, title: 'Process control', html: resourceOutcomeHTML(r) });
  }
  for (const inc of h.incidents) {
    for (const step of ((inc.remediation || {}).steps || [])) {
      if (step.status !== 'reported') continue;
      rows.push({ key: 'incident:' + inc.id + ':' + step.id, at: step.reported_at, title: 'External action reported', html: `<p>${escapeHTML(step.item.name)} · ${escapeHTML(step.item.action)}</p><p>Credential verification: ${escapeHTML(step.verification || 'unverified')}</p>${step.newer_evidence ? '<p>Newer evidence exists; this report does not establish its remediation.</p>' : ''}<button type="button" class="link-btn" data-action="open-incident" data-id="${escapeHTML(inc.id)}">View incident report</button>` });
    }
  }
  rows.sort((a, b) => (Date.parse(a.at) || 0) - (Date.parse(b.at) || 0) || a.key.localeCompare(b.key));
  const history = rows.map(row => {
    const date = new Date(row.at);
    const time = Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString();
    return `<article class="sd-outcome" data-session-part="${escapeHTML(row.key)}" data-row-id="${escapeHTML(row.key)}"><h5>${escapeHTML(row.title)}</h5><time datetime="${escapeHTML(row.at || '')}">${escapeHTML(time)}</time>${row.html}</article>`;
  }).join('');
  return head + `<div data-session-part="outcomes-limits">${limits}${Object.values(h.evidence).some(source => !source.available) ? retry : ''}${!rows.length && !limits ? '<p>No saved decisions or results in the retained history. This is not a safety verdict.</p>' : ''}</div>` + history;
}

function sessionDetailHTML(sess, events, trees, state = window.SA) {
  if (!sess) {
    return `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>Select a session to see its memory</span></div>`;
  }
  const tree = liveTreeFor(sess, trees);
  const title = sessionTitle(sess, tree && tree.root.cwd);
  const path = sess.workspace && sess.workspace !== '/' ? sess.workspace : '';
  const meta = [
    sess.started_at ? 'started ' + fmtAge(sess.started_at, Date.now()) + ' ago' : '',
    sess.ended_at ? 'ended ' + fmtAge(sess.ended_at, Date.now()) + ' ago' : '',
  ].filter(Boolean).map(escapeHTML).join(' · ');
  const contextHTML = `<section class="session-context" data-session-part="session-context" aria-label="Session context">
      <button type="button" class="btn btn-sm btn-ghost" data-action="session-events" data-id="${escapeHTML(sess.id)}" title="Inspect retained file, connection, and tool events attributed to this session">View session events</button>
      <details class="session-metadata" data-session-details>
        <summary>Details</summary>
        <div class="sd-metadata-body">
          <span class="sd-harness">${escapeHTML(harnessMeta(sess.harness).label)}</span>
          ${sess.confidence ? `<span class="ss-chip sd-conf" title="How this session was identified">${escapeHTML(sess.confidence)}</span>` : ''}
          ${path ? `<button type="button" class="sd-path" data-action="copy-path" data-path="${escapeHTML(path)}" title="${escapeHTML(path)} — click to copy">${escapeHTML(path)}</button>` : ''}
          ${meta ? `<span class="sd-meta">${meta}</span>` : ''}
        </div>
      </details>
    </section>`;
  return `<div class="session-detail-chrome">
    <div class="session-detail-actions">
      <button type="button" class="btn btn-sm btn-ghost sd-back" data-action="session-list">Back to sessions</button>
      <button type="button" class="btn btn-sm btn-ghost sd-export" data-action="copy-report" data-id="${escapeHTML(sess.id)}" title="Copy this session's report as markdown"><svg class="icon"><use href="#i-copy"/></svg>Copy report</button>
    </div>
    <div class="session-detail-head">
      ${harnessChipHTML(sess.harness)}
      <h3 tabindex="-1">${escapeHTML(title)}</h3>
    </div>
    <div class="sd-detail-controls">
      <div class="sd-view-switch" role="group" aria-label="Session detail view">
        <button type="button" class="sd-view${state.sessionView === 'memory' ? ' active' : ''}" data-action="session-view" data-view="memory" aria-pressed="${state.sessionView === 'memory'}">Memory</button>
        <button type="button" class="sd-view${state.sessionView === 'results' ? ' active' : ''}" data-action="session-view" data-view="results" aria-pressed="${state.sessionView === 'results'}">Results</button>
        <button type="button" class="sd-view${state.sessionView === 'trace' ? ' active' : ''}" data-action="session-view" data-view="trace" aria-pressed="${state.sessionView === 'trace'}">Trace</button>
        <button type="button" class="sd-view${state.sessionView === 'hooks' ? ' active' : ''}" data-action="session-view" data-view="hooks" aria-pressed="${state.sessionView === 'hooks'}">Hooks</button>
      </div>
      <button type="button" class="btn btn-sm btn-ghost sd-latest" data-action="session-latest" hidden>Jump to latest</button>
      <button type="button" class="btn btn-sm btn-ghost" data-action="session-status">Current status</button>
    </div>
    </div>
    <div class="session-detail-body" tabindex="-1">${state.sessionView === 'hooks' ? contextHTML + sessionHooksHTML(state.sessionHooks, state.sessionHooksState) : state.sessionView === 'results' ? contextHTML + sessionOutcomesHTML(state.sessionOutcomes, state.sessionOutcomesState) : sessionOverviewHTML(state.sessionOverview, state.sessionOverviewState, contextHTML) + (state.sessionView === 'trace' ? sessionTraceHTML(events, state.sessionTimelineState) : sessionMemoryHTML(state.sessionMemoryPage, state.sessionMemoryState))}</div>`;
}

// One workbench owns selection, retained reads, rendering and reading position.
function createSessionWorkbench({ apiFetch, renderNow, onSelect = () => {} }) {
  // The generation invalidates late responses when selection changes; it
  // also protects an earlier-page request from writing into another session.
  const SESSION_SELECTION_KEY = 'sa.selected-session';
  let selectedSessionId = '';
  try { selectedSessionId = sessionStorage.getItem(SESSION_SELECTION_KEY) || ''; } catch { /* memory only */ }
  let sessionSelectionInitialized = false;
  let sessionFilterTransition = false;
  let sessionReveal = false;
  let sessionPane = 'detail';
  let sessionView = 'memory';
  let sessionMemoryPage = { rows: [], has_earlier: false, next_cursor: '' };
  let sessionMemoryState = { loading: false, loadingEarlier: false, error: '' };
  let sessionMemoryGeneration = 0;
  let sessionMemoryAt = 0;
  let sessionMemoryHistoryLoaded = false;
  let sessionTimeline = [];
  let sessionTimelineState = { loading: false, loaded: false, error: '' };
  let sessionTimelineAt = 0;
  let sessionTimelineRequest = 0;
  let sessionOverview = null;
  let sessionOverviewState = { loading: false, error: '' };
  let sessionOverviewGeneration = 0;
  let sessionOverviewAt = 0;
  let sessionOverviewRefreshAgain = false;
  let sessionOutcomes = null;
  let sessionOutcomesState = { loading: false, error: '' };
  let sessionOutcomesGeneration = 0;
  let sessionOutcomesAt = 0;
  let sessionHooks = null;
  let sessionHooksState = { loading: false, error: '' };
  let sessionHooksAt = 0;
  function refreshCurrent(force) {
    if (selectedSessionId) {
      loadSessionOverview(selectedSessionId, force);
      if (sessionView === 'results') loadSessionOutcomes(selectedSessionId, force);
      if (sessionView === 'hooks') loadSessionHooks(selectedSessionId, force);
    }
  }
  async function loadSessionOutcomes(id, force = true) {
    if (!id || id !== selectedSessionId || sessionOutcomesState.loading) return;
    if (!force && Date.now() - sessionOutcomesAt < 5000) return;
    sessionOutcomesAt = Date.now();
    const generation = sessionOutcomesGeneration;
    sessionOutcomesState = { loading: true, error: sessionOutcomesState.error };
    renderNow(['sessions']);
    try {
      const response = await apiFetch('/sessions/' + encodeURIComponent(id) + '/outcomes');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      if (generation !== sessionOutcomesGeneration || id !== selectedSessionId) return;
      if (!validSessionOutcomes(data, id)) throw new Error('Invalid response');
      if (sessionOutcomes) for (const key of ['reviews', 'incidents', 'interventions']) {
        if (!data.history.evidence[key].available) data.history[key] = sessionOutcomes.history[key];
      }
      sessionOutcomes = data;
      sessionOutcomesState = { loading: false, error: '' };
    } catch {
      if (generation !== sessionOutcomesGeneration || id !== selectedSessionId) return;
      sessionOutcomesState = { loading: false, error: 'unavailable' };
    }
    renderNow(['sessions']);
  }
  async function loadSessionHooks(id, force = true) {
    if (!id || id !== selectedSessionId || sessionHooksState.loading) return;
    if (!force && Date.now() - sessionHooksAt < 5000) return;
    sessionHooksAt = Date.now();
    const generation = sessionMemoryGeneration;
    const current = () => id === selectedSessionId && generation === sessionMemoryGeneration;
    sessionHooksState = { loading: true, error: sessionHooksState.error };
    renderNow(['sessions']);
    try {
      const response = await apiFetch('/sessions/' + encodeURIComponent(id) + '/hooks');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const rows = await response.json();
      if (!current()) return;
      if (!validSessionHooks(rows)) throw new Error('Invalid response');
      sessionHooks = rows;
      sessionHooksState = { loading: false, error: '' };
    } catch {
      if (!current()) return;
      sessionHooksState = { loading: false, error: 'unavailable' };
    }
    renderNow(['sessions']);
  }
  async function loadSessionOverview(id, force = true) {
    if (!id || id !== selectedSessionId) return;
    if (sessionOverviewState.loading) { if (force) sessionOverviewRefreshAgain = true; return; }
    if (!force && Date.now() - sessionOverviewAt < 5000) return;
    sessionOverviewAt = Date.now();
    const generation = sessionOverviewGeneration;
    sessionOverviewState = { loading: true, error: sessionOverviewState.error };
    renderNow(['sessions']);
    try {
      const response = await apiFetch('/sessions/' + encodeURIComponent(id) + '/overview');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const overview = await response.json();
      if (generation !== sessionOverviewGeneration || id !== selectedSessionId) return;
      if (!validSessionOverview(overview, id)) throw new Error('Invalid response');
      sessionOverview = overview;
      sessionOverviewState = { loading: false, error: '' };
    } catch {
      if (generation !== sessionOverviewGeneration || id !== selectedSessionId) return;
      sessionOverviewState = { loading: false, error: 'unavailable' };
    }
    renderNow(['sessions']);
    if (sessionOverviewRefreshAgain) { sessionOverviewRefreshAgain = false; loadSessionOverview(id); }
  }
  function resetSessionMemory() {
    sessionMemoryGeneration++;
    sessionMemoryHistoryLoaded = false;
    sessionMemoryAt = 0;
    sessionMemoryPage = { rows: [], has_earlier: false, next_cursor: '' };
    sessionMemoryState = { loading: false, loadingEarlier: false, error: '' };
    sessionTimelineAt = 0;
    sessionTimelineState = { loading: false, loaded: false, error: '' };
    sessionOverviewGeneration++;
    sessionOverview = null;
    sessionOverviewState = { loading: false, error: '' };
    sessionOverviewAt = 0;
    sessionOverviewRefreshAgain = false;
    sessionOutcomesGeneration++;
    sessionOutcomes = null;
    sessionOutcomesState = { loading: false, error: '' };
    sessionOutcomesAt = 0;
    sessionHooks = null;
    sessionHooksState = { loading: false, error: '' };
    sessionHooksAt = 0;
  }
  function takeSessionReveal() {
    const reveal = sessionReveal;
    sessionReveal = false;
    return reveal;
  }
  function reconcileSessionSelection(groups) {
    const visible = visibleSessionMembers(groups);
    const transition = sessionFilterTransition;
    sessionFilterTransition = false;
    if (!sessionSelectionInitialized || transition) {
      if (visible.length || transition) sessionSelectionInitialized = true;
      const id = initialSessionId(visible, selectedSessionId);
      if (id !== selectedSessionId) {
        window.SA.closeSessionPermissions?.();
        window.SA.clearSessionInvestigation?.();
        selectedSessionId = id;
        resetSessionMemory();
        sessionTimeline = [];
        try { id ? sessionStorage.setItem(SESSION_SELECTION_KEY, id) : sessionStorage.removeItem(SESSION_SELECTION_KEY); } catch { /* memory only */ }
        if (id) queueMicrotask(() => loadSelectedSession(id));
      } else if (id && !sessionMemoryState.loading && !sessionMemoryPage.rows.length && !sessionTimeline.length) {
        queueMicrotask(() => loadSelectedSession(id));
      }
      sessionReveal = !!id;
    }
    const panel = document.getElementById('session-board-panel');
    if (panel) panel.dataset.pane = sessionPane;
  }
  async function loadSelectedSession(id) {
    const history = sessionView === 'trace' ? loadSessionTimeline(id, true).catch(() => {})
      : sessionView === 'results' ? loadSessionOutcomes(id)
        : sessionView === 'hooks' ? loadSessionHooks(id) : loadSessionMemory(id);
    await Promise.all([history, loadSessionOverview(id)]);
    renderNow(['sessions']);
  }
  let sessionHeightFrame = 0;
  let sessionHeightChrome = null;
  const sessionHeightObserver = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(scheduleSessionWorkbenchHeight) : null;
  function scheduleSessionWorkbenchHeight() {
    if (sessionHeightFrame) return;
    sessionHeightFrame = requestAnimationFrame(() => {
      sessionHeightFrame = 0;
      const panel = document.getElementById('session-board-panel');
      if (!panel || !panel.classList.contains('session-workbench') || !panel.getClientRects().length) return;
      const body = panel.querySelector('.session-detail-body');
      const followLatest = body && body.scrollHeight - body.clientHeight - body.scrollTop < 64;
      const chrome = panel.querySelector('.session-detail-chrome');
      if (sessionHeightObserver && chrome !== sessionHeightChrome) {
        if (sessionHeightChrome) sessionHeightObserver.unobserve(sessionHeightChrome);
        if (chrome) sessionHeightObserver.observe(chrome);
        sessionHeightChrome = chrome;
      }
      const style = getComputedStyle(panel);
      const bodyStyle = body && getComputedStyle(body);
      const paragraph = body?.querySelector('.sm-content p, .sd-outcome p, .sm-state');
      const lineHeight = paragraph ? parseFloat(getComputedStyle(paragraph).lineHeight) || 18 : 18;
      const readingReserve = Math.ceil(8 * lineHeight + 44
        + (parseFloat(bodyStyle?.paddingTop) || 0) + (parseFloat(bodyStyle?.paddingBottom) || 0));
      const visibleHeight = el => el?.getClientRects().length ? el.getBoundingClientRect().height : 0;
      const detailVisible = !!body?.getClientRects().length;
      const splitMinimum = (detailVisible ? visibleHeight(chrome) : 0) + readingReserve;
      const minimum = visibleHeight(panel.querySelector('.session-toolbar')) + splitMinimum
        + (parseFloat(style.borderTopWidth) || 0) + (parseFloat(style.borderBottomWidth) || 0);
      const bottom = parseFloat(getComputedStyle(document.querySelector('.app') || document.body).paddingBottom) || 16;
      const height = Math.floor((window.visualViewport?.height || window.innerHeight) - panel.getBoundingClientRect().top - bottom);
      // When chrome and a useful reading area cannot fit, the document scrolls.
      panel.classList.toggle('session-workbench-short', height < minimum);
      for (const [name, value] of [['--session-workbench-height', Math.max(minimum, height) + 'px'], ['--session-split-height', splitMinimum + 'px']]) {
        if (panel.style.getPropertyValue(name) !== value) panel.style.setProperty(name, value);
      }
      // Sizing changes the scroll range after the initial detail render.
      if (followLatest) body.scrollTop = body.scrollHeight;
      const latest = panel.querySelector('[data-action="session-latest"]');
      if (latest && body) latest.hidden = body.scrollHeight - body.clientHeight - body.scrollTop < 64;
    });
  }
  window.addEventListener('resize', scheduleSessionWorkbenchHeight);
  window.visualViewport?.addEventListener('resize', scheduleSessionWorkbenchHeight);
  if (sessionHeightObserver) {
    for (const el of document.querySelectorAll('.masthead, #tabs-bar, .subtabs, #session-board-panel .session-toolbar')) sessionHeightObserver.observe(el);
  }
  async function loadSessionMemory(sessionID, before) {
    if (!sessionID || sessionID !== selectedSessionId) return;
    if (sessionMemoryState.loadingEarlier || (!before && sessionMemoryState.loading)) return;
    const generation = ++sessionMemoryGeneration;
    sessionMemoryAt = Date.now();
    sessionMemoryState = { ...sessionMemoryState, loading: !before, loadingEarlier: !!before, error: '' };
    renderNow(['sessions']);
    try {
      const query = before ? '?before=' + encodeURIComponent(before) : '';
      const response = await apiFetch('/sessions/' + encodeURIComponent(sessionID) + '/memory' + query);
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const page = await response.json();
      if (generation !== sessionMemoryGeneration || sessionID !== selectedSessionId) return;
      const incoming = Array.isArray(page.rows) ? page.rows : [];
      if (before) {
        sessionMemoryHistoryLoaded = true;
        const seen = new Set((sessionMemoryPage.rows || []).map(row => row.id));
        const older = incoming.filter(row => {
          if (seen.has(row.id)) return false;
          seen.add(row.id);
          return true;
        });
        sessionMemoryPage = { rows: [...older, ...sessionMemoryPage.rows], has_earlier: !!page.has_earlier, next_cursor: page.next_cursor || '' };
      } else if (sessionMemoryHistoryLoaded || sessionReadingHistory(sessionID, 'memory')) {
        const merged = new Map(sessionMemoryPage.rows.map(row => [row.id, row]));
        for (const row of incoming) merged.set(row.id, row);
        sessionMemoryPage = { ...sessionMemoryPage, rows: [...merged.values()].sort((a, b) => String(a.at).localeCompare(String(b.at)) || String(a.id).localeCompare(String(b.id))) };
      } else {
        sessionMemoryPage = { rows: incoming, has_earlier: !!page.has_earlier, next_cursor: page.next_cursor || '' };
      }
      sessionMemoryState = { loading: false, loadingEarlier: false, error: '' };
    } catch {
      if (generation !== sessionMemoryGeneration || sessionID !== selectedSessionId) return;
      sessionMemoryState = { loading: false, loadingEarlier: false, error: before ? 'earlier' : 'latest' };
    }
    renderNow(['sessions']);
  }
  async function loadSessionTimeline(id, force) {
    if (!id || id !== selectedSessionId) return;
    const generation = sessionMemoryGeneration;
    // Throttle refetches: deltas for the selected session arrive per event.
    if (!force && Date.now() - sessionTimelineAt < 2000) return;
    sessionTimelineAt = Date.now();
    const request = ++sessionTimelineRequest;
    const current = () => id === selectedSessionId && generation === sessionMemoryGeneration
      && request === sessionTimelineRequest && sessionView === 'trace';
    sessionTimelineState = { ...sessionTimelineState, loading: true };
    renderNow(['sessions']);
    try {
      const r = await apiFetch('/sessions/' + encodeURIComponent(id) + '/timeline?limit=500');
      if (!r.ok) throw new Error('Trace unavailable');
      const rows = await r.json();
      if (!validSessionTrace(rows, id)) throw new Error('Invalid session trace');
      if (!current()) return;
      sessionTimeline = rows;
      sessionTimelineState = { loading: false, loaded: true, error: '' };
    } catch {
      if (!current()) return;
      sessionTimelineState = { ...sessionTimelineState, loading: false, error: 'unavailable' };
    }
    if (current()) renderNow(['sessions']);
  }
  function retrySessionTrace() {
    if (selectedSessionId && sessionView === 'trace' && !sessionTimelineState.loading) {
      return loadSessionTimeline(selectedSessionId, true);
    }
  }
  async function selectSession(id) {
    if (!id) return;
    const changed = selectedSessionId !== id;
    if (changed) window.SA.closeSessionPermissions?.();
    if (changed) window.SA.clearSessionInvestigation?.();
    selectedSessionId = id;
    sessionSelectionInitialized = true;
    sessionReveal = true;
    sessionPane = 'detail';
    try { sessionStorage.setItem(SESSION_SELECTION_KEY, id); } catch { /* memory only */ }
    onSelect(id);
    if (changed) { resetSessionMemory(); sessionTimeline = []; }
    renderNow(['sessions']);
    if (window.matchMedia('(max-width: 900px)').matches) {
      document.querySelector('#session-detail h3')?.focus({ preventScroll: true });
    }
    if (changed || (!sessionMemoryPage.rows.length && !sessionTimeline.length)) await loadSelectedSession(id);
  }
  function showSessionList() {
    // Capture the current reading position before narrow CSS hides detail.
    renderNow(['sessions']);
    sessionPane = 'list';
    const panel = document.getElementById('session-board-panel');
    if (panel) panel.dataset.pane = sessionPane;
    const detail = document.getElementById('session-detail');
    if (detail) detail._sessionReadingVisible = false;
    const rail = document.getElementById('session-rail');
    const scroll = rail?.scrollTop || 0;
    const selected = Array.from(rail?.querySelectorAll('[data-action="select-session"]') || []).find(el => el.dataset.id === selectedSessionId);
    const search = document.getElementById('session-cwd-filter');
    const target = selected?.getClientRects().length ? selected : search?.getClientRects().length ? search : rail;
    target?.focus({ preventScroll: true });
    if (rail) rail.scrollTop = scroll;
  }
  function jumpToLatestSession() {
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
  function showCurrentSessionStatus() {
    if (sessionView === 'results' || sessionView === 'hooks') { setSessionView('memory').then(showCurrentSessionStatus); return; }
    const body = document.querySelector('#session-detail .session-detail-body');
    if (body) body.scrollTop = 0;
    document.querySelector('#session-detail .sd-current-head h4')?.focus({ preventScroll: true });
  }
  async function setSessionView(view) {
    if (!['memory', 'trace', 'results', 'hooks'].includes(view)) return;
    sessionView = view;
    renderNow(['sessions']);
    if (view === 'results' && selectedSessionId) {
      await loadSessionOutcomes(selectedSessionId);
    } else if (view === 'hooks' && selectedSessionId) {
      await loadSessionHooks(selectedSessionId);
    } else if (view === 'trace' && selectedSessionId) {
      try { await loadSessionTimeline(selectedSessionId, true); } catch { /* trace retries on next activation */ }
      renderNow(['sessions']);
    } else if (view === 'memory' && selectedSessionId && !sessionMemoryPage.rows.length) {
      await loadSessionMemory(selectedSessionId);
    }
  }
  function loadEarlierSessionMemory() {
    if (selectedSessionId && sessionMemoryPage.has_earlier && sessionMemoryPage.next_cursor) {
      return loadSessionMemory(selectedSessionId, sessionMemoryPage.next_cursor);
    }
  }

  // Reading state belongs to a session and a mode, not to a telemetry render.
  const sessionReadingState = new Map();
  function sessionReadingHistory(sessionId, mode) {
    const key = sessionId + '|' + mode;
    const detail = document.getElementById('session-detail');
    const body = detail?._sessionReadingKey === key ? detail.querySelector('.session-detail-body') : null;
    if (body?.getClientRects().length) return body.scrollHeight - body.clientHeight - body.scrollTop >= 64;
    // Back hides the pane; zero geometry must not replace its saved reading state.
    return sessionReadingState.get(key)?.nearLatest === false;
  }

  function renderSessionDetail(detail, selected, trees, emptyHTML) {
    const key = selectedSessionId + '|' + sessionView;
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
      const prev = sessionReadingState.get(oldKey) || {};
      sessionReadingState.set(oldKey, { ...prev, top: oldBody.scrollTop,
        nearLatest: oldBody.scrollHeight - oldBody.clientHeight - oldBody.scrollTop < 64,
        anchor: anchor?.dataset.rowId, offset: anchor ? anchor.getBoundingClientRect().top - bounds.top : 0,
        first: oldBody.querySelector('[data-row-id]')?.dataset.rowId,
        detailsOpen: !!detail.querySelector('details.session-metadata')?.open });
    }
    const html = selected ? sessionDetailHTML(selected, sessionTimeline, trees, snapshot()) : sessionEmptyDetailHTML(emptyHTML);
    if (detail._sessionMarkup !== html) {
      const disclosures = new Map(Array.from(detail.querySelectorAll('[data-row-id]')).map(row =>
        [row.dataset.rowId, Array.from(row.querySelectorAll('details'), d => d.open)]));
      if (selected) patchSessionDetail(detail, selected.id, html);
      else detail.innerHTML = html;
      if (oldSession === selectedSessionId) for (const row of detail.querySelectorAll('[data-row-id]')) {
        const saved = disclosures.get(row.dataset.rowId);
        if (saved) Array.from(row.querySelectorAll('details')).forEach((d, i) => { d.open = !!saved[i]; });
      }
      detail._sessionMarkup = html;
      applyInlineMetrics(detail);
    }
    detail._sessionReadingKey = key;
    detail._sessionSelectedId = selectedSessionId;
    const body = detail.querySelector('.session-detail-body');
    detail._sessionReadingVisible = !!body?.getClientRects().length;
    if (!body) return;
    const state = sessionReadingState.get(key) || {};
    const metadata = detail.querySelector('details.session-metadata');
    if (metadata) metadata.open = !!state.detailsOpen;
    const rows = Array.from(body.querySelectorAll('[data-row-id]'));
    const loaded = sessionView === 'trace' ? !!sessionTimeline?.length : sessionView === 'results' ? !!sessionOutcomes : !!sessionMemoryPage?.rows.length;
    const prepended = state.first && rows.length && rows[0].dataset.rowId !== state.first && rows.some(row => row.dataset.rowId === state.first);
    if (!detail._sessionReadingVisible) return;
    if ((!state.loaded && loaded) || (state.nearLatest && !prepended)) body.scrollTop = body.scrollHeight;
    else {
      body.scrollTop = state.top || 0;
      const anchor = state.anchor && rows.find(row => row.dataset.rowId === state.anchor);
      if (anchor) body.scrollTop += anchor.getBoundingClientRect().top - body.getBoundingClientRect().top - state.offset;
    }
    sessionReadingState.set(key, { ...state, loaded: state.loaded || loaded });
    const updateLatest = () => {
      const latest = detail.querySelector('[data-action="session-latest"]');
      if (latest) latest.hidden = body.scrollHeight - body.clientHeight - body.scrollTop < 64;
    };
    if (!body._sessionScrollBound) { body.addEventListener('scroll', updateLatest, { passive: true }); body._sessionScrollBound = true; }
    updateLatest();
    if (focusKey && oldSession === selectedSessionId && !focused.isConnected) {
      const target = detail.querySelector(focusKey);
      if (target && (!currentStatusFocus || target.getClientRects().length)) target.focus({ preventScroll: true });
    }
  }

  function renderSessionBoard() {
    const SA = window.SA;

    const rail = document.getElementById('session-rail');
    const detail = document.getElementById('session-detail');
    const legacy = document.getElementById('session-board');
    const badge = document.getElementById('badge-session-count');
    const pills = document.getElementById('session-harness-pills');
    const strip = document.getElementById('session-count-strip');
    if (!rail) return;
    const agents = (SA.t.status && SA.t.status.agents) ? SA.t.status.agents : [];
    const trees = SA.t.status && SA.t.status.trees;
    const filter = SA.harnessFilter;
    const q = filter.text || '';
    const filtered = !!String(q).trim() || Object.values(filter.harnesses).some(v => v === false);
    const noMatch = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No sessions match — <button type="button" class="link-btn" data-action="clear-harness-filter">clear the filter</button></span></div>`;
    const quiet = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>All quiet. Nothing is running.</span></div>`;
    // The durable session spine (/sessions) is the source of truth when the
    // daemon provides it; process-tree grouping is the fallback for older
    // daemons.
    const durable = SA.t.sessions;
    const useDurable = Array.isArray(durable);
    const panel = document.getElementById('session-board-panel');
    if (panel) panel.classList.toggle('session-workbench', useDurable);
    if (useDurable) scheduleSessionWorkbenchHeight();

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
      if (strip) strip.textContent = sessionCountStrip(groups, SA.t.status && SA.t.status.coverage);
      if (pills) {
        const present = applySessionFilters(groups, { liveOnly: filter.liveOnly }).filter(g => !g.infra).map(g => g.key);
        renderFilterPills(pills, harnessPillsHTML(present, filter.harnesses));
        applyInlineMetrics(pills);
      }
      const shown = applySessionFilters(groups, filter);
      const emptyHTML = sessionEmptyHTML(groups, filter);
      reconcileSessionSelection(shown);
      const reveal = takeSessionReveal();
      const sessionGroups = stableSessionOrder(shown.filter(g => !g.infra), rail._sessionGroupOrder, g => g.key);
      rail._sessionGroupOrder = sessionGroups.map(g => g.key);
      const infra = shown.find(g => g.infra);
      // A group's open state is DOM state: patchList keeps an unchanged group's
      // node and carries open across a rebuilt one.
      // Rows patch inside each group's shell, keyed by session id or folded
      // title, so a selected or expanded row survives a reconcile. The shell
      // hashes by key and whether it has an ended tail: its counts change in
      // place (syncSessionGroupShell), never by rebuilding the group.
      const parts = sessionGroups.length
        ? sessionGroups.map(g => ({ key: 'group:' + g.key, group: g, shell: `group:${g.key}|${g.ended.length ? 'ended' : ''}`, html: sessionGroupHTML(g, visibleSessionMembers([g]).some(s => s.id === selectedSessionId), !!SA.endedSessionsOpen[g.key]) }))
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
        if (reveal && visibleSessionMembers([p.group]).some(s => s.id === selectedSessionId)) {
          node.open = true;
          if (visibleSessionMembers([{ ...p.group, live: [] }]).some(s => s.id === selectedSessionId)) SA.endedSessionsOpen[p.group.key] = true;
          for (const bucket of ['live', 'ended']) {
            const titleOf = s => { const t = liveTreeFor(s, trees); return sessionTitle(s, t && t.root.cwd); };
            for (const row of collapseSessionFamilies(p.group[bucket], p.group.key, titleOf)) {
              if (row.dup && row.sessions.some(s => s.id === selectedSessionId)) SA.sessionDupOpen[bucket + '|' + row.key] = true;
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
          const list = sessionRailRows(fams, p.group.key, trees, selectedSessionId, SA.sessionDupOpen, bucket);
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
      const selected = durable.find(s => s.id === selectedSessionId);
      const emptyDetail = selectedSessionId
        ? `<div class="empty"><span>Session unavailable. It is no longer listed. <button type="button" class="link-btn" data-action="session-list">Back to sessions</button></span></div>`
        : filter.liveOnly || filtered ? emptyHTML : `<div class="empty"><span>No sessions available. Start an agent session, then refresh.</span></div>`;
      if (detail) renderSessionDetail(detail, selected, trees, emptyDetail);
      return;
    }

    // Legacy fallback: process-tree board, no rail, no harness grouping.
    const rows = filterSessionRows(sessionRows(agents, trees), q);
    if (badge) badge.textContent = rows.length;
    SA.setTabBadge('sessions', rows.length);
    if (pills) pills.innerHTML = '';
    if (strip) strip.textContent = '';
    rail.hidden = true;
    if (detail) detail.hidden = true;
    if (legacy) legacy.hidden = false;
    if (rows.length === 0) {
      legacy.innerHTML = String(q).trim() ? noMatch : quiet;
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

  function invalidate() {
    sessionMemoryGeneration++;
    sessionTimelineRequest++;
    sessionOverviewGeneration++;
    sessionOutcomesGeneration++;
    sessionMemoryState = { ...sessionMemoryState, loading: false, loadingEarlier: false };
    sessionTimelineState = { ...sessionTimelineState, loading: false, error: 'unavailable' };
    sessionOverviewState = { loading: false, error: 'unavailable' };
    sessionOverviewRefreshAgain = false;
    sessionOutcomesState = { loading: false, error: 'unavailable' };
    sessionHooksState = { loading: false, error: 'unavailable' };
  }
  function refresh(kind, { id = selectedSessionId, before, force = true } = {}) {
    if (kind === 'memory') return loadSessionMemory(id, before);
    if (kind === 'trace') return loadSessionTimeline(id, force);
    if (kind === 'results') return loadSessionOutcomes(id, force);
    if (kind === 'hooks') return loadSessionHooks(id, force);
    if (kind === 'overview') return loadSessionOverview(id, force);
    return loadSelectedSession(id);
  }
  function activity(event) {
    if (!selectedSessionId || event.session_id !== selectedSessionId) return;
    if (sessionView === 'trace') return loadSessionTimeline(selectedSessionId);
    if (sessionView === 'hooks') return loadSessionHooks(selectedSessionId, false);
    if (sessionView === 'memory' && Date.now() - sessionMemoryAt >= 2000) return loadSessionMemory(selectedSessionId);
  }
  function restoreView(view) {
    if (['memory', 'trace', 'results', 'hooks'].includes(view)) sessionView = view;
  }
  function snapshot() { return { selectedSessionId, sessionTimeline, sessionTimelineState, sessionView, sessionMemoryPage, sessionMemoryState, sessionOverview, sessionOverviewState, sessionOutcomes, sessionOutcomesState, sessionHooks, sessionHooksState }; }
  return {
    selectSession, setView: setSessionView, render: renderSessionBoard,
    refresh, refreshCurrent, activity, invalidate, restoreView,
    showList: showSessionList, jumpToLatest: jumpToLatestSession, showCurrentStatus: showCurrentSessionStatus,
    loadEarlier: loadEarlierSessionMemory, retryTrace: retrySessionTrace,
    reconcileSelection: reconcileSessionSelection, takeReveal: takeSessionReveal,
    filterChanged() { sessionFilterTransition = true; },
    readingHistory: sessionReadingHistory,
    get selectedSessionId() { return selectedSessionId; },
    get sessionTimeline() { return sessionTimeline; },
    get sessionTimelineState() { return sessionTimelineState; },
    get sessionView() { return sessionView; },
    get sessionMemoryPage() { return sessionMemoryPage; },
    get sessionMemoryState() { return sessionMemoryState; },
    get sessionOverview() { return sessionOverview; },
    get sessionOverviewState() { return sessionOverviewState; },
    get sessionOutcomes() { return sessionOutcomes; },
    get sessionOutcomesState() { return sessionOutcomesState; },
    get sessionHooks() { return sessionHooks; },
    get sessionHooksState() { return sessionHooksState; },
  };
}
