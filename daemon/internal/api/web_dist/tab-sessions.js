// Sessions tab: session-first. A rail of durable sessions (the P1 spine)
// grouped by harness on the left; the selected session's memory or trace on
// the right. renderSessionBoard (app.js's panel registry) delegates here when
// durable sessions exist; the legacy process-tree board remains the fallback.

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
    return `${dayHTML}<article class="sm-row" data-row-id="${escapeHTML(row.id || '')}">
      <div class="sm-marker"><time datetime="${escapeHTML(row.at)}" title="${escapeHTML(fullTime)}" aria-label="${escapeHTML(fullTime)}">${escapeHTML(time)}</time><span class="sm-source">${source}</span></div>
      <div class="sm-content"><strong>${escapeHTML(row.title)}</strong>${row.detail ? `<p>${escapeHTML(row.detail)}</p>` : ''}<div class="sm-chips">${severity}${status}</div></div>
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

function sessionOverviewHTML(data, state) {
  state = state || {};
  const retry = '<button type="button" class="link-btn" data-action="session-overview-retry">Retry current status</button>';
  const status = state.error ? `Last known session status. Refresh failed; requests and measurements may have changed. ${retry}`
    : !data ? state.loading ? 'Loading current session status…' : `Current session status unavailable. ${retry}` : '';
  const head = `<div class="sd-current-head" data-session-part="current-head"><h4 tabindex="-1">Current session status</h4>${status ? `<p class="sd-current-status" role="status">${status}</p>` : ''}</div>`;
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

function sessionDetailHTML(sess, events, trees) {
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
  return `<div class="session-detail-chrome">
    <div class="session-detail-head">
      <button type="button" class="btn btn-sm btn-ghost sd-back" data-action="session-list">Back to sessions</button>
      ${harnessChipHTML(sess.harness)}
      <h3 tabindex="-1">${escapeHTML(title)}</h3>
      <button type="button" class="btn btn-sm btn-ghost sd-export" data-action="copy-report" data-id="${escapeHTML(sess.id)}" title="Copy this session's report as markdown"><svg class="icon"><use href="#i-copy"/></svg>Copy report</button>
    </div>
    <div class="sd-detail-controls">
      <div class="sd-view-switch" role="group" aria-label="Session detail view">
        <button type="button" class="sd-view${window.SA.sessionView === 'memory' ? ' active' : ''}" data-action="session-view" data-view="memory" aria-pressed="${window.SA.sessionView === 'memory'}">Memory</button>
        <button type="button" class="sd-view${window.SA.sessionView === 'trace' ? ' active' : ''}" data-action="session-view" data-view="trace" aria-pressed="${window.SA.sessionView === 'trace'}">Trace</button>
      </div>
      <button type="button" class="btn btn-sm btn-ghost sd-latest" data-action="session-latest" hidden>Jump to latest</button>
      <button type="button" class="btn btn-sm btn-ghost" data-action="session-status">Current status</button>
      <details class="session-metadata" data-session-details>
        <summary>Details</summary>
        <div class="sd-metadata-body">
          <span class="sd-harness">${escapeHTML(harnessMeta(sess.harness).label)}</span>
          ${sess.confidence ? `<span class="ss-chip sd-conf" title="How this session was identified">${escapeHTML(sess.confidence)}</span>` : ''}
          ${path ? `<button type="button" class="sd-path" data-action="copy-path" data-path="${escapeHTML(path)}" title="${escapeHTML(path)} — click to copy">${escapeHTML(path)}</button>` : ''}
          ${meta ? `<span class="sd-meta">${meta}</span>` : ''}
        </div>
      </details>
    </div>
    </div>
    <div class="session-detail-body">${sessionOverviewHTML(window.SA.sessionOverview, window.SA.sessionOverviewState)}${window.SA.sessionView === 'trace' ? sessionWaterfallHTML(events) : sessionMemoryHTML(window.SA.sessionMemoryPage, window.SA.sessionMemoryState)}</div>`;
}
