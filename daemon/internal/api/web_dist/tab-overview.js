// Overview tab: session strip, activity, events, posture.

function renderActivity() {
  const SA = window.SA;

  const svg = document.getElementById('activity-chart');
  if (!svg) return;
  const hours = Number(document.getElementById('activity-window')?.value || 24);
  const s = rollupSeries(SA.t.rollup, hours, Date.now()); // lib.js
  const max = Math.max(1, ...s.events.map((v, i) => v + s.flags[i]));
  const W = 1200, H = 96, bw = W / hours;
  let bars = '';
  for (let i = 0; i < hours; i++) {
    const evH = (s.events[i] / max) * (H - 14);
    const flH = (s.flags[i] / max) * (H - 14);
    const x = (i * bw).toFixed(1);
    if (s.events[i] > 0) {
      bars += `<rect x="${x}" y="${(H - evH).toFixed(1)}" width="${(bw - 1).toFixed(1)}" height="${evH.toFixed(1)}" rx="1.5" class="act-ev"><title>${s.labels[i]} — ${s.events[i]} events${s.flags[i] ? `, ${s.flags[i]} flags` : ''}</title></rect>`;
    }
    if (s.flags[i] > 0) {
      bars += `<rect x="${x}" y="${(H - evH - flH).toFixed(1)}" width="${(bw - 1).toFixed(1)}" height="${flH.toFixed(1)}" rx="1.5" class="act-fl"/>`;
    }
    if (s.events[i] === 0 && s.flags[i] === 0) {
      bars += `<rect x="${x}" y="${H - 2}" width="${(bw - 1).toFixed(1)}" height="2" class="act-zero"/>`;
    }
  }
  svg.innerHTML = bars;
}

function renderSessionStrip() {
  const SA = window.SA;
  const panel = document.getElementById('session-strip-panel');
  const el = document.getElementById('session-strip');
  if (!el) return;
  const agents = (SA.t.status && SA.t.status.agents) ? SA.t.status.agents : [];
  const trees = SA.t.status && SA.t.status.trees;
  const all = sessionRows(agents, trees);
  const top = sessionStripRows(all, 3);
  if (!top.length) {
    if (panel) panel.hidden = true;
    el.innerHTML = '';
    return;
  }
  if (panel) panel.hidden = false;
  el.innerHTML = sessionStripHTML(top, all.length, Date.now(), SA.t.flags);
}

function renderSessionBoard() {
  const SA = window.SA;

  const container = document.getElementById('session-board');
  const badge = document.getElementById('badge-session-count');
  if (!container) return;
  const agents = (SA.t.status && SA.t.status.agents) ? SA.t.status.agents : [];
  const trees = SA.t.status && SA.t.status.trees;
  const q = (document.getElementById('session-cwd-filter') || {}).value || '';
  const rows = filterSessionRows(sessionRows(agents, trees), q);
  if (badge) badge.textContent = rows.length;
  SA.setTabBadge('sessions', rows.length);
  if (rows.length === 0) {
    const msg = String(q).trim()
      ? `No sessions match “${escapeHTML(String(q).trim())}”`
      : 'No agents running yet — start Claude Code, Cursor, or Codex and they\'ll appear here';
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>${msg}</span></div>`;
    return;
  }
  const now = Date.now();
  container.innerHTML = sessionBoardHTML(rows, now, SA.sessionHelpOpen);
  container.querySelectorAll('details.session-helpers').forEach(el => {
    el.addEventListener('toggle', () => {
      SA.sessionHelpOpen[el.dataset.pid] = el.open;
    });
  });
}

function renderPosture() {
  const SA = window.SA;

  const banner = document.getElementById('posture-banner');
  const stateEl = document.getElementById('posture-state');
  const summaryEl = document.getElementById('posture-summary');
  const itemsEl = document.getElementById('posture-items');
  const p = SA.t.posture;
  if (!banner || !p) return;

  banner.dataset.state = p.state || 'all-clear';
  if (p.state === 'all-clear') {
    stateEl.textContent = 'All clear';
    summaryEl.textContent = 'Agents monitored, no action needed';
  } else if (p.state === 'critical') {
    stateEl.textContent = 'Critical';
  } else {
    stateEl.textContent = 'Needs attention';
  }
  summaryEl.textContent = p.summary || '';

  // Each item deep-links to its panel: flags/incidents scroll to their
  // section, guard prompts open the resolve flow, collectors explain.
  const items = (p.items || []).map(it => {
    const sev = it.severity >= 3 ? 's3' : it.severity === 2 ? 's2' : 's1';
    let link = '';
    if (it.kind === 'flag') link = `<a href="#" data-action="goto-tab" data-tab="findings">view evidence</a>`;
    if (it.kind === 'incident') link = `<a href="#" data-action="open-incident" data-id="${escapeHTML(it.id)}">view report</a>`;
    if (it.kind === 'guard_pending') link = `<span>resolve it in the menu bar app</span>`;
    if (it.kind === 'collector_down') link = `<span>— ${escapeHTML(it.detail || 'collector stopped')} <a href="#" data-action="open-fda">open Full Disk Access settings</a></span>`;
    if (it.kind === 'uninspected_egress') link = `<a href="#" data-action="open-uninspected">see endpoints</a>`;
    return `<li><span class="sev ${sev}">●</span><span>${escapeHTML(it.title)} ${link}</span></li>`;
  });
  // The fatigue reducer: when the local advisor has triaged the critical
  // flags and some read benign, say so at the one-glance level.
  const vis = inspectionVisible(SA.t.status, SA.t.audit);
  const criticals = vis.advisor
    ? (SA.t.flags || []).filter(f => f.severity >= 3 && f.advisor && f.advisor.assessment)
    : [];
  const benignCount = criticals.filter(f => f.advisor.assessment === 'benign').length;
  if (criticals.length > 0) {
    items.push(`<li><span class="sev s1">●</span><span>advisor: ${benignCount} of ${criticals.length} triaged critical flags look benign</span></li>`);
  }
  itemsEl.innerHTML = items.join('');
}

function renderEvents() {
  const SA = window.SA;

  const container = document.getElementById('events-container');
  const allEvents = SA.t.eventsView || [];
  let events = allEvents;
  if (SA.timelineSession) events = filterEventsBySession(allEvents, SA.timelineSession);
  else if (SA.timelinePids && SA.timelinePids.length) events = filterEventsByPids(allEvents, SA.timelinePids);

  const chip = document.getElementById('session-filter');
  if (chip) SA.paintSessionChip('session-filter', 'session-filter-id', events.length);

  if (events.length === 0) {
    const msg = SA.timelineSession
      ? `No events for session ${sessionShort(SA.timelineSession)} in the loaded window`
      : (SA.timelinePids && SA.timelinePids.length)
        ? `No events for ${SA.timelinePidLabel || 'this session'} in the loaded window`
      : SA.isEventsFiltered() ? 'No events match the current filter' : 'No system events logged';
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>${msg}</span></div>`;
    SA.prevEventKeys = new Set();
    SA.firstEventRender = false;
    SA.suppressFreshOnce = false;
    return;
  }

  container.innerHTML = events.map(e => {
    let kindLabel = 'EVENT';
    let kindClass = '';
    if (e.kind === 8) { kindLabel = 'TOOL USE'; kindClass = 'tool'; }
    else if (e.kind === 9) { kindLabel = 'PROXY HIT'; kindClass = 'proxy'; }
    else if (e.kind === 5) { kindLabel = 'NET CONN'; kindClass = 'conn'; }

    // fmtTime (lib.js) keeps the 68px time column single-line and
    // locale-proof ("16:03:58", always zero-padded).
    const timeStr = fmtTime(new Date(e.ts));
    const detailStr = e.detail || e.path || (e.remote_host ? `${e.remote_host}:${e.remote_port}` : '');
    // A bare PID is the ambiguous-process complaint — prefix the agent
    // name when the tagged tree can supply one.
    const agentName = SA.agentNameFor(e.pid);
    const pidLabel = agentName ? `${agentName} · PID ${e.pid}` : `PID ${e.pid}`;

    // Animate only events that weren't in the previous render — the whole
    // list re-renders on every poll, and rows the user already saw must
    // not flicker. The initial page load never animates.
    let freshCls = '';
    if (!SA.reducedMotion && !SA.firstEventRender && !SA.suppressFreshOnce && !SA.prevEventKeys.has(eventKey(e))) {
      freshCls = e.kind === 9 ? ' fresh-sev' : ' fresh';
    }

    return `
      <div class="timeline-item${freshCls}">
        <span class="t">${timeStr}</span>
        <span class="event-kind ${kindClass}">${kindLabel}</span>
        <span class="pid" title="PID ${e.pid}">${escapeHTML(pidLabel)}</span>
        <span class="dtl">${escapeHTML(detailStr)}</span>
      </div>
    `;
  }).join('');

  SA.prevEventKeys = new Set(events.map(eventKey));
  SA.firstEventRender = false;
  SA.suppressFreshOnce = false;
}

