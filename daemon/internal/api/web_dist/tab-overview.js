// Overview tab: session board, activity, events, posture.

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

function resourceActivityMarkers(activities, samples, width, height) {
  if (!activities.length || !samples.length) return '';
  const times = samples.map(sample => new Date(sample.at).getTime()).filter(Number.isFinite);
  if (!times.length) return '';
  const start = Math.min(...times);
  const end = Math.max(...times);
  const span = Math.max(1, end - start);
  return activities.slice(-24).map(activity => {
    const at = new Date(activity.at).getTime();
    if (!Number.isFinite(at) || at < start || at > end) return '';
    const x = Math.max(2, Math.min(width - 2, ((at - start) / span) * width));
    const kind = String(activity.kind || 'activity').replace(/[^a-z0-9-]/gi, '');
    return `<g class="resource-activity-marker kind-${escapeHTML(kind)}"><line x1="${x.toFixed(1)}" x2="${x.toFixed(1)}" y1="2" y2="${height - 2}"/><circle cx="${x.toFixed(1)}" cy="5" r="2.4"/><title>${escapeHTML(activity.summary || 'Recorded activity')}</title></g>`;
  }).join('');
}

function resourceActivityLabel(kind) {
  const labels = { 'process-start': 'START', process: 'PROCESS', tool: 'TOOL', file: 'FILE', network: 'NETWORK', guard: 'GUARD', security: 'SECURITY' };
  return labels[kind] || 'ACTIVITY';
}

function resourceFlightRecorderHTML(snapshot) {
  const episodes = snapshot.episodes || [];
  return `<section class="resource-flight-recorder">
    <div class="resource-flight-head"><div><span class="resource-eyebrow">Local history</span><h3>Pressure flight recorder</h3></div><span>${episodes.length ? `${episodes.length} recent episode${episodes.length === 1 ? '' : 's'}` : 'No pressure captured yet'}</span></div>
    <p class="resource-flight-intro">When a session crosses a diagnostic threshold, secure-agent keeps a bounded ten-minute prelude and the highest-impact processes for post-mortem review.</p>
    <div class="resource-episode-list">${episodes.map((episode, index) => {
      const session = episode.session || {};
      const label = cwdLabel(session.workspace) || familyTitle(session.name);
      const diagnoses = session.diagnoses || [];
      const primary = diagnoses[0] || {};
      const processes = [...(session.processes || [])].sort((a, b) => Number(b.rss_bytes || 0) - Number(a.rss_bytes || 0));
      const visibleProcesses = processes.slice(0, 10);
      const omittedCount = Math.max(0, Number(session.process_count || processes.length) - visibleProcesses.length);
      const activities = episode.activities || [];
      const correlations = episode.correlations || [];
      const correlation = correlations[0];
      const drivers = visibleProcesses.map(process => {
        const share = session.rss_bytes ? Math.round(Number(process.rss_bytes || 0) / Number(session.rss_bytes) * 100) : 0;
        return `<div class="resource-episode-process"><span><b>${escapeHTML(process.name || 'process')}</b> · PID ${Number(process.pid || 0)}${process.is_orphan ? ' · leftover' : ''}</span><span>${escapeHTML(fmtRSS(process.rss_bytes) || '—')} · ${share}%</span></div>`;
      }).join('');
      const evidence = diagnoses.flatMap(d => d.evidence || []).map(item => `<li>${escapeHTML(item)}</li>`).join('');
      const memoryPoints = resourceSparkPoints(session.samples, 'rss_bytes', 220, 38);
      const cpuPoints = resourceSparkPoints(session.samples, 'cpu_percent', 220, 38);
      const activityMarkers = resourceActivityMarkers(activities, session.samples || [], 220, 38);
      const activityRows = activities.slice(-8).map(activity => `
        <div class="resource-activity-row">
          <time>${escapeHTML(fmtTime(new Date(activity.at)))}</time>
          <span class="resource-activity-kind kind-${escapeHTML(activity.kind || 'activity')}">${escapeHTML(resourceActivityLabel(activity.kind))}</span>
          <span><b>${escapeHTML(activity.process || `PID ${Number(activity.pid || 0)}`)}</b> · ${escapeHTML(activity.summary || 'Recorded activity')}</span>
        </div>`).join('');
      const activityOmitted = Math.max(0, activities.length - 8);
      const age = episode.captured_at ? fmtAge(episode.captured_at, Date.now()) : '';
      return `<details class="resource-episode severity-${escapeHTML(episode.severity || 'warning')}"${index === 0 ? ' open' : ''}>
        <summary><span><b>${escapeHTML(label)}</b><small>${escapeHTML(primary.summary || (episode.diagnosis_codes || []).join(', ') || 'Resource pressure')}</small></span><span class="resource-episode-metrics"><b>${escapeHTML(fmtRSS(session.rss_bytes) || '—')}</b><b>${escapeHTML(fmtCPU(session.cpu_percent) || '—')}</b><time>${age ? `${escapeHTML(age)} ago` : 'recorded'}</time></span></summary>
        <div class="resource-episode-body">
          <div><span class="resource-eyebrow">What drove it</span><div class="resource-episode-processes">${drivers || '<span>No process breakdown recorded</span>'}${omittedCount ? `<small>${omittedCount} lower-impact process${omittedCount === 1 ? '' : 'es'} omitted</small>` : ''}</div></div>
          <div><span class="resource-eyebrow">Evidence</span>${evidence ? `<ul>${evidence}</ul>` : '<p>No additional evidence recorded.</p>'}<svg class="resource-episode-spark" viewBox="0 0 220 38" preserveAspectRatio="none" role="img" aria-label="Resource trend and nearby activity before capture">${memoryPoints ? `<polyline class="resource-spark-memory" points="${memoryPoints}"/>` : ''}${cpuPoints ? `<polyline class="resource-spark-cpu" points="${cpuPoints}"/>` : ''}${activityMarkers}</svg></div>
          <div class="resource-episode-context">
            <div class="resource-context-head"><span class="resource-eyebrow">What happened nearby</span>${correlation ? '<span class="resource-correlation-badge">Observed correlation</span>' : ''}</div>
            ${correlation ? `<strong>${escapeHTML(correlation.summary)}</strong><p>Timing evidence can narrow an investigation, but does not prove which action caused the resource change.</p>` : '<p>No matching activity was recorded during this pressure window.</p>'}
            <div class="resource-activity-list">${activityRows || '<span>No bounded activity references were available.</span>'}</div>
            <div class="resource-context-actions">${activityOmitted ? `<small>${activityOmitted} earlier activities omitted from this view</small>` : '<span></span>'}<small>${episode.activity_status === 'settling' ? 'Activity context is still settling' : 'Scoped to this captured process lifetime'}</small></div>
          </div>
        </div>
      </details>`;
    }).join('') || '<div class="resource-detail-empty">The recorder is armed. Episodes appear here when a session becomes heavy, grows rapidly, or leaves resource-holding processes behind.</div>'}</div>
  </section>`;
}

function renderResourceMissionControl() {
  const SA = window.SA;
  const container = document.getElementById('resource-board');
  const observed = document.getElementById('resource-observed');
  if (!container) return;
  const snapshot = SA.t.resources;
  if (!snapshot) return;

  if (observed) {
    const age = snapshot.observed_at ? fmtAge(snapshot.observed_at, Date.now()) : '';
    observed.textContent = age ? `${age} ago` : 'Live';
  }

  const sessions = [...(snapshot.sessions || [])].sort((a, b) => {
    const impact = resourceImpact(b) - resourceImpact(a);
    if (impact) return impact;
    return Number(b.rss_bytes || 0) - Number(a.rss_bytes || 0);
  });
  const control = snapshot.control || {};
  const limits = [
    control.max_rss_bytes ? `${fmtRSS(control.max_rss_bytes)} memory` : '',
    control.max_cpu_percent ? `${fmtCPU(control.max_cpu_percent)} CPU` : ''
  ].filter(Boolean).join(' · ');
  const policy = `<div class="resource-policy"><span><b>${escapeHTML(control.mode || 'observe')}</b> machine policy${limits ? ` · ${escapeHTML(limits)}` : ' · budgets disabled'}${control.sustain_seconds ? ` · ${Number(control.sustain_seconds)}s grace` : ''} · ${(control.workspace_overrides || []).length} workspace override${(control.workspace_overrides || []).length === 1 ? '' : 's'}</span><span><span>${(control.pending || []).length} approval${(control.pending || []).length === 1 ? '' : 's'} pending</span><button type="button" class="btn btn-ghost btn-sm" data-action="edit-resource-policy">Edit policy</button></span></div>`;
  const flightRecorder = resourceFlightRecorderHTML(snapshot);
  if (sessions.length === 0) {
    container.innerHTML = policy + `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>No attributed agent resource use right now</span></div>` + flightRecorder;
    return;
  }

  if (SA.selectedResourceKey && !sessions.some(s => s.key === SA.selectedResourceKey)) {
    SA.selectedResourceKey = '';
  }
  const selected = sessions.find(s => s.key === SA.selectedResourceKey);
  const totalCPU = Object.prototype.hasOwnProperty.call(snapshot, 'cpu_percent') ? fmtCPU(snapshot.cpu_percent) : '';
  const posture = `
    <div class="resource-posture" aria-label="Attributed machine resource posture">
      <div class="resource-posture-lead"><span class="resource-eyebrow">Attributed now</span><strong>${sessions.length} session${sessions.length === 1 ? '' : 's'}</strong></div>
      <div class="resource-stat"><span>Memory</span><strong>${escapeHTML(fmtRSS(snapshot.rss_bytes) || 'Unavailable')}</strong></div>
      <div class="resource-stat"><span>CPU</span><strong>${escapeHTML(totalCPU || 'Unavailable')}</strong></div>
      <div class="resource-stat"><span>Processes</span><strong>${Number(snapshot.process_count || 0)}</strong></div>
    </div>`;

  const cards = sessions.map((session, index) => {
    const label = cwdLabel(session.workspace) || familyTitle(session.name);
    const diagnoses = session.diagnoses || [];
    const primary = diagnoses[0];
    const pids = (session.processes || []).map(p => Number(p.pid)).filter(Number.isFinite);
    const memoryPoints = resourceSparkPoints(session.samples, 'rss_bytes', 140, 30);
    const cpuPoints = resourceSparkPoints(session.samples, 'cpu_percent', 140, 30);
    const pressure = diagnoses.length ? ` pressure-${escapeHTML(primary.severity || 'warning')}` : '';
    const active = selected && selected.key === session.key ? ' selected' : '';
    const reclaim = fmtRSS(session.estimated_reclaim_bytes);
    const sessionControl = session.control || {};
    const policySource = sessionControl.policy_source === 'workspace'
      ? `workspace policy · ${sessionControl.policy_scope || session.workspace || ''}`
      : 'machine default';
    const approval = sessionControl.pending_id ? `
      <span class="resource-approval">
        <button type="button" class="btn btn-danger btn-sm" data-action="resource-control" data-id="${escapeHTML(sessionControl.pending_id)}" data-decision="terminate">Contain session</button>
        <button type="button" class="btn btn-ghost btn-sm" data-action="resource-control" data-id="${escapeHTML(sessionControl.pending_id)}" data-decision="dismiss">Keep running</button>
      </span>` : '';
    return `
      <div class="resource-session-card${pressure}${active}">
        <button type="button" class="resource-session-main" data-action="resource-session" data-key="${escapeHTML(session.key)}">
          <span class="resource-rank">${index + 1}</span>
          <span class="resource-identity">
            <strong>${escapeHTML(label)}</strong>
            <span>${escapeHTML(session.name || 'agent')} · root PID ${Number(session.root_pid || 0)} · ${Number(session.process_count || 0)} process${Number(session.process_count || 0) === 1 ? '' : 'es'}</span>
          </span>
          <span class="resource-metric"><b>${escapeHTML(fmtRSS(session.rss_bytes) || '—')}</b><small>memory</small></span>
          <span class="resource-metric"><b>${escapeHTML(fmtCPU(session.cpu_percent) || '—')}</b><small>CPU</small></span>
          <svg class="resource-spark" viewBox="0 0 140 30" preserveAspectRatio="none" role="img" aria-label="Recent memory and CPU trend">
            ${memoryPoints ? `<polyline class="resource-spark-memory" points="${memoryPoints}"/>` : ''}
            ${cpuPoints ? `<polyline class="resource-spark-cpu" points="${cpuPoints}"/>` : ''}
          </svg>
        </button>
        <div class="resource-session-foot">
          <span class="resource-diagnosis${primary ? '' : ' quiet'}">${primary ? resourceDiagnosisText(primary) : 'Within current thresholds'}</span>
          ${reclaim ? `<span class="resource-reclaim">up to ${escapeHTML(reclaim)} reclaimable</span>` : ''}
          ${sessionControl.state && sessionControl.state !== 'healthy' ? `<span class="resource-control-state">${escapeHTML(sessionControl.state)}</span>` : ''}
          <span class="resource-policy-source">${escapeHTML(policySource)}</span>
          ${approval}
          <button type="button" class="btn btn-ghost btn-sm" data-action="filter-pids" data-pids="${escapeHTML(pids.join(','))}" data-label="${escapeHTML(label)}">Open family activity</button>
        </div>
      </div>`;
  }).join('');

  let detail = `<div class="resource-detail-empty">Select a session to inspect its complete process family.</div>`;
  if (selected) {
    const label = cwdLabel(selected.workspace) || familyTitle(selected.name);
    const processes = (selected.processes || []).map(process => `
      <div class="resource-process${process.is_orphan ? ' orphan' : ''}">
        <span><b>PID ${Number(process.pid || 0)}</b>${Number(process.pid) === Number(selected.root_pid) ? ' · root' : ` · child of ${Number(process.ppid || 0)}`}${process.is_orphan ? ' · leftover' : ''}</span>
        <span>${escapeHTML(fmtRSS(process.rss_bytes) || '—')} · ${escapeHTML(fmtCPU(process.cpu_percent) || '—')}</span>
      </div>`).join('');
    detail = `
      <div class="resource-detail">
        <div class="resource-detail-head"><div><span class="resource-eyebrow">Process topology</span><strong>${escapeHTML(label)}</strong></div><span>root PID ${Number(selected.root_pid || 0)}</span></div>
        <div class="resource-processes">${processes}</div>
      </div>`;
  }

  container.innerHTML = posture + policy + `<div class="resource-layout"><div class="resource-session-list">${cards}</div><aside class="resource-detail-wrap">${detail}</aside></div>` + flightRecorder;
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
