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

function resourceHostContextHTML(host) {
  if (!host || !Number(host.total_memory_bytes)) return '';
  const total = Number(host.total_memory_bytes);
  const available = Number(host.available_memory_bytes || 0);
  const memoryKnown = String(host.memory_pressure || 'unknown') !== 'unknown';
  const agentPercent = Math.max(0, Math.min(100, Number(host.agent_memory_percent || 0)));
  const otherPercent = Math.max(0, Math.min(100 - agentPercent,
    Number(host.non_agent_memory_bytes || 0) / total * 100));
  const availablePercent = Math.max(0, 100 - agentPercent - otherPercent);
  const capacity = String(host.capacity || 'unknown');
  const pressure = familyTitle(host.memory_pressure || 'unknown');
  const thermal = familyTitle(host.thermal_state || 'unknown');
  const cpuUnavailable = host.system_cpu_percent === null || host.system_cpu_percent === undefined;
  const cpuAttributionUnavailable = host.agent_cpu_percent === null || host.agent_cpu_percent === undefined
    || host.non_agent_cpu_percent === null || host.non_agent_cpu_percent === undefined;
  const cpu = cpuUnavailable ? 'Unavailable' : cpuAttributionUnavailable
    ? `${Number(host.system_cpu_percent).toFixed(1)}% total · attribution unavailable`
    : `${Number(host.system_cpu_percent).toFixed(1)}% total · ${Number(host.agent_cpu_percent).toFixed(1)}% agents · ${Number(host.non_agent_cpu_percent).toFixed(1)}% other`;
  const swap = Number(host.swap_total_bytes || 0)
    ? `${fmtRSS(host.swap_used_bytes) || '0 B'} / ${fmtRSS(host.swap_total_bytes)}`
    : 'Not configured';
  return `<section class="resource-host-context capacity-${escapeHTML(capacity)}" aria-label="Whole-machine resource pressure">
    <div class="resource-host-heading">
      <div><span class="resource-eyebrow">Whole machine</span><h3>Machine headroom</h3></div>
      <span class="resource-capacity"><b>${Number(host.headroom_score || 0)} / 100</b><small>${escapeHTML(capacity)}</small></span>
    </div>
    <div class="resource-host-memory">
      <div><strong>${memoryKnown ? escapeHTML(fmtRSS(available) || '0 B') : 'Unavailable'} available</strong><span>of ${escapeHTML(fmtRSS(total))} physical memory</span></div>
      ${memoryKnown ? `<div class="resource-host-bar" role="img" aria-label="Memory: ${agentPercent.toFixed(1)} percent agents, ${otherPercent.toFixed(1)} percent other, ${availablePercent.toFixed(1)} percent available">
        <span class="resource-host-segment agent" data-w="${agentPercent.toFixed(1)}"></span>
        <span class="resource-host-segment other" data-w="${otherPercent.toFixed(1)}"></span>
        <span class="resource-host-segment available" data-w="${availablePercent.toFixed(1)}"></span>
      </div>
      <div class="resource-host-legend"><span><i class="agent"></i>Agents ${agentPercent.toFixed(1)}%</span><span><i class="other"></i>Other ${otherPercent.toFixed(1)}%</span><span><i class="available"></i>Available ${availablePercent.toFixed(1)}%</span></div>` : '<div class="resource-host-legend"><span>Memory breakdown unavailable</span></div>'}
    </div>
    <div class="resource-host-stats">
      <div><span>Memory pressure</span><strong>${escapeHTML(pressure)}</strong></div>
      <div><span>CPU</span><strong>${escapeHTML(cpu)}</strong></div>
      <div><span>Swap</span><strong>${escapeHTML(swap)}</strong></div>
      <div><span>Thermal</span><strong>${escapeHTML(thermal)}</strong></div>
    </div>
  </section>`;
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
      const host = episode.host;
      const hostAtCapture = host ? `<div class="resource-episode-host"><span class="resource-eyebrow">Host at capture</span><strong>${escapeHTML(fmtRSS(host.available_memory_bytes) || 'Unavailable')} available</strong><span>${escapeHTML(familyTitle(host.memory_pressure || 'unknown'))} pressure · ${escapeHTML(familyTitle(host.thermal_state || 'unknown'))} thermal · headroom ${Number(host.headroom_score || 0)} / 100</span></div>` : '';
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
      return `<details class="resource-episode severity-${escapeHTML(episode.severity || 'warning')}">
        <summary><span><b>${escapeHTML(label)}</b><small>${escapeHTML(primary.summary || (episode.diagnosis_codes || []).join(', ') || 'Resource pressure')}</small></span><span class="resource-episode-metrics"><b>${escapeHTML(fmtRSS(session.rss_bytes) || '—')}</b><b>${escapeHTML(fmtCPU(session.cpu_percent) || '—')}</b><time>${age ? `${escapeHTML(age)} ago` : 'recorded'}</time></span></summary>
        <div class="resource-episode-body">
          ${hostAtCapture}
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
  const hostContext = resourceHostContextHTML(snapshot.host);
  const limits = [
    control.max_rss_bytes ? `${fmtRSS(control.max_rss_bytes)} memory` : '',
    control.max_cpu_percent ? `${fmtCPU(control.max_cpu_percent)} CPU` : ''
  ].filter(Boolean).join(' · ');
	const ladder = (control.interventions || []).map(step => String(step.action || '').replaceAll('_', ' ')).join(' → ');
  const policy = `<div class="resource-policy"><span><b>${escapeHTML(control.mode || 'observe')}</b> machine policy${limits ? ` · ${escapeHTML(limits)}` : ' · budgets disabled'}${control.sustain_seconds ? ` · ${Number(control.sustain_seconds)}s grace` : ''}${ladder ? ` · ${escapeHTML(ladder)}` : ''} · ${(control.workspace_overrides || []).length} workspace override${(control.workspace_overrides || []).length === 1 ? '' : 's'}</span><span><span>${(control.pending || []).length} approval${(control.pending || []).length === 1 ? '' : 's'} pending</span><button type="button" class="btn btn-ghost btn-sm" data-action="edit-resource-policy">Edit policy</button></span></div>`;
  if (sessions.length === 0) {
    container.innerHTML = hostContext + policy + `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>No attributed agent resource use right now</span></div>`;
    applyInlineMetrics(container);
    return;
  }

  if (SA.selectedResourceKey && !sessions.some(s => s.key === SA.selectedResourceKey)) {
    SA.selectedResourceKey = '';
  }
  const selected = sessions.find(s => s.key === SA.selectedResourceKey);
  const totalCPU = Object.prototype.hasOwnProperty.call(snapshot, 'cpu_percent') ? fmtCPU(snapshot.cpu_percent) : '';
  // One thin attributed-now line instead of a 66px four-cell grid: the machine
  // numbers already fill the headroom card above, so this only carries the
  // agent-attributed totals, and it reads as a subtitle to the list.
  const sessionCount = Number(snapshot.session_count ?? sessions.length);
  const infraNote = snapshot.infra_count ? ` · ${Number(snapshot.infra_count)} infra` : '';
  const posture = `<div class="resource-attributed">
    <span><b>${sessionCount}</b> session${sessionCount === 1 ? '' : 's'}${infraNote}</span>
    <span><b>${escapeHTML(fmtRSS(snapshot.rss_bytes) || '—')}</b> memory</span>
    <span><b>${escapeHTML(totalCPU || '—')}</b> CPU</span>
    <span><b>${Number(snapshot.process_count || 0)}</b> processes</span>
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
		<button type="button" class="btn btn-danger btn-sm" data-action="resource-control" data-id="${escapeHTML(sessionControl.pending_id)}" data-decision="apply" data-intervention="${escapeHTML(sessionControl.next_action || '')}">Apply ${escapeHTML(String(sessionControl.next_action || 'intervention').replaceAll('_', ' '))}</button>
        <button type="button" class="btn btn-ghost btn-sm" data-action="resource-control" data-id="${escapeHTML(sessionControl.pending_id)}" data-decision="dismiss">Keep running</button>
      </span>` : '';
	const resume = sessionControl.paused ? `<button type="button" class="btn btn-primary btn-sm" data-action="resource-control" data-session="${escapeHTML(session.key)}" data-decision="resume">Resume session</button>` : '';
	const interventionError = sessionControl.last_error ? `<span class="resource-control-error">Intervention failed: ${escapeHTML(sessionControl.last_error)}</span>` : '';
    return `
      <div class="resource-session-card${pressure}${active}">
        <button type="button" class="resource-session-main" data-action="resource-session" data-key="${escapeHTML(session.key)}">
          <span class="resource-rank">${index + 1}</span>
          <span class="resource-identity">
            <strong>${escapeHTML(label)}</strong>
            <span>${escapeHTML(session.name || 'agent')} · root PID ${Number(session.root_pid || 0)} · ${Number(session.process_count || 0)} process${Number(session.process_count || 0) === 1 ? '' : 'es'}${session.kind === 'infra' ? ' · infra' : ''}</span>
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
		  ${resume}
		  ${interventionError}
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

  container.innerHTML = hostContext + posture + policy + `<div class="resource-layout"><div class="resource-session-list">${cards}</div><aside class="resource-detail-wrap">${detail}</aside></div>`;
  applyInlineMetrics(container);
}

// History tab: the pressure flight recorder on its own page. It was stacked
// under the live resource view where a single episode (host at capture, the
// process breakdown, evidence, a sparkline and nearby activity) opened inline
// and buried everything else.
function renderResourceHistory() {
  const SA = window.SA;
  const board = document.getElementById('history-board');
  const observed = document.getElementById('history-observed');
  if (!board) return;
  // Episodes moved off /resources onto /resources/episodes (the hot payload
  // dropped ~0.5 MB of historical detail no live view rendered).
  const snapshot = { episodes: SA.t.episodes || [] };
  if (observed) {
    const episodes = snapshot.episodes.length;
    observed.textContent = episodes ? `${episodes} episode${episodes === 1 ? '' : 's'}` : 'None yet';
  }
  board.innerHTML = resourceFlightRecorderHTML(snapshot);
}

// Findings-by-rule chart: one bar per rule, ranked by count in the window.
// The point is shape — "is one rule dominating?" — not exact values.
function renderChartFlags() {
  const SA = window.SA;
  const el = document.getElementById('chart-flags');
  const total = document.getElementById('chart-flags-total');
  if (!el) return;
  const flags = SA.t.flagsView || [];
  if (total) total.textContent = flags.length;
  if (!flags.length) {
    el.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-alert"/></svg><span>No findings in the window</span></div>`;
    return;
  }
  const byRule = {};
  for (const f of flags) {
    byRule[f.rule] = byRule[f.rule] || { n: 0, crit: 0 };
    byRule[f.rule].n++;
    if ((f.severity || 0) >= 3) byRule[f.rule].crit++;
  }
  const rows = Object.entries(byRule)
    .sort((a, b) => b[1].n - a[1].n)
    .map(([rule, v]) => ({
      label: ruleTitle(rule),
      value: v.n,
      cls: v.crit > 0 ? 'crit' : 'warn',
      sub: v.crit > 0 ? `${v.crit} critical` : '',
      titleAttr: rule,
    }));
  el.innerHTML = hbarsHTML(rows);
  applyInlineMetrics(el);
}

// Memory-by-session chart: resident memory per attributed session, ranked.
// Uses the durable session rows joined with live tree RSS; falls back to the
// process-tree families when the daemon predates the session spine.
function renderChartMemory() {
  const SA = window.SA;
  const el = document.getElementById('chart-memory');
  const total = document.getElementById('chart-mem-total');
  if (!el) return;
  const trees = (SA.t.status && SA.t.status.trees) || [];
  const durable = SA.t.sessions || [];
  const byRoot = {};
  for (const t of trees) if (t.root) byRoot[Number(t.root.pid)] = t;

  let sessions = durable.map(s => {
    const live = s.root_pid ? byRoot[Number(s.root_pid)] : null;
    return {
      label: s.repo ? `${s.harness} · ${s.repo}` : `${s.harness} · ${cwdLabel(s.workspace) || 'unknown'}`,
      rss: live ? Number(live.rss_bytes || 0) : 0,
      infra: s.kind === 'infra',
    };
  }).filter(s => s.rss > 0);

  if (!sessions.length) {
    // Legacy fallback: process-tree families.
    sessions = trees.map(t => ({
      label: `${(t.root && t.root.name) || 'agent'} · ${cwdLabel(t.root && t.root.cwd) || 'unknown'}`,
      rss: Number(t.rss_bytes || 0),
      infra: false,
    })).filter(s => s.rss > 0);
  }
  if (total) total.textContent = sessions.filter(s => !s.infra).length;
  if (!sessions.length) {
    el.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No attributed sessions yet</span></div>`;
    return;
  }
  const rows = sessions.sort((a, b) => b.rss - a.rss).slice(0, 8).map(s => ({
    label: s.label,
    value: s.rss,
    cls: s.infra ? 'infra' : '',
    sub: s.infra ? 'infra' : '',
  }));
  el.innerHTML = hbarsHTML(rows, { format: v => fmtRSS(v) || '0 B' });
  applyInlineMetrics(el);
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
  const useDurable = !!(durable && durable.length);

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
      pills.innerHTML = harnessPillsHTML(present, filter.harnesses);
      applyInlineMetrics(pills);
    }
    const shown = applySessionFilters(groups, filter);
    const sessionGroups = shown.filter(g => !g.infra);
    const infra = shown.find(g => g.infra);
    const isOpen = (key, dflt) => (Object.prototype.hasOwnProperty.call(SA.sessionGroupOpen, key) ? !!SA.sessionGroupOpen[key] : dflt);
    rail.innerHTML = (sessionGroups.length
      ? sessionGroups.map(g => sessionGroupHTML(g, trees, SA.selectedSessionId, isOpen(g.key, true), !!SA.endedSessionsOpen[g.key])).join('')
      : (filtered ? noMatch : quiet))
      + (infra ? sessionInfraGroupHTML(infra, isOpen('infra', false)) : '');
    applyInlineMetrics(rail);
    rail.querySelectorAll('details.session-group').forEach(el => {
      el.addEventListener('toggle', () => {
        SA.sessionGroupOpen[el.dataset.harness] = el.open;
      });
    });
    // Detail: the selected session's trace waterfall.
    const selected = durable.find(s => s.id === SA.selectedSessionId);
    if (detail) {
      if (selected) {
        detail.innerHTML = sessionDetailHTML(selected, SA.sessionTimeline || [], trees);
        applyInlineMetrics(detail);
      } else if (SA.selectedSessionId) {
        detail.innerHTML = `<div class="empty"><span>Session no longer listed</span></div>`;
      } else {
        detail.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>Select a session to see its trace</span></div>`;
      }
    }
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

function renderPosture() {
  const SA = window.SA;

  const banner = document.getElementById('posture-banner');
  const stateEl = document.getElementById('posture-state');
  const summaryEl = document.getElementById('posture-summary');
  const itemsEl = document.getElementById('posture-items');
  const p = SA.t.posture;
  if (!banner || !p) return;

  banner.dataset.state = p.state || 'all-clear';
  // Announce escalations only (not every re-render): the screen-reader
  // equivalent of the eye catching a banner turn red.
  const prevState = banner.dataset.announcedState || '';
  const nextState = p.state || 'all-clear';
  if (nextState !== prevState && nextState !== 'all-clear') {
    (window.saAnnounce || function(){})((nextState === 'critical' ? 'Critical: ' : 'Attention: ') + (p.summary || ''));
  }
  banner.dataset.announcedState = nextState;
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
  const term = SA.globalSearchTerm ? SA.globalSearchTerm() : '';
  if (term) events = events.filter(e => matchesSearch(term, e.path, e.remote_host, e.detail, e.exe_path, e.session_id));

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
