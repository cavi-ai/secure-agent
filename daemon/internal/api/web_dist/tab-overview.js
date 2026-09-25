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

// The machine strip: headroom, memory (agents / other / available on one
// stacked bar), CPU and swap as four compact tiles, pressure and thermal as
// chips on the right. Same numbers the tall host block carried.
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
  const pressure = capFirst(host.memory_pressure || 'unknown');
  const thermal = capFirst(host.thermal_state || 'unknown');
  const cpuUnavailable = host.system_cpu_percent === null || host.system_cpu_percent === undefined;
  const cpuAttributionUnavailable = host.agent_cpu_percent === null || host.agent_cpu_percent === undefined
    || host.non_agent_cpu_percent === null || host.non_agent_cpu_percent === undefined;
  const cpu = cpuUnavailable ? 'Unavailable' : `${Number(host.system_cpu_percent).toFixed(1)}% total`;
  const cpuSplit = cpuUnavailable ? '' : cpuAttributionUnavailable
    ? 'attribution unavailable'
    : `${Number(host.agent_cpu_percent).toFixed(1)}% agents · ${Number(host.non_agent_cpu_percent).toFixed(1)}% other`;
  const swap = Number(host.swap_total_bytes || 0)
    ? `${fmtRSS(host.swap_used_bytes) || '0 B'} / ${fmtRSS(host.swap_total_bytes)}`
    : 'Not configured';
  const memory = memoryKnown
    ? `<div class="resource-host-bar" role="img" aria-label="Memory: ${agentPercent.toFixed(1)} percent agents, ${otherPercent.toFixed(1)} percent other, ${availablePercent.toFixed(1)} percent available">
        <span class="resource-host-segment agent" data-w="${agentPercent.toFixed(1)}"></span>
        <span class="resource-host-segment other" data-w="${otherPercent.toFixed(1)}"></span>
        <span class="resource-host-segment available" data-w="${availablePercent.toFixed(1)}"></span>
      </div>
      <div class="resource-host-legend"><span><i class="agent"></i>Agents ${agentPercent.toFixed(1)}%</span><span><i class="other"></i>Other ${otherPercent.toFixed(1)}%</span><span><i class="available"></i>${escapeHTML(fmtRSS(available) || '0 B')} available of ${escapeHTML(fmtRSS(total))}</span></div>`
    : '<b>Unavailable</b>';
  return `<section class="machine-strip capacity-${escapeHTML(capacity)}" aria-label="Whole-machine resource pressure">
    <div class="machine-tile machine-headroom"><span class="resource-eyebrow">Machine headroom</span><b>${Number(host.headroom_score || 0)} / 100</b><small>${escapeHTML(capacity)}</small></div>
    <div class="machine-tile machine-memory"><span class="resource-eyebrow">Memory</span>${memory}</div>
    <div class="machine-tile"><span class="resource-eyebrow">CPU</span><b>${escapeHTML(cpu)}</b>${cpuSplit ? `<small>${escapeHTML(cpuSplit)}</small>` : ''}</div>
    <div class="machine-tile"><span class="resource-eyebrow">Swap</span><b>${escapeHTML(swap)}</b></div>
    <div class="machine-chips"><span class="machine-chip">${escapeHTML(pressure)} pressure</span><span class="machine-chip">${escapeHTML(thermal)} thermal</span></div>
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
      const hostAtCapture = host ? `<div class="resource-episode-host"><span class="resource-eyebrow">Host at capture</span><strong>${escapeHTML(fmtRSS(host.available_memory_bytes) || 'Unavailable')} available</strong><span>${escapeHTML(capFirst(host.memory_pressure || 'unknown'))} pressure · ${escapeHTML(capFirst(host.thermal_state || 'unknown'))} thermal · headroom ${Number(host.headroom_score || 0)} / 100</span></div>` : '';
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

// Samples inside the last hour: the 60-minute sparklines.
function resourceLastHour(samples, now) {
  return (samples || []).filter(sample => {
    const t = Date.parse(sample && sample.at);
    return !Number.isFinite(t) || t >= now - 3600e3;
  });
}

function resourceProcessCount(f) {
  const n = Number(f.process_count || 0);
  return `${n} process${n === 1 ? '' : 'es'}`;
}

// A family's pending controls: the approval pair, Resume when paused, the
// last intervention error. Shared by the attention card and the drawer foot.
function resourceControlHTML(f) {
  const c = f.control || {};
  const approval = c.pending_id ? `<span class="resource-approval">
      <button type="button" class="btn btn-danger btn-sm" data-action="resource-control" data-id="${escapeHTML(c.pending_id)}" data-decision="apply" data-intervention="${escapeHTML(c.next_action || '')}">Apply ${escapeHTML(String(c.next_action || 'intervention').replaceAll('_', ' '))}</button>
      <button type="button" class="btn btn-ghost btn-sm" data-action="resource-control" data-id="${escapeHTML(c.pending_id)}" data-decision="dismiss">Keep running</button>
    </span>` : '';
  const resume = c.paused ? `<button type="button" class="btn btn-primary btn-sm" data-action="resource-control" data-session="${escapeHTML(f.key)}" data-decision="resume">Resume session</button>` : '';
  const error = c.last_error ? `<span class="resource-control-error">Intervention failed: ${escapeHTML(c.last_error)}</span>` : '';
  return approval + resume + error;
}

function resourceViewFamilyHTML(f) {
  return `<button type="button" class="btn btn-ghost btn-sm" data-action="view-family" data-key="${escapeHTML(f.key)}">View family</button>`;
}

// One needs-attention card: name, memory · CPU · processes, the diagnosis,
// the reclaim estimate, pending controls, View family.
function resourceAttentionCardHTML(f, sessions) {
  const diagnoses = f.diagnoses || [];
  const primary = diagnoses[0] || {};
  const reclaim = fmtRSS(f.estimated_reclaim_bytes);
  const c = f.control || {};
  const state = c.state && c.state !== 'healthy' ? `<span class="resource-control-state">${escapeHTML(c.state)}</span>` : '';
  const policy = c.policy_source === 'workspace'
    ? `<span class="resource-policy-source">workspace policy · ${escapeHTML(c.policy_scope || f.workspace || '')}</span>` : '';
  return `<article class="resource-session-card needs-attention-card pressure-${escapeHTML(primary.severity || 'warning')}" data-key="${escapeHTML(f.key)}">
    <div class="family-name">${harnessChipHTML(f.name)}<strong>${escapeHTML(familyLabel(f, sessions))}</strong></div>
    <div class="family-metrics"><b>${escapeHTML(fmtRSS(f.rss_bytes) || '—')}</b> memory · <b>${escapeHTML(fmtCPU(f.cpu_percent) || '—')}</b> CPU · ${resourceProcessCount(f)}</div>
    <p class="resource-diagnosis">${resourceDiagnosisText(primary)}${diagnoses.length > 1 ? ` <small>+${diagnoses.length - 1} more</small>` : ''}</p>
    <div class="resource-session-foot">
      ${reclaim ? `<span class="resource-reclaim">up to ${escapeHTML(reclaim)} reclaimable</span>` : ''}
      ${state}${policy}${resourceControlHTML(f)}
      ${resourceViewFamilyHTML(f)}
    </div>
  </article>`;
}

function resourceAttentionHTML(families, sessions) {
  const cards = families.map(f => resourceAttentionCardHTML(f, sessions)).join('');
  return `<section class="needs-attention" aria-label="Families that need attention">
    <h3 class="family-section-head">Needs attention${families.length ? `<span>${families.length}</span>` : ''}</h3>
    ${cards ? `<div class="needs-attention-cards">${cards}</div>` : '<div class="needs-attention-empty">Every family is within its thresholds.</div>'}
  </section>`;
}

// One compact family row: name, memory, CPU, processes, the 60-minute RSS
// sparkline, View family. nested indents an orchestrated child.
function resourceFamilyRowHTML(f, sessions, nested, now) {
  const points = resourceSparkPoints(resourceLastHour(f.samples, now), 'rss_bytes', 120, 24);
  const primary = (f.diagnoses || [])[0];
  const n = Number(f.process_count || 0);
  return `<div class="family-row${nested ? ' nested' : ''}${primary ? ` pressure-${escapeHTML(primary.severity || 'warning')}` : ''}">
    <span class="family-name" title="${escapeHTML(f.workspace || '')}"><strong>${escapeHTML(familyLabel(f, sessions))}</strong></span>
    <span class="resource-metric"><b>${escapeHTML(fmtRSS(f.rss_bytes) || '—')}</b><small>memory</small></span>
    <span class="resource-metric"><b>${escapeHTML(fmtCPU(f.cpu_percent) || '—')}</b><small>CPU</small></span>
    <span class="resource-metric"><b>${n}</b><small>process${n === 1 ? '' : 'es'}</small></span>
    <svg class="resource-spark" viewBox="0 0 120 24" preserveAspectRatio="none" role="img" aria-label="Memory over the last hour">${points ? `<polyline class="resource-spark-memory" points="${points}"/>` : ''}</svg>
    ${resourceViewFamilyHTML(f)}
  </div>`;
}

// A folded family row (collapseFamilyRows): "label ×N" with summed memory,
// CPU and processes; open, it lists each family as a nested row.
function resourceFamilyDupHTML(d, sessions, open, now) {
  const n = Number(d.process_count || 0);
  const kids = open
    ? `<div class="family-children">${d.families.map(f => resourceFamilyRowHTML(f, sessions, true, now)).join('')}</div>` : '';
  return `<div class="family-branch family-dup${open ? ' open' : ''}">
    <div class="family-row">
      <span class="family-name"><button type="button" class="family-dup-toggle" data-action="toggle-family-dup" data-key="${escapeHTML(d.key)}" aria-expanded="${open}"><strong>${escapeHTML(d.label)}</strong><span class="family-dup-count">×${d.families.length}</span><svg class="icon"><use href="#i-arrow"/></svg></button></span>
      <span class="resource-metric"><b>${escapeHTML(fmtRSS(d.rss_bytes) || '—')}</b><small>memory</small></span>
      <span class="resource-metric"><b>${escapeHTML(fmtCPU(d.cpu_percent) || '—')}</b><small>CPU</small></span>
      <span class="resource-metric"><b>${n}</b><small>process${n === 1 ? '' : 'es'}</small></span>
    </div>${kids}
  </div>`;
}

// resourceFamilyGroupCounts: a harness group's head text — family count,
// total memory and CPU.
function resourceFamilyGroupCounts(g) {
  const n = g.infra ? g.rows.length : g.families;
  return `${n} ${g.infra ? 'tracked' : n === 1 ? 'family' : 'families'} · ${fmtRSS(g.rss) || '—'} · ${fmtCPU(g.cpu) || '—'} CPU`;
}

// One harness group's shell (resourceFamilyGroups): mark, name and
// resourceFamilyGroupCounts in the head, an empty body that
// resourceFamilyGroupRows fills through patchList; open by default only when
// a family in it needs attention.
function resourceFamilyGroupHTML(g, sessions, flagged) {
  const open = g.rows.some(r => [r.family, ...r.children].some(f => flagged.has(f.key)));
  const head = g.infra ? '<span class="family-group-title">Infrastructure</span>' : harnessChipHTML(g.key, { label: true });
  return `<details class="family-group${g.infra ? ' infra' : ''}" data-harness="${escapeHTML(g.key)}"${open ? ' open' : ''}>
    <summary class="family-group-head">${head}<span class="family-group-counts">${escapeHTML(resourceFamilyGroupCounts(g))}</span></summary>
    <div class="family-group-body"></div>
  </details>`;
}

// resourceFamilyGroupRows: a harness group's body as patchList items keyed
// by family key, or by group:<harness>|<label> for families with an
// identical label folded into one expandable row; dupOpen maps a folded
// row's key to its expanded state (unset: open while it holds a family that
// needs attention).
function resourceFamilyGroupRows(g, sessions, flagged, now, dupOpen) {
  const branch = r => {
    const kids = r.children.length
      ? `<div class="family-children">${r.children.map(c => resourceFamilyRowHTML(c, sessions, true, now)).join('')}</div>` : '';
    return `<div class="family-branch">${resourceFamilyRowHTML(r.family, sessions, false, now)}${kids}</div>`;
  };
  const folded = g.infra
    ? g.rows.map(r => ({ dup: false, row: r }))
    : collapseFamilyRows(g.rows, g.key, f => familyLabel(f, sessions));
  return folded.map(x => {
    if (!x.dup) return { key: String(x.row.family.key), html: branch(x.row) };
    const set = dupOpen && Object.prototype.hasOwnProperty.call(dupOpen, x.key);
    return { key: x.key, html: resourceFamilyDupHTML(x, sessions, set ? !!dupOpen[x.key] : x.families.some(f => flagged.has(f.key)), now) };
  });
}

function resourcePolicyLineHTML(control) {
  const limits = [
    control.max_rss_bytes ? `${fmtRSS(control.max_rss_bytes)} memory` : '',
    control.max_cpu_percent ? `${fmtCPU(control.max_cpu_percent)} CPU` : ''
  ].filter(Boolean).join(' · ');
  const ladder = (control.interventions || []).map(step => String(step.action || '').replaceAll('_', ' ')).join(' → ');
  const overrides = (control.workspace_overrides || []).length;
  const pending = (control.pending || []).length;
  return `<div class="resource-policy"><span><b>${escapeHTML(control.mode || 'observe')}</b> machine policy${limits ? ` · ${escapeHTML(limits)}` : ' · budgets disabled'}${control.sustain_seconds ? ` · ${Number(control.sustain_seconds)}s grace` : ''}${ladder ? ` · ${escapeHTML(ladder)}` : ''} · ${overrides} workspace override${overrides === 1 ? '' : 's'}</span><span><span>${pending} approval${pending === 1 ? '' : 's'} pending</span><button type="button" class="btn btn-ghost btn-sm" data-action="edit-resource-policy">Edit policy</button></span></div>`;
}

// Resources tab, top to bottom: the machine strip, needs attention (at most
// five), families grouped by harness with orchestrated children nested and
// infrastructure trailing, then the policy line. Keyed through patchList so
// a group's open state survives the 30s reconcile. View family opens the
// family drawer (app.js) instead of leaving the tab.
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

  const families = snapshot.sessions || [];
  if (SA.selectedResourceKey && !families.some(f => f.key === SA.selectedResourceKey)) {
    SA.selectedResourceKey = '';
  }
  const parts = [];
  let rowsOf = null;
  const strip = resourceHostContextHTML(snapshot.host);
  if (strip) parts.push({ key: 'strip', html: strip });
  if (!families.length) {
    parts.push({ key: 'empty', html: '<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>No attributed agent resource use right now</span></div>' });
  } else {
    const sessions = SA.t.sessions || [];
    const now = Date.now();
    const attention = resourceNeedsAttention(families, 5);
    const flagged = new Set(attention.map(f => f.key));
    const groups = resourceFamilyGroups(families, sessions);
    const count = groups.reduce((n, g) => n + g.families, 0);
    const infra = groups.filter(g => g.infra).reduce((n, g) => n + g.rows.length, 0);
    parts.push({ key: 'attention', html: resourceAttentionHTML(attention, sessions) });
    parts.push({ key: 'families-head', html: `<h3 class="family-section-head">Families by harness<span>${count} ${count === 1 ? 'family' : 'families'}${infra ? ` · ${infra} infrastructure` : ''}</span></h3>` });
    // A group's shell hashes by key alone: its counts change in place and
    // its body reconciles per row, so a metric update rebuilds only the rows
    // that changed.
    for (const g of groups) parts.push({ key: 'group:' + g.key, group: g, shell: 'group:' + g.key, html: resourceFamilyGroupHTML(g, sessions, flagged) });
    rowsOf = g => resourceFamilyGroupRows(g, sessions, flagged, now, SA.familyDupOpen);
  }
  parts.push({ key: 'policy', html: resourcePolicyLineHTML(snapshot.control || {}) });
  patchList(container, parts, { key: p => p.key, html: p => p.html, hash: p => p.shell || p.html });
  const rowOpts = { key: r => r.key, html: r => r.html };
  for (const p of parts) {
    if (!p.group || !rowsOf) continue;
    const node = Array.from(container.children).find(n => n._saKey === p.key);
    if (!node) continue;
    const counts = node.querySelector('.family-group-counts');
    const text = resourceFamilyGroupCounts(p.group);
    if (counts && counts.textContent !== text) counts.textContent = text;
    patchList(node.querySelector('.family-group-body'), rowsOf(p.group), rowOpts);
  }
}

// Family drawer (app.js openFamilyDrawer): the inspector View family opens
// beside the board. Keyed sections for patchList, so the 30s refill keeps
// the unchanged ones; the process table's Show more rides in ctx.expanded.
// ctx: { sessions, events, flags, expanded, now }.
function familyDrawerSections(f, ctx) {
  const c = ctx || {};
  const now = c.now || Date.now();
  const procs = [...(f.processes || [])].sort((a, b) => Number(b.rss_bytes || 0) - Number(a.rss_bytes || 0));
  const pids = new Set(procs.map(p => Number(p.pid)).filter(Number.isFinite));
  if (f.root_pid) pids.add(Number(f.root_pid));
  const nameOf = new Map(procs.map(p => [Number(p.pid), p.name]));
  const ws = f.workspace && f.workspace !== '/' ? f.workspace : '';
  const head = `<div class="family-drawer-head">${harnessChipHTML(f.name, { label: true })}${ws ? `<button type="button" class="sd-path" data-action="copy-path" data-path="${escapeHTML(ws)}" title="${escapeHTML(ws)} — click to copy">${escapeHTML(middleTruncate(ws, 48))}</button>` : ''}</div>`;

  const samples = resourceLastHour(f.samples, now);
  const memPoints = resourceSparkPoints(samples, 'rss_bytes', 480, 56);
  const cpuPoints = resourceSparkPoints(samples, 'cpu_percent', 480, 56);
  const diagnoses = f.diagnoses || [];
  const evidence = diagnoses.flatMap(d => d.evidence || []);
  const reclaim = fmtRSS(f.estimated_reclaim_bytes);
  const usage = `<section class="family-drawer-section">
    <h4>Memory and CPU <small>last 60 min</small></h4>
    <div class="family-drawer-now"><span><b>${escapeHTML(fmtRSS(f.rss_bytes) || '—')}</b> memory</span><span><b>${escapeHTML(fmtCPU(f.cpu_percent) || '—')}</b> CPU</span>${reclaim ? `<span><b>${escapeHTML(reclaim)}</b> reclaimable</span>` : ''}</div>
    <svg class="family-drawer-spark" viewBox="0 0 480 56" preserveAspectRatio="none" role="img" aria-label="Memory and CPU over the last hour">${memPoints ? `<polyline class="resource-spark-memory" points="${memPoints}"/>` : ''}${cpuPoints ? `<polyline class="resource-spark-cpu" points="${cpuPoints}"/>` : ''}</svg>
    ${diagnoses.length ? diagnoses.map(d => `<p class="resource-diagnosis">${resourceDiagnosisText(d)}</p>`).join('') : '<p class="resource-diagnosis quiet">Within current thresholds</p>'}
    ${evidence.length ? `<ul class="family-drawer-evidence">${evidence.map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul>` : ''}
  </section>`;

  const orphan = p => !!p.is_orphan || (Number(p.pid) !== Number(f.root_pid) && !pids.has(Number(p.ppid)));
  const row = p => `<tr class="family-proc-row${orphan(p) ? ' orphan' : ''}">
      <td>${escapeHTML(p.name || 'process')}${orphan(p) ? ' <span class="agent-status orphan">leftover</span>' : ''}</td>
      <td>${Number(p.pid || 0)}</td><td>${escapeHTML(fmtRSS(p.rss_bytes) || '—')}</td><td>${escapeHTML(fmtCPU(p.cpu_percent) || '—')}</td><td>${escapeHTML(p.started_at ? fmtAge(p.started_at, now) : '—')}</td>
    </tr>`;
  const cap = cappedList(procs, 12, null, 'family-procs:' + f.key, c.expanded);
  const table = `<section class="family-drawer-section">
    <h4>Processes <small>${procs.length}</small></h4>
    <table class="family-drawer-procs"><thead><tr><th>Name</th><th>PID</th><th>Memory</th><th>CPU</th><th>Age</th></tr></thead><tbody>${cap.shown.map(row).join('')}</tbody></table>
    ${cap.more}
  </section>`;

  const kinds = { 8: 'TOOL USE', 9: 'PROXY HIT', 5: 'NET CONN' };
  const recent = filterEventsByPids(c.events, [...pids]).slice(0, 30);
  const eventRow = e => {
    const detail = e.detail || e.path || (e.remote_host ? `${e.remote_host}:${e.remote_port}` : '');
    return `<div class="family-event"><time>${escapeHTML(fmtTime(new Date(e.ts)))}</time><span class="event-kind">${kinds[e.kind] || 'EVENT'}</span><span><b>${escapeHTML(nameOf.get(Number(e.pid)) || 'process')}</b> ${escapeHTML(detail)}</span></div>`;
  };
  const activity = `<section class="family-drawer-section">
    <h4>Recent activity <small>${recent.length}</small></h4>
    ${recent.length ? `<div class="family-drawer-events">${recent.map(eventRow).join('')}</div>` : '<p class="family-drawer-empty">No events from these processes in the loaded window.</p>'}
    <button type="button" class="link-btn" data-action="family-events" data-key="${escapeHTML(f.key)}">Open in Events</button>
  </section>`;

  const found = (c.flags || []).filter(fl => fl && !fl.acknowledged && pids.has(Number(fl.pid)));
  const findingRow = fl => {
    const sev = fl.severity >= 3 ? 's3' : fl.severity === 2 ? 's2' : 's1';
    const age = fl.ts ? fmtAge(fl.ts, now) : '';
    return `<div class="family-finding"><span class="sev ${sev}">●</span><span>${escapeHTML(fl.title || ruleTitle(fl.rule))}</span>${age ? `<time>${escapeHTML(age)} ago</time>` : ''}</div>`;
  };
  const findings = `<section class="family-drawer-section">
    <h4>Findings <small>${found.length}</small></h4>
    ${found.length ? found.map(findingRow).join('') + '<button type="button" class="link-btn" data-action="goto-tab" data-tab="home" data-group="findings">Open Findings</button>' : '<p class="family-drawer-empty">No open findings for these processes.</p>'}
  </section>`;

  return [
    { key: 'head', html: head }, { key: 'usage', html: usage }, { key: 'procs', html: table },
    { key: 'activity', html: activity }, { key: 'findings', html: findings },
  ];
}

// The drawer foot: pending controls, Terminate orphans (N), Terminate family
// (the root's process tree through the existing /kill confirm).
function familyDrawerFootHTML(f, label) {
  const orphans = Number(f.orphan_count || 0);
  return resourceControlHTML(f)
    + (orphans > 0 ? `<button type="button" class="btn btn-danger btn-sm" data-action="kill-family-orphans" data-key="${escapeHTML(f.key)}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate orphans (${orphans})</span></button>` : '')
    + `<button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="${Number(f.root_pid || 0)}" data-started="${escapeHTML(f.root_started_at || '')}" data-family="${escapeHTML(label || '')}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate family</span></button>`;
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

// memoryRowsByFamily: one memory row per live process family. Durable
// sessions group by root pid; each family counts its tree's RSS once, however
// many sessions share it. Sessions without a live root are dropped. A family
// is infra when its tree root is (sessions carry no kind). Rows are ranked by
// RSS, largest first. Pure.
function memoryRowsByFamily(sessions, trees) {
  const byRoot = {};
  for (const t of trees || []) if (t && t.root) byRoot[Number(t.root.pid)] = t;
  const families = new Map();
  for (const s of sessions || []) {
    const pid = Number(s && s.root_pid) || 0;
    if (!pid || !byRoot[pid]) continue;
    if (!families.has(pid)) families.set(pid, []);
    families.get(pid).push(s);
  }
  const rows = [];
  for (const [pid, fam] of families) {
    const t = byRoot[pid];
    const label = familyLabel({ root_pid: pid, name: t.root.name, workspace: t.root.cwd }, fam);
    rows.push({
      pid,
      label: fam.length > 1 ? `${label} · ${fam.length} sessions` : label,
      rss: Number(t.rss_bytes || 0),
      infra: t.root.kind === 'infra',
    });
  }
  return rows.filter(r => r.rss > 0).sort((a, b) => b.rss - a.rss);
}

// Memory-by-family chart: resident memory per live process family, ranked.
// Uses the durable session rows grouped onto live tree RSS; falls back to the
// process-tree families when the daemon predates the session spine. Rows are
// keyed by family root pid, so an unchanged row keeps its node.
function renderChartMemory() {
  const SA = window.SA;
  const el = document.getElementById('chart-memory');
  const total = document.getElementById('chart-mem-total');
  if (!el) return;
  const trees = (SA.t.status && SA.t.status.trees) || [];
  let families = memoryRowsByFamily(SA.t.sessions || [], trees);

  if (!families.length) {
    // Legacy fallback: process-tree families.
    families = trees.map(t => ({
      pid: t.root && t.root.pid,
      label: familyLabel({ root_pid: t.root && t.root.pid, name: t.root && t.root.name, workspace: t.root && t.root.cwd }, []),
      rss: Number(t.rss_bytes || 0),
      infra: !!(t.root && t.root.kind === 'infra'),
    })).filter(s => s.rss > 0);
  }
  if (total) total.textContent = families.filter(f => !f.infra).length;
  if (!families.length) {
    el.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No attributed sessions yet</span></div>`;
    return;
  }
  const top = families.sort((a, b) => b.rss - a.rss).slice(0, 8);
  const max = Math.max(1, ...top.map(f => f.rss));
  const fmt = v => fmtRSS(v) || '0 B';
  patchList(el, top, {
    key: f => f.pid,
    html: f => hbarRowHTML({ label: f.label, value: f.rss, cls: f.infra ? 'infra' : '', sub: f.infra ? 'infra' : '' }, max, fmt),
  });
  applyInlineMetrics(el);
}

// Spend: the stat-strip tile (24h total, by repo, from SA.t.costs) and the
// Spend card (SA.t.costsCard: the dimension and window its controls chose),
// headed by one plan-headroom line per SA.t.costPlans entry. Plan and
// unpriced calls are counted, never priced. While the daemon recomputes an
// old report it answered from its usage cache (spendUpdating), the card head
// says so and the tile's line ends "updating".
function renderSpend() {
  const SA = window.SA;
  const report = SA.t.costs;
  const total = (report && report.total) || {};
  const num = document.getElementById('count-spend');
  const hint = document.getElementById('hint-spend');
  if (num) num.textContent = Number(total.calls) ? fmtUSD(total.cost_usd) : '—';
  if (hint) hint.textContent = [spendHintText(total), spendUpdating(report) ? 'updating…' : ''].filter(Boolean).join(' · ');
  const notice = document.getElementById('spend-cache');
  if (notice) {
    const text = spendCacheText([report, SA.t.costsCard]);
    notice.textContent = text;
    notice.hidden = !text;
  }

  const el = document.getElementById('spend-card');
  if (!el) return;
  let plansEl = el.firstElementChild;
  let body = plansEl && plansEl.nextElementSibling;
  if (el.childElementCount !== 2 || plansEl.className !== 'spend-plans' || body.className !== 'spend-body') {
    el.innerHTML = '<div class="spend-plans"></div><div class="spend-body"></div>';
    plansEl = el.firstElementChild;
    body = plansEl.nextElementSibling;
  }
  const plans = SA.t.costPlans && Array.isArray(SA.t.costPlans.plans) ? SA.t.costPlans.plans : [];
  patchList(plansEl, spendPlanItems(plans), { key: i => i.key, html: i => i.html });

  const card = SA.t.costsCard;
  if (!card) {
    body.innerHTML = `<div class="empty"><span>Loading spend…</span></div>`;
    return;
  }
  const rows = Array.isArray(card.rows) ? card.rows : [];
  if (!rows.some(row => Number(row.cost_usd) > 0 || Number(row.plan_calls) > 0)) {
    body.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>No priced model calls in this window.</span></div>`;
    return;
  }
  // Keyed through patchList so the slow refresh keeps unchanged rows and
  // the day bars' horizontal scroll.
  const day = card.by === 'day';
  const cls = day ? 'spend-bars' : 'spend-list';
  let wrap = body.firstElementChild;
  if (!wrap || body.childElementCount !== 1 || wrap.className !== cls) {
    body.innerHTML = `<div class="${cls}"></div>`;
    wrap = body.firstElementChild;
  }
  const left = wrap.scrollLeft;
  const items = day ? spendDayItems(rows) : spendListItems(rows, 8, { by: card.by, expanded: SA.expanded });
  patchList(wrap, items, { key: i => i.key, html: i => i.html });
  wrap.scrollLeft = left;
}

// spendUpdating: whether a /costs report is shown while the daemon
// recomputes it (refreshing) and is at least a minute old: older than the
// console's 30 s refresh keeps it, so it came from the usage cache (a
// restart, a view not asked lately). One that does not say when it was
// computed counts.
function spendUpdating(r, nowMs) {
  if (!r || !r.refreshing) return false;
  const at = Date.parse(r.generated_at);
  return !isFinite(at) || (nowMs || Date.now()) - at >= 60000;
}

// spendCacheText: the Spend card's notice while spendUpdating holds for a
// shown report — "Updating usage cache… (cached 3h ago)", the oldest one's
// age; '' when it holds for none.
function spendCacheText(reports, nowMs) {
  const shown = (reports || []).filter(r => spendUpdating(r, nowMs));
  if (!shown.length) return '';
  const at = Math.min(...shown.map(r => Date.parse(r.generated_at)).filter(isFinite));
  return 'Updating usage cache…' + (isFinite(at) ? ` (cached ${fmtAge(new Date(at).toISOString(), nowMs)} ago)` : '');
}

// spendHintText: the stat-strip line under the 24h spend — "N calls", then
// " · P on plans" and " · U unpriced" when non-zero; '' with no calls.
function spendHintText(total) {
  const t = total || {};
  const calls = Number(t.calls) || 0;
  if (!calls) return '';
  const plan = Number(t.plan_calls) || 0;
  const unpriced = Number(t.unpriced_calls) || 0;
  return `${calls} call${calls === 1 ? '' : 's'}`
    + (plan ? ` · ${plan} on plans` : '')
    + (unpriced ? ` · ${unpriced} unpriced` : '');
}

// planWindowLabel: a rate-limit window's length — 10080 min "weekly", 300
// "5-hour", else "<n>h".
function planWindowLabel(minutes) {
  const m = Number(minutes) || 0;
  if (m === 10080) return 'weekly';
  if (m === 300) return '5-hour';
  return `${Math.round((m / 60) * 10) / 10}h`;
}

// planLineText: one /costs/plans entry as "Codex Pro · codex · weekly 52%
// used · resets Fri 3:10 PM" (local time), one clause per window.
function planLineText(p) {
  const cap = s => { s = String(s || ''); return s ? s[0].toUpperCase() + s.slice(1) : ''; };
  const parts = [[cap(p.harness), cap(p.plan_type)].filter(Boolean).join(' '), String(p.home || '')];
  for (const w of Array.isArray(p.windows) ? p.windows : []) {
    const reset = Date.parse(w.resets_at);
    parts.push(`${planWindowLabel(w.window_minutes)} ${Math.round(Number(w.used_percent) || 0)}% used`
      + (isNaN(reset) ? '' : ` · resets ${fmtDayClock(new Date(reset))}`));
  }
  return parts.filter(Boolean).join(' · ');
}

// spendPlanItems: the Spend card's plan-headroom lines as patchList items
// { key: "plan:<home>", html } — the line, then one bar per window filled to
// used_percent. No items for an empty list.
function spendPlanItems(plans) {
  return (plans || []).map(p => {
    const bars = (Array.isArray(p.windows) ? p.windows : []).map(w => {
      const pct = Math.min(100, Math.max(0, Number(w.used_percent) || 0));
      const cls = pct >= 90 ? ' crit' : pct >= 75 ? ' warn' : '';
      return `<span class="hbar-track" title="${escapeHTML(planWindowLabel(w.window_minutes))}"><span class="hbar-fill${cls}" data-w="${pct.toFixed(1)}"></span></span>`;
    }).join('');
    return { key: `plan:${p.home_path || p.home}`, html: `<div class="spend-plan">
      <span class="spend-plan-text">${escapeHTML(planLineText(p))}</span>${bars}
    </div>` };
  });
}

// spendListItems: the Spend card's repo/provider/model list as patchList
// items { key: "<by>:<row key>", html } — the top n rows by cost (key,
// harness chip, calls, cost), then the Show more button (list key "spend").
// opts: { by, expanded }. A by=provider "(unknown)" row says the provider
// was not recorded; a row whose calls are all on plans reads "plan" where
// the cost goes.
function spendListItems(rows, n, opts) {
  opts = opts || {};
  const list = rows || [];
  const row = r => {
    const calls = Number(r.calls) || 0;
    const onPlan = calls > 0 && Number(r.plan_calls) === calls;
    const unknown = opts.by === 'provider' && r.key === '(unknown)';
    return `<div class="spend-row">
      <span class="spend-key" title="${escapeHTML(r.key)}">${escapeHTML(r.key)}</span>
      ${unknown ? '<span class="spend-hint">provider not recorded</span>' : ''}
      ${r.harness ? harnessChipHTML(r.harness) : ''}
      <span class="spend-calls">${calls} call${calls === 1 ? '' : 's'}</span>
      <span class="spend-cost">${onPlan ? 'plan' : escapeHTML(fmtUSD(r.cost_usd))}</span>
    </div>`;
  };
  const cap = cappedList(topCostRows({ rows: list }, list.length), n, null, 'spend', opts.expanded);
  const items = cap.shown.map(r => ({ key: `${opts.by}:${r.key}`, html: row(r) }));
  if (cap.more) items.push({ key: 'more:spend', html: cap.more });
  return items;
}

// spendDayItems: the Spend card's by=day view as patchList items
// { key: "day:<YYYY-MM-DD>", html } — one column per row in ascending key
// order, bar height by share of the costliest day, a "Mon 23" label and the
// cost under the bar; calls in the title.
function spendDayItems(rows) {
  const list = [...(rows || [])].sort((a, b) => {
    const x = String(a.key), y = String(b.key);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  const max = Math.max(0, ...list.map(r => Number(r.cost_usd) || 0));
  return list.map(r => {
    const cost = Number(r.cost_usd) || 0;
    const calls = Number(r.calls) || 0;
    const pct = max > 0 ? (cost / max) * 100 : 0;
    const label = spendDayLabel(r.key);
    const title = `${r.key} · ${fmtUSD(cost)} · ${calls} call${calls === 1 ? '' : 's'}`;
    return { key: `day:${r.key}`, html: `<div class="spend-day" title="${escapeHTML(title)}">
      <span class="spend-day-track"><span class="spend-day-bar" data-h="${pct.toFixed(1)}"></span></span>
      <span class="spend-day-cost">${escapeHTML(fmtUSDCompact(cost))}</span>
      <span class="spend-day-label">${escapeHTML(label)}</span>
    </div>` };
  });
}

// spendDayLabel: "2026-09-23" → "Wed 23"; anything else as given.
function spendDayLabel(key) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(key || ''));
  if (!m) return String(key || '');
  const day = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))).getUTCDay();
  return `${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][day]} ${Number(m[3])}`;
}

// fmtUSDCompact: a cost that fits under a day bar — "$0", "$0.42", "$677",
// "$1.2k".
function fmtUSDCompact(v) {
  const n = Number(v) || 0;
  if (n >= 1000) return `$${(n / 1000).toFixed(1)}k`;
  if (n >= 10) return `$${Math.round(n)}`;
  if (n > 0) return `$${n.toFixed(2)}`;
  return '$0';
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
    // A group's open state is DOM state: patchList keeps an unchanged group's
    // node and carries open across a rebuilt one.
    // Rows patch inside each group's shell, keyed by session id or folded
    // title, so a selected or expanded row survives a reconcile. The shell
    // hashes by key and whether it has an ended tail: its counts change in
    // place (syncSessionGroupShell), never by rebuilding the group.
    const parts = sessionGroups.length
      ? sessionGroups.map(g => ({ key: 'group:' + g.key, group: g, shell: `group:${g.key}|${g.ended.length ? 'ended' : ''}`, html: sessionGroupHTML(g, true, !!SA.endedSessionsOpen[g.key]) }))
      : [{ key: filtered ? 'empty:nomatch' : 'empty:quiet', html: filtered ? noMatch : quiet }];
    if (infra) parts.push({ key: 'infra', html: sessionInfraGroupHTML(infra, false) });
    patchList(rail, parts, { key: p => p.key, html: p => p.html, hash: p => p.shell || p.html });
    const rowOpts = { key: r => r.key, html: r => r.html };
    for (const p of parts) {
      if (!p.group) continue;
      const node = Array.from(rail.children).find(n => n._saKey === p.key);
      if (!node) continue;
      syncSessionGroupShell(node, p.group, !!SA.endedSessionsOpen[p.group.key]);
      const rows = (fams, bucket) => sessionRailRows(fams, p.group.key, trees, SA.selectedSessionId, SA.sessionDupOpen, bucket);
      patchList(node.querySelector('.session-rows'), rows(p.group.live, 'live'), rowOpts);
      patchList(node.querySelector('.session-ended-body'), rows(p.group.ended, 'ended'), rowOpts);
    }
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

// One posture item: severity dot, title, and the link to where it is acted on.
function postureItemHTML(it) {
  const sev = it.severity >= 3 ? 's3' : it.severity === 2 ? 's2' : 's1';
  let link = '';
  if (it.kind === 'flag') link = `<a href="#" data-action="goto-tab" data-tab="home" data-group="findings">view evidence</a>`;
  if (it.kind === 'incident') link = `<a href="#" data-action="open-incident" data-id="${escapeHTML(it.id)}">view report</a>`;
  if (it.kind === 'guard_pending') link = `<span>resolve it in the menu bar app</span>`;
  if (it.kind === 'collector_down') link = `<span>— ${escapeHTML(it.detail || 'collector stopped')} <a href="#" data-action="open-fda">open Full Disk Access settings</a></span>`;
  if (it.kind === 'uninspected_egress') link = `<a href="#" data-action="open-uninspected">see endpoints</a>`;
  return `<li class="posture-item"><span class="sev ${sev}">●</span><span>${escapeHTML(it.title)} ${link}</span></li>`;
}

// The banner summarises, the queue lists. On Home the attention queue below
// is the list, so the banner lists nothing (''); on any other tab it lists
// the first POSTURE_ITEM_CAP items and links the rest to Home. extra holds
// summary lines (the advisor's triage) that follow the list. Pure.
const POSTURE_ITEM_CAP = 3;
function postureItemsHTML(items, tab, extra) {
  if (tab === 'home') return '';
  const list = items || [];
  const extraList = extra || [];
  // extra (the advisor's triage summary) counts toward the cap too: content
  // rows (items + extra) never exceed POSTURE_ITEM_CAP, and the "more" link
  // — not a content row itself — counts only the items it hides.
  const itemSlots = Math.max(0, POSTURE_ITEM_CAP - extraList.length);
  const shown = list.slice(0, itemSlots);
  const out = shown.map(postureItemHTML);
  const more = list.length - shown.length;
  if (more > 0) out.push(`<li class="posture-more"><a href="#" data-action="goto-tab" data-tab="home">and ${more} more</a></li>`);
  return out.concat(extraList).join('');
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

  // The fatigue reducer: when the local advisor has triaged the critical
  // flags and some read benign, say so at the one-glance level.
  const vis = inspectionVisible(SA.t.status, SA.t.audit);
  const criticals = vis.advisor
    ? (SA.t.flags || []).filter(f => f.severity >= 3 && f.advisor && f.advisor.assessment)
    : [];
  const benignCount = criticals.filter(f => f.advisor.assessment === 'benign').length;
  const extra = criticals.length > 0
    ? [`<li class="posture-advisor"><span class="sev s1">●</span><span>advisor: ${benignCount} of ${criticals.length} triaged critical flags look benign</span></li>`]
    : [];
  const html = postureItemsHTML(p.items, SA.activeTab, extra);
  itemsEl.innerHTML = html;
  itemsEl.hidden = !html;
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
  events = eventsNewestFirst(events);

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

  const now = new Date();
  const row = (e, freshCls) => {
    const { label, cls, detail } = eventRow(e);
    // eventTime (lib.js): locale-proof HH:MM:SS today, "Mon DD HH:MM" on
    // another day, so a backfilled row cannot pass for a live one.
    const timeStr = eventTime(new Date(e.ts), now);
    // A bare PID is the ambiguous-process complaint: a trace row names its
    // session, any other row prefixes the agent name the tagged tree gives.
    const who = eventWho(e, SA.t.sessions, Number(e.pid) ? SA.agentNameFor(e.pid) : '');
    const mark = who.harness ? harnessChipHTML(who.harness) : '';

    return `
      <div class="timeline-item${freshCls}">
        <span class="t">${escapeHTML(timeStr)}</span>
        <span class="event-kind ${cls}">${label}</span>
        <span class="pid" title="${escapeHTML(who.title)}">${mark}${escapeHTML(who.text)}</span>
        <span class="dtl">${escapeHTML(detail)}</span>
      </div>
    `;
  };
  // Animate only rows new to the container — the initial page load never
  // animates. The hash leaves the fresh class out, so a row seen once keeps
  // its node (and does not re-animate) on the next render. The newest 50
  // rows show, then Show more: a live row pushes the oldest visible one out.
  const cap = cappedList(events, 50, null, 'events', SA.expanded);
  const items = cap.hidden ? [...cap.shown, { more: cap.more }] : cap.shown;
  patchList(container, items, {
    key: e => (e.more !== undefined ? 'show-more' : eventKey(e)),
    hash: e => (e.more !== undefined ? e.more : row(e, '')),
    html: e => (e.more !== undefined ? `<div class="list-more">${e.more}</div>`
      : row(e, !SA.reducedMotion && !SA.firstEventRender && !SA.suppressFreshOnce && !SA.prevEventKeys.has(eventKey(e))
        ? (e.kind === 9 ? ' fresh-sev' : ' fresh') : '')),
  });
  applyInlineMetrics(container);

  SA.prevEventKeys = new Set(events.map(eventKey));
  SA.firstEventRender = false;
  SA.suppressFreshOnce = false;
}
