// Attention tab: a session-grouped operator queue followed by detailed
// findings, incidents, and the policy audit ledger.

function renderAttention() {
  const SA = window.SA;
  const container = document.getElementById('attention-list');
  const badge = document.getElementById('badge-attention-count');
  if (!container) return;
  const groups = buildAttentionGroups({
    status: SA.t.status,
    resources: SA.t.resources,
    guardPending: SA.t.guardPending,
    flags: SA.t.flags,
    incidents: SA.t.incidents,
    uninspected: SA.t.uninspected,
  });
  const count = groups.reduce((sum, group) => sum + group.items.length, 0);
  if (badge) badge.textContent = count;
  SA.setTabBadge('findings', count);
  if (!groups.length) {
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-shield"/></svg><span>No decisions waiting — monitored sessions are within policy</span></div>`;
    return;
  }

  const advisorHealth = (SA.t.status && SA.t.status.advisor_health) || null;
  const advisorVisible = !!(SA.t.status && SA.t.status.advisor_enabled);
  const advisorOffline = !!(advisorHealth && advisorHealth.circuit_open);

  const actions = item => {
    if (item.kind === 'guard') return `
      <button class="btn btn-primary btn-sm" data-action="guard-resolve" data-id="${escapeHTML(item.id)}" data-verdict="allow" data-scope="once">Allow once</button>
      <button class="btn btn-ghost btn-sm" data-action="guard-resolve" data-id="${escapeHTML(item.id)}" data-verdict="allow" data-scope="always">Allow rule</button>
      <button class="btn btn-danger btn-sm" data-action="guard-resolve" data-id="${escapeHTML(item.id)}" data-verdict="deny" data-scope="always">Deny rule</button>`;
    if (item.kind === 'resource') return `
      <button class="btn btn-danger btn-sm" data-action="resource-control" data-id="${escapeHTML(item.id)}" data-decision="apply" data-intervention="${escapeHTML(item.action)}">Apply ${escapeHTML(String(item.action).replaceAll('_', ' '))}</button>
      <button class="btn btn-ghost btn-sm" data-action="resource-control" data-id="${escapeHTML(item.id)}" data-decision="dismiss">Keep running</button>`;
    if (item.kind === 'incident') return `
      <button class="btn btn-ghost btn-sm" data-action="open-incident" data-id="${escapeHTML(item.id)}">View report</button>
      ${item.status === 'open' ? `<button class="btn btn-ghost btn-sm" data-action="incident-status" data-id="${escapeHTML(item.id)}" data-status="acknowledged">Acknowledge</button>` : ''}`;
    if (item.kind === 'flag') return `
      <button class="btn btn-ghost btn-sm" data-action="dismiss-flag" data-id="${escapeHTML(item.id)}">Dismiss</button>
      ${!advisorVisible ? '' : advisorOffline
        ? `<button class="btn btn-ghost btn-sm" disabled title="Advisor offline — verdicts paused (${escapeHTML(advisorHealth.last_error || 'model server unreachable')})">Advisor offline</button>`
        : `<button class="btn btn-ghost btn-sm" data-action="retriage" data-id="${escapeHTML(item.id)}">Re-run advisor</button>`}`;
    return `<button class="btn btn-ghost btn-sm" data-action="open-uninspected">Review endpoints</button>`;
  };

  container.innerHTML = `<div class="attention-groups">${groups.map(group => {
    const urgent = group.items[0] && group.items[0].priority >= 4 ? ' urgent' : '';
    const metrics = [
      group.rssBytes ? `<span><b>${escapeHTML(fmtRSS(group.rssBytes))}</b> memory</span>` : '',
      group.cpuPercent ? `<span><b>${escapeHTML(fmtCPU(group.cpuPercent))}</b> CPU</span>` : '',
      group.processCount ? `<span><b>${Number(group.processCount)}</b> process${group.processCount === 1 ? '' : 'es'}</span>` : '',
    ].filter(Boolean).join('');
    return `<article class="attention-group${urgent}">
      <header class="attention-group-head">
        <div class="attention-identity">
          <span class="attention-agent">${escapeHTML(group.agent)}</span>
          <strong>${escapeHTML(group.label)}</strong>
          ${group.workspace ? `<span class="attention-workspace">${escapeHTML(group.workspace)}</span>` : '<span class="attention-workspace">Signals could not be safely attributed to one live session</span>'}
        </div>
        <div class="attention-metrics">${metrics}</div>
        <span class="attention-total">${group.items.length} item${group.items.length === 1 ? '' : 's'}</span>
      </header>
      <div class="attention-items">${group.items.map(item => `
        <div class="attention-item kind-${escapeHTML(item.kind)}">
          <span class="attention-kind">${escapeHTML(item.title)}</span>
          <div class="attention-reason">
            <strong>${escapeHTML(item.detail)}</strong>
            ${item.scopeText ? `<span>${escapeHTML(item.scopeText)}</span>` : ''}
            ${item.advisor ? advisorAdviceHTML(item.advisor) : ''}
          </div>
          <div class="attention-actions">${actions(item)}</div>
        </div>`).join('')}</div>
    </article>`;
  }).join('')}</div>`;
}

function renderIncidents() {
  const SA = window.SA;

  const container = document.getElementById('incidents-container');
  const badge = document.getElementById('badge-incidents-count');
  const incidents = scopedBySession(SA.t.incidents || [], SA.timelineSession, SA.timelinePids);

  badge.textContent = incidents.length;

  if (incidents.length === 0) {
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-incident"/></svg><span>No incidents — nothing to contain right now</span></div>`;
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const wf = inc.workflow || {};
    const status = wf.status || 'open';
    const statusChip = status === 'resolved'
      ? `<span class="workflow-chip resolved">resolved</span>`
      : status === 'acknowledged'
        ? `<span class="workflow-chip acked">ack</span>`
        : '';
    const riskClass = (inc.risk || '').toUpperCase() === 'CRITICAL' ? 'high'
      : (inc.risk || '').toUpperCase() === 'HIGH' ? 'high' : '';
    // Aggregated incidents read as one row with a repeat count — the flag
    // storm is evidence, not 323 cards.
    const countChip = (inc.aggregate_count || 0) > 1
      ? `<span class="workflow-chip">×${Number(inc.aggregate_count)} flags</span>`
      : '';
    return `
    <div class="incident-card ${status === 'resolved' ? 'is-resolved' : ''}">
      <div class="incident-header">
        <span class="risk-tag ${riskClass}"><svg class="icon"><use href="#i-alert"/></svg>${escapeHTML(inc.risk)}</span>
        <span class="kpi-hint">${inc.agent ? escapeHTML(inc.agent) + ' · ' : ''}${escapeHTML(inc.rule)}${inc.subject ? ' — ' + escapeHTML(inc.subject) : ''}</span>
        ${countChip}
        ${statusChip}
      </div>
      <div class="incident-summary">${escapeHTML(inc.summary)}</div>
      ${inspectionVisible(SA.t.status, SA.t.audit).advisor && inc.advisor_narrative ? `<div class="advisor-narrative"><svg class="icon"><use href="#i-agent"/></svg><span>${escapeHTML(inc.advisor_narrative)}</span></div>` : ''}
      ${wf.resolution_note ? `<div class="incident-note">Resolution: ${escapeHTML(wf.resolution_note)}</div>` : ''}
      <div class="incident-actions">
        <button class="btn btn-ghost" data-action="open-incident" data-id="${escapeHTML(inc.id)}"><svg class="icon"><use href="#i-doc"/></svg><span>View report</span></button>
        ${status === 'open' ? `<button class="btn btn-ghost" data-action="incident-status" data-id="${escapeHTML(inc.id)}" data-status="acknowledged"><svg class="icon"><use href="#i-history"/></svg><span>Acknowledge</span></button>` : ''}
        ${status !== 'resolved' ? `<button class="btn btn-ghost" data-action="incident-status" data-id="${escapeHTML(inc.id)}" data-status="resolved"><svg class="icon"><use href="#i-shield"/></svg><span>Resolve</span></button>` : ''}
      </div>
      <div class="rotate-list">
        ${(inc.rotate_list || []).map(item => `
          <div class="rotate-item-row">
            <span class="rk"><svg class="icon"><use href="#i-key"/></svg><strong>${escapeHTML(item.name)}</strong> (${escapeHTML(item.category)})</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;}).join('');
}

function renderAudit() {
  const SA = window.SA;

  const vis = inspectionVisible(SA.t.status, SA.t.audit);
  const panel = document.getElementById('audit-panel');
  if (panel) panel.hidden = !vis.audit;
  if (!vis.audit) return;

  const container = document.getElementById('audit-container');
  const badge = document.getElementById('badge-audit-count');
  const audit = SA.t.audit || [];

  badge.textContent = audit.length;

  if (audit.length === 0) {
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-history"/></svg><span>No policy changes yet — promotions and secret registrations are logged here</span></div>`;
    return;
  }

  container.innerHTML = audit.map(a => {
    const timeStr = new Date(a.ts).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    let label = escapeHTML(a.detail || '');
    let cls = '';
    if (a.action === 'rule-mode') {
      label = `${escapeHTML(a.rule)}: ${escapeHTML(a.from_mode)} → ${escapeHTML(a.to_mode)}`;
      cls = a.to_mode === 'block' ? 'ok' : '';
    } else if (a.action === 'fingerprint-ingest') {
      cls = 'tool';
    } else if (a.action === 'fingerprint-reload') {
      label = label || 'fingerprints reloaded';
      cls = 'tool';
    }
    const actionLabel = a.action.replace(/-/g, ' ').toUpperCase();
    return `
      <div class="audit-item">
        <div class="audit-head">
          <span class="event-kind ${cls}">${actionLabel}</span>
          <span class="audit-t">${timeStr}</span>
        </div>
        <div class="audit-dtl">${label}</div>
      </div>
    `;
  }).join('');
}

function renderFlags() {
  const SA = window.SA;

  const container = document.getElementById('flags-list');
  const badge = document.getElementById('badge-flags-count');

  // Seed the filter dropdowns from the unfiltered flags so options don't
  // vanish once a filter narrows the view.
  (SA.t.flags || []).forEach(f => {
    if (f.agent) SA.seenAgents.add(f.agent);
    if (f.rule) SA.seenRules.add(f.rule);
  });
  SA.syncSelect('flags-agent', SA.seenAgents);
  SA.syncSelect('flags-rule', SA.seenRules);

  const flags = scopedBySession(SA.t.flagsView || [], SA.timelineSession, SA.timelinePids)
    .filter(f => matchesSearch(SA.globalSearchTerm(), f.agent, f.rule, f.evidence, f.sessionId, f.workspace));
  const scopedInc = scopedBySession(SA.t.incidents || [], SA.timelineSession, SA.timelinePids);
  SA.paintSessionChip('flags-session-filter', 'flags-session-filter-id', flags.length);
  badge.textContent = flags.length;

  if (flags.length === 0) {
    const msg = SA.sessionScopeOn()
      ? `No flags for ${SA.sessionScopeTag()} in the loaded window`
      : SA.isFlagsFiltered() ? 'No flags match the current filter' : 'No security flags — agent egress looks clean';
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-alert"/></svg><span>${msg}</span></div>`;
    return;
  }

  const advisorHealth = (SA.t.status && SA.t.status.advisor_health) || null;
  const advisorOffline = !!(advisorHealth && advisorHealth.circuit_open);
  const vis = inspectionVisible(SA.t.status, SA.t.audit);

  container.innerHTML = flags.map((f, i) => {
    const chain = buildEvidenceChain(f);
    const chainHTML = chain.length
      ? `<div class="chain">${chain.map((n, j) => `
          ${j > 0 ? '<span class="chain-link" aria-hidden="true"></span>' : ''}
          <div class="chain-node ${n.cls}">
            <span class="cn-icon"><svg class="icon"><use href="#${n.icon}"/></svg></span>
            <span class="cn-body">
              <span class="cn-label">${escapeHTML(n.label)}</span>
              <span class="cn-sub">${escapeHTML(n.sub)}</span>
            </span>
          </div>`).join('')}</div>`
      : '';
    const isKeychain = f.rule === 'keychain-access' || f.rule === 'keychain-security-cli';
    const retriageBtn = !vis.advisor ? ''
      : SA.pendingRetriage.has(f.id)
      ? `<span class="advisor-pending" title="The model is re-reading this flag — the fresh verdict lands here"><span class="spinner" aria-hidden="true"></span>advisor re-reading…</span>`
      : advisorOffline
        ? `<button class="btn btn-ghost btn-sm" disabled title="Advisor offline — verdicts paused (${escapeHTML(advisorHealth.last_error || 'model server unreachable')})"><svg class="icon"><use href="#i-refresh"/></svg><span>Advisor offline</span></button>`
        : `<button class="btn btn-ghost btn-sm" data-action="retriage" data-id="${escapeHTML(f.id)}" title="Ask the local model to re-read this flag"><svg class="icon"><use href="#i-refresh"/></svg><span>Re-run advisor</span></button>`;
    return `
    <div class="flag-card ${f.severity >= 3 ? 'sev3' : ''}${i === 0 ? ' expanded' : ''}">
      <button class="flag-head" data-action="toggle-flag" aria-expanded="${i === 0}">
        <svg class="icon flag-ico"><use href="#i-alert"/></svg>
        <span class="flag-rule-text">${escapeHTML(f.rule)} — ${escapeHTML(f.agent)} (PID ${f.pid})</span>
        ${vis.advisor && f.advisor && f.advisor.assessment ? `<span class="advisor-chip adv-${escapeHTML(f.advisor.assessment)}" title="${escapeHTML(f.advisor.rationale)}">advisor: ${escapeHTML(f.advisor.assessment)}</span>` : ''}
        ${f.session_id ? `<span class="flag-session">session ${escapeHTML(sessionShort(f.session_id))}</span>` : ''}
        <svg class="icon flag-chev"><use href="#i-arrow"/></svg>
      </button>
      <div class="flag-detail"><div class="flag-detail-inner">
        ${chainHTML}
        ${isKeychain ? `<div class="flag-context"><svg class="icon"><use href="#i-key"/></svg><span>Apps read the keychain to load their own credentials — this is usually routine. Informational only: dismiss this flag if reviewed, or dismiss the class if it's noise.</span></div>` : ''}
        <div class="flag-actions-row">
          <button class="btn btn-ghost btn-sm" data-action="dismiss-flag" data-id="${escapeHTML(f.id)}" title="Mark reviewed — this flag leaves the list; the rule keeps watching"><svg class="icon"><use href="#i-shield"/></svg><span>Dismiss</span></button>
          ${retriageBtn}
          ${f.session_id ? `<button class="btn btn-ghost btn-sm" data-action="filter-session" data-session="${escapeHTML(f.session_id)}"><svg class="icon"><use href="#i-activity"/></svg><span>View session in timeline</span></button>` : ''}
          ${f.advisor && f.advisor.assessment === 'benign' && flagHost(f) ? `<button class="btn btn-ghost btn-sm" data-action="mute-flag" data-rule="${escapeHTML(f.rule)}" data-host="${escapeHTML(flagHost(f))}" title="Stop flagging ${escapeHTML(f.rule)} for ${escapeHTML(flagHost(f))} — reversible"><svg class="icon"><use href="#i-close"/></svg><span>Mute rule+host</span></button>` : ''}
          ${isKeychain ? `<button class="btn btn-ghost btn-sm" data-action="mute-rule" data-rule="${escapeHTML(f.rule)}" title="Stop flagging ${escapeHTML(f.rule)} entirely — reversible from the muted list below"><svg class="icon"><use href="#i-close"/></svg><span>Dismiss this flag class</span></button>` : ''}
          <button class="btn btn-danger btn-sm" data-action="kill" data-pid="${f.pid}" title="Terminate the agent process tree (pid ${f.pid})"><svg class="icon"><use href="#i-power"/></svg><span>Kill ${escapeHTML(f.agent)}</span></button>
        </div>
        <div class="flag-evidence">
          ${(f.evidence || []).map(ev => `<div>${escapeHTML(ev)}</div>`).join('')}
        </div>
      </div></div>
    </div>`;
  }).join('');

  // Dispositions: muted (rule, host) pairs, visible so the quiet is
  // deliberate and reversible.
  const mutes = SA.t.mutes || [];
  if (mutes.length > 0) {
    container.innerHTML += `<div class="mute-list"><div class="mute-head">Muted</div>` + mutes.map(m => `
      <div class="mute-row">
        <span class="mute-pair">${escapeHTML(m.rule)} · ${m.host === '*' ? 'all hosts' : escapeHTML(m.host)}</span>
        <button class="source-remove" title="Unmute" data-action="unmute" data-rule="${escapeHTML(m.rule)}" data-host="${escapeHTML(m.host)}"><svg class="icon"><use href="#i-close"/></svg></button>
      </div>`).join('') + `</div>`;
  }
}
