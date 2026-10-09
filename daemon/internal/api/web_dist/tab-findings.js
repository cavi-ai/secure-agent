// Home decisions and coverage, followed by detailed findings and incidents.

function renderCoverage() {
  const status = window.SA.t.status || {};
  const p = window.SA.t.posture || {};
  const panel = document.getElementById('coverage-center');
  const list = document.getElementById('coverage-list');
  const badge = document.getElementById('badge-coverage-count');
  if (!panel || !list) return;
  const items = p.coverage_items || [];
  const harnesses = (status.coverage && status.coverage.harnesses) || [];
  panel.hidden = items.length === 0 && harnesses.length === 0;
  if (badge) badge.textContent = Number(p.coverage_count) || items.length;
  if (panel.hidden) return;
  list.innerHTML = items.map(it => {
    const action = it.kind === 'uninspected_egress'
      ? '<button type="button" class="btn btn-ghost btn-sm" data-action="open-uninspected">Review endpoints</button>'
      : it.kind === 'collector_down' && it.id === 'eslogger'
        ? '<button type="button" class="btn btn-ghost btn-sm" data-action="open-fda">Open permissions</button>'
        : it.kind === 'storage_loss'
          ? '<span class="coverage-guidance">Check disk space and state-directory permissions. Run Doctor for details.</span>'
          : it.kind === 'event_loss'
            ? '<span class="coverage-guidance">Run Doctor to review lost telemetry. Restarting cannot restore missing evidence.</span>'
        : '<span class="coverage-guidance">Check Setup &amp; Permissions in the menu bar</span>';
    return `<div class="coverage-row"><span><strong>${escapeHTML(it.title)}</strong><span>${escapeHTML(it.detail || '')}</span></span>${action}</div>`;
  }).join('') + harnesses.map(h => {
    const trace = !h.trace_supported ? 'not supported' : h.trace_last_seen ? 'activity observed in 24h' : 'supported; no activity observed in 24h';
    const guard = !h.guard_supported ? 'not supported' : h.hook_last_seen ? 'hook activity observed in 24h' : 'supported; no hook activity observed in 24h';
    return `<div class="coverage-row"><span><strong>${escapeHTML(h.name)}</strong><span>Trace: ${escapeHTML(trace)} · Guard: ${escapeHTML(guard)}</span></span></div>`;
  }).join('') + (harnesses.length ? `<p class="coverage-guidance">${status.proxy_enabled
    ? 'Payload inspection covers connections routed through the proxy; review Egress for coverage.'
    : 'Payload inspection is off (proxy disabled).'} Recent harness activity does not prove every current session is guarded.</p>` : '');
}

function renderAttention() {
  const SA = window.SA;
  const container = document.getElementById('attention-list');
  const badge = document.getElementById('badge-attention-count');
  const footer = document.getElementById('attention-footer');
  if (!container) return;
  renderCoverage();
  // The daemon serves the grouped queue on /posture — one derivation, no
  // client-side regrouping that could disagree with the menubar. The count
  // is the hero's needs_you, which the daemon keeps equal to the groups.
  const groups = (SA.t.posture && SA.t.posture.groups) || [];
  const count = attentionCount(SA.t.posture);
  if (badge) badge.textContent = count;
  SA.setTabBadge('home', count);
  if (!groups.length) {
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-shield"/></svg><span>No pending decisions</span></div>`;
    if (footer) footer.hidden = true;
    return;
  }
  if (footer) footer.hidden = groups.length <= 3 && groups.every(g => g.items.length <= 2);

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
      ${retriage(item)}`;
    if (item.kind === 'recurring_egress') return `
      <button class="btn btn-ghost btn-sm" data-action="expect-egress" data-episode-id="${escapeHTML(item.id)}" data-kind="destination">Expect destination</button>
      ${item.action === 'scope' ? `<button class="btn btn-ghost btn-sm" data-action="expect-egress" data-episode-id="${escapeHTML(item.id)}" data-kind="scope">Expect activity scope</button>` : ''}
      <button class="btn btn-ghost btn-sm" data-action="goto-tab" data-tab="egress">Review evidence</button>`;
    return '';
  };
  const retriage = item => !advisorVisible ? '' : advisorOffline
    ? `<button class="btn btn-ghost btn-sm" disabled title="Advisor offline — verdicts paused (${escapeHTML(advisorHealth.last_error || 'model server unreachable')})">Advisor offline</button>`
    : `<button class="btn btn-ghost btn-sm" data-action="retriage" data-id="${escapeHTML(item.id)}">Re-run advisor</button>`;
  // The same choice as a More-menu item on an explained finding.
  const retriageItems = item => !advisorVisible ? [] : advisorOffline
    ? [{ label: 'Advisor offline', attrs: '', disabled: true, title: `Advisor offline — verdicts paused (${advisorHealth.last_error || 'model server unreachable'})` }]
    : [{ label: 'Re-run advisor', attrs: `data-action="retriage" data-id="${escapeHTML(item.id)}"` }];

  // A flag item whose flag the daemon explained renders the finding card's
  // lines — who, what, verdict — and its served actions; a pattern item
  // renders its pattern card, a routine item its routine group.
  const flagsById = new Map((SA.t.flags || []).map(f => [f.id, f]));
  const patternsByKey = new Map((SA.t.patterns || []).map(p => [p.key, p]));
  const routineByKey = new Map((SA.t.routine || []).map(r => [r.key, r]));
  const now = Date.now();
  const itemHTML = item => {
    if (item.kind === 'review' && item.review) return reviewHTML(item.review, SA.reviewDrafts && SA.reviewDrafts.get(item.id));
    const rg = item.kind === 'routine' ? routineByKey.get(item.id) : null;
    if (rg) return routineHTML(rg);
    const p = item.kind === 'pattern' ? patternsByKey.get(item.id) : null;
    if (p) return patternHTML(p, now, { flags: SA.t.flags, expanded: SA.expanded });
    const f = item.kind === 'flag' ? flagsById.get(item.id) : null;
    const l = f && explainLines(f);
    if (l) return `
        <div class="attention-item kind-flag finding-item ${l.cls}">
          <div class="attention-reason">
            <div class="decision-head">${l.state ? `<span class="disp-badge">${escapeHTML(l.state)}</span>` : ''}<strong class="finding-what">${escapeHTML(l.what)}</strong></div>
            ${factChipsHTML(f, l.who)}
            ${l.why ? `<p class="finding-why">${escapeHTML(l.why)}</p>` : ''}
            ${assessmentHTML(f.explain.assessment)}
          </div>
          <div class="attention-actions">${explainActionsHTML(f, retriageItems(item))}</div>
        </div>`;
    return `
        <div class="attention-item kind-${escapeHTML(item.kind)}">
          <div class="attention-reason">
            <div class="decision-head"><span class="attention-kind">${escapeHTML(item.title)}</span><strong>${escapeHTML(item.detail)}</strong></div>
            ${item.scopeText ? `<p class="finding-why">${escapeHTML(item.scopeText)}</p>` : ''}
            ${item.advisor ? advisorAdviceHTML(item.advisor) : ''}
          </div>
          <div class="attention-actions">${actions(item)}</div>
        </div>`;
  };

  let wrap = container.firstElementChild;
  if (!wrap || !wrap.classList.contains('attention-groups')) {
    container.innerHTML = '<div class="attention-groups"></div>';
    wrap = container.firstElementChild;
  }
  // The group node is keyed on its identity; urgency, the metrics and the
  // item count update in place and the items patch inside it, so an open
  // pattern <details> or a focused button survives a memory or CPU tick.
  const groupKey = group => group.key || group.label;
  patchList(wrap, groups, { key: groupKey,
    hash: group => JSON.stringify([group.key, group.label, group.agent, group.workspace, group.summary]),
    html: group => `<article class="attention-group">
      <header class="attention-group-head">
        <div class="attention-identity">
          <span class="attention-agent">${escapeHTML(group.key === 'routine' ? 'recurring' : group.agent || 'machine')}</span>
          <strong>${escapeHTML(group.agent && group.label === group.agent ? familyTitle(group.agent) : group.label)}</strong>
          ${attentionSubtitle(group) ? `<span class="attention-workspace">${escapeHTML(attentionSubtitle(group))}</span>` : ''}
        </div>
        <div class="attention-metrics"></div>
        <span class="attention-total"></span>
      </header>
      <div class="attention-items"></div>
    </article>` });
  const nodes = new Map(Array.from(wrap.children).map(n => [n._saKey, n]));
  for (const group of groups) {
    const node = nodes.get(String(groupKey(group)));
    if (!node) continue;
    node.classList.toggle('urgent', !!(group.items[0] && group.items[0].priority >= 4));
    const metrics = [
      group.rssBytes ? `<span><b>${escapeHTML(fmtRSS(group.rssBytes))}</b> memory</span>` : '',
      group.cpuPercent ? `<span><b>${escapeHTML(fmtCPU(group.cpuPercent))}</b> CPU</span>` : '',
      group.processCount ? `<span><b>${Number(group.processCount)}</b> process${group.processCount === 1 ? '' : 'es'}</span>` : '',
    ].filter(Boolean).join('');
    const m = node.querySelector('.attention-metrics');
    if (m._saHTML !== metrics) { m.innerHTML = metrics; m._saHTML = metrics; }
    const total = `${group.items.length} item${group.items.length === 1 ? '' : 's'}`;
    const t = node.querySelector('.attention-total');
    if (t.textContent !== total) t.textContent = total;
    patchList(node.querySelector('.attention-items'), group.items, { key: item => item.kind + ':' + item.id, html: itemHTML });
  }
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

  patchList(container, incidents, { key: inc => inc.id, html: inc => {
    const wf = inc.workflow || {};
    const status = wf.status || 'open';
    const statusChip = status === 'resolved'
      ? `<span class="workflow-chip resolved">closure reported</span>`
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
      ${wf.resolution_note ? `<div class="incident-note">Reported resolution: ${escapeHTML(wf.resolution_note)}</div>` : ''}
      <div class="incident-actions">
        <button class="btn btn-ghost" data-action="open-incident" data-id="${escapeHTML(inc.id)}"><svg class="icon"><use href="#i-doc"/></svg><span>View report</span></button>
        ${status === 'open' ? `<button class="btn btn-ghost" data-action="incident-status" data-id="${escapeHTML(inc.id)}" data-status="acknowledged"><svg class="icon"><use href="#i-history"/></svg><span>Acknowledge</span></button>` : ''}
        ${status !== 'resolved' ? `<button class="btn btn-ghost" data-action="incident-status" data-id="${escapeHTML(inc.id)}" data-status="resolved"><svg class="icon"><use href="#i-shield"/></svg><span>Report resolved</span></button>` : ''}
      </div>
      <div class="rotate-list">
        ${(inc.rotate_list || []).map(item => `
          <div class="rotate-item-row">
            <span class="rk"><svg class="icon"><use href="#i-key"/></svg><strong>${escapeHTML(item.name)}</strong> (${escapeHTML(item.category)})</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;} });
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

  patchList(container, audit, { key: a => `${a.ts}|${a.action}|${a.rule || ''}|${a.detail || ''}`, html: a => {
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
  } });
}

function renderFlags() {
  const SA = window.SA;

  const container = document.getElementById('flags-list');
  const badge = document.getElementById('badge-flags-count');

  // Seed the filter dropdowns from the unfiltered flags so options don't
  // vanish once a filter narrows the view.
  const allPatterns = SA.t.patterns || [];
  [...(SA.t.flags || []), ...allPatterns].forEach(f => {
    if (f.agent) SA.seenAgents.add(f.agent);
    if (f.rule) SA.seenRules.add(f.rule);
  });
  SA.syncSelect('flags-agent', SA.seenAgents);
  SA.syncSelect('flags-rule', SA.seenRules);

  if (SA.t.flagsView === null) {
    badge.textContent = '—';
    container.innerHTML = '<div class="loading">Finding history has not loaded yet.</div>';
    return;
  }

  // A covered flag appears only in its pattern; urgency orders both forms.
  const selected = id => {
    const v = (document.getElementById(id) || {}).value || 'all';
    return v === 'all' ? '' : v;
  };
  const scopedFlags = scopedBySession(SA.t.flagsView || [], SA.timelineSession, SA.timelinePids);
  const reviewPage = SA.t.reviews || {reviews:[]};
  const reviews = (reviewPage.reviews || []).filter(r => (!SA.timelineSession || r.context.session_id === SA.timelineSession)
    && (!selected('flags-agent') || r.agent === selected('flags-agent')) && (!selected('flags-rule') || r.context.rule === selected('flags-rule'))
    && matchesSearch(SA.globalSearchTerm(), r.agent, r.context.rule, r.context.resources, r.context.destinations, r.context.workspace)
    && (selected('flags-severity') !== '3' || r.assessment.risk === 'critical' || (r.assessment.risk === 'unknown' && r.severity >= 3))
    && (!selected('flags-window') || Date.parse(r.last_seen) >= Date.now() - ({'1h':3600000,'24h':86400000,'7d':604800000}[selected('flags-window')] || Infinity)));
  const representedReviews = new Set(reviewPage.degraded ? [] : reviews.map(r => r.id));
  const represented = new Set(scopedFlags.filter(f => f.review_id && representedReviews.has(f.review_id)).map(f => f.id));
  const patterns = patternsInView(allPatterns.filter(p => !(p.flag_ids || []).some(id => represented.has(id))), {
    term: SA.globalSearchTerm(), agent: selected('flags-agent'), rule: selected('flags-rule'),
    session: SA.timelineSession, pids: SA.timelinePids, flags: scopedFlags, filtered: SA.isFlagsFiltered(),
  });
  const flags = uncoveredFlags(scopedFlags.filter(f => !represented.has(f.id))
    .filter(f => matchesSearch(SA.globalSearchTerm(), f.agent, f.rule, f.evidence, f.sessionId, f.workspace)), patterns);
  SA.paintSessionChip('flags-session-filter', 'flags-session-filter-id', patterns.length + flags.length);
  badge.textContent = patterns.length + flags.length + reviews.length;

  if (flags.length === 0 && patterns.length === 0 && reviews.length === 0 && !reviewPage.next && !SA.reviewCursor) {
    const msg = SA.sessionScopeOn()
      ? `No flags for ${SA.sessionScopeTag()} in the loaded window`
      : SA.isFlagsFiltered() ? 'No flags match the current filter' : 'No findings in the loaded window';
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-alert"/></svg><span>${msg}</span></div>`;
    return;
  }

  const advisorHealth = (SA.t.status && SA.t.status.advisor_health) || null;
  const advisorOffline = !!(advisorHealth && advisorHealth.circuit_open);
  const vis = inspectionVisible(SA.t.status, SA.t.audit);
  const now = Date.now();

  const cardHTML = (f, i) => {
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
    const sessionBtn = f.session_id ? `<button class="btn btn-ghost btn-sm" data-action="filter-session" data-session="${escapeHTML(f.session_id)}"><svg class="icon"><use href="#i-activity"/></svg><span>View session in timeline</span></button>` : '';
    const l = explainLines(f, now);
    if (l) return findingHTML(f, l, chainHTML, retriageBtn + sessionBtn);
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
          ${sessionBtn}
          ${f.advisor && f.advisor.assessment === 'benign' && flagHost(f) ? `<button class="btn btn-ghost btn-sm" data-action="mute-flag" data-rule="${escapeHTML(f.rule)}" data-host="${escapeHTML(flagHost(f))}" data-agent="${escapeHTML(f.agent || '')}" title="Stop flagging ${escapeHTML(f.rule)} for ${escapeHTML(flagHost(f))} — reversible"><svg class="icon"><use href="#i-close"/></svg><span>Mute rule+host</span></button>` : ''}
          ${isKeychain ? `<button class="btn btn-ghost btn-sm" data-action="mute-rule" data-rule="${escapeHTML(f.rule)}" data-agent="${escapeHTML(f.agent || '')}" title="Stop flagging ${escapeHTML(f.rule)} ${f.agent ? 'for ' + escapeHTML(f.agent) : 'entirely'} — reversible from the muted list below"><svg class="icon"><use href="#i-close"/></svg><span>Dismiss this flag class</span></button>` : ''}
          <button class="btn btn-danger btn-sm" data-action="kill" data-pid="${f.pid}" title="Terminate the agent process tree (pid ${f.pid})"><svg class="icon"><use href="#i-power"/></svg><span>Kill ${escapeHTML(f.agent)}</span></button>
        </div>
        <div class="flag-evidence">
          ${(f.evidence || []).map(ev => `<div>${escapeHTML(typeof ev === 'string' ? ev
            : ev.text || (ev.sub ? (ev.label || '') + ' (' + ev.sub + ')' : ev.label))}</div>`).join('')}
        </div>
      </div></div>
    </div>`;
  };
  const parts = patterns.map(p => ({
    key: 'pattern:' + p.key, priority: findingPriority(p), html: patternHTML(p, now, { flags: SA.t.flags, expanded: SA.expanded }),
  })).concat(flags.map((f, i) => {
    const html = cardHTML(f, i);
    // The age in a finding's meta ticks without rebuilding the card (so an
    // open Details and a focused button survive): the hash leaves it out and
    // the text is set in place below. Verdict and actions stay in the hash.
    const l = explainLines(f, now);
    const hash = l ? html.replace(metaHTML(l.meta), metaHTML('')) : html;
    return { key: 'flag:' + f.id, priority: findingPriority(f), html, hash, meta: l ? l.meta : null };
  })).sort((a, b) => b.priority - a.priority);
  parts.unshift(...reviews.map(r => ({key:'review:'+r.id, priority:3, html:reviewHTML(r, SA.reviewDrafts && SA.reviewDrafts.get(r.id))})));
  if (reviewPage.degraded) parts.unshift({key:'review-degraded',html:'<p role="alert">Review storage is degraded. Original findings remain available below.</p>'});
  if (reviewPage.next) parts.push({key:'review-next',html:`<button class="btn btn-ghost" data-action="review-page" data-after="${escapeHTML(reviewPage.next)}">Next reviews</button>`});
  if (SA.reviewCursor) parts.push({key:'review-first',html:'<button class="btn btn-ghost" data-action="review-page">First reviews</button>'});

  // Dispositions: muted (rule, host, agent) rows, visible so the quiet is
  // deliberate and reversible. The list node persists; its rows patch one by
  // one, so a change leaves the other rows (and a focused unmute) in place.
  const mutes = SA.t.mutes || [];
  if (mutes.length > 0) parts.push({ key: 'mutes', html: '<div class="mute-list"></div>' });
  patchList(container, parts, { key: p => p.key, html: p => p.html, hash: p => p.hash || p.html });
  const muteList = Array.from(container.children).find(el => el._saKey === 'mutes');
  if (muteList) {
    patchList(muteList, [{ key: 'head', html: '<div class="mute-head">Muted</div>' }]
      .concat(mutes.map(m => ({ key: `${m.rule}|${m.host}|${m.agent || ''}`, html: muteRowHTML(m) }))),
    { key: p => p.key, html: p => p.html });
  }
  const metaById = new Map(parts.filter(p => p.meta !== null && p.meta !== undefined).map(p => [p.key, p.meta]));
  for (const el of container.children) {
    const m = metaById.get(el._saKey);
    const span = m !== undefined && el.querySelector('.finding-meta');
    if (span && span.textContent !== m) span.textContent = m;
  }
}

function findingPriority(f) {
  const a = f.assessment || (f.explain || {}).assessment;
  if (a) {
    if (f.acknowledged || a.review_state === 'reviewed' || a.review_state === 'closed-reported') return 0;
    if (a.risk === 'critical' || (a.risk === 'unknown' && f.severity >= 3)) return 3;
    return a.risk === 'informational' ? 1 : 2;
  }
  const state = (f.disposition || (f.explain || {}).disposition || {}).state;
  if (f.acknowledged || state === 'acknowledged') return 0;
  if (state === 'benign-likely') return 1;
  if (state === 'critical' || (!state && f.severity >= 3)) return 3;
  return 2;
}

// muteRowHTML: one disposition in the Muted list — rule, host, and the agent
// when the mute is scoped to one ("all agents" is implied when it is not).
function muteRowHTML(m) {
  const agent = m.agent ? ` · ${escapeHTML(m.agent)}` : '';
  return `
      <div class="mute-row">
        <span class="mute-pair">${escapeHTML(m.rule)} · ${m.host === '*' ? 'all hosts' : escapeHTML(m.host)}${agent}</span>
        <button class="source-remove" title="Unmute" data-action="unmute" data-rule="${escapeHTML(m.rule)}" data-host="${escapeHTML(m.host)}" data-agent="${escapeHTML(m.agent || '')}"><svg class="icon"><use href="#i-close"/></svg></button>
      </div>`;
}

function metaHTML(meta) {
  return `<span class="finding-meta">${escapeHTML(meta)}</span>`;
}

// findingHTML: the finding card for a flag the daemon explained — who, what,
// the one verdict and the served actions; the raw evidence chain, pid,
// session, ISO timestamps and full path/addresses sit behind Details.
function findingHTML(f, l, chainHTML, toolsHTML) {
  const ex = f.explain;
  const c = ex.context || {};
  const s = ex.subject || {};
  const dest = (ex.egress || []).map(e => {
    const addr = e.port ? (e.host.includes(':') ? `[${e.host}]:${e.port}` : `${e.host}:${e.port}`) : e.host;
    return e.org ? `${addr} (${e.org})` : addr;
  }).join(', ');
  const facts = [
    ['Rule', f.rule], ['Matched rule', s.rule], ['File', s.path], ['Destinations', dest],
    ['PID', f.pid], ['Session', f.session_id || c.session_id], ['Raised', f.ts],
    ['Tool', c.tool ? c.tool + (c.tool_at ? ' at ' + c.tool_at : '') : ''], ['Model', c.model],
  ].filter(([, v]) => v !== undefined && v !== null && v !== '');
  return `
    <article class="finding ${l.cls}" data-flag-id="${escapeHTML(f.id)}">
      <header class="finding-head">
        ${harnessChipHTML(f.agent)}
        <span class="finding-title">${escapeHTML(f.title || ruleTitle(f.rule))}</span>
        <span class="finding-who">${escapeHTML(l.who)}</span>
        ${metaHTML(l.meta)}
      </header>
      <p class="finding-what">${escapeHTML(l.what)}</p>
      ${factChipsHTML(f, '')}
      <p class="finding-verdict">${escapeHTML(ex.assessment ? l.state : l.verdict)}</p>
      ${assessmentHTML(ex.assessment)}
      ${labelsLineHTML(ex.labels)}
      <div class="finding-actions">${explainActionsHTML(f, [{ label: 'What to do', attrs: `data-action="open-plan" data-subject="flag:${escapeHTML(f.id)}"` }])}</div>
      <details class="finding-details"><summary>Details</summary>
        ${chainHTML}
        <dl class="finding-facts">${facts.map(([k, v]) => `<dt>${escapeHTML(k)}</dt><dd>${k === 'File'
          ? `<button type="button" class="file-link" data-action="open-file" data-path="${escapeHTML(v)}">${escapeHTML(v)}</button>`
          : escapeHTML(v)}</dd>`).join('')}</dl>
        ${toolsHTML ? `<div class="flag-actions-row">${toolsHTML}</div>` : ''}
        <div class="flag-actions-row">${markButtonsHTML('flag:' + f.id)}</div>
      </details>
    </article>`;
}

// ---------- routine: the same reads across agents as one decision ----------

const ROUTINE_CONSOLE_ACTIONS = ['expect-all', 'dismiss-all'];

// routineHTML: one routine group — the state pill and the served summary;
// the reader, the file area, the agents and the busiest destinations as
// chips; Treat as routine and Dismiss all as buttons. The click handler
// reads every request from the served group (key + action id).
function routineHTML(rg) {
  const d = assessmentDisplay(rg.assessment, rg.disposition);
  const dests = rg.destinations || [];
  const more = (Number(rg.destination_count) || 0) - dests.length;
  const chips = [
    rg.reader ? `<span class="fact"><svg class="icon"><use href="#i-terminal"/></svg>${escapeHTML(rg.reader)}</span>` : '',
    `<span class="fact fact-file"><svg class="icon"><use href="#i-doc"/></svg>${escapeHTML(rg.area)}${rg.files > 1 ? ` · ${Number(rg.files)} files` : ''}</span>`,
    `<span class="fact"><svg class="icon"><use href="#i-agent"/></svg>${escapeHTML((rg.agents || []).join(', '))}</span>`,
    ...dests.map(x => `<span class="fact fact-dest" title="${escapeHTML(x.host)} · cited by ${Number(x.count)} flag${Number(x.count) === 1 ? '' : 's'}"><svg class="icon"><use href="#i-globe"/></svg>${escapeHTML(x.org || x.host)}</span>`),
    more > 0 ? `<span class="fact">+${more} more</span>` : '',
  ].filter(Boolean).join('');
  const acts = assessmentActions(rg.actions, rg.assessment).filter(a => a && ROUTINE_CONSOLE_ACTIONS.includes(a.id));
  const attrs = a => `data-action="routine-act" data-routine-key="${escapeHTML(rg.key)}" data-action-id="${escapeHTML(a.id)}"`;
  return `
        <div class="attention-item kind-routine finding-item ${DISPOSITION_CLASS[d.state] || 'disp-warning'}" data-routine-key="${escapeHTML(rg.key)}">
          <div class="attention-reason">
            <div class="decision-head">${d.text ? `<span class="disp-badge">${escapeHTML(d.text)}</span>` : ''}<strong class="finding-what">${escapeHTML(rg.summary)}</strong></div>
            <div class="facts">${chips}</div>
            ${assessmentHTML(rg.assessment)}
          </div>
          <div class="attention-actions">${actionBarHTML(actionItems(acts, [], attrs, a => a.label || a.id))}</div>
        </div>`;
}

// routineAfterOptimistic: the state once a routine group's ids were
// resolved — the group and its decision leave, its flags leave the lists,
// and the patterns they sat in drop their open counts, until the next
// snapshot reconciles.
function routineAfterOptimistic(t, key, ids) {
  const done = new Set(ids || []);
  return {
    routine: (t.routine || []).filter(r => r.key !== key),
    patterns: (t.patterns || []).map(p => {
      const n = (p.flag_ids || []).filter(id => done.has(id)).length;
      return n ? patternAfterDismiss(p, n) : p;
    }),
    flags: (t.flags || []).filter(f => !done.has(f.id)),
    flagsView: t.flagsView === null ? null : (t.flagsView || []).map(f => done.has(f.id) ? reviewedFlag(f) : f),
    posture: mapPostureAttention(t.posture, it => ((it.kind === 'routine' && it.id === key)
      || (it.kind === 'flag' && done.has(it.id))) ? null : it),
  };
}

// ---------- patterns: a repeating finding as one card ----------

// Served pattern action ids the console performs.
const PATTERN_CONSOLE_ACTIONS = ['expect', 'expect-file', 'review-local', 'inspect-file', 'allow-host', 'mute-rule-host', 'mute-class', 'dismiss-all', 'kill'];
const PATTERN_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// uncoveredFlags: the flags no pattern covers (flag_ids). Handed the
// patterns in view, so a flag is hidden only behind a card that shows.
function uncoveredFlags(flags, patterns) {
  const covered = new Set();
  for (const p of patterns || []) for (const id of p.flag_ids || []) covered.add(id);
  return (flags || []).filter(f => !covered.has(f.id));
}

// patternsInView: the patterns the Flags filters admit — the search over
// agent, rule, title, subject and summary; the agent and rule selects; the
// session or pid scope, by the pattern's capped sessions / pids or by any
// of its flag_ids among the loaded scoped flags (opts.flags).
function patternsInView(patterns, opts) {
  const o = opts || {};
  const scoped = new Set((o.flags || []).map(f => f.id));
  const coversScoped = p => (p.flag_ids || []).some(id => scoped.has(id));
  return (patterns || []).filter(p => {
    if (o.filtered && (!(p.flag_ids || []).length || !(p.flag_ids || []).every(id => scoped.has(id)))) return false;
    if (o.agent && p.agent !== o.agent) return false;
    if (o.rule && p.rule !== o.rule) return false;
    if (o.session) {
      if (!(p.sessions || []).includes(o.session) && !coversScoped(p)) return false;
    } else if (o.pids && o.pids.length && !(p.pids || []).some(pid => o.pids.includes(pid)) && !coversScoped(p)) {
      return false;
    }
    return matchesSearch(o.term, p.agent, p.rule, p.title, (p.subject || {}).label, p.summary);
  });
}

// patternAfterDismiss: the pattern once n of its open flags were
// acknowledged. A served dismiss-all carries at most the newest 500 ids, so
// the open count drops by n and the card reads dismissed only at 0; the next
// /snapshot reconciles.
function patternAfterDismiss(p, n) {
  const unacked = Math.max(0, (Number(p.unacked) || 0) - (Number(n) || 0));
  if (unacked > 0) return { ...p, unacked };
  return { ...p, unacked: 0, dismissed: true, ...(p.assessment ? { assessment: { ...p.assessment, review_state: 'reviewed' } } : {}), disposition: { state: 'acknowledged', text: 'Reviewed', why: p.title || '' } };
}

// The attention queue and finding cards are different snapshots. A local
// dismissal must update both atomically until the daemon's next snapshot.
function patternAfterOptimisticDismiss(t, key, submitted) {
  const p = (t.patterns || []).find(x => x.key === key);
  if (!p) return t;
  const ids = new Set(submitted || p.flag_ids || []);
  const updated = patternAfterDismiss(p, submitted ? submitted.length : p.unacked);
  return {
    patterns: (t.patterns || []).map(x => x.key === key ? updated : x),
    flags: (t.flags || []).filter(f => !ids.has(f.id)),
    flagsView: t.flagsView === null ? null : (t.flagsView || []).map(f => ids.has(f.id) ? reviewedFlag(f) : f),
    posture: mapPostureAttention(t.posture, it => ((it.kind === 'flag' && ids.has(it.id))
      || (it.kind === 'pattern' && it.id === key && updated.dismissed)) ? null : it),
  };
}

// patternWindowText: "03:00→03:08" in local time; a day other than today
// leads with its date.
function patternWindowText(p, nowMs) {
  const pad = n => String(n).padStart(2, '0');
  const first = new Date(p.first), last = new Date(p.last);
  if (isNaN(first) || isNaN(last)) return '';
  const hm = d => pad(d.getHours()) + ':' + pad(d.getMinutes());
  const day = d => `${PATTERN_MONTHS[d.getMonth()]} ${d.getDate()} `;
  const today = new Date(nowMs || Date.now()).toDateString();
  const a = (first.toDateString() === today ? '' : day(first)) + hm(first);
  const b = (last.toDateString() === first.toDateString() ? '' : day(last)) + hm(last);
  return a === b ? a : `${a}→${b}`;
}

// patternBarsHTML: 24 bars, heights as classes h0..h8 relative to the
// busiest bucket (a non-empty bucket is at least h1).
function patternBarsHTML(hourly) {
  const h = Array.from({ length: 24 }, (_, i) => Math.max(0, Number((hourly || [])[i]) || 0));
  const max = Math.max(1, ...h);
  return h.map(n => `<i class="h${n ? Math.max(1, Math.round(n / max * 8)) : 0}"></i>`).join('');
}

function patternActionLabel(p, a) {
  const agent = p.agent || 'agent';
  if (a.id === 'kill') return `Kill ${agent}`;
  const host = a.body && typeof a.body.host === 'string' ? a.body.host : '';
  if (a.id === 'allow-host' && host.includes(':')) return `Allow this address for ${agent}`;
  return a.label || a.id;
}

// patternActionsHTML: the served actions on an action bar — recommended,
// the exact expectation and Dismiss all as buttons, the rest under More. The
// click handler reads the request from the served pattern (key + action id
// + host). A card dismissed in place keeps its choices, disabled.
function patternActionsHTML(p) {
  const acts = assessmentActions(p.actions, p.assessment).filter(a => a && PATTERN_CONSOLE_ACTIONS.includes(a.id))
    .map(a => (p.dismissed ? { ...a, disabled: true } : a));
  const attrs = a => {
    const host = a.body && typeof a.body.host === 'string' ? a.body.host : '';
    return `data-action="explain-act" data-pattern-key="${escapeHTML(p.key)}" data-action-id="${escapeHTML(a.id)}"`
      + (host ? ` data-host="${escapeHTML(host)}"` : '');
  };
  return actionBarHTML(actionItems(acts, [], attrs, a => patternActionLabel(p, a)));
}

// patternHTML: one repeating finding — title, count and window; the served
// summary; the cadence strip (24 bars, the cadence phrase, open count); the
// disposition; the served actions; the covered flags behind Details.
// opts.flags are the loaded flags (the covered ones list), opts.expanded
// the console's opened-list keys.
function patternHTML(p, nowMs, opts) {
  const o = opts || {};
  const d = assessmentDisplay(p.assessment, p.disposition);
  const count = Number(p.count) || 0;
  const open = p.dismissed ? 0 : Number(p.unacked) || 0;
  const covered = new Set(p.flag_ids || []);
  const rows = (o.flags || []).filter(f => covered.has(f.id));
  const cap = cappedList(rows, 10, null, 'pattern:' + p.key, o.expanded);
  const row = f => {
    const t = new Date(f.ts);
    const at = isNaN(t) ? String(f.ts || '') : t.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return `<li><button type="button" class="pattern-flag-link" data-action="open-flag" data-id="${escapeHTML(f.id)}" aria-label="View security flag ${escapeHTML(f.id)}">
      <span>${escapeHTML(at)}</span><span>pid ${Number(f.pid) || 0}</span>`
      + `${f.session_id ? `<span>session ${escapeHTML(sessionShort(f.session_id))}</span>` : ''}<code>${escapeHTML(f.id)}</code><span aria-hidden="true">↗</span></button></li>`;
  };
  return `
    <article class="finding pattern-card ${DISPOSITION_CLASS[d.state] || 'disp-warning'}" data-pattern-key="${escapeHTML(p.key)}">
      <header class="finding-head pattern-head">
        ${harnessChipHTML(p.agent)}
        <strong class="finding-title">${escapeHTML(p.title || ruleTitle(p.rule))}</strong>
        <span class="pattern-meta">${count}× · ${escapeHTML(patternWindowText(p, nowMs))}</span>
      </header>
      <p class="pattern-summary">${escapeHTML(p.summary)}</p>
      ${patternProcessesText(p.processes) ? `<p class="pattern-processes">${escapeHTML(patternProcessesText(p.processes))}</p>` : ''}
      <div class="pattern-cadence">
        <span class="pattern-bars" role="img" aria-label="Flags per bucket over the window, oldest first">${patternBarsHTML(p.hourly)}</span>
        <span class="pattern-cadence-text">${p.cadence ? escapeHTML(p.cadence) + ' · ' : ''}<b class="pattern-open">${open} open</b></span>
      </div>
      <p class="finding-verdict">${escapeHTML((d.text || '') + (d.why ? ': ' + d.why : ''))}</p>
      ${assessmentHTML(p.assessment)}
      <div class="finding-actions">${patternActionsHTML(p)}</div>
      <details class="finding-details pattern-flags"><summary>Individual flags (${Number(p.flags ?? count) || 0})</summary>
        ${rows.length ? `<ul class="pattern-flag-list">${cap.shown.map(row).join('')}</ul>${cap.more}`
          : '<p class="pattern-flags-note">None of them is open in the loaded window.</p>'}
      </details>
    </article>`;
}
