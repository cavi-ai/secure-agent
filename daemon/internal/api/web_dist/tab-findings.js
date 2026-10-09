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
  panel.hidden = items.length === 0;
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
  }).join('') + (harnesses.length ? `<details class="coverage-harness"><summary>Per-agent coverage</summary>${harnesses.map(h => {
    const trace = !h.trace_supported ? 'not supported' : h.trace_last_seen ? 'activity observed in 24h' : 'supported; no activity observed in 24h';
    const guard = !h.guard_supported ? 'not supported' : h.hook_last_seen ? 'hook activity observed in 24h' : 'supported; no hook activity observed in 24h';
    return `<div class="coverage-row"><span><strong>${escapeHTML(h.name)}</strong><span>Trace: ${escapeHTML(trace)} · Guard: ${escapeHTML(guard)}</span></span></div>`;
  }).join('')}<p class="coverage-guidance">${status.proxy_enabled
    ? 'Payload inspection covers connections routed through the proxy; review Egress for coverage.'
    : 'Payload inspection is off (proxy disabled).'} Recent harness activity does not prove every current session is guarded.</p></details>` : '');
}

// ---------- Home: the needs-you list ----------

// needsItems: the daemon's queue flattened to one list, carrying each item's
// group; highest priority first, served order within a priority.
function needsItems(posture) {
  const out = [];
  for (const g of (posture && posture.groups) || []) {
    for (const it of g.items || []) out.push({ ...it, group: g });
  }
  return out.map((it, i) => [it, i]).sort((a, b) => (b[0].priority - a[0].priority) || (a[1] - b[1])).map(x => x[0]);
}

const NEED_KIND_WORD = { guard: 'guard', resource: 'resource', incident: 'incident' };

function needDomID(item) {
  return 'need-' + item.kind + '-' + String(item.id).replace(/[^A-Za-z0-9_-]/g, '_');
}

function needTimestamp(item, SA) {
  if (item.kind === 'flag') {
    const f = (SA.t.flags || []).find(x => x.id === item.id);
    return f ? f.ts : '';
  }
  if (item.kind === 'incident') {
    const inc = (SA.t.incidents || []).find(x => x.id === item.id);
    return inc ? inc.timestamp : '';
  }
  return '';
}

// needHTML: one decision row — what the agent wants, why, and the one or two
// choices. age is the ticking suffix of the meta, set in place after patching.
function needHTML(item, age) {
  const SA = window.SA;
  const group = item.group || {};
  const agent = group.agent || '';
  const id = escapeHTML(item.id);
  const workspaceBase = String(group.workspace || '').split('/').filter(Boolean).pop() || '';
  const flag = item.kind === 'flag' ? (SA.t.flags || []).find(f => f.id === item.id) : null;
  const l = flag ? explainLines(flag) : null;
  const pattern = item.kind === 'pattern' ? (SA.t.patterns || []).find(p => p.key === item.id) : null;
  const routine = item.kind === 'routine' ? (SA.t.routine || []).find(r => r.key === item.id) : null;
  const advisorHealth = (SA.t.status && SA.t.status.advisor_health) || null;
  const advisorVisible = !!(SA.t.status && SA.t.status.advisor_enabled);
  const advisorOffline = !!(advisorHealth && advisorHealth.circuit_open);
  const retriageItems = !advisorVisible ? [] : advisorOffline
    ? [{ label: 'Advisor offline', attrs: '', disabled: true, title: `Advisor offline — verdicts paused (${advisorHealth.last_error || 'model server unreachable'})` }]
    : [{ label: 'Re-run advisor', attrs: `data-action="retriage" data-id="${id}"` }];
  const bar = (label, attrs, kind) => ({ label, attrs, kind, bar: true });
  const menu = (label, attrs, kind) => ({ label, attrs, kind });

  let what = item.detail || item.title || '';
  let why = '';
  let actions = '';
  let detail = '';
  const sev = item.kind === 'guard' || item.kind === 'resource' ? 'sev-warn' : 'sev-bad';
  const word = NEED_KIND_WORD[item.kind] || 'critical';
  if (item.kind === 'guard') {
    why = [`${agent || 'The agent'} is paused until you answer`, item.scopeText, workspaceBase].filter(Boolean).join(' · ');
    const a = (verdict, scope) => `data-action="guard-resolve" data-id="${id}" data-verdict="${verdict}" data-scope="${scope}"`;
    actions = actionBarHTML([
      bar('Allow once', a('allow', 'once'), 'ghost'), bar('Deny', a('deny', 'once'), 'danger'),
      menu('Allow rule', a('allow', 'always')), menu('Deny rule', a('deny', 'always')),
    ]);
    detail = `<dl class="finding-facts"><dt>Path</dt><dd>${escapeHTML(item.path || '')}</dd><dt>Rule</dt><dd>${escapeHTML(item.rule || '')}</dd><dt>Scope</dt><dd>${escapeHTML(item.scopeText || '')}</dd></dl>`
      + (item.advisor ? advisorAdviceHTML(item.advisor) : '');
  } else if (item.kind === 'resource') {
    why = [group.label, group.rssBytes ? `${fmtRSS(group.rssBytes)} memory` : '', group.cpuPercent ? `${fmtCPU(group.cpuPercent)} CPU` : ''].filter(Boolean).join(' · ');
    actions = actionBarHTML([
      bar('Keep running', `data-action="resource-control" data-id="${id}" data-decision="dismiss"`, 'ghost'),
      bar(`Apply ${String(item.action).replaceAll('_', ' ')}`, `data-action="resource-control" data-id="${id}" data-decision="apply" data-intervention="${escapeHTML(item.action)}"`, 'danger'),
    ]);
    detail = `<dl class="finding-facts"><dt>Session</dt><dd>${escapeHTML(group.label || '')}</dd><dt>Memory</dt><dd>${escapeHTML(group.rssBytes ? fmtRSS(group.rssBytes) : '')}</dd><dt>CPU</dt><dd>${escapeHTML(group.cpuPercent ? fmtCPU(group.cpuPercent) : '')}</dd><dt>Processes</dt><dd>${Number(group.processCount) || 0}</dd></dl>`;
  } else if (item.kind === 'incident') {
    why = [item.title, item.status].filter(Boolean).join(' · ');
    actions = actionBarHTML([
      bar('View report', `data-action="open-incident" data-id="${id}"`, 'ghost'),
      item.status === 'open' ? menu('Acknowledge', `data-action="incident-status" data-id="${id}" data-status="acknowledged"`) : null,
    ]);
  } else if (item.kind === 'flag') {
    what = (l && l.what) || item.detail || '';
    why = (l && (l.why || l.state)) || (item.disposition && item.disposition.why) || '';
    if (flag && l) {
      const plan = { label: 'What to do', attrs: `data-action="open-plan" data-subject="flag:${id}"`, lead: true };
      actions = explainActionsHTML(flag, [plan, ...retriageItems], 1);
      detail = factChipsHTML(flag, l.who) + assessmentHTML(flag.explain.assessment) + findingFactsHTML(flag);
    } else {
      actions = actionBarHTML([bar('Dismiss', `data-action="dismiss-flag" data-id="${id}"`, 'ghost'), ...retriageItems]);
    }
  } else if (pattern) {
    what = `${pattern.title || item.title} — ${Number(pattern.count) || 0}×`;
    why = pattern.summary || item.detail || '';
    actions = patternActionsHTML(pattern, 1);
    detail = assessmentHTML(pattern.assessment);
  } else if (routine) {
    why = routine.summary || item.detail || '';
    what = item.title || 'Recurring read';
    actions = routineActionsHTML(routine, 1);
    detail = assessmentHTML(routine.assessment);
  }
  const key = `need:${item.kind}:${item.id}`;
  const expandable = !!detail;
  const open = expandable && SA.expanded.has(key);
  const dom = needDomID(item);
  const meta = `<span class="need-meta">${escapeHTML(word)}<span class="need-age">${age ? ' · ' + escapeHTML(age) : ''}</span>${expandable ? '<svg class="icon need-chev" aria-hidden="true"><use href="#i-arrow"/></svg>' : ''}</span>`;
  const headInner = `${harnessChipHTML(agent)}<span class="need-what" title="${escapeHTML(what)}">${escapeHTML(what)}</span><span class="need-why">${escapeHTML(why)}</span>${meta}`;
  const head = expandable
    ? `<button type="button" class="need-head" data-action="toggle-need" data-key="${escapeHTML(key)}" aria-expanded="${open}" aria-controls="${dom}">${headInner}</button>`
    : `<div class="need-head">${headInner}</div>`;
  return `<li class="need ${sev}${open ? ' open' : ''}" data-kind="${escapeHTML(item.kind)}">
      ${head}
      <div class="need-actions">${actions}</div>
      ${expandable ? `<div class="need-detail" id="${dom}"${open ? '' : ' hidden'}>${detail}</div>` : ''}
    </li>`;
}

function renderAttention() {
  const SA = window.SA;
  const panel = document.getElementById('attention-center');
  const list = document.getElementById('attention-list');
  const badge = document.getElementById('badge-attention-count');
  if (!list) return;
  renderCoverage();
  // The daemon serves the queue on /posture — one derivation, no client-side
  // regrouping that could disagree with the menubar. The count is the hero's
  // needs_you, which the daemon keeps equal to the items.
  const count = attentionCount(SA.t.posture);
  if (badge) badge.textContent = count;
  SA.setTabBadge('home', count);
  if (panel) panel.hidden = count === 0;
  const items = needsItems(SA.t.posture);
  const now = Date.now();
  const ageOf = it => fmtAge(needTimestamp(it, SA), now);
  patchList(list, items, {
    key: it => it.kind + ':' + it.id,
    html: it => needHTML(it, ageOf(it)),
    hash: it => needHTML(it, ''),
  });
  for (const el of list.children) {
    const it = items.find(x => x.kind + ':' + x.id === el._saKey);
    const span = it && el.querySelector('.need-age');
    const age = it ? ageOf(it) : '';
    if (span && span.textContent !== (age ? ' · ' + age : '')) span.textContent = age ? ' · ' + age : '';
  }
}

// ---------- Home: findings history ----------

function logWhen(iso, nowMs) {
  const t = new Date(iso);
  if (isNaN(t)) return '';
  const pad = n => String(n).padStart(2, '0');
  if (t.toDateString() === new Date(nowMs || Date.now()).toDateString()) return pad(t.getHours()) + ':' + pad(t.getMinutes());
  return `${PATTERN_MONTHS[t.getMonth()]} ${t.getDate()}`;
}

// historyVerdict: the Verdict column — the observed risk, then the review
// state once reviewed; the legacy disposition only when no assessment is served.
function historyVerdict(a, legacy) {
  const d = assessmentDisplay(a, legacy);
  if (!a || (a.review_state !== 'reviewed' && a.review_state !== 'closed-reported')) return d;
  return { state: d.state, text: d.text + ' · ' + (a.review_state === 'reviewed' ? 'Reviewed' : 'Closure reported'), why: d.why };
}

// historyCritical: critical observed risk (or an unknown risk at detector
// severity 3) sorts first, whether or not it has been reviewed.
function historyCritical(a, legacy, severity) {
  if (a) return a.risk === 'critical' || (a.risk === 'unknown' && (Number(severity) >= 3 || (legacy || {}).state === 'critical'));
  return (legacy || {}).state === 'critical';
}

function logKey(row) { return row.kind + ':' + row.key; }

// logRowHTML: one history row — a select box and a head button over the
// columns; the detail holds the existing card and builds only while open.
function logRowHTML(row, SA, nowMs, withSelection = true) {
  const rk = logKey(row);
  const openKey = 'log:' + rk;
  const open = SA.expanded.has(openKey);
  const dom = 'log-' + rk.replace(/[^A-Za-z0-9_-]/g, '_');
  const d = row.disposition || {};
  const cls = DISPOSITION_CLASS[d.state] || 'disp-warning';
  const verdict = d.text || '';
  const finding = escapeHTML(row.title) + (row.sub ? ` <span class="c-sub-text">· ${escapeHTML(row.sub)}</span>` : '');
  const selectable = !row.reviewed;
  const bars = row.hourly ? `<span class="pattern-bars log-bars${row.critical ? ' crit' : ''}" aria-hidden="true">${patternBarsHTML(row.hourly)}</span>` : '';
  return `<li class="log-row${row.critical ? ' crit' : ''}${open ? ' open' : ''}" data-row-key="${escapeHTML(rk)}">
      <div class="log-line">
        <input type="checkbox" class="log-check" data-action="history-select" data-row-key="${escapeHTML(rk)}" aria-label="Select: ${escapeHTML(row.title)}"${withSelection && SA.historySelected.has(rk) ? ' checked' : ''}${selectable ? '' : ' disabled'}>
        <button type="button" class="log-head" data-action="toggle-log-row" data-key="${escapeHTML(openKey)}" aria-expanded="${open}" aria-controls="${dom}">
          <span class="c-when">${escapeHTML(logWhen(row.last, nowMs))}</span>
          <span class="c-agent">${harnessChipHTML(row.agent)}<span>${escapeHTML(row.agent || '')}</span></span>
          <span class="c-finding"><span class="c-title" title="${escapeHTML(row.title + (row.sub ? ' · ' + row.sub : ''))}">${finding}</span><span class="c-sub">${escapeHTML([row.agent, row.count > 1 ? row.count + '×' : '', logWhen(row.last, nowMs), verdict].filter(Boolean).join(' · '))}</span></span>
          <span class="c-count">${row.count > 1 ? row.count + '×' : '1'}</span>
          <span class="c-bars">${bars}</span>
          <span class="c-verdict"><i class="vdot ${cls}" aria-hidden="true"></i><span class="c-verdict-text">${escapeHTML(verdict)}</span></span>
          <svg class="icon log-chev" aria-hidden="true"><use href="#i-arrow"/></svg>
        </button>
      </div>
      <div class="log-detail" id="${dom}"${open ? '' : ' hidden'}>${open ? row.detail() : ''}</div>
    </li>`;
}

function incidentCardHTML(inc, SA) {
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
    </div>`;
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

  const now = Date.now();
  const rows = incidents.map(inc => {
    const status = (inc.workflow || {}).status || 'open';
    const risk = String(inc.risk || '').toUpperCase();
    return {
      kind: 'incident', key: inc.id, last: inc.timestamp, agent: inc.agent || '',
      title: [inc.rule, inc.subject].filter(Boolean).join(' — '), sub: '',
      count: Number(inc.aggregate_count) || 1, hourly: null,
      critical: risk === 'CRITICAL', reviewed: true,
      disposition: { state: risk === 'CRITICAL' ? 'critical' : risk === 'HIGH' ? 'warning' : 'acknowledged', text: `${inc.risk || ''} · ${status === 'resolved' ? 'closure reported' : status}` },
      detail: () => incidentCardHTML(inc, SA),
    };
  }).sort((a, b) => (Number(b.critical) - Number(a.critical)) || (Date.parse(b.last) || 0) - (Date.parse(a.last) || 0));
  const cap = cappedList(rows, 50, null, 'history-incidents', SA.expanded);
  const parts = cap.shown.map(r => ({ key: logKey(r), html: logRowHTML(r, SA, now) }));
  if (cap.more) parts.push({ key: 'more', html: `<li class="log-more">${cap.more}</li>` });
  patchList(container, parts, { key: p => p.key, html: p => p.html });
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
  const patterns = patternsInView(allPatterns, {
    term: SA.globalSearchTerm(), agent: selected('flags-agent'), rule: selected('flags-rule'),
    session: SA.timelineSession, pids: SA.timelinePids, flags: scopedFlags, filtered: SA.isFlagsFiltered(),
  });
  const flags = uncoveredFlags(scopedFlags
    .filter(f => matchesSearch(SA.globalSearchTerm(), f.agent, f.rule, f.evidence, f.sessionId, f.workspace)), patterns);
  const agentSel = selected('flags-agent');
  const routines = (SA.sessionScopeOn() || SA.isFlagsFiltered() || selected('flags-rule')) ? [] : (SA.t.routine || []).filter(rg =>
    (!agentSel || (rg.agents || []).includes(agentSel)) && matchesSearch(SA.globalSearchTerm(), rg.reader, rg.area, rg.summary, (rg.agents || []).join(' ')));
  SA.paintSessionChip('flags-session-filter', 'flags-session-filter-id', patterns.length + flags.length + routines.length);
  badge.textContent = patterns.length + flags.length + routines.length;

  if (flags.length === 0 && patterns.length === 0 && routines.length === 0) {
    SA.historyRows = new Map();
    paintHistoryBulk(SA);
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
  const rows = patterns.map(p => {
    const d = historyVerdict(p.assessment, p.disposition);
    return {
      kind: 'pattern', key: p.key, last: p.last, agent: p.agent, title: p.title || ruleTitle(p.rule),
      sub: (p.subject || {}).label || '', count: Number(p.count) || 0, hourly: p.hourly,
      critical: historyCritical(p.assessment, p.disposition, 0), reviewed: !!p.dismissed || !(Number(p.unacked) > 0),
      disposition: d, detail: () => patternHTML(p, now, { flags: SA.t.flags, expanded: SA.expanded }),
    };
  }).concat(flags.map(f => {
    const l = explainLines(f, now);
    const ex = f.explain || {};
    const legacy = ex.disposition || (f.severity >= 3 ? { state: 'critical', text: 'Act now' } : { state: 'warning', text: 'Needs a look' });
    const d = historyVerdict(ex.assessment, legacy);
    return {
      kind: 'flag', key: f.id, last: f.ts, agent: f.agent, title: f.title || ruleTitle(f.rule),
      sub: (ex.subject || {}).display || (l && l.what) || '', count: 1, hourly: null,
      critical: historyCritical(ex.assessment, legacy, f.severity), reviewed: !!f.acknowledged || (ex.disposition || {}).state === 'acknowledged',
      disposition: d, detail: () => cardHTML(f, 0),
    };
  })).concat(routines.map(rg => {
    const d = historyVerdict(rg.assessment, rg.disposition);
    return {
      kind: 'routine', key: rg.key, last: '', agent: (rg.agents || [])[0] || '', title: rg.summary || 'Recurring read',
      sub: '', count: Number(rg.count) || 0, hourly: null, critical: historyCritical(rg.assessment, rg.disposition, 0),
      reviewed: (rg.disposition || {}).state === 'acknowledged' || (rg.assessment || {}).review_state === 'reviewed',
      disposition: d, detail: () => routineHTML(rg),
    };
  })).sort((a, b) => (Number(b.critical) - Number(a.critical)) || (Date.parse(b.last) || 0) - (Date.parse(a.last) || 0));
  const cap = cappedList(rows, 50, null, 'history', SA.expanded);

  // Selection lives on the visible open rows only.
  SA.historyRows = new Map(cap.shown.filter(r => !r.reviewed).map(r => [logKey(r), r]));
  for (const k of Array.from(SA.historySelected)) if (!SA.historyRows.has(k)) SA.historySelected.delete(k);

  const parts = cap.shown.map(r => ({ key: logKey(r), html: logRowHTML(r, SA, now), hash: logRowHTML(r, SA, now, false) }));
  if (cap.more) parts.push({ key: 'more', html: `<li class="log-more">${cap.more}</li>` });

  // Dispositions: muted (rule, host, agent) rows, visible so the quiet is
  // deliberate and reversible. The list node persists; its rows patch one by
  // one, so a change leaves the other rows (and a focused unmute) in place.
  const mutes = SA.t.mutes || [];
  if (mutes.length > 0) parts.push({ key: 'mutes', html: '<li class="mute-list"></li>' });
  patchList(container, parts, { key: p => p.key, html: p => p.html, hash: p => p.hash || p.html });
  const muteList = Array.from(container.children).find(el => el._saKey === 'mutes');
  if (muteList) {
    patchList(muteList, [{ key: 'head', html: '<div class="mute-head">Muted</div>' }]
      .concat(mutes.map(m => ({ key: `${m.rule}|${m.host}|${m.agent || ''}`, html: muteRowHTML(m) }))),
    { key: p => p.key, html: p => p.html });
  }
  paintHistoryBulk(SA);
}

// paintHistoryBulk: the selection bar and the header checkbox follow the
// visible open rows and the selection.
function paintHistoryBulk(SA) {
  const bulk = document.getElementById('flags-bulk');
  const all = document.getElementById('flags-select-all');
  const n = SA.historySelected.size;
  if (bulk) {
    bulk.hidden = n === 0;
    bulk.innerHTML = n === 0 ? '' : `<span>${n} selected</span>`
      + `<button type="button" class="btn btn-ghost btn-sm" data-action="history-bulk-review">Mark reviewed</button>`
      + `<button type="button" class="btn btn-ghost btn-sm" data-action="history-bulk-clear">Clear</button>`;
  }
  if (all) {
    const open = SA.historyRows ? SA.historyRows.size : 0;
    all.disabled = open === 0;
    all.checked = open > 0 && n === open;
    all.indeterminate = n > 0 && n < open;
  }
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

// findingFactsHTML: the raw facts behind an explained flag — rule, file,
// destinations, pid, session, timestamps — as a definition list.
function findingFactsHTML(f) {
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
  return `<dl class="finding-facts">${facts.map(([k, v]) => `<dt>${escapeHTML(k)}</dt><dd>${k === 'File'
    ? `<button type="button" class="file-link" data-action="open-file" data-path="${escapeHTML(v)}">${escapeHTML(v)}</button>`
    : escapeHTML(v)}</dd>`).join('')}</dl>`;
}

// findingHTML: the finding card for a flag the daemon explained — who, what,
// the one verdict and the served actions; the raw evidence chain, pid,
// session, ISO timestamps and full path/addresses sit behind Details.
function findingHTML(f, l, chainHTML, toolsHTML) {
  const ex = f.explain;
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
        ${findingFactsHTML(f)}
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
  return `
        <div class="attention-item kind-routine finding-item ${DISPOSITION_CLASS[d.state] || 'disp-warning'}" data-routine-key="${escapeHTML(rg.key)}">
          <div class="attention-reason">
            <div class="decision-head">${d.text ? `<span class="disp-badge">${escapeHTML(d.text)}</span>` : ''}<strong class="finding-what">${escapeHTML(rg.summary)}</strong></div>
            <div class="facts">${chips}</div>
            ${assessmentHTML(rg.assessment)}
          </div>
          <div class="attention-actions">${routineActionsHTML(rg)}</div>
        </div>`;
}

// routineActionsHTML: the routine group's served actions on an action bar;
// max caps the bar.
function routineActionsHTML(rg, max) {
  const acts = assessmentActions(rg.actions, rg.assessment).filter(a => a && ROUTINE_CONSOLE_ACTIONS.includes(a.id));
  const attrs = a => `data-action="routine-act" data-routine-key="${escapeHTML(rg.key)}" data-action-id="${escapeHTML(a.id)}"`;
  return actionBarHTML(actionItems(acts, [], attrs, a => a.label || a.id), max);
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
function patternActionsHTML(p, max) {
  const acts = assessmentActions(p.actions, p.assessment).filter(a => a && PATTERN_CONSOLE_ACTIONS.includes(a.id))
    .map(a => (p.dismissed ? { ...a, disabled: true } : a));
  const attrs = a => {
    const host = a.body && typeof a.body.host === 'string' ? a.body.host : '';
    return `data-action="explain-act" data-pattern-key="${escapeHTML(p.key)}" data-action-id="${escapeHTML(a.id)}"`
      + (host ? ` data-host="${escapeHTML(host)}"` : '');
  };
  return actionBarHTML(actionItems(acts, [], attrs, a => patternActionLabel(p, a)), max);
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
