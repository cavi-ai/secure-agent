// Home: the decisions waiting on the operator and the findings history. Both
// lists render one row per thing from a view; a row's detail body renders
// only while the row is open.

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

// ---------- shared row parts ----------

const PATTERN_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// homeContext: one render's lookups — flags, patterns, routine groups and
// incidents by id — with the clock and the advisor state.
function homeContext(SA) {
  const status = SA.t.status || {};
  const health = status.advisor_health || null;
  return {
    SA, now: Date.now(),
    flags: new Map((SA.t.flags || []).map(f => [f.id, f])),
    patterns: new Map((SA.t.patterns || []).map(p => [p.key, p])),
    routine: new Map((SA.t.routine || []).map(r => [r.key, r])),
    incidents: new Map((SA.t.incidents || []).map(i => [i.id, i])),
    advisor: inspectionVisible(status, SA.t.audit).advisor
      ? { offline: !!(health && health.circuit_open), error: (health && health.last_error) || 'model server unreachable' }
      : null,
  };
}

// clockText: "14:03" for today, else "Oct 6".
function clockText(iso, nowMs) {
  const t = new Date(iso);
  if (!iso || isNaN(t)) return '';
  const pad = n => String(n).padStart(2, '0');
  if (t.toDateString() === new Date(nowMs || Date.now()).toDateString()) return pad(t.getHours()) + ':' + pad(t.getMinutes());
  return `${PATTERN_MONTHS[t.getMonth()]} ${t.getDate()}`;
}

// riskOf: a row's risk — the served assessment with its review state, else
// the legacy disposition. An unknown risk at detector severity 3 is critical.
function riskOf(a, legacy, severity) {
  const d = assessmentDisplay(a, legacy);
  const review = a && { reviewed: 'Reviewed', 'closed-reported': 'Closure reported' }[a.review_state];
  const critical = a
    ? a.risk === 'critical' || (a.risk === 'unknown' && (Number(severity) >= 3 || (legacy || {}).state === 'critical'))
    : (legacy || {}).state === 'critical';
  return { cls: DISPOSITION_CLASS[d.state] || 'disp-warning', text: [d.text, review].filter(Boolean).join(' · '), critical };
}

// retriageItem: Re-run advisor as a menu item — a spinner label while the
// model re-reads, disabled while the advisor is offline; null when it is off.
function retriageItem(ctx, id) {
  if (!ctx.advisor) return null;
  if (ctx.SA.pendingRetriage && ctx.SA.pendingRetriage.has(id)) return { label: 'Advisor re-reading…', attrs: '', disabled: true };
  if (ctx.advisor.offline) return { label: 'Advisor offline', attrs: '', disabled: true, title: `Advisor offline — verdicts paused (${ctx.advisor.error})` };
  return { label: 'Re-run advisor', attrs: `data-action="retriage" data-id="${escapeHTML(id)}"`, title: 'Ask the local model to re-read this flag' };
}

// bodyHTML: a row's detail — the lead sentence, the parts in between, the
// actions, and the raw evidence behind a closed Details.
function bodyHTML(attrs, b) {
  return `<div class="row-body" ${attrs}>`
    + (b.lead ? `<p class="body-lead">${escapeHTML(b.lead)}</p>` : '')
    + (b.parts || '')
    + (b.actions ? `<div class="body-actions">${b.actions}</div>` : '')
    + (b.evidence ? `<details class="body-evidence"><summary>${escapeHTML(b.evidenceLabel || 'Evidence')}</summary>${b.evidence}</details>` : '')
    + '</div>';
}

function evidenceChainHTML(f) {
  const chain = buildEvidenceChain(f);
  return chain.length ? `<div class="chain">${chain.map((n, j) => `${j > 0 ? '<span class="chain-link" aria-hidden="true"></span>' : ''}`
    + `<div class="chain-node ${n.cls}"><span class="cn-icon"><svg class="icon"><use href="#${n.icon}"/></svg></span>`
    + `<span class="cn-body"><span class="cn-label">${escapeHTML(n.label)}</span><span class="cn-sub">${escapeHTML(n.sub)}</span></span></div>`).join('')}</div>` : '';
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

// ---------- detail bodies, shared by both lists ----------

// flagActionItems: an explained flag's served actions plus What to do,
// Re-run advisor and the session link; an unexplained flag gets the
// console's own Dismiss, mutes and Kill.
function flagActionItems(f, ctx) {
  const id = escapeHTML(f.id);
  const retriage = retriageItem(ctx, f.id);
  const session = f.session_id ? { label: 'View session in timeline', attrs: `data-action="filter-session" data-session="${escapeHTML(f.session_id)}"` } : null;
  if (f.explain) {
    return explainActionItems(f, [{ label: 'What to do', attrs: `data-action="open-plan" data-subject="flag:${id}"` }, retriage, session].filter(Boolean));
  }
  const agent = escapeHTML(f.agent || '');
  const rule = escapeHTML(f.rule);
  const host = flagHost(f);
  return [
    { label: 'Dismiss', attrs: `data-action="dismiss-flag" data-id="${id}"`, title: 'Mark reviewed — this flag leaves the list; the rule keeps watching', bar: true },
    retriage, session,
    f.advisor && f.advisor.assessment === 'benign' && host
      ? { label: 'Mute rule+host', attrs: `data-action="mute-flag" data-rule="${rule}" data-host="${escapeHTML(host)}" data-agent="${agent}"`, title: `Stop flagging ${f.rule} for ${host} — reversible` } : null,
    isKeychainRule(f.rule)
      ? { label: 'Dismiss this flag class', attrs: `data-action="mute-rule" data-rule="${rule}" data-agent="${agent}"`, title: `Stop flagging ${f.rule}${f.agent ? ' for ' + f.agent : ' entirely'} — reversible from the muted list below` } : null,
    { label: `Kill ${f.agent || 'agent'}`, attrs: `data-action="kill" data-pid="${Number(f.pid) || 0}"`, kind: 'danger', title: `Terminate the agent process tree (pid ${Number(f.pid) || 0})` },
  ].filter(Boolean);
}

function isKeychainRule(rule) {
  return rule === 'keychain-access' || rule === 'keychain-security-cli';
}

// flagBodyHTML: the served sentence, chips and assessment, then the evidence
// chain and facts behind Evidence. actions: false when the row carries them.
function flagBodyHTML(f, ctx, actions = true) {
  const l = explainLines(f, ctx.now);
  const bar = actions ? actionBarHTML(flagActionItems(f, ctx)) : '';
  if (!l) {
    const lines = (f.evidence || []).map(ev => `<div>${escapeHTML(typeof ev === 'string' ? ev
      : ev.text || (ev.sub ? (ev.label || '') + ' (' + ev.sub + ')' : ev.label))}</div>`).join('');
    const a = ctx.advisor && f.advisor && f.advisor.assessment;
    return bodyHTML(`data-flag-id="${escapeHTML(f.id)}"`, {
      lead: isKeychainRule(f.rule) ? 'Apps read the keychain to load their own credentials; this is usually routine.' : '',
      parts: a ? `<p class="body-note"><span class="advisor-chip adv-${escapeHTML(a)}" title="${escapeHTML(f.advisor.rationale || '')}">advisor: ${escapeHTML(a)}</span></p>` : '',
      actions: bar, evidence: evidenceChainHTML(f) + (lines ? `<div class="flag-evidence">${lines}</div>` : ''),
    });
  }
  const ex = f.explain;
  return bodyHTML(`data-flag-id="${escapeHTML(f.id)}"`, {
    lead: l.what,
    parts: factChipsHTML(f, l.who)
      + (ex.assessment ? assessmentHTML(ex.assessment) : `<p class="body-verdict">${escapeHTML(l.verdict)}</p>`)
      + labelsLineHTML(ex.labels),
    actions: bar,
    evidence: evidenceChainHTML(f) + findingFactsHTML(f) + `<div class="body-marks">${markButtonsHTML('flag:' + f.id)}</div>`,
  });
}

// Served pattern action ids the console performs.
const PATTERN_CONSOLE_ACTIONS = ['expect', 'expect-file', 'review-local', 'inspect-file', 'allow-host', 'mute-rule-host', 'mute-class', 'dismiss-all', 'kill'];

function patternActionLabel(p, a) {
  const agent = p.agent || 'agent';
  if (a.id === 'kill') return `Kill ${agent}`;
  const host = a.body && typeof a.body.host === 'string' ? a.body.host : '';
  if (a.id === 'allow-host' && host.includes(':')) return `Allow this address for ${agent}`;
  return a.label || a.id;
}

// patternActionItems: the served actions, recommended first. The click
// handler reads the request from the served pattern (key + action id +
// host). A pattern dismissed in place keeps its choices, disabled.
function patternActionItems(p) {
  const acts = assessmentActions(p.actions, p.assessment).filter(a => a && PATTERN_CONSOLE_ACTIONS.includes(a.id))
    .map(a => (p.dismissed ? { ...a, disabled: true } : a));
  const attrs = a => {
    const host = a.body && typeof a.body.host === 'string' ? a.body.host : '';
    return `data-action="explain-act" data-pattern-key="${escapeHTML(p.key)}" data-action-id="${escapeHTML(a.id)}"`
      + (host ? ` data-host="${escapeHTML(host)}"` : '');
  };
  return actionItems(acts, [], attrs, a => patternActionLabel(p, a));
}

// patternBodyHTML: the served summary, its processes, the cadence strip
// (count, window, 24 bars, the cadence phrase, open count), the assessment,
// the actions and the covered flags behind Details.
function patternBodyHTML(p, ctx, actions = true) {
  const d = assessmentDisplay(p.assessment, p.disposition);
  const count = Number(p.count) || 0;
  const open = p.dismissed ? 0 : Number(p.unacked) || 0;
  const covered = new Set(p.flag_ids || []);
  const rows = (ctx.SA.t.flags || []).filter(f => covered.has(f.id));
  const cap = cappedList(rows, 10, null, 'pattern:' + p.key, ctx.SA.expanded);
  const row = f => {
    const t = new Date(f.ts);
    const at = isNaN(t) ? String(f.ts || '') : t.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return `<li><button type="button" class="pattern-flag-link" data-action="open-flag" data-id="${escapeHTML(f.id)}" aria-label="View security flag ${escapeHTML(f.id)}">`
      + `<span>${escapeHTML(at)}</span><span>pid ${Number(f.pid) || 0}</span>`
      + `${f.session_id ? `<span>session ${escapeHTML(sessionShort(f.session_id))}</span>` : ''}<code>${escapeHTML(f.id)}</code><span aria-hidden="true">↗</span></button></li>`;
  };
  const procs = patternProcessesText(p.processes);
  const cadence = [`${count}×`, patternWindowText(p, ctx.now), p.cadence].filter(Boolean).map(escapeHTML).join(' · ');
  return bodyHTML(`data-pattern-key="${escapeHTML(p.key)}"`, {
    lead: p.summary,
    parts: (procs ? `<p class="body-note pattern-processes">${escapeHTML(procs)}</p>` : '')
      + `<div class="pattern-cadence"><span class="pattern-bars" role="img" aria-label="Flags per bucket over the window, oldest first">${patternBarsHTML(p.hourly)}</span>`
      + `<span class="pattern-cadence-text">${cadence} · <b class="pattern-open">${open} open</b></span></div>`
      + (p.assessment ? assessmentHTML(p.assessment) : `<p class="body-verdict">${escapeHTML((d.text || '') + (d.why ? ': ' + d.why : ''))}</p>`),
    actions: actions ? actionBarHTML(patternActionItems(p)) : '',
    evidenceLabel: `Individual flags (${Number(p.flags ?? count) || 0})`,
    evidence: rows.length ? `<ul class="pattern-flag-list">${cap.shown.map(row).join('')}</ul>${cap.more}`
      : '<p class="pattern-flags-note">None of them is open in the loaded window.</p>',
  });
}

const ROUTINE_CONSOLE_ACTIONS = ['expect-all', 'dismiss-all'];

// routineActionItems: Treat as routine and Dismiss all, read by the click
// handler from the served group (key + action id).
function routineActionItems(rg) {
  const acts = assessmentActions(rg.actions, rg.assessment).filter(a => a && ROUTINE_CONSOLE_ACTIONS.includes(a.id));
  const attrs = a => `data-action="routine-act" data-routine-key="${escapeHTML(rg.key)}" data-action-id="${escapeHTML(a.id)}"`;
  return actionItems(acts, [], attrs, a => a.label || a.id);
}

// routineBodyHTML: the reader, the file area, the agents and the busiest
// destinations as chips, the assessment and the actions.
function routineBodyHTML(rg, actions = true) {
  const dests = rg.destinations || [];
  const more = (Number(rg.destination_count) || 0) - dests.length;
  const chips = [
    rg.reader ? `<span class="fact"><svg class="icon"><use href="#i-terminal"/></svg>${escapeHTML(rg.reader)}</span>` : '',
    `<span class="fact fact-file"><svg class="icon"><use href="#i-doc"/></svg>${escapeHTML(rg.area)}${rg.files > 1 ? ` · ${Number(rg.files)} files` : ''}</span>`,
    `<span class="fact"><svg class="icon"><use href="#i-agent"/></svg>${escapeHTML((rg.agents || []).join(', '))}</span>`,
    ...dests.map(x => `<span class="fact fact-dest" title="${escapeHTML(x.host)} · cited by ${Number(x.count)} flag${Number(x.count) === 1 ? '' : 's'}"><svg class="icon"><use href="#i-globe"/></svg>${escapeHTML(x.org || x.host)}</span>`),
    more > 0 ? `<span class="fact">+${more} more</span>` : '',
  ].filter(Boolean).join('');
  return bodyHTML(`data-routine-key="${escapeHTML(rg.key)}"`, {
    lead: rg.summary,
    parts: `<div class="facts">${chips}</div>${assessmentHTML(rg.assessment)}`,
    actions: actions ? actionBarHTML(routineActionItems(rg)) : '',
  });
}

function incidentActionItems(inc) {
  const id = escapeHTML(inc.id);
  const status = (inc.workflow || {}).status || 'open';
  return [
    { label: 'View report', attrs: `data-action="open-incident" data-id="${id}"`, bar: true },
    status === 'open' ? { label: 'Acknowledge', attrs: `data-action="incident-status" data-id="${id}" data-status="acknowledged"`, bar: true } : null,
    status !== 'resolved' ? { label: 'Report resolved', attrs: `data-action="incident-status" data-id="${id}" data-status="resolved"` } : null,
  ].filter(Boolean);
}

// incidentBodyHTML: the summary, the advisor's narrative and the reported
// resolution, the workflow actions, and the secrets to rotate as evidence.
function incidentBodyHTML(inc, ctx, actions = true) {
  const wf = inc.workflow || {};
  const rotate = (inc.rotate_list || []).map(item => `<div class="rotate-item-row"><span class="rk"><svg class="icon"><use href="#i-key"/></svg>`
    + `<strong>${escapeHTML(item.name)}</strong> (${escapeHTML(item.category)})</span></div>`).join('');
  return bodyHTML(`data-incident-id="${escapeHTML(inc.id)}"`, {
    lead: inc.summary,
    parts: (ctx.advisor && inc.advisor_narrative ? `<p class="body-note">${escapeHTML(inc.advisor_narrative)}</p>` : '')
      + (wf.resolution_note ? `<p class="body-note">Reported resolution: ${escapeHTML(wf.resolution_note)}</p>` : ''),
    actions: actions ? actionBarHTML(incidentActionItems(inc)) : '',
    evidenceLabel: 'Secrets to rotate', evidence: rotate,
  });
}

// ---------- needs you: the daemon's queue ----------

// needsItems: the queue flattened to one list, each item carrying its group;
// highest priority first, served order within a priority.
function needsItems(posture) {
  const out = [];
  for (const g of (posture && posture.groups) || []) {
    for (const it of g.items || []) out.push({ ...it, group: g });
  }
  return out.map((it, i) => [it, i]).sort((a, b) => (b[0].priority - a[0].priority) || (a[1] - b[1])).map(x => x[0]);
}

// needView: one queue item as a row — what, why, the kind word and clock,
// its choices (one or two on the row, the rest under More) and the detail
// body when the item has one.
function needView(item, ctx) {
  const g = item.group || {};
  const id = escapeHTML(item.id);
  const v = { key: `${item.kind}:${item.id}`, kind: item.kind, agent: g.agent || '', sev: 'sev-bad', word: 'critical',
    what: item.detail || item.title || '', why: '', at: '', items: [], body: null };
  switch (item.kind) {
    case 'guard': {
      const workspace = String(g.workspace || '').split('/').filter(Boolean).pop() || '';
      const a = (verdict, scope) => `data-action="guard-resolve" data-id="${id}" data-verdict="${verdict}" data-scope="${scope}"`;
      return { ...v, sev: 'sev-warn', word: 'guard',
        why: [`${v.agent || 'The agent'} is paused until you answer`, item.scopeText, workspace].filter(Boolean).join(' · '),
        items: [
          { label: 'Allow once', attrs: a('allow', 'once'), bar: true },
          { label: 'Deny', attrs: a('deny', 'once'), kind: 'danger', bar: true },
          { label: 'Allow rule', attrs: a('allow', 'always') },
          { label: 'Deny rule', attrs: a('deny', 'always') },
        ],
        body: () => `<dl class="finding-facts"><dt>Path</dt><dd>${escapeHTML(item.path || '')}</dd><dt>Rule</dt><dd>${escapeHTML(item.rule || '')}</dd>`
          + `<dt>Scope</dt><dd>${escapeHTML(item.scopeText || '')}</dd></dl>${item.advisor ? advisorAdviceHTML(item.advisor) : ''}` };
    }
    case 'resource':
      return { ...v, sev: 'sev-warn', word: 'resource',
        why: [g.label, g.rssBytes ? `${fmtRSS(g.rssBytes)} memory` : '', g.cpuPercent ? `${fmtCPU(g.cpuPercent)} CPU` : ''].filter(Boolean).join(' · '),
        items: [
          { label: 'Keep running', attrs: `data-action="resource-control" data-id="${id}" data-decision="dismiss"`, bar: true },
          { label: `Apply ${String(item.action).replaceAll('_', ' ')}`, attrs: `data-action="resource-control" data-id="${id}" data-decision="apply" data-intervention="${escapeHTML(item.action)}"`, kind: 'danger', bar: true },
        ] };
    case 'incident': {
      const inc = ctx.incidents.get(item.id);
      return { ...v, word: 'incident', why: [item.title, item.status].filter(Boolean).join(' · '), at: inc ? inc.timestamp : '',
        items: inc ? incidentActionItems(inc) : [{ label: 'View report', attrs: `data-action="open-incident" data-id="${id}"`, bar: true }] };
    }
    case 'flag': {
      const f = ctx.flags.get(item.id);
      if (!f) return { ...v, items: [{ label: 'Dismiss', attrs: `data-action="dismiss-flag" data-id="${id}"`, bar: true }] };
      const l = explainLines(f, ctx.now);
      const plan = { label: 'What to do', attrs: `data-action="open-plan" data-subject="flag:${id}"` };
      return { ...v, what: (l && l.what) || v.what, why: (l && (l.why || l.state)) || '', at: f.ts,
        items: f.explain ? leadOnly(explainActionItems(f, [retriageItem(ctx, f.id)].filter(Boolean)), plan) : flagActionItems(f, ctx),
        body: () => flagBodyHTML(f, ctx, false) };
    }
    case 'pattern': {
      const p = ctx.patterns.get(item.id);
      if (!p) return v;
      return { ...v, what: `${p.title || item.title} — ${Number(p.count) || 0}×`, why: p.summary || '', at: p.last,
        items: leadOnly(patternActionItems(p)), body: () => patternBodyHTML(p, ctx, false) };
    }
    case 'routine': {
      const rg = ctx.routine.get(item.id);
      if (!rg) return v;
      return { ...v, what: item.title || 'Recurring read', why: rg.summary || '',
        items: leadOnly(routineActionItems(rg)), body: () => routineBodyHTML(rg, false) };
    }
    default:
      return v;
  }
}

// needRowHTML: one decision — the agent, what it wants or did, why, the kind
// and clock; the row's choices; the detail body while open.
function needRowHTML(v, open, nowMs) {
  const dom = 'need-' + v.key.replace(/[^A-Za-z0-9_-]/g, '_');
  const clock = clockText(v.at, nowMs);
  const meta = `<span class="need-meta">${escapeHTML(v.word + (clock ? ' · ' + clock : ''))}`
    + `${v.body ? '<svg class="icon need-chev" aria-hidden="true"><use href="#i-arrow"/></svg>' : ''}</span>`;
  const inner = `${harnessChipHTML(v.agent)}<span class="need-what" title="${escapeHTML(v.what)}">${escapeHTML(v.what)}</span>`
    + `<span class="need-why">${escapeHTML(v.why)}</span>${meta}`;
  const head = v.body
    ? `<button type="button" class="need-head" data-action="toggle-row" data-key="need:${escapeHTML(v.key)}" aria-expanded="${open}" aria-controls="${dom}">${inner}</button>`
    : `<div class="need-head">${inner}</div>`;
  return `<li class="need ${v.sev}${open ? ' open' : ''}" data-kind="${escapeHTML(v.kind)}">${head}`
    + `<div class="need-actions">${actionBarHTML(v.items)}</div>`
    + (v.body ? `<div class="need-detail" id="${dom}"${open ? '' : ' hidden'}>${open ? v.body() : ''}</div>` : '')
    + '</li>';
}

function renderAttention() {
  const SA = window.SA;
  const panel = document.getElementById('attention-center');
  const list = document.getElementById('attention-list');
  const badge = document.getElementById('badge-attention-count');
  if (!list) return;
  renderCoverage();
  // The daemon serves the queue on /posture; needs_you counts its items, the
  // same set the menubar shows.
  const count = attentionCount(SA.t.posture);
  if (badge) badge.textContent = count;
  SA.setTabBadge('home', count);
  if (panel) panel.hidden = count === 0;
  const ctx = homeContext(SA);
  const views = needsItems(SA.t.posture).map(it => needView(it, ctx));
  patchList(list, views, { key: v => v.key, html: v => needRowHTML(v, SA.expanded.has('need:' + v.key), ctx.now) });
}

// ---------- findings history ----------

function flagRow(f, ctx) {
  const ex = f.explain || {};
  const legacy = ex.disposition || (f.severity >= 3 ? { state: 'critical', text: 'Act now' } : { state: 'warning', text: 'Needs a look' });
  const l = explainLines(f, ctx.now);
  return { kind: 'flag', key: f.id, at: f.ts, agent: f.agent, title: f.title || ruleTitle(f.rule),
    sub: (ex.subject || {}).display || (l && l.what) || '', count: 1, hourly: null,
    risk: riskOf(ex.assessment, legacy, f.severity),
    reviewed: !!f.acknowledged || (ex.disposition || {}).state === 'acknowledged',
    flagIds: [f.id], body: () => flagBodyHTML(f, ctx) };
}

function patternRow(p, ctx) {
  return { kind: 'pattern', key: p.key, at: p.last, agent: p.agent, title: p.title || ruleTitle(p.rule),
    sub: (p.subject || {}).label || '', count: Number(p.count) || 0, hourly: p.hourly,
    risk: riskOf(p.assessment, p.disposition, 0), reviewed: !!p.dismissed || !(Number(p.unacked) > 0),
    flagIds: p.flag_ids || [], body: () => patternBodyHTML(p, ctx) };
}

function routineRow(rg) {
  return { kind: 'routine', key: rg.key, at: '', agent: (rg.agents || [])[0] || '', title: rg.summary || 'Recurring read',
    sub: '', count: Number(rg.count) || 0, hourly: null, risk: riskOf(rg.assessment, rg.disposition, 0),
    reviewed: (rg.disposition || {}).state === 'acknowledged' || (rg.assessment || {}).review_state === 'reviewed',
    flagIds: rg.flag_ids || [], body: () => routineBodyHTML(rg) };
}

function incidentRow(inc, ctx) {
  const risk = String(inc.risk || '').toUpperCase();
  const status = (inc.workflow || {}).status || 'open';
  return { kind: 'incident', key: inc.id, at: inc.timestamp, agent: inc.agent || '',
    title: [inc.rule, inc.subject].filter(Boolean).join(' — '), sub: '', count: Number(inc.aggregate_count) || 1, hourly: null,
    risk: { cls: risk === 'CRITICAL' ? 'disp-critical' : risk === 'HIGH' ? 'disp-warning' : 'disp-acknowledged',
      text: [inc.risk, status === 'resolved' ? 'closure reported' : status].filter(Boolean).join(' · '), critical: risk === 'CRITICAL' },
    reviewed: true, flagIds: [], body: () => incidentBodyHTML(inc, ctx) };
}

// byUrgency: critical first, then the newest.
function byUrgency(a, b) {
  return (Number(b.risk.critical) - Number(a.risk.critical)) || (Date.parse(b.at) || 0) - (Date.parse(a.at) || 0);
}

function logKey(row) { return row.kind + ':' + row.key; }

// logRowHTML: one history row — a select box and a head over the columns
// (when, agent, finding, count, 24 h bars, risk); the body while open. The
// checkbox state is painted after patching, so ticking never rebuilds a row.
function logRowHTML(row, open, nowMs) {
  const rk = logKey(row);
  const dom = 'log-' + rk.replace(/[^A-Za-z0-9_-]/g, '_');
  const when = clockText(row.at, nowMs);
  const count = row.count > 1 ? row.count + '×' : '1';
  const finding = escapeHTML(row.title) + (row.sub ? ` <span class="c-sub-text">· ${escapeHTML(row.sub)}</span>` : '');
  const bars = row.hourly ? `<span class="pattern-bars log-bars${row.risk.critical ? ' crit' : ''}" aria-hidden="true">${patternBarsHTML(row.hourly)}</span>` : '';
  return `<li class="log-row${row.risk.critical ? ' crit' : ''}${open ? ' open' : ''}" data-row-key="${escapeHTML(rk)}">`
    + `<div class="log-line"><input type="checkbox" class="log-check" data-action="history-select" data-row-key="${escapeHTML(rk)}" aria-label="Select: ${escapeHTML(row.title)}"${row.reviewed ? ' disabled' : ''}>`
    + `<button type="button" class="log-head" data-action="toggle-row" data-key="log:${escapeHTML(rk)}" aria-expanded="${open}" aria-controls="${dom}">`
    + `<span class="c-when">${escapeHTML(when)}</span>`
    + `<span class="c-agent">${harnessChipHTML(row.agent)}<span>${escapeHTML(row.agent || '')}</span></span>`
    + `<span class="c-finding"><span class="c-title" title="${escapeHTML(row.title + (row.sub ? ' · ' + row.sub : ''))}">${finding}</span>`
    + `<span class="c-sub">${escapeHTML([row.agent, row.count > 1 ? count : '', when, row.risk.text].filter(Boolean).join(' · '))}</span></span>`
    + `<span class="c-count">${count}</span><span class="c-bars">${bars}</span>`
    + `<span class="c-verdict"><i class="vdot ${row.risk.cls}" aria-hidden="true"></i><span class="c-verdict-text">${escapeHTML(row.risk.text)}</span></span>`
    + '<svg class="icon log-chev" aria-hidden="true"><use href="#i-arrow"/></svg></button></div>'
    + `<div class="log-detail" id="${dom}"${open ? '' : ' hidden'}>${open ? row.body() : ''}</div></li>`;
}

// patchLog: a capped history list patched row by row; extra parts follow.
function patchLog(container, rows, capKey, SA, nowMs, extra) {
  const cap = cappedList(rows, 50, null, capKey, SA.expanded);
  const parts = cap.shown.map(r => ({ key: logKey(r), html: logRowHTML(r, SA.expanded.has('log:' + logKey(r)), nowMs) }));
  if (cap.more) parts.push({ key: 'more', html: `<li class="log-more">${cap.more}</li>` });
  patchList(container, parts.concat(extra || []), { key: p => p.key, html: p => p.html });
  return cap.shown;
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
  const ctx = homeContext(SA);
  patchLog(container, incidents.map(inc => incidentRow(inc, ctx)).sort(byUrgency), 'history-incidents', SA, ctx.now);
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

  // A covered flag appears only in its pattern's row.
  const selected = id => {
    const v = (document.getElementById(id) || {}).value || 'all';
    return v === 'all' ? '' : v;
  };
  const term = SA.globalSearchTerm();
  const scopedFlags = scopedBySession(SA.t.flagsView || [], SA.timelineSession, SA.timelinePids);
  const patterns = patternsInView(allPatterns, {
    term, agent: selected('flags-agent'), rule: selected('flags-rule'),
    session: SA.timelineSession, pids: SA.timelinePids, flags: scopedFlags, filtered: SA.isFlagsFiltered(),
  });
  const flags = uncoveredFlags(scopedFlags.filter(f => matchesSearch(term, f.agent, f.rule, f.evidence, f.sessionId, f.workspace)), patterns);
  const agentSel = selected('flags-agent');
  const routines = (SA.sessionScopeOn() || SA.isFlagsFiltered() || selected('flags-rule')) ? [] : (SA.t.routine || []).filter(rg =>
    (!agentSel || (rg.agents || []).includes(agentSel)) && matchesSearch(term, rg.reader, rg.area, rg.summary, (rg.agents || []).join(' ')));
  const total = patterns.length + flags.length + routines.length;
  SA.paintSessionChip('flags-session-filter', 'flags-session-filter-id', total);
  badge.textContent = total;

  if (total === 0) {
    SA.historyRows = new Map();
    paintHistoryBulk(SA);
    const msg = SA.sessionScopeOn()
      ? `No flags for ${SA.sessionScopeTag()} in the loaded window`
      : SA.isFlagsFiltered() ? 'No flags match the current filter' : 'No findings in the loaded window';
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-alert"/></svg><span>${msg}</span></div>`;
    return;
  }

  const ctx = homeContext(SA);
  const rows = patterns.map(p => patternRow(p, ctx)).concat(flags.map(f => flagRow(f, ctx)), routines.map(routineRow)).sort(byUrgency);
  // Muted (rule, host, agent) pairs follow the rows, so the quiet is
  // deliberate and reversible.
  const mutes = SA.t.mutes || [];
  const shown = patchLog(container, rows, 'history', SA, ctx.now, mutes.length ? [{ key: 'mutes', html: '<li class="mute-list"></li>' }] : []);
  const muteList = Array.from(container.children).find(el => el._saKey === 'mutes');
  if (muteList) {
    patchList(muteList, [{ key: 'head', html: '<div class="mute-head">Muted</div>' }]
      .concat(mutes.map(m => ({ key: `${m.rule}|${m.host}|${m.agent || ''}`, html: muteRowHTML(m) }))),
    { key: p => p.key, html: p => p.html });
  }

  // Selection lives on the visible open rows only.
  SA.historyRows = new Map(shown.filter(r => !r.reviewed).map(r => [logKey(r), r]));
  for (const k of Array.from(SA.historySelected)) if (!SA.historyRows.has(k)) SA.historySelected.delete(k);
  for (const c of container.querySelectorAll('.log-check')) c.checked = SA.historySelected.has(c.dataset.rowKey);
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

// ---------- optimistic review ----------

// reviewedAfterOptimistic: the state once these flag ids were reviewed — the
// flags leave the live list and read reviewed in history, the patterns they
// sat in drop their open counts, routine groups they fully cover leave, and
// so do their queue items, until the next snapshot reconciles.
function reviewedAfterOptimistic(t, ids) {
  const done = new Set(ids || []);
  const covered = list => (list || []).length > 0 && list.every(id => done.has(id));
  return {
    routine: (t.routine || []).filter(r => !covered(r.flag_ids)),
    patterns: (t.patterns || []).map(p => {
      const n = (p.flag_ids || []).filter(id => done.has(id)).length;
      return n ? patternAfterDismiss(p, n) : p;
    }),
    flags: (t.flags || []).filter(f => !done.has(f.id)),
    flagsView: t.flagsView === null ? null : (t.flagsView || []).map(f => done.has(f.id) ? reviewedFlag(f) : f),
    posture: mapPostureAttention(t.posture, it => ((it.kind === 'flag' && done.has(it.id))
      || (it.kind === 'routine' && covered(((t.routine || []).find(r => r.key === it.id) || {}).flag_ids))) ? null : it),
  };
}

// routineAfterOptimistic: reviewedAfterOptimistic for a routine group's
// served ids, with the group and its queue item gone even when the ids were
// capped.
function routineAfterOptimistic(t, key, ids) {
  const next = reviewedAfterOptimistic(t, ids);
  return { ...next, routine: next.routine.filter(r => r.key !== key),
    posture: mapPostureAttention(next.posture, it => (it.kind === 'routine' && it.id === key ? null : it)) };
}

// ---------- patterns: a repeating finding as one row ----------

// uncoveredFlags: the flags no pattern covers (flag_ids). Handed the
// patterns in view, so a flag is hidden only behind a row that shows.
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
// the open count drops by n and the pattern reads dismissed only at 0; the
// next /snapshot reconciles.
function patternAfterDismiss(p, n) {
  const unacked = Math.max(0, (Number(p.unacked) || 0) - (Number(n) || 0));
  if (unacked > 0) return { ...p, unacked };
  return { ...p, unacked: 0, dismissed: true, ...(p.assessment ? { assessment: { ...p.assessment, review_state: 'reviewed' } } : {}), disposition: { state: 'acknowledged', text: 'Reviewed', why: p.title || '' } };
}

// The attention queue and finding rows are different snapshots. A local
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
