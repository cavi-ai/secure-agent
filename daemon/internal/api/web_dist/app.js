document.addEventListener('DOMContentLoaded', () => {
  // Console auth: the menubar opens /dashboard/?ct=<console-token>. The token
  // gates the telemetry endpoints on this listener (the proxy token agents
  // carry is a different credential and is NOT accepted here). Lift it into
  // memory and strip it from the address bar so it doesn't linger in history.
  const consoleToken = new URLSearchParams(location.search).get('ct') || '';
  if (consoleToken && window.history.replaceState) {
    history.replaceState(null, '', location.pathname);
  }
  const authHeaders = consoleToken ? { 'X-SecureAgent-Console-Token': consoleToken } : {};
  const apiFetch = (path, opts = {}) => fetch(path, { ...opts, headers: { ...authHeaders, ...(opts.headers || {}) } });

  const btnRefresh = document.getElementById('btn-refresh');
  const reportModal = document.getElementById('report-modal');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const btnCopyReport = document.getElementById('btn-copy-report');

  let currentRawMarkdown = '';

  btnRefresh.addEventListener('click', () => {
    fetchTelemetry();
    showToast('Refreshing telemetry data...', 'info');
  });

  const btnAddSource = document.getElementById('btn-add-source');
  const sourceInput = document.getElementById('source-input');
  if (btnAddSource) btnAddSource.addEventListener('click', () => window.addSource());
  if (sourceInput) sourceInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') window.addSource(); });

  if (btnCloseModal && reportModal) {
    btnCloseModal.addEventListener('click', () => {
      reportModal.close();
    });
  }

  if (btnCopyReport) {
    btnCopyReport.addEventListener('click', async () => {
      if (!currentRawMarkdown) return;
      try {
        await navigator.clipboard.writeText(currentRawMarkdown);
        showToast('Incident report copied to clipboard!', 'success');
      } catch (err) {
        showToast('Failed to copy report: ' + err, 'danger');
      }
    });
  }

  let telemetryData = {
    status: null,
    flags: [],       // unfiltered — feeds KPIs
    flagsView: [],   // filtered — feeds the flags panel
    incidents: [],
    events: [],       // unfiltered — feeds KPIs
    eventsView: [],   // filtered — feeds the event timeline
    fleet: [],
    audit: [],
    sources: [],
    connected: true
  };

  // Server-side history filters. Change handlers mutate this and call
  // fetchTelemetry(), so the poll loop keeps honoring the active filter.
  const filters = {
    events: { kind: 'all', since: 'all' },
    flags: { agent: 'all', rule: 'all', minsev: 'all', since: 'all' }
  };
  const seenAgents = new Set();
  const seenRules = new Set();

  // ---------- liveness state ----------
  // Reduced-motion users get instant updates with no tweening or flashes.
  const reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Sparkline: 60 one-second buckets of event counts. Bumped by SSE pushes;
  // in polling-fallback mode, fetchTelemetry backfills buckets from the
  // timestamps of events it hasn't counted yet.
  const SPARK_BUCKETS = 60;
  const sparkBuckets = new Array(SPARK_BUCKETS).fill(0);
  let sparkLastTick = Math.floor(Date.now() / 1000);
  const countedEventKeys = new Set();

  function sparkAdvance() {
    const nowSec = Math.floor(Date.now() / 1000);
    const steps = nowSec - sparkLastTick;
    if (steps <= 0) return;
    advanceBuckets(sparkBuckets, steps); // lib.js
    sparkLastTick = nowSec;
  }

  function sparkBump(n, tsMs) {
    sparkAdvance();
    sparkBuckets[bucketIndexFor(Date.now(), tsMs, SPARK_BUCKETS)] += (n || 1); // lib.js
    drawSpark();
  }

  function drawSpark() {
    const line = document.getElementById('spark-line');
    const rate = document.getElementById('spark-rate');
    if (!line) return;
    line.setAttribute('points', sparkPoints(sparkBuckets, 120, 26, 24, 2)); // lib.js
    if (rate) rate.textContent = `${sparkBuckets[SPARK_BUCKETS - 1]}/s`;
  }

  setInterval(() => { sparkAdvance(); drawSpark(); }, 1000);

  // Count events the poll path surfaced that SSE didn't announce (fallback
  // mode), so the sparkline stays honest when push is unavailable.
  function sparkIngestEvents(events) {
    (events || []).forEach(e => {
      const k = eventKey(e);
      if (countedEventKeys.has(k)) return;
      countedEventKeys.add(k);
      sparkBump(1, Date.parse(e.ts) || 0);
    });
    // Bound the set: keys older than the spark window can never be bumped.
    if (countedEventKeys.size > 500) {
      const arr = Array.from(countedEventKeys);
      arr.slice(0, arr.length - 300).forEach(k => countedEventKeys.delete(k));
    }
  }

  // KPI tween: animate numeric transitions, flash green/rose on change.
  const kpiPrev = {};
  function setKpi(id, val) {
    const el = document.getElementById(id);
    if (!el) return;
    const prev = kpiPrev[id];
    kpiPrev[id] = val;
    if (prev === undefined || prev === val || reducedMotion) {
      el.textContent = val;
      return;
    }
    const cls = val > prev ? 'bump-up' : 'bump-down';
    el.classList.remove('bump-up', 'bump-down');
    void el.offsetWidth; // restart the animation on consecutive changes
    el.classList.add(cls);
    const start = performance.now(), dur = 400, from = prev, to = val;
    (function tick(now) {
      const p = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * eased);
      if (p < 1) requestAnimationFrame(tick);
    })(start);
  }

  // Track which timeline events the user has already seen, so only genuinely
  // new rows animate (polling re-renders must never flicker).
  let prevEventKeys = new Set();
  let firstEventRender = true;
  // Filter changes re-render with deeper-history rows that are "new" to the
  // view but not to the user — suppress the fresh animation for that render.
  let suppressFreshOnce = false;
  // Session drill-down: set from a flag card ("view session in timeline"),
  // filters the timeline client-side (lib.js filterEventsBySession).
  let timelineSession = null;

  // Firewall diff: which rules gained blocked/would-block counts since the
  // last render (i.e. a fresh interception).
  let prevFwStats = null;

  function flashFirewallPanel() {
    if (reducedMotion) return;
    const panel = document.getElementById('firewall-panel');
    if (!panel) return;
    panel.classList.remove('intercepted');
    void panel.offsetWidth;
    panel.classList.add('intercepted');
  }

  function sinceParam(v) {
    const ms = { '1h': 3600e3, '24h': 86400e3, '7d': 604800e3 }[v];
    return ms ? new Date(Date.now() - ms).toISOString() : '';
  }
  function isFlagsFiltered() {
    const f = filters.flags;
    return f.agent !== 'all' || f.rule !== 'all' || f.minsev !== 'all' || f.since !== 'all';
  }
  function isEventsFiltered() {
    const f = filters.events;
    return f.kind !== 'all' || f.since !== 'all';
  }
  function flagsQuery() {
    const f = filters.flags, p = new URLSearchParams();
    if (f.agent !== 'all') p.set('agent', f.agent);
    if (f.rule !== 'all') p.set('rule', f.rule);
    if (f.minsev !== 'all') p.set('min_severity', f.minsev);
    const since = sinceParam(f.since);
    if (since) p.set('since', since);
    p.set('limit', '200');
    return '/flags?' + p.toString();
  }
  function eventsQuery() {
    const f = filters.events, p = new URLSearchParams();
    if (f.kind !== 'all') p.set('kind', f.kind);
    const since = sinceParam(f.since);
    if (since) p.set('since', since);
    p.set('limit', '200');
    return '/events?' + p.toString();
  }

  function wireFilter(id, obj, key) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => { obj[key] = el.value; suppressFreshOnce = true; fetchTelemetry(); });
  }
  wireFilter('event-filter', filters.events, 'kind');
  wireFilter('event-window', filters.events, 'since');
  wireFilter('flags-agent', filters.flags, 'agent');
  wireFilter('flags-rule', filters.flags, 'rule');
  wireFilter('flags-severity', filters.flags, 'minsev');
  wireFilter('flags-window', filters.flags, 'since');

  async function fetchTelemetry() {
    try {
      const [statusRes, flagsRes, incidentsRes, eventsRes, fleetRes, auditRes, sourcesRes, postureRes] = await Promise.all([
        apiFetch('/status').catch(() => null),
        apiFetch('/flags?limit=20').catch(() => null),
        apiFetch('/incidents?limit=10').catch(() => null),
        apiFetch('/events?limit=50').catch(() => null),
        apiFetch('/fleet').catch(() => null),
        apiFetch('/audit?limit=50').catch(() => null),
        apiFetch('/firewall/sources').catch(() => null),
        apiFetch('/posture').catch(() => null)
      ]);

      if (statusRes && statusRes.ok) {
        telemetryData.status = await statusRes.json();
      }
      if (flagsRes && flagsRes.ok) {
        telemetryData.flags = await flagsRes.json() || [];
      }
      if (incidentsRes && incidentsRes.ok) {
        telemetryData.incidents = await incidentsRes.json() || [];
      }
      if (eventsRes && eventsRes.ok) {
        telemetryData.events = await eventsRes.json() || [];
      }
      if (fleetRes && fleetRes.ok) {
        telemetryData.fleet = await fleetRes.json() || [];
      }
      if (auditRes && auditRes.ok) {
        telemetryData.audit = await auditRes.json() || [];
      }
      if (sourcesRes && sourcesRes.ok) {
        telemetryData.sources = await sourcesRes.json() || [];
      }
      if (postureRes && postureRes.ok) {
        telemetryData.posture = await postureRes.json() || null;
      }

      // The panels show the filtered view; KPIs keep reading the unfiltered
      // lists above. When no filter is active, the view is the unfiltered list
      // (no extra request); a filter triggers one scoped fetch that can reach
      // deeper into history than the 50-row summary.
      telemetryData.flagsView = telemetryData.flags;
      telemetryData.eventsView = telemetryData.events;
      sparkIngestEvents(telemetryData.events);
      if (isFlagsFiltered()) {
        const r = await apiFetch(flagsQuery()).catch(() => null);
        if (r && r.ok) telemetryData.flagsView = await r.json() || [];
      }
      if (isEventsFiltered()) {
        const r = await apiFetch(eventsQuery()).catch(() => null);
        if (r && r.ok) telemetryData.eventsView = await r.json() || [];
      }

      telemetryData.connected = !!(statusRes && statusRes.ok);
      const banner = document.getElementById('offline-banner');
      if (banner) banner.hidden = telemetryData.connected;

      renderAll();
    } catch (err) {
      console.error('Error fetching telemetry:', err);
      telemetryData.connected = false;
      const banner = document.getElementById('offline-banner');
      if (banner) banner.hidden = false;
      renderStatus();
    }
  }

  function renderAll() {
    renderPosture();
    renderStatus();
    renderAgents();
    renderFirewall();
    renderIncidents();
    renderFleet();
    renderAudit();
    renderSources();
    renderFlags();
    renderEvents();
  }

  function renderStatus() {
    const chip = document.getElementById('system-status');
    if (!telemetryData.connected) {
      if (chip) chip.className = 'status-chip down';
      document.getElementById('status-text').textContent = 'Disconnected';
      return; // keep last-known metrics visible
    }

    const s = telemetryData.status;
    if (!s) return;

    document.getElementById('status-text').textContent = s.running ? 'Daemon Active' : 'Disconnected';
    if (chip) chip.className = 'status-chip ' + (s.running ? 'active' : 'down');
    if (s.version) document.getElementById('app-version').textContent = s.version;
    document.getElementById('uptime-val').textContent = s.uptime || '--';
    document.getElementById('proxy-status').textContent = s.proxy_enabled ? `127.0.0.1:${s.proxy_port || 8443}` : 'Disabled';

    setKpi('count-agents', s.active_agents || (s.agents ? s.agents.length : 0));
    setKpi('count-flags', telemetryData.flags.length);
    setKpi('count-incidents', telemetryData.incidents.length);

    const proxyEvents = telemetryData.events.filter(e => e.kind === 9 || (e.detail && e.detail.includes('proxy')));
    setKpi('count-proxy', proxyEvents.length);
  }

  function renderAgents() {
    const container = document.getElementById('agents-container');
    const badge = document.getElementById('badge-agents-count');
    const agents = (telemetryData.status && telemetryData.status.agents) ? telemetryData.status.agents : [];

    badge.textContent = agents.length;

    if (agents.length === 0) {
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No agents running yet — start Claude Code, Cursor, or Codex and they'll appear here</span></div>`;
      return;
    }

    container.innerHTML = agents.map(a => `
      <div class="agent-card">
        <div class="agent-info">
          <div class="agent-name">
            <svg class="icon"><use href="#i-agent"/></svg>${escapeHTML(a.name)}
            <span class="agent-pid">PID ${a.pid}</span>
          </div>
          <div class="agent-cwd">${escapeHTML(a.cwd || '—')}</div>
        </div>
        <button class="btn btn-danger" data-action="kill" data-pid="${a.pid}"><svg class="icon"><use href="#i-power"/></svg><span>Kill</span></button>
      </div>
    `).join('');
  }

  function renderFirewall() {
    const container = document.getElementById('firewall-container');
    const badge = document.getElementById('badge-firewall-mode');
    const s = telemetryData.status;
    const stats = (s && s.firewall_stats) ? s.firewall_stats : {};
    const uninspected = (s && s.uninspected_egress) ? s.uninspected_egress : 0;
    const rules = Object.keys(stats).sort();

    const anyBlock = rules.some(r => stats[r].mode === 'block');
    badge.textContent = anyBlock ? 'enforcing' : 'monitor';
    badge.className = 'badge' + (anyBlock ? ' badge-ok' : '');

    if (rules.length === 0 && uninspected === 0) {
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-shield"/></svg><span>No egress inspected yet — traffic is scanned as your agents run</span></div>`;
      prevFwStats = stats;
      return;
    }

    let html = '';
    if (uninspected > 0) {
      html += `<div class="fw-uninspected"><svg class="icon"><use href="#i-globe"/></svg><span>${uninspected} endpoint${uninspected === 1 ? '' : 's'} reached without inspection (pinned or unrouted)</span></div>`;
    }
    html += rules.map(r => {
      const st = stats[r];
      const blocking = st.mode === 'block';
      // A rule whose blocked/would-block counters grew since the last render
      // just intercepted something — flash its row once.
      const prev = prevFwStats ? prevFwStats[r] : null;
      const grew = !reducedMotion && prevFwStats !== null &&
        prev && ((st.blocked || 0) > (prev.blocked || 0) || (st.would_block || 0) > (prev.would_block || 0));
      const action = blocking
        ? `<span class="mode-chip block">blocking</span>`
        : `<button class="btn btn-primary btn-sm" data-action="promote" data-rule="${escapeHTML(r)}"><svg class="icon"><use href="#i-arrow"/></svg><span>Promote to block</span></button>`;
      return `
        <div class="fw-rule${grew ? ' fw-flash' : ''}">
          <div class="fw-rule-main">
            <span class="fw-rule-id">${escapeHTML(r)}</span>
            <div class="fw-metrics">
              <span class="fw-metric"><b>${st.would_block || 0}</b> would-block</span>
              <span class="fw-metric"><b>${st.blocked || 0}</b> blocked</span>
              <span class="fw-metric dim"><b>${st.legit || 0}</b> legit</span>
            </div>
          </div>
          ${action}
        </div>`;
    }).join('');
    container.innerHTML = html;
    prevFwStats = stats;
  }

  // Posture headline: the one-glance answer, plus clickable jump-off points
  // into the panels below (drill-down without leaving the page).
  function renderPosture() {
    const banner = document.getElementById('posture-banner');
    const stateEl = document.getElementById('posture-state');
    const summaryEl = document.getElementById('posture-summary');
    const itemsEl = document.getElementById('posture-items');
    const p = telemetryData.posture;
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
      if (it.kind === 'flag') link = `<a href="#flags-list">view evidence</a>`;
      if (it.kind === 'incident') link = `<a href="#" data-action="open-incident" data-id="${escapeHTML(it.id)}">view report</a>`;
      if (it.kind === 'guard_pending') link = `<span>resolve it in the menu bar app</span>`;
      if (it.kind === 'collector_down') link = `<span>— ${escapeHTML(it.detail || 'collector stopped')}</span>`;
      if (it.kind === 'uninspected_egress') link = `<a href="#firewall-container">see firewall</a>`;
      return `<li><span class="sev ${sev}">●</span><span>${escapeHTML(it.title)} ${link}</span></li>`;
    });
    // The fatigue reducer: when the local advisor has triaged the critical
    // flags and some read benign, say so at the one-glance level.
    const criticals = (telemetryData.flags || []).filter(f => f.severity >= 3 && f.advisor && f.advisor.assessment);
    const benignCount = criticals.filter(f => f.advisor.assessment === 'benign').length;
    if (criticals.length > 0) {
      items.push(`<li><span class="sev s1">●</span><span>advisor: ${benignCount} of ${criticals.length} triaged critical flags look benign</span></li>`);
    }
    itemsEl.innerHTML = items.join('');
  }

  // Incident workflow: acknowledge keeps it visible but marked seen; resolve
  // closes it with a note. Both hit /incidents/status and refresh.
  window.setIncidentStatus = async function(id, status) {
    const body = { id, status };
    if (status === 'resolved') {
      const note = prompt('Resolution note (what did you do?):', '');
      if (note === null) return; // cancelled
      body.note = note;
    }
    try {
      const r = await apiFetch('/incidents/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (!r.ok) throw new Error(await r.text());
      showToast(status === 'resolved' ? 'Incident resolved' : 'Incident acknowledged', 'success');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to update incident: ' + err.message, 'danger');
    }
  };

  function renderIncidents() {
    const container = document.getElementById('incidents-container');
    const badge = document.getElementById('badge-incidents-count');
    const incidents = telemetryData.incidents;

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
      return `
      <div class="incident-card ${status === 'resolved' ? 'is-resolved' : ''}">
        <div class="incident-header">
          <span class="risk-tag ${riskClass}"><svg class="icon"><use href="#i-alert"/></svg>${escapeHTML(inc.risk)}</span>
          <span class="kpi-hint">${escapeHTML(inc.rule)} — PID ${inc.pid}</span>
          ${statusChip}
        </div>
        <div class="incident-summary">${escapeHTML(inc.summary)}</div>
        ${inc.advisor_narrative ? `<div class="advisor-narrative"><svg class="icon"><use href="#i-agent"/></svg><span>${escapeHTML(inc.advisor_narrative)}</span></div>` : ''}
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

  function renderFleet() {
    const container = document.getElementById('fleet-container');
    const badge = document.getElementById('badge-fleet-count');
    const fleet = telemetryData.fleet || [];

    badge.textContent = fleet.length;

    if (fleet.length === 0) {
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-server"/></svg><span>No remote fleet nodes registered</span></div>`;
      return;
    }

    container.innerHTML = fleet.map(node => `
      <div class="fleet-node-card">
        <div class="fleet-node-header">
          <span class="fleet-node-name"><svg class="icon"><use href="#i-server"/></svg>${escapeHTML(node.hostname || node.id || 'Fleet node')}</span>
          <span class="status-badge ${node.online ? 'online' : 'offline'}">${node.online ? 'ONLINE' : 'OFFLINE'}</span>
        </div>
        <div class="fleet-node-meta">
          <span>IP ${escapeHTML(node.ip || '—')}</span>
          <span>${escapeHTML(node.version || 'v1.0')}</span>
        </div>
      </div>
    `).join('');
  }

  function renderAudit() {
    const container = document.getElementById('audit-container');
    const badge = document.getElementById('badge-audit-count');
    const audit = telemetryData.audit || [];

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

  function renderSources() {
    const list = document.getElementById('sources-list');
    const badge = document.getElementById('badge-sources-count');
    const sources = telemetryData.sources || [];

    badge.textContent = sources.length;

    if (sources.length === 0) {
      list.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-key"/></svg><span>No secret files watched yet — add the credential files whose keys must never leave</span></div>`;
      return;
    }

    list.innerHTML = sources.map(s => {
      const isUser = s.origin === 'user';
      const remove = isUser
        ? `<button class="source-remove" title="Stop watching" data-action="remove-source" data-source="${escapeHTML(s.source)}"><svg class="icon"><use href="#i-close"/></svg></button>`
        : `<span class="origin-chip config">CONFIG</span>`;
      return `
        <div class="source-item">
          <svg class="icon source-ico"><use href="#i-key"/></svg>
          <span class="source-path">${escapeHTML(s.source)}</span>
          ${isUser ? `<span class="origin-chip user">USER</span>` : ''}
          ${remove}
        </div>
      `;
    }).join('');
  }

  window.addSource = async function() {
    const input = document.getElementById('source-input');
    const value = (input.value || '').trim();
    if (!value) return;
    try {
      const res = await apiFetch('/firewall/sources', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: value, op: 'add' })
      });
      if (!res.ok) { showToast('Failed to add source: ' + (await res.text()), 'danger'); return; }
      const data = await res.json();
      input.value = '';
      showToast(`Watching ${value} — ${data.registered} secret(s) registered`, 'success');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to add source: ' + err, 'danger');
    }
  };

  window.removeSource = async function(source) {
    try {
      const res = await apiFetch('/firewall/sources', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, op: 'remove' })
      });
      if (!res.ok) { showToast('Failed to remove source: ' + (await res.text()), 'danger'); return; }
      showToast(`Stopped watching ${source}`, 'info');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to remove source: ' + err, 'danger');
    }
  };

  function syncSelect(id, values) {
    const el = document.getElementById(id);
    if (!el) return;
    const have = new Set(Array.from(el.options).map(o => o.value));
    Array.from(values).sort().forEach(v => {
      if (!have.has(v)) {
        const opt = document.createElement('option');
        opt.value = v;
        opt.textContent = v;
        el.appendChild(opt);
      }
    });
  }

  function renderFlags() {
    const container = document.getElementById('flags-list');
    const badge = document.getElementById('badge-flags-count');

    // Seed the filter dropdowns from the unfiltered flags so options don't
    // vanish once a filter narrows the view.
    (telemetryData.flags || []).forEach(f => {
      if (f.agent) seenAgents.add(f.agent);
      if (f.rule) seenRules.add(f.rule);
    });
    syncSelect('flags-agent', seenAgents);
    syncSelect('flags-rule', seenRules);

    const flags = telemetryData.flagsView || [];
    badge.textContent = flags.length;

    if (flags.length === 0) {
      const msg = isFlagsFiltered() ? 'No flags match the current filter' : 'No security flags — agent egress looks clean';
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-alert"/></svg><span>${msg}</span></div>`;
      return;
    }

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
      return `
      <div class="flag-card ${f.severity >= 3 ? 'sev3' : ''}${i === 0 ? ' expanded' : ''}">
        <button class="flag-head" data-action="toggle-flag" aria-expanded="${i === 0}">
          <svg class="icon flag-ico"><use href="#i-alert"/></svg>
          <span class="flag-rule-text">${escapeHTML(f.rule)} — ${escapeHTML(f.agent)} (PID ${f.pid})</span>
          ${f.advisor && f.advisor.assessment ? `<span class="advisor-chip adv-${escapeHTML(f.advisor.assessment)}" title="${escapeHTML(f.advisor.rationale)}">advisor: ${escapeHTML(f.advisor.assessment)}</span>` : ''}
          ${f.session_id ? `<span class="flag-session">session ${escapeHTML(sessionShort(f.session_id))}</span>` : ''}
          <svg class="icon flag-chev"><use href="#i-arrow"/></svg>
        </button>
        <div class="flag-detail"><div class="flag-detail-inner">
          ${chainHTML}
          ${f.session_id ? `<div class="flag-actions-row">
            <button class="btn btn-ghost btn-sm" data-action="filter-session" data-session="${escapeHTML(f.session_id)}"><svg class="icon"><use href="#i-activity"/></svg><span>View session in timeline</span></button>
          </div>` : ''}
          <div class="flag-evidence">
            ${(f.evidence || []).map(ev => `<div>${escapeHTML(ev)}</div>`).join('')}
          </div>
        </div></div>
      </div>`;
    }).join('');
  }

  function renderEvents() {
    const container = document.getElementById('events-container');
    const allEvents = telemetryData.eventsView || [];
    const events = filterEventsBySession(allEvents, timelineSession); // lib.js

    // Session filter chip in the panel head mirrors the current drill-down.
    const chip = document.getElementById('session-filter');
    if (chip) {
      chip.hidden = !timelineSession;
      if (timelineSession) {
        document.getElementById('session-filter-id').textContent = `${sessionShort(timelineSession)} · ${events.length}`;
      }
    }

    if (events.length === 0) {
      const msg = timelineSession
        ? `No events for session ${sessionShort(timelineSession)} in the loaded window`
        : isEventsFiltered() ? 'No events match the current filter' : 'No system events logged';
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>${msg}</span></div>`;
      prevEventKeys = new Set();
      firstEventRender = false;
      suppressFreshOnce = false;
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

      // Animate only events that weren't in the previous render — the whole
      // list re-renders on every poll, and rows the user already saw must
      // not flicker. The initial page load never animates.
      let freshCls = '';
      if (!reducedMotion && !firstEventRender && !suppressFreshOnce && !prevEventKeys.has(eventKey(e))) {
        freshCls = e.kind === 9 ? ' fresh-sev' : ' fresh';
      }

      return `
        <div class="timeline-item${freshCls}">
          <span class="t">${timeStr}</span>
          <span class="event-kind ${kindClass}">${kindLabel}</span>
          <span class="pid">PID ${e.pid}</span>
          <span class="dtl">${escapeHTML(detailStr)}</span>
        </div>
      `;
    }).join('');

    prevEventKeys = new Set(events.map(eventKey));
    firstEventRender = false;
    suppressFreshOnce = false;
  }

  window.openIncidentReport = async function(incidentId) {
    if (!reportModal) return;
    const bodyEl = document.getElementById('modal-report-body');
    const titleEl = document.getElementById('modal-title');
    titleEl.innerHTML = `<svg class="icon"><use href="#i-doc"/></svg>Incident report — ${escapeHTML(incidentId)}`;
    bodyEl.innerHTML = `<div class="loading-spinner">Fetching incident report…</div>`;
    reportModal.showModal();

    try {
      const res = await apiFetch(`/incidents?id=${encodeURIComponent(incidentId)}&format=markdown`);
      if (res.ok) {
        const text = await res.text();
        currentRawMarkdown = text;
        bodyEl.innerHTML = parseMarkdownToHTML(text);
      } else {
        bodyEl.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Failed to load the incident report.</span></div>`;
      }
    } catch (err) {
      bodyEl.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Error: ${escapeHTML(err.message)}</span></div>`;
    }
  };

  window.killProcess = async function(pid) {
    if (!confirm(`Are you sure you want to SIGKILL PID ${pid}?`)) return;
    try {
      const res = await apiFetch('/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      if (res.ok) {
        showToast(`Process PID ${pid} terminated.`, 'success');
        fetchTelemetry();
      } else {
        showToast(`Failed to kill PID ${pid}.`, 'danger');
      }
    } catch (err) {
      showToast(`Error killing PID ${pid}: ${err}`, 'danger');
    }
  };

  window.promoteRule = async function(rule) {
    try {
      const res = await apiFetch('/firewall/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, mode: 'block' })
      });
      if (res.ok) {
        showToast(`Rule “${rule}” promoted to block.`, 'success');
        fetchTelemetry();
      } else {
        showToast(`Failed to promote “${rule}”.`, 'danger');
      }
    } catch (err) {
      showToast(`Error promoting “${rule}”: ${err}`, 'danger');
    }
  };

  // Session drill-down: jump from a flag to just its harness session's events.
  window.filterTimelineToSession = function(sid) {
    timelineSession = sid;
    suppressFreshOnce = true;
    renderEvents();
    const el = document.getElementById('events-container');
    if (el && el.scrollIntoView) {
      el.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'nearest' });
    }
  };

  window.clearTimelineSession = function() {
    timelineSession = null;
    suppressFreshOnce = true;
    renderEvents();
  };

  const btnSessionClear = document.getElementById('session-clear');
  if (btnSessionClear) btnSessionClear.addEventListener('click', () => window.clearTimelineSession());

  // Event delegation: every actionable element carries data-action + data-*
  // attributes and is dispatched here. Values pass through the HTML attribute
  // context ONLY (escapeHTML suffices) — no JS-string context exists at all,
  // which removes the inline-handler injection class structurally rather than
  // by escaping discipline.
  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const d = el.dataset;
    switch (d.action) {
      case 'kill':
        window.killProcess(Number(d.pid));
        break;
      case 'promote':
        window.promoteRule(d.rule);
        break;
      case 'open-incident':
        e.preventDefault();
        window.openIncidentReport(d.id);
        break;
      case 'incident-status':
        window.setIncidentStatus(d.id, d.status);
        break;
      case 'remove-source':
        window.removeSource(d.source);
        break;
      case 'filter-session':
        window.filterTimelineToSession(d.session);
        break;
      case 'toggle-flag': {
        const card = el.parentElement;
        card.classList.toggle('expanded');
        el.setAttribute('aria-expanded', card.classList.contains('expanded'));
        break;
      }
    }
  });

  function showToast(msg, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 4000);
  }

  // Live updates: SSE push when the endpoint is available, with a 2s poll as
  // the fallback (older daemon, or a stream that keeps failing). The stream
  // carries the guard lifecycle (guard-prompt/guard-resolved), so pending
  // prompts surface immediately instead of up to 2s late. A slow 30s refresh
  // always runs for status/uptime, which change without any bus event.
  fetchTelemetry();
  setInterval(fetchTelemetry, 30000);

  let pollTimer = null;
  const startPolling = () => { if (!pollTimer) pollTimer = setInterval(fetchTelemetry, 2000); };
  const stopPolling = () => { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } };

  if (window.EventSource) {
    const streamURL = '/events/stream' + (consoleToken ? '?ct=' + encodeURIComponent(consoleToken) : '');
    let esFailures = 0;
    let refreshPending = false;
    const scheduleRefresh = () => {
      if (refreshPending) return;
      refreshPending = true;
      setTimeout(() => { refreshPending = false; fetchTelemetry(); }, 400);
    };
    const es = new EventSource(streamURL);
    es.onopen = () => { esFailures = 0; stopPolling(); };
    ['file-open', 'file-write', 'file-delete', 'exec', 'tcc-modify', 'conn-open', 'conn-close',
     'transcript-hit', 'plugin-action', 'proxy-hit', 'guard-prompt', 'guard-resolved']
      .forEach(kind => es.addEventListener(kind, (msg) => {
        // Push path: count the event immediately so the sparkline reflects
        // bursts between fetches. Record its key so sparkIngestEvents won't
        // double-count it when the 400ms-later fetch lands.
        let tsMs = 0;
        try {
          const e = JSON.parse(msg.data);
          countedEventKeys.add(eventKey(e));
          tsMs = Date.parse(e.ts) || 0;
        } catch { /* frame without a parseable body still counts */ }
        sparkBump(1, tsMs);
        if (kind === 'proxy-hit') flashFirewallPanel();
        scheduleRefresh();
      }));
    es.onerror = () => {
      // EventSource auto-reconnects while CONNECTING; only fall back to
      // polling when the stream is hard-closed or keeps failing.
      esFailures++;
      if (es.readyState === EventSource.CLOSED || esFailures > 5) startPolling();
    };
  } else {
    startPolling();
  }
});
