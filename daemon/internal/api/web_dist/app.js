document.addEventListener('DOMContentLoaded', () => {
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
    if (el) el.addEventListener('change', () => { obj[key] = el.value; fetchTelemetry(); });
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
        fetch('/status').catch(() => null),
        fetch('/flags?limit=20').catch(() => null),
        fetch('/incidents?limit=10').catch(() => null),
        fetch('/events?limit=50').catch(() => null),
        fetch('/fleet').catch(() => null),
        fetch('/audit?limit=50').catch(() => null),
        fetch('/firewall/sources').catch(() => null),
        fetch('/posture').catch(() => null)
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
      if (isFlagsFiltered()) {
        const r = await fetch(flagsQuery()).catch(() => null);
        if (r && r.ok) telemetryData.flagsView = await r.json() || [];
      }
      if (isEventsFiltered()) {
        const r = await fetch(eventsQuery()).catch(() => null);
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
    document.getElementById('uptime-val').textContent = s.uptime || '--';
    document.getElementById('proxy-status').textContent = s.proxy_enabled ? `127.0.0.1:${s.proxy_port || 8443}` : 'Disabled';

    document.getElementById('count-agents').textContent = s.active_agents || (s.agents ? s.agents.length : 0);
    document.getElementById('count-flags').textContent = telemetryData.flags.length;
    document.getElementById('count-incidents').textContent = telemetryData.incidents.length;

    const proxyEvents = telemetryData.events.filter(e => e.kind === 9 || (e.detail && e.detail.includes('proxy')));
    document.getElementById('count-proxy').textContent = proxyEvents.length;
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
        <button class="btn btn-danger" onclick="killProcess(${a.pid})"><svg class="icon"><use href="#i-power"/></svg><span>Kill</span></button>
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
      return;
    }

    let html = '';
    if (uninspected > 0) {
      html += `<div class="fw-uninspected"><svg class="icon"><use href="#i-globe"/></svg><span>${uninspected} endpoint${uninspected === 1 ? '' : 's'} reached without inspection (pinned or unrouted)</span></div>`;
    }
    html += rules.map(r => {
      const st = stats[r];
      const blocking = st.mode === 'block';
      const action = blocking
        ? `<span class="mode-chip block">blocking</span>`
        : `<button class="btn btn-primary btn-sm" onclick="promoteRule('${escapeHTML(r)}')"><svg class="icon"><use href="#i-arrow"/></svg><span>Promote to block</span></button>`;
      return `
        <div class="fw-rule">
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
    itemsEl.innerHTML = (p.items || []).map(it => {
      const sev = it.severity >= 3 ? 's3' : it.severity === 2 ? 's2' : 's1';
      let link = '';
      if (it.kind === 'flag') link = `<a href="#flags-list">view evidence</a>`;
      if (it.kind === 'incident') link = `<a href="#" onclick="openIncidentReport('${escapeHTML(it.id)}');return false;">view report</a>`;
      if (it.kind === 'guard_pending') link = `<span>resolve it in the menu bar app</span>`;
      if (it.kind === 'collector_down') link = `<span>— ${escapeHTML(it.detail || 'collector stopped')}</span>`;
      if (it.kind === 'uninspected_egress') link = `<a href="#firewall-container">see firewall</a>`;
      return `<li><span class="sev ${sev}">●</span><span>${escapeHTML(it.title)} ${link}</span></li>`;
    }).join('');
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
      const r = await fetch('/incidents/status', {
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
        ? `<span class="status-chip resolved">resolved</span>`
        : status === 'acknowledged'
          ? `<span class="status-chip acked">ack</span>`
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
        ${wf.resolution_note ? `<div class="incident-note">Resolution: ${escapeHTML(wf.resolution_note)}</div>` : ''}
        <div class="incident-actions">
          <button class="btn btn-ghost" onclick="openIncidentReport('${escapeHTML(inc.id)}')"><svg class="icon"><use href="#i-doc"/></svg><span>View report</span></button>
          ${status === 'open' ? `<button class="btn btn-ghost" onclick="setIncidentStatus('${escapeHTML(inc.id)}','acknowledged')"><svg class="icon"><use href="#i-history"/></svg><span>Acknowledge</span></button>` : ''}
          ${status !== 'resolved' ? `<button class="btn btn-ghost" onclick="setIncidentStatus('${escapeHTML(inc.id)}','resolved')"><svg class="icon"><use href="#i-shield"/></svg><span>Resolve</span></button>` : ''}
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
        ? `<button class="source-remove" title="Stop watching" onclick="removeSource('${encodeURIComponent(s.source)}')"><svg class="icon"><use href="#i-close"/></svg></button>`
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
      const res = await fetch('/firewall/sources', {
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

  window.removeSource = async function(encoded) {
    const source = decodeURIComponent(encoded);
    try {
      const res = await fetch('/firewall/sources', {
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

    container.innerHTML = flags.map(f => `
      <div class="flag-card ${f.severity >= 3 ? 'sev3' : ''}">
        <div class="flag-rule"><svg class="icon"><use href="#i-alert"/></svg>${escapeHTML(f.rule)} — ${escapeHTML(f.agent)} (PID ${f.pid})</div>
        <div class="flag-evidence">
          ${(f.evidence || []).map(ev => `<div>${escapeHTML(ev)}</div>`).join('')}
        </div>
      </div>
    `).join('');
  }

  function renderEvents() {
    const container = document.getElementById('events-container');
    const events = telemetryData.eventsView || [];

    if (events.length === 0) {
      const msg = isEventsFiltered() ? 'No events match the current filter' : 'No system events logged';
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>${msg}</span></div>`;
      return;
    }

    container.innerHTML = events.map(e => {
      let kindLabel = 'EVENT';
      let kindClass = '';
      if (e.kind === 8) { kindLabel = 'TOOL USE'; kindClass = 'tool'; }
      else if (e.kind === 9) { kindLabel = 'PROXY HIT'; kindClass = 'proxy'; }
      else if (e.kind === 5) { kindLabel = 'NET CONN'; kindClass = 'conn'; }

      const timeStr = new Date(e.ts).toLocaleTimeString();
      const detailStr = e.detail || e.path || (e.remote_host ? `${e.remote_host}:${e.remote_port}` : '');

      return `
        <div class="timeline-item">
          <span class="t">${timeStr}</span>
          <span class="event-kind ${kindClass}">${kindLabel}</span>
          <span class="pid">PID ${e.pid}</span>
          <span class="dtl">${escapeHTML(detailStr)}</span>
        </div>
      `;
    }).join('');
  }

  window.openIncidentReport = async function(incidentId) {
    if (!reportModal) return;
    const bodyEl = document.getElementById('modal-report-body');
    const titleEl = document.getElementById('modal-title');
    titleEl.innerHTML = `<svg class="icon"><use href="#i-doc"/></svg>Incident report — ${escapeHTML(incidentId)}`;
    bodyEl.innerHTML = `<div class="loading-spinner">Fetching incident report…</div>`;
    reportModal.showModal();

    try {
      const res = await fetch(`/incidents?id=${encodeURIComponent(incidentId)}&format=markdown`);
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
      const res = await fetch('/kill', {
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
      const res = await fetch('/firewall/mode', {
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

  function parseMarkdownToHTML(md) {
    if (!md) return '';
    let html = escapeHTML(md);

    // Code blocks
    html = html.replace(/```([\s\S]*?)```/g, (_, code) => `<pre class="md-codeblock"><code>${code}</code></pre>`);
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code class="md-inline-code">$1</code>');
    // Headers
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');
    // Bold
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    // Bullet lists
    html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
    // Paragraphs
    html = html.replace(/\n\n/g, '<br/><br/>');

    return `<div class="markdown-view">${html}</div>`;
  }

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

  function escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Initial fetch and poll every 2 seconds
  fetchTelemetry();
  setInterval(fetchTelemetry, 2000);
});
