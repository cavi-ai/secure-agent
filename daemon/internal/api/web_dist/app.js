document.addEventListener('DOMContentLoaded', () => {
  const btnRefresh = document.getElementById('btn-refresh');
  const eventFilter = document.getElementById('event-filter');
  const reportModal = document.getElementById('report-modal');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const btnCopyReport = document.getElementById('btn-copy-report');

  let currentRawMarkdown = '';

  btnRefresh.addEventListener('click', () => {
    fetchTelemetry();
    showToast('Refreshing telemetry data...', 'info');
  });

  eventFilter.addEventListener('change', () => {
    renderEvents();
  });

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
    flags: [],
    incidents: [],
    events: [],
    fleet: []
  };

  async function fetchTelemetry() {
    try {
      const [statusRes, flagsRes, incidentsRes, eventsRes, fleetRes] = await Promise.all([
        fetch('/status').catch(() => null),
        fetch('/flags?limit=20').catch(() => null),
        fetch('/incidents?limit=10').catch(() => null),
        fetch('/events?limit=50').catch(() => null),
        fetch('/fleet').catch(() => null)
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

      renderAll();
    } catch (err) {
      console.error('Error fetching telemetry:', err);
    }
  }

  function renderAll() {
    renderStatus();
    renderAgents();
    renderIncidents();
    renderFleet();
    renderFlags();
    renderEvents();
  }

  function renderStatus() {
    const s = telemetryData.status;
    if (!s) return;

    document.getElementById('status-text').textContent = s.running ? 'Daemon Active' : 'Disconnected';
    const chip = document.getElementById('system-status');
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
      container.innerHTML = `<div class="empty-state">No active AI agent processes detected</div>`;
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

  function renderIncidents() {
    const container = document.getElementById('incidents-container');
    const badge = document.getElementById('badge-incidents-count');
    const incidents = telemetryData.incidents;

    badge.textContent = incidents.length;

    if (incidents.length === 0) {
      container.innerHTML = `<div class="empty-state">No security containment incidents recorded</div>`;
      return;
    }

    container.innerHTML = incidents.map(inc => `
      <div class="incident-card">
        <div class="incident-header">
          <span class="risk-tag ${(inc.risk || '').toUpperCase() === 'HIGH' ? 'high' : ''}"><svg class="icon"><use href="#i-alert"/></svg>${escapeHTML(inc.risk)}</span>
          <span class="kpi-hint">${escapeHTML(inc.rule)} — PID ${inc.pid}</span>
        </div>
        <div class="incident-summary">${escapeHTML(inc.summary)}</div>
        <div class="incident-actions">
          <button class="btn btn-ghost" onclick="openIncidentReport('${escapeHTML(inc.id)}')"><svg class="icon"><use href="#i-doc"/></svg><span>View report</span></button>
        </div>
        <div class="rotate-list">
          ${(inc.rotate_list || []).map(item => `
            <div class="rotate-item-row">
              <span class="rk"><svg class="icon"><use href="#i-key"/></svg><strong>${escapeHTML(item.name)}</strong> (${escapeHTML(item.category)})</span>
              <button class="btn btn-primary" onclick="triggerRotation('${escapeHTML(inc.id)}', '${escapeHTML(item.id)}')"><svg class="icon"><use href="#i-refresh"/></svg><span>Rotate</span></button>
            </div>
          `).join('')}
        </div>
      </div>
    `).join('');
  }

  function renderFleet() {
    const container = document.getElementById('fleet-container');
    const badge = document.getElementById('badge-fleet-count');
    const fleet = telemetryData.fleet || [];

    badge.textContent = fleet.length;

    if (fleet.length === 0) {
      container.innerHTML = `<div class="empty-state">No remote fleet nodes registered</div>`;
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

  function renderFlags() {
    const container = document.getElementById('flags-container');
    const badge = document.getElementById('badge-flags-count');
    const flags = telemetryData.flags;

    badge.textContent = flags.length;

    if (flags.length === 0) {
      container.innerHTML = `<div class="empty-state">No security correlation flags active</div>`;
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
    const filter = eventFilter.value;
    let events = telemetryData.events;

    if (filter !== 'all') {
      const k = parseInt(filter);
      events = events.filter(e => e.kind === k);
    }

    if (events.length === 0) {
      container.innerHTML = `<div class="empty-state">No matching timeline events</div>`;
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
        bodyEl.innerHTML = `<div class="empty-state">Failed to load incident report specification.</div>`;
      }
    } catch (err) {
      bodyEl.innerHTML = `<div class="empty-state">Error: ${escapeHTML(err.message)}</div>`;
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

  window.triggerRotation = async function(incidentId, itemId) {
    try {
      const res = await fetch('/rotate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_id: incidentId, item_id: itemId })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        showToast(`Rotation Successful: ${data.message}`, 'success');
        fetchTelemetry();
      } else {
        showToast(`Rotation Failed: ${data.message || 'Error'}`, 'danger');
      }
    } catch (err) {
      showToast(`Error triggering rotation: ${err}`, 'danger');
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
