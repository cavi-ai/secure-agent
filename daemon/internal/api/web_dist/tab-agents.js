// Agents tab: family groups, instances, fleet (hidden until configured).

function renderAgents() {
  const SA = window.SA;

  const container = document.getElementById('agents-container');
  const badge = document.getElementById('badge-agents-count');
  const agents = (SA.t.status && SA.t.status.agents) ? SA.t.status.agents : [];
  const families = groupAgents(agents);

  badge.textContent = families.length;
  SA.setTabBadge('agents', families.length); // informative count, neutral styling

  if (agents.length === 0) {
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No agents running yet — start Claude Code, Cursor, or Codex and they'll appear here</span></div>`;
    return;
  }

  const now = Date.now();
  const totalInstances = families.reduce((n, fam) => n + fam.roots.length, 0);
  container.innerHTML = families.map(f => {
    const open = familyShouldExpand(f, families.length, totalInstances, SA.agentGroupOpen);
    const earliestAbs = f.earliest ? fmtTime(new Date(f.earliest)) : '';
    const earliestAge = f.earliest ? fmtAge(f.earliest, now) : '';
    const rss = fmtRSS(f.rss);
    const orphanBtn = f.orphanCount
      ? `<button type="button" class="btn btn-danger btn-sm" data-action="kill-orphans" data-family="${escapeHTML(f.name)}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate orphans (${f.orphanCount})</span></button>`
      : '';
    return `
    <details class="agent-group" data-family="${escapeHTML(f.name)}"${open ? ' open' : ''}>
      <summary class="agent-group-head">
        <span class="agent-group-title">
          <svg class="icon"><use href="#i-agent"/></svg>
          <span class="agent-family-name">${escapeHTML(f.title)}</span>
          <span class="agent-pid">${f.roots.length} ${f.roots.length === 1 ? 'instance' : 'instances'}</span>
        </span>
        <span class="agent-group-meta">
          ${earliestAbs ? `<span class="agent-meta-item" title="${escapeHTML(f.earliest)}">${escapeHTML(earliestAbs)}${earliestAge ? ' · ' + earliestAge : ''}</span>` : ''}
          ${rss ? `<span class="agent-meta-item">${escapeHTML(rss)}</span>` : ''}
          ${f.orphanCount ? `<span class="agent-orphan-count">${f.orphanCount} leftover</span>` : ''}
          ${orphanBtn}
        </span>
      </summary>
      <div class="agent-instances">
        ${f.roots.map(root => renderInstance(root, f.members, now)).join('')}
      </div>
    </details>`;
  }).join('');

  container.querySelectorAll('details.agent-group').forEach(el => {
    el.addEventListener('toggle', () => {
      SA.agentGroupOpen[el.dataset.family] = el.open;
    });
  });
}

function renderInstance(root, members, now) {
  const kids = childrenOf(root, members);
  return `${renderProcessRow(root, now, false)}${kids.map(c => renderProcessRow(c, now, true)).join('')}`;
}

function renderFleet() {
  const SA = window.SA;

  const vis = inspectionVisible(SA.t.status, SA.t.audit);
  const raw = SA.t.fleet;
  // /fleet.fleet_configured is the collector-configured bit; status.fleet_configured
  // is the same signal on /status. Hide if either says the node has no collector.
  const fromFleet = raw && !Array.isArray(raw) && raw.fleet_configured === false;
  const show = vis.fleet && !fromFleet;
  const fleetCol = document.getElementById('fleet-col');
  const panel = document.getElementById('fleet-panel');
  if (fleetCol) fleetCol.hidden = !show;
  if (panel) panel.style.display = show ? '' : 'none';
  if (!show) {
    const badge = document.getElementById('badge-fleet-count');
    if (badge) badge.textContent = '0';
    return;
  }

  const container = document.getElementById('fleet-container');
  const badge = document.getElementById('badge-fleet-count');
  // /fleet returns THIS node's status OBJECT (hostname/os/agents/…), not an
  // array of remote nodes. Older console builds did fleet.map on it and
  // crashed renderAll — killing every panel below fleet on every poll.
  // Accept both shapes: object → one local node card; array → remote list.
  const fleet = Array.isArray(raw)
    ? raw
    : (raw && (raw.hostname || raw.node_id) ? [{ ...raw, online: raw.running !== false }] : []);

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
        ${node.os ? `<span>${escapeHTML(node.os)}${node.arch ? '/' + escapeHTML(node.arch) : ''}</span>` : ''}
        ${node.ip ? `<span>IP ${escapeHTML(node.ip)}</span>` : ''}
        <span>${escapeHTML(node.version || 'v1.0')}</span>
        ${typeof node.active_agents === 'number' ? `<span>${node.active_agents} agents</span>` : ''}
        ${typeof node.recent_flags === 'number' ? `<span>${node.recent_flags} flags</span>` : ''}
      </div>
    </div>
  `).join('');
}

