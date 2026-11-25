// Agents tab: harness groups (same order, marks and filter state as the
// Sessions rail), instances, an Infrastructure section, fleet (hidden until
// configured).

function renderAgents() {
  const SA = window.SA;

  const container = document.getElementById('agents-container');
  const badge = document.getElementById('badge-agents-count');
  const pills = document.getElementById('agent-harness-pills');
  const agents = (SA.t.status && SA.t.status.agents) ? SA.t.status.agents : [];
  const groups = groupAgentsByHarness(agents);
  const agentGroups = groups.filter(g => !g.infra);

  // Infra is never counted as an agent.
  badge.textContent = agentGroups.length;
  SA.setTabBadge('processes', agentGroups.length); // informative count, neutral styling
  if (pills) {
    renderFilterPills(pills, harnessPillsHTML(agentGroups.map(g => g.key), SA.harnessFilter.harnesses));
    applyInlineMetrics(pills);
  }

  if (agents.length === 0) {
    container.innerHTML = html`<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No agents running yet — start Claude Code, Cursor, or Codex and they'll appear here</span></div>`;
    return;
  }

  const now = Date.now();
  const shown = applyAgentFilters(groups, SA.harnessFilter);
  const visible = shown.filter(g => !g.infra);
  const infra = shown.filter(g => g.infra);
  // Group and helper-tree open state is recorded by one capture-phase toggle
  // listener on the container (app.js); patchList keeps unchanged groups.
  // /status joins session identity (repo, branch, the spawning agent) onto
  // tree roots only; a row reads it from the root of its own tree.
  const roots = new Map(((SA.t.status && SA.t.status.trees) || []).filter(t => t && t.root).map(t => [Number(t.root.pid), t.root]));
  const isOpen = (key, dflt) => (Object.prototype.hasOwnProperty.call(SA.agentGroupOpen, key) ? !!SA.agentGroupOpen[key] : dflt);
  const parts = visible.length
    ? visible.map(g => ({ key: 'group:' + g.key, html: agentGroupHTML(g, now, isOpen(g.key, true), SA.agentTreeOpen, SA.expanded, roots) }))
    : agentGroups.length
      ? [{ key: 'empty:nomatch', html: html`<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No agents match — <button type="button" class="link-btn" data-action="clear-harness-filter">clear the filter</button></span></div>` }]
      : [{ key: 'empty:infra-only', html: html`<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No agents running — only infrastructure below</span></div>` }];
  if (infra.length) {
    parts.push({ key: 'infra', html: html`<section class="agent-infra" aria-label="Infrastructure"><h3 class="agent-infra-head">Infrastructure <span>IDEs and model servers — not counted as agents</span></h3>${infra.map(g => raw(agentGroupHTML(g, now, isOpen(g.key, false), SA.agentTreeOpen, SA.expanded, roots)))}</section>` });
  }
  patchList(container, parts, { key: p => p.key, html: p => p.html });
}

// One harness group: mark + display name, then instances, processes, RSS,
// CPU and last seen over the instances shown; leftovers get a bulk kill. The
// first 8 instances list, then Show more (expanded holds opened groups).
function agentGroupHTML(g, now, open, treeOpen, expanded, roots) {
  const t = agentGroupTotals(g);
  const rss = fmtRSS(t.rss);
  const cpu = fmtCPU(t.cpu);
  const seen = t.lastSeen ? fmtAge(t.lastSeen, now) : '';
  // One separator between every fact in the family header.
  const facts = [
    html`${t.instances} ${t.instances === 1 ? 'instance' : 'instances'}`,
    html`${t.processes} ${t.processes === 1 ? 'process' : 'processes'}`,
    rss ? html`${rss}` : '',
    cpu ? html`${cpu} CPU` : '',
    seen ? html`<span class="agent-lastseen" title="${t.lastSeen}">seen ${seen} ago</span>` : '',
  ].filter(Boolean).join(' · ');
  const orphanBtn = t.orphans
    ? html`<button type="button" class="btn btn-danger btn-sm" data-action="kill-orphans" data-family="${g.key}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate orphans (${t.orphans})</span></button>`
    : '';
  return html`
    <details class="agent-group${g.infra ? ' infra' : ''}" data-harness="${g.key}"${open ? ' open' : ''}>
      <summary class="agent-group-head">
        <span class="agent-group-title">${raw(harnessChipHTML(g.key, { label: true }))}</span>
        <span class="agent-group-meta">
          <span class="agent-meta-item">${raw(facts)}</span>
          ${t.orphans ? raw(html`<span class="agent-orphan-count">${t.orphans} leftover</span>`) : ''}
          ${raw(orphanBtn)}
        </span>
      </summary>
      <div class="agent-instances">
        ${raw(cappedList(g.instances, 8, inst => agentInstanceHTML(inst, now, treeOpen, roots), 'agents:' + g.key, expanded).html)}
      </div>
    </details>`;
}

// One instance: what it works on (repo@branch, else its folder) with the pid
// beside it, leftover badge, activity, RSS of its tree, kill; helper
// processes sit behind a disclosure. roots maps a pid to its /status tree
// root, which carries the session join (" · <agent>" via sessionTitle).
function agentInstanceHTML(inst, now, treeOpen, roots) {
  const a = inst.root;
  const joined = roots && roots.get(Number(a.pid));
  const title = sessionTitle(joined ? { ...a, ...joined } : a, a.cwd) || harnessMeta(a.name).label;
  const seenAge = a.last_seen_at ? fmtAge(a.last_seen_at, now) : '';
  const stale = a.last_seen_at ? (now - Date.parse(a.last_seen_at)) > 10 * 60 * 1000 : true;
  const rss = fmtRSS([a, ...inst.children].reduce((n, p) => n + Number(p.rss_bytes || 0), 0));
  const n = inst.children.length;
  const tree = n
    ? html`<details class="session-helpers agent-tree" data-pid="${a.pid}"${treeOpen[a.pid] ? ' open' : ''}><summary class="session-helpers-sum">${n} helper process${n === 1 ? '' : 'es'}</summary>${inst.children.map(c => raw(renderProcessRow(c, now, true)))}</details>`
    : '';
  return html`
      <div class="agent-instance agent-row${n ? ' has-tree' : ''}${a.is_orphan ? ' orphan' : ''}${stale ? ' stale' : ''}">
        <div class="agent-row-main" title="${a.cwd || a.workspace || ''}">
          <span class="agent-row-title">${title}</span>
          <div class="agent-row-meta">
          <span class="agent-pid">PID ${a.pid}</span>
          ${a.is_orphan ? raw('<span class="agent-status orphan">leftover</span>') : ''}
          ${raw(seenAge ? html`<span class="agent-meta-item agent-lastseen" title="last event ${a.last_seen_at}">active ${seenAge} ago</span>` : '<span class="agent-meta-item agent-lastseen">no activity</span>')}
          ${rss ? raw(html`<span class="agent-meta-item">${rss}</span>`) : ''}
          </div>
        </div>
        <button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="${a.pid}" data-started="${a.started_at || ''}" data-family="${a.name || ''}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>
        ${raw(tree)}
      </div>`;
}

function renderFleet() {
  const SA = window.SA;

  const vis = inspectionVisible(SA.t.status, SA.t.audit);
  const served = SA.t.fleet;
  // /fleet.fleet_configured is the collector-configured bit; status.fleet_configured
  // is the same signal on /status. Hide if either says the node has no collector.
  const fromFleet = served && !Array.isArray(served) && served.fleet_configured === false;
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
  const fleet = Array.isArray(served)
    ? served
    : (served && (served.hostname || served.node_id) ? [{ ...served, online: served.running !== false }] : []);

  badge.textContent = fleet.length;

  if (fleet.length === 0) {
    container.innerHTML = html`<div class="empty"><svg class="icon"><use href="#i-server"/></svg><span>No remote fleet nodes registered</span></div>`;
    return;
  }

  container.innerHTML = fleet.map(node => html`
    <div class="fleet-node-card">
      <div class="fleet-node-header">
        <span class="fleet-node-name"><svg class="icon"><use href="#i-server"/></svg>${node.hostname || node.id || 'Fleet node'}</span>
        <span class="status-badge ${node.online ? 'online' : 'offline'}">${node.online ? 'ONLINE' : 'OFFLINE'}</span>
      </div>
      <div class="fleet-node-meta">
        ${node.os ? raw(html`<span>${node.os}${node.arch ? '/' + node.arch : ''}</span>`) : ''}
        ${node.ip ? raw(html`<span>IP ${node.ip}</span>`) : ''}
        <span>${node.version || 'v1.0'}</span>
        ${typeof node.active_agents === 'number' ? raw(html`<span>${node.active_agents} agents</span>`) : ''}
        ${typeof node.recent_flags === 'number' ? raw(html`<span>${node.recent_flags} flags</span>`) : ''}
      </div>
    </div>
  `).join('');
}

