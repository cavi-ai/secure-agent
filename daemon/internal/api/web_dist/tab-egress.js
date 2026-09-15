// Egress tab: firewall rules, watched sources, uninspected drill-down.

function renderFirewall() {
  const SA = window.SA;

  const container = document.getElementById('firewall-container');
  const badge = document.getElementById('badge-firewall-mode');
  const s = SA.t.status;
  const stats = (s && s.firewall_stats) ? s.firewall_stats : {};
  const uninspected = (s && s.uninspected_egress) ? s.uninspected_egress : 0;
  const rules = Object.keys(stats).sort();

  const anyBlock = rules.some(r => stats[r].mode === 'block');
  badge.textContent = anyBlock ? 'enforcing' : 'monitor';
  badge.className = 'badge' + (anyBlock ? ' badge-ok' : '');
  SA.setTabBadge('egress', uninspected);

  if (rules.length === 0 && uninspected === 0) {
    container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-shield"/></svg><span>No egress inspected yet — traffic is scanned as your agents run</span></div>`;
    SA.prevFwStats = stats;
    return;
  }

  let html = '';
  if (uninspected > 0) {
    html += `<button type="button" class="fw-uninspected fw-drill" data-action="open-uninspected"><svg class="icon"><use href="#i-globe"/></svg><span>${uninspected} endpoint${uninspected === 1 ? '' : 's'} reached without inspection in the last 24h (pinned or unrouted)</span><span class="fw-drill-hint">view endpoints</span></button>`;
  }
  html += vendorKeyPromoteHTML(monitorVendorKeyIDs(stats));
  // Egress suggestions: recurring uninspected endpoints the user can approve
  // into the vendor allowlist with one click (drives the blind spot to zero).
  const suggestions = SA.t.suggestions || [];
  if (suggestions.length > 0) {
    const vis = inspectionVisible(SA.t.status, SA.t.audit);
    html += suggestions.map(sg => `
      <div class="fw-rule fw-suggestion">
        <div class="fw-rule-main">
          <span class="fw-rule-id">${escapeHTML(sg.host)}</span>
          <div class="fw-metrics">
            <span class="fw-metric dim">${escapeHTML(sg.agent)} · seen <b>${sg.count}×</b> uninspected</span>
            ${vis.advisor && sg.assessment ? `<span class="advisor-chip adv-${escapeHTML(sg.assessment)}" title="${escapeHTML(sg.rationale)}">advisor: ${escapeHTML(sg.assessment)}</span>` : ''}
          </div>
        </div>
        <button class="btn btn-ghost btn-sm" data-action="allow-host" data-agent="${escapeHTML(sg.agent)}" data-host="${escapeHTML(sg.host)}"><svg class="icon"><use href="#i-shield"/></svg><span>Allow for ${escapeHTML(sg.agent)}</span></button>
      </div>`).join('');
  }
  html += rules.map(r => {
    const st = stats[r];
    const blocking = st.mode === 'block';
    // A rule whose blocked/would-block counters grew since the last render
    // just intercepted something — flash its row once.
    const prev = SA.prevFwStats ? SA.prevFwStats[r] : null;
    const grew = !SA.reducedMotion && SA.prevFwStats !== null &&
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
  SA.prevFwStats = stats;
}

function renderSources() {
  const SA = window.SA;

  const list = document.getElementById('sources-list');
  const badge = document.getElementById('badge-sources-count');
  const sources = SA.t.sources || [];

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

function fillUninspected(bodyEl) {
  const SA = window.SA;

  const rows = SA.t.uninspected || [];
  if (rows.length === 0) {
    bodyEl.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>No uninspected endpoints in the last 24h — the blind spot is closed</span></div>`;
    return;
  }
  bodyEl.innerHTML = `<div class="uninspected-expl">These agents connected directly, bypassing the inspection proxy — usually pinned TLS certificates or tooling that ignores the proxy environment. Allowing a host marks the traffic as expected and closes the blind spot; routing the agent through the proxy (source <code>~/.config/secure-agent/agent-env.sh</code>) inspects it instead.</div>` + rows.map(e => `
    <div class="fw-rule">
      <div class="fw-rule-main">
        <span class="fw-rule-id">${escapeHTML(e.host)}</span>
        <div class="fw-metrics">
          <span class="fw-metric dim">${escapeHTML(e.agent)} · <b>${e.count}×</b> in 24h${e.last_seen ? ` · last ${escapeHTML(fmtAge(e.last_seen, Date.now()))} ago` : ''}</span>
          ${inspectionVisible(SA.t.status, SA.t.audit).advisor && e.assessment ? `<span class="advisor-chip adv-${escapeHTML(e.assessment)}" title="${escapeHTML(e.rationale)}">advisor: ${escapeHTML(e.assessment)}</span>` : ''}
        </div>
      </div>
      <button class="btn btn-ghost btn-sm" data-action="allow-host" data-agent="${escapeHTML(e.agent)}" data-host="${escapeHTML(e.host)}"><svg class="icon"><use href="#i-shield"/></svg><span>Allow for ${escapeHTML(e.agent)}</span></button>
    </div>`).join('');
}

