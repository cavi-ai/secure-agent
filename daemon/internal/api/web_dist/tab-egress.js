// Egress tab: where traffic went (uninspected endpoints), firewall rules,
// watched sources, and the uninspected drill-down drawer.

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

  const parts = [];
  const vendor = vendorKeyPromoteHTML(monitorVendorKeyIDs(stats));
  if (vendor) parts.push({ key: 'vendor', html: vendor });
  // Egress suggestions: recurring uninspected endpoints the user can approve
  // into the vendor allowlist with one click (drives the blind spot to zero).
  const suggestions = SA.t.suggestions || [];
  if (suggestions.length > 0) {
    const vis = inspectionVisible(SA.t.status, SA.t.audit);
    suggestions.forEach(sg => parts.push({ key: `sg:${sg.agent}|${sg.host}`, html: `
      <div class="fw-rule fw-suggestion">
        <div class="fw-rule-main">
          <span class="fw-rule-id">${escapeHTML(sg.host)}</span>${identityLabel(sg) ? ` <span class="fw-metric dim">${escapeHTML(identityLabel(sg))}</span>` : ''}
          <div class="fw-metrics">
            <span class="fw-metric dim">${escapeHTML(sg.agent)} · seen <b>${sg.count}×</b> uninspected</span>
            ${vis.advisor && sg.assessment ? `<span class="advisor-chip adv-${escapeHTML(sg.assessment)}" title="${escapeHTML(sg.rationale)}">advisor: ${escapeHTML(sg.assessment)}</span>` : ''}
          </div>
        </div>
        <button class="btn btn-ghost btn-sm" data-action="allow-host" data-agent="${escapeHTML(sg.agent)}" data-host="${escapeHTML(sg.host)}"><svg class="icon"><use href="#i-shield"/></svg><span>Allow for ${escapeHTML(sg.agent)}</span></button>
      </div>` }));
  }
  // A rule whose blocked/would-block counters grew since the last render
  // just intercepted something — flash its row once.
  const grew = r => {
    const st = stats[r];
    const prev = SA.prevFwStats ? SA.prevFwStats[r] : null;
    return !SA.reducedMotion && SA.prevFwStats !== null &&
      !!prev && ((st.blocked || 0) > (prev.blocked || 0) || (st.would_block || 0) > (prev.would_block || 0));
  };
  // Rules with hits stay listed; the rest fold into one collapsed row.
  const { hit, quiet } = foldRules(stats);
  for (const r of hit) parts.push({ key: 'rule:' + r, html: fwRuleHTML(r, stats[r], grew(r)) });
  if (quiet.length > 0) {
    parts.push({ key: 'rules-quiet', html: `<details class="fw-fold" data-key="rules-quiet"><summary>${quiet.length} rule${quiet.length === 1 ? '' : 's'} with no hits in 24 h</summary>${quiet.map(r => fwRuleHTML(r, stats[r], false)).join('')}</details>` });
  }
  // User-approved (agent, host) allowlist entries — every one reversible.
  const allowlist = SA.t.allowlist || [];
  if (allowlist.length > 0) {
    parts.push({ key: 'allowlist', html: `<div class="mute-list"><div class="mute-head">Allowed endpoints</div>` + allowlist.map(p => `
      <div class="mute-row">
        <span class="mute-pair">${escapeHTML(p.host)} · ${escapeHTML(p.agent)}</span>
        <button class="source-remove" title="Remove — the endpoint goes back to uninspected" data-action="allowlist-remove" data-agent="${escapeHTML(p.agent)}" data-host="${escapeHTML(p.host)}"><svg class="icon"><use href="#i-close"/></svg></button>
      </div>`).join('') + `</div>` });
  }
  patchList(container, parts, { key: p => p.key, html: p => p.html,
    empty: `<div class="empty"><svg class="icon"><use href="#i-shield"/></svg><span>No egress inspected yet — traffic is scanned as your agents run</span></div>` });
  SA.prevFwStats = stats;
}

// Split rule ids into those with any would-block, blocked or legit hit and
// the quiet ones (every counter 0), each sorted. Pure.
function foldRules(stats) {
  const hit = [];
  const quiet = [];
  for (const r of Object.keys(stats || {}).sort()) {
    const st = stats[r] || {};
    ((st.would_block || 0) + (st.blocked || 0) + (st.legit || 0) > 0 ? hit : quiet).push(r);
  }
  return { hit, quiet };
}

// One firewall rule: its counters and the Promote (or Demote) action.
function fwRuleHTML(r, st, flash) {
  const action = st.mode === 'block'
    ? `<span class="mode-chip block">blocking</span><button class="btn btn-ghost btn-sm" data-action="demote" data-rule="${escapeHTML(r)}" title="Back to monitor-only — blocking is reversible"><svg class="icon"><use href="#i-arrow"/></svg><span>Demote to monitor</span></button>`
    : `<button class="btn btn-primary btn-sm" data-action="promote" data-rule="${escapeHTML(r)}"><svg class="icon"><use href="#i-arrow"/></svg><span>Promote to block</span></button>`;
  return `
      <div class="fw-rule${flash ? ' fw-flash' : ''}">
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
}

// Where traffic went: the uninspected endpoints, inline as the Egress tab's
// first panel. Same rows, rollups and actions as the drill-down drawer; one
// node per endpoint, so an Allow drops only its row and an open disclosure
// or a focused button survives a refresh.
function renderEndpoints() {
  const SA = window.SA;
  const container = document.getElementById('endpoints-container');
  const title = document.getElementById('endpoints-title');
  if (!container) return;
  const rows = SA.t.uninspected || [];
  const s = SA.t.status;
  const n = (s && s.uninspected_egress) || rows.length;
  if (title) title.textContent = `${n} endpoint${n === 1 ? '' : 's'} reached without inspection in 24 h`;
  const opened = new Set([...container.querySelectorAll('details[data-key][open]')].map(d => d.dataset.key));
  patchList(container, uninspectedParts(rows, inspectionVisible(SA.t.status, SA.t.audit).advisor), {
    key: p => p.key, html: p => p.html,
    empty: `<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>No uninspected endpoints in the last 24h — the blind spot is closed</span></div>`,
  });
  for (const d of container.querySelectorAll('details[data-key]')) if (opened.has(d.dataset.key)) d.open = true;
}

// The uninspected list as keyed parts, one root element each: per agent a
// head (with its bulk-allow buttons) then one row per endpoint, the vendor
// API rollups, and the CDN/cloud carriers. Pure but for fmtAge's clock.
function uninspectedParts(rows, advisorOn) {
  const { unknown, vendors, carriers } = groupUninspected(rows);
  const parts = [];
  for (const [agent, list] of unknownByAgent(unknown)) {
    parts.push({ key: 'agent:' + agent, html: `<div class="egress-agent-lead"><div class="egress-agent-head">${agentHeadInnerHTML(agent, list)}</div>${bulkAllowHTML(agent, list)}</div>` });
    for (const e of list) parts.push({ key: `ep:${e.agent}|${e.host}`, html: egressRowHTML(e, advisorOn) });
  }
  if (vendors.length > 0) {
    parts.push({ key: 'vendors', html: `<div class="egress-agent-lead"><div class="egress-agent-head">${VENDOR_HEAD_HTML}</div></div>` });
    for (const g of vendors) parts.push({ key: `vendor:${g.agent}|${g.org}`, html: `<div class="egress-vendor">${vendorRollupHTML(g, advisorOn)}</div>` });
  }
  if (carriers.length > 0) parts.push({ key: 'carriers', html: carriersHTML(carriers) });
  return parts;
}

// Unknown endpoints grouped by agent, most-used first within an agent.
function unknownByAgent(unknown) {
  const byAgent = new Map();
  for (const e of unknown) {
    if (!byAgent.has(e.agent)) byAgent.set(e.agent, []);
    byAgent.get(e.agent).push(e);
  }
  for (const list of byAgent.values()) list.sort((a, b) => (b.count || 0) - (a.count || 0));
  return [...byAgent.entries()];
}

// An agent's head: its name and the endpoint count.
function agentHeadInnerHTML(agent, list) {
  return `<span class="egress-agent-name">${escapeHTML(agent)}</span><span class="fw-metric dim">${list.length} uninspected endpoint${list.length === 1 ? '' : 's'}</span>`;
}

// One bulk decision per host-suffix family that has two or more hosts.
function bulkAllowHTML(agent, list) {
  const bulkGroups = {};
  for (const e of list) (bulkGroups[hostSuffix(e.host)] = bulkGroups[hostSuffix(e.host)] || []).push(e);
  const bulkButtons = Object.entries(bulkGroups)
    .filter(([, g]) => g.length >= 2)
    .sort((a, b) => b[1].length - a[1].length)
    .map(([suffix, g]) =>
      `<button class="btn btn-ghost btn-sm" data-action="bulk-allow" data-agent="${escapeHTML(agent)}" data-hosts="${escapeHTML(g.map(e => e.host).join(','))}"><svg class="icon"><use href="#i-shield"/></svg><span>Allow all ${g.length} ${escapeHTML(suffix)} hosts</span></button>`).join('');
  return bulkButtons ? `<div class="bulk-allow">${bulkButtons}</div>` : '';
}

const VENDOR_HEAD_HTML = `<span class="egress-agent-name">Vendor APIs</span><span class="fw-metric dim">the agent's own model or tooling vendor, reached without the proxy — decide: Allow it, or Route the agent through the proxy</span>`;

// CDN/cloud carriers: one routing note per org, collapsed.
function carriersHTML(infra) {
  const infraByOrg = {};
  for (const e of infra) {
    (infraByOrg[e.infra] = infraByOrg[e.infra] || { endpoints: 0, hits: 0 });
    infraByOrg[e.infra].endpoints += 1;
    infraByOrg[e.infra].hits += e.count || 0;
  }
  const orgRows = Object.entries(infraByOrg)
    .sort((a, b) => b[1].endpoints - a[1].endpoints)
    .map(([org, v]) => `<div class="mute-row"><span class="mute-pair">${escapeHTML(org)}</span><span class="fw-metric dim">${v.endpoints} endpoint${v.endpoints === 1 ? '' : 's'} · ${v.hits}× in 24h</span></div>`).join('');
  return `<details class="infra-group" data-key="carriers"><summary>Known cloud/CDN infrastructure (${infra.length} endpoint${infra.length === 1 ? '' : 's'}) — these are the agents' own API carriers (Anthropic, OpenAI, GitHub, AWS…); nothing to decide, shown for completeness</summary>${orgRows}</details>`;
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

// Dim label naming who a host is: the org (with "· telemetry" for analytics
// endpoints) and the reverse name when it differs from the host.
function identityLabel(e) {
  const id = (e && e.identity) || {};
  const parts = [];
  if (id.org) parts.push(id.class === 'telemetry' ? `${id.org} · telemetry` : id.org);
  if (id.name && id.name !== e.host) parts.push(id.name);
  return parts.join(' · ');
}

// Split uninspected rows three ways: CDN/cloud carriers (infra set), the
// agents' own vendor APIs (identity.class vendor, no infra) rolled up per
// (agent, org), and the rest — cloud and telemetry hosts included, since
// those can front anyone. Pure — unit-tested in packaging/test/console.
function groupUninspected(rows) {
  const unknown = [];
  const carriers = [];
  const byKey = new Map();
  for (const e of rows || []) {
    if (e.infra) { carriers.push(e); continue; }
    const org = e.identity && e.identity.class === 'vendor' && e.identity.org;
    if (!org) { unknown.push(e); continue; }
    const key = e.agent + '|' + org;
    let g = byKey.get(key);
    if (!g) {
      g = { agent: e.agent, org, rows: [], count: 0, first_seen: '' };
      byKey.set(key, g);
    }
    g.rows.push(e);
    g.count += e.count || 0;
    if (e.first_seen && (!g.first_seen || Date.parse(e.first_seen) < Date.parse(g.first_seen))) g.first_seen = e.first_seen;
  }
  const vendors = [...byKey.values()];
  for (const g of vendors) g.rows.sort((a, b) => (b.count || 0) - (a.count || 0));
  vendors.sort((a, b) => b.count - a.count);
  return { unknown, vendors, carriers };
}

// One (agent, vendor) rollup: a single decision row, the endpoints behind a
// <details>.
function vendorRollupHTML(g, advisorOn) {
  const first = g.first_seen ? fmtAge(g.first_seen, Date.now()) : '';
  const n = g.rows.length;
  const facts = [
    `${n} endpoint${n === 1 ? '' : 's'}`,
    `<b>${g.count}×</b> in 24h`,
    first ? `first seen ${escapeHTML(first)} ago` : '',
  ].filter(Boolean).join(' · ');
  const agent = escapeHTML(g.agent);
  return `<div class="fw-rule egress-row">
    <div class="fw-rule-main">
      <span class="fw-rule-id">${agent} → ${escapeHTML(g.org)}</span>
      <div class="fw-metrics"><span class="fw-metric dim">${facts}</span></div>
    </div>
    <div class="egress-actions">
      <button class="btn btn-primary btn-sm" data-action="bulk-allow" data-agent="${agent}" data-hosts="${escapeHTML(g.rows.map(e => e.host).join(','))}" title="Mark these ${escapeHTML(g.org)} endpoints expected for ${agent}; they leave this list"><svg class="icon"><use href="#i-shield"/></svg><span>Allow all for ${agent}</span></button>
      <button class="btn btn-ghost btn-sm" data-action="endpoint-detail" data-host="${escapeHTML(g.rows[0].host)}" data-agent="${agent}" title="Identify the busiest endpoint and see every connection to it"><svg class="icon"><use href="#i-activity"/></svg><span>Evidence</span></button>
    </div>
  </div>
  <details class="infra-group" data-key="${escapeHTML(`vendor:${g.agent}|${g.org}`)}"><summary>${n} ${escapeHTML(g.org)} endpoint${n === 1 ? '' : 's'} for ${agent}</summary>${g.rows.map(e => egressRowHTML(e, advisorOn)).join('')}</details>`;
}

function fillUninspected(bodyEl) {
  const SA = window.SA;
  // A refill (after allow, remove, or an advisor verdict) must not snap shut a
  // disclosure the operator opened or jump the scroll position.
  const opened = new Set([...bodyEl.querySelectorAll('details[data-key][open]')].map(d => d.dataset.key));
  const scroll = bodyEl.scrollTop;

  const rows = SA.t.uninspected || [];
  if (rows.length === 0) {
    bodyEl.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>No uninspected endpoints in the last 24h — the blind spot is closed</span></div>`;
    return;
  }
  const vis = inspectionVisible(SA.t.status, SA.t.audit);
  const advisorOn = vis.advisor;
  // Split actionable unknowns from the agents' own vendor APIs and CDN/cloud
  // carriers: 130 Cloudflare IPs is one routing note, not 130 rows to review.
  const { unknown, vendors, carriers: infra } = groupUninspected(rows);

  // Frame the job: these are connections the agents made that bypassed the
  // inspection proxy, so the operator's decision is "is this expected for
  // this agent?" — not "do you know what 160.79.104.10 is?".
  let html = `<div class="uninspected-expl">
    <b>What this is:</b> these agents connected directly to the internet, bypassing the inspection proxy — usually an app with pinned TLS certs or tooling that ignores the proxy environment.
    <br><b>What to do:</b> for each endpoint, <b>Allow</b> it if it's expected for that agent (future connections stop asking), or <b>Route</b> the agent through the proxy to inspect it instead. ${advisorOn ? 'Not sure? <b>Ask the advisor</b> for a plain-English read.' : '<b>Advisor is off</b> — enable it in Settings for automatic endpoint guidance.'}
  </div>`;

  if (unknown.length === 0) {
    html += `<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>No unknown endpoints — everything unrouted is a known vendor API or cloud/CDN carrier (below)</span></div>`;
  }

  // Group by agent so the operator reads "cursor is reaching 12 hosts"
  // rather than twelve loose rows.
  html += unknownByAgent(unknown).map(([agent, list]) => `<div class="egress-agent-group">
      <div class="egress-agent-head">${agentHeadInnerHTML(agent, list)}</div>
      ${bulkAllowHTML(agent, list)}
      ${list.map(e => egressRowHTML(e, advisorOn)).join('')}
    </div>`).join('');

  if (vendors.length > 0) {
    html += `<div class="egress-agent-group">
      <div class="egress-agent-head">${VENDOR_HEAD_HTML}</div>
      ${vendors.map(g => vendorRollupHTML(g, advisorOn)).join('')}
    </div>`;
  }

  if (infra.length > 0) html += carriersHTML(infra);
  bodyEl.innerHTML = html;
  for (const d of bodyEl.querySelectorAll('details[data-key]')) if (opened.has(d.dataset.key)) d.open = true;
  bodyEl.scrollTop = scroll;
}

// One uninspected endpoint as a decision row: what/who/when on the left, the
// advisor's read in the middle, and the concrete actions on the right.
function egressRowHTML(e, advisorOn) {
  const first = e.first_seen ? fmtAge(e.first_seen, Date.now()) : '';
  const last = e.last_seen ? fmtAge(e.last_seen, Date.now()) : '';
  const idLabel = identityLabel(e);
  const facts = [
    `<b>${e.count || 0}×</b> in 24h`,
    last ? `last ${escapeHTML(last)} ago` : '',
    first ? `first seen ${escapeHTML(first)} ago` : '',
    e.session_id ? `session ${escapeHTML(String(e.session_id).slice(0, 8))}` : '',
  ].filter(Boolean).join(' · ');

  let advisor;
  if (e.assessment) {
    advisor = `<span class="advisor-chip adv-${escapeHTML(e.assessment)}" title="${escapeHTML(e.rationale || '')}">advisor: ${escapeHTML(e.assessment)}</span>`;
    if (e.rationale) advisor += `<div class="egress-advice">${escapeHTML(e.rationale)}</div>`;
  } else if (advisorOn) {
    advisor = `<button class="btn btn-ghost btn-sm" data-action="assess-host" data-agent="${escapeHTML(e.agent)}" data-host="${escapeHTML(e.host)}"><svg class="icon"><use href="#i-agent"/></svg><span>Ask the advisor</span></button>`;
  } else {
    advisor = `<span class="fw-metric dim">advisor off</span>`;
  }

  return `<div class="fw-rule egress-row">
    <div class="fw-rule-main">
      <span class="fw-rule-id">${escapeHTML(e.host)}</span>${idLabel ? ` <span class="fw-metric dim">${escapeHTML(idLabel)}</span>` : ''}
      <div class="fw-metrics"><span class="fw-metric dim">${facts}</span></div>
      ${advisor}
    </div>
    <div class="egress-actions">
      <button class="btn btn-primary btn-sm" data-action="allow-host" data-agent="${escapeHTML(e.agent)}" data-host="${escapeHTML(e.host)}" title="Mark this endpoint expected for ${escapeHTML(e.agent)}; it leaves this list"><svg class="icon"><use href="#i-shield"/></svg><span>Allow</span></button>
      <button class="btn btn-ghost btn-sm" data-action="endpoint-detail" data-host="${escapeHTML(e.host)}" data-agent="${escapeHTML(e.agent)}" title="Identify this endpoint and see every connection to it"><svg class="icon"><use href="#i-activity"/></svg><span>Evidence</span></button>
    </div>
  </div>`;
}

