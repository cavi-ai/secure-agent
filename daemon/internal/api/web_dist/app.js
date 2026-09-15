document.addEventListener('DOMContentLoaded', () => {
  // Console auth: the menubar opens /dashboard/#ct=<console-token>. The token
  // gates the telemetry endpoints on this listener (the proxy token agents
  // carry is a different credential and is NOT accepted here). A fragment is
  // used because fragments are never sent to the server — the token stays off
  // the wire and out of server logs.
  //
  // The fragment is lifted, kept for the life of the TAB in sessionStorage,
  // and stripped from the address bar. Without the sessionStorage copy a
  // single reload lost the token (fragments don't survive navigation) and the
  // console sat behind a wall of 403s showing "can't reach the daemon"
  // forever. sessionStorage (not localStorage): the token dies with the tab
  // and never touches disk-backed storage.
  const SS_TOKEN_KEY = 'sa.console-token';
  let consoleToken = new URLSearchParams(location.hash.slice(1)).get('ct') || '';
  if (consoleToken) {
    try { sessionStorage.setItem(SS_TOKEN_KEY, consoleToken); } catch { /* private mode: memory only */ }
    if (window.history.replaceState) {
      history.replaceState(null, '', location.pathname + location.search);
    }
  } else {
    try { consoleToken = sessionStorage.getItem(SS_TOKEN_KEY) || ''; } catch { consoleToken = ''; }
  }
  const authHeaders = consoleToken ? { 'X-SecureAgent-Console-Token': consoleToken } : {};

  // Every request carries a timeout: a hung endpoint must not wedge the whole
  // refresh cycle (Promise.all resolves only as fast as its slowest member).
  const FETCH_TIMEOUT_MS = 5000;
  const apiFetch = (path, opts = {}) => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
    return fetch(path, { ...opts, signal: ctl.signal, headers: { ...authHeaders, ...(opts.headers || {}) } })
      .finally(() => clearTimeout(timer));
  };

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
    uninspected: [],  // /egress/uninspected rows — the drill-down list
    notifyCfg: null,  // /notify/rules payload — notification preferences
    connected: true
  };

  // ---------- connectivity ----------
  // Three honest states, never conflated:
  //  - 'ok':           fetches succeed.
  //  - 'auth-expired': the daemon answers 403 — the token is missing or
  //                    rotated. Only the menubar can mint a fresh session;
  //                    say so instead of pretending the daemon is down.
  //  - 'unreachable':  network-level failure — the daemon or its proxy
  //                    listener is gone; the last known state stays visible.
  let connState = 'ok';
  let prevUptimeSec = 0;
  // Endpoints that failed in the last cycle — each failure surfaces ONCE as a
  // toast so a dying endpoint can't silently blank its panel.
  const failedEndpoints = new Set();

  function noteEndpointFailure(key) {
    if (failedEndpoints.has(key)) return;
    failedEndpoints.add(key);
    showToast(`Couldn't load ${key} — will keep retrying`, 'danger');
  }

  // parseUptimeSec reads Go duration strings ("20h3m44s", "2s", "1m5s").
  function parseUptimeSec(s) {
    if (!s) return 0;
    let sec = 0, m;
    const re = /(\d+)(h|m|s)/g;
    while ((m = re.exec(s)) !== null) {
      const v = Number(m[1]);
      sec += m[2] === 'h' ? v * 3600 : m[2] === 'm' ? v * 60 : v;
    }
    return sec;
  }

  function updateOfflineBanner() {
    const banner = document.getElementById('offline-banner');
    if (!banner) return;
    const text = banner.querySelector('span');
    if (connState === 'ok') { banner.hidden = true; return; }
    banner.hidden = false;
    if (text) {
      text.textContent = connState === 'auth-expired'
        ? 'Session expired — reopen the console from the Secure Agent menu bar to reconnect.'
        : "Can't reach the Secure Agent daemon — showing the last known state and retrying…";
    }
  }

  function setConnState(next) {
    connState = next;
    updateOfflineBanner();
    renderStatus();
  }

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
  let timelinePids = null;
  let timelinePidLabel = '';

  function sessionScopeOn() {
    return !!(timelineSession || (timelinePids && timelinePids.length));
  }
  function sessionScopeTag() {
    return timelineSession ? sessionShort(timelineSession) : (timelinePidLabel || ('PID ' + timelinePids[0]));
  }
  function paintSessionChip(chipId, labelId, count) {
    const chip = document.getElementById(chipId);
    if (!chip) return;
    const on = sessionScopeOn();
    chip.hidden = !on;
    if (on) {
      const el = document.getElementById(labelId);
      if (el) el.textContent = `${sessionScopeTag()} · ${count}`;
    }
  }

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

  // ---------- tabs ----------
  // The console is organized by question (Overview / Agents / Egress /
  // Findings), not by data source. State persists per tab-session; the hash
  // carries the tab for deep links (#ct is lifted and stripped BEFORE this
  // runs, so the two never collide).
  const TABS = ['overview', 'agents', 'egress', 'findings'];
  let activeTab = 'overview';

  function switchTab(id, opts = {}) {
    if (!TABS.includes(id)) id = 'overview';
    activeTab = id;
    document.querySelectorAll('.tab-btn').forEach(b => {
      const on = b.dataset.tab === id;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.tabpanel').forEach(p => { p.hidden = p.id !== 'tab-' + id; });
    try { sessionStorage.setItem('sa.console-tab', id); } catch { /* private mode */ }
    if (!opts.skipHash && window.history.replaceState) {
      history.replaceState(null, '', location.pathname + location.search + '#' + id);
    }
  }

  document.querySelectorAll('.tab-btn').forEach(b =>
    b.addEventListener('click', () => switchTab(b.dataset.tab)));

  // Initial tab: hash (deep link) > session memory > overview.
  let initialTab = (location.hash || '').replace('#', '');
  if (!TABS.includes(initialTab)) {
    try { initialTab = sessionStorage.getItem('sa.console-tab') || 'overview'; }
    catch { initialTab = 'overview'; }
  }
  switchTab(initialTab, { skipHash: true });

  // Tab badges: the "something needs you here" signal for hidden panels.
  function setTabBadge(id, n) {
    const el = document.getElementById('tab-badge-' + id);
    if (!el) return;
    el.hidden = !(n > 0);
    el.textContent = n > 0 ? n : '';
  }

  async function fetchTelemetry(opts) {
    // grab(): one fetch with honest failure semantics. 403 = the session is
    // dead (drives the auth-expired state); other HTTP errors mark just that
    // endpoint failed; network errors drive the unreachable state. A failed
    // endpoint NEVER overwrites the panel's last good data.
    const slow = !opts || opts.slow !== false;
    let sawAuth = false;
    const grab = async (key, path) => {
      try {
        const r = await apiFetch(path);
        if (r.status === 403) { sawAuth = true; return null; }
        if (!r.ok) { noteEndpointFailure(key); return null; }
        failedEndpoints.delete(key);
        return await r.json();
      } catch { return null; } // network error, timeout, or corrupt JSON
    };

    const snap = await grab('snapshot', '/snapshot');
    if (snap) {
      const status = snap.status;
      if (status) {
        const up = parseUptimeSec(status.uptime);
        if (prevUptimeSec > 0 && up < prevUptimeSec - 5) {
          showToast('Daemon restarted — reconnected to the new instance', 'info');
          prevEventKeys = new Set();
          firstEventRender = true;
        }
        prevUptimeSec = up;
        telemetryData.status = status;
      }
      if (snap.flags) telemetryData.flags = (snap.flags || []).filter(f => !f.acknowledged);
      if (snap.incidents) telemetryData.incidents = snap.incidents || [];
      if (snap.events) telemetryData.events = snap.events || [];
      if (snap.posture) telemetryData.posture = snap.posture;
      if (snap.suggestions) telemetryData.suggestions = snap.suggestions || [];
      if (snap.mutes) telemetryData.mutes = snap.mutes || [];
    }

    if (slow) {
      const [fleet, audit, sources, rollup, uninspected, notifyCfg] = await Promise.all([
        grab('fleet', '/fleet'),
        grab('audit', '/audit?limit=50'),
        grab('firewall sources', '/firewall/sources'),
        grab('activity rollup', '/stats/rollup?hours=168'),
        grab('uninspected egress', '/egress/uninspected?hours=24&limit=200'),
        grab('notification rules', '/notify/rules')
      ]);
      if (fleet) telemetryData.fleet = fleet || [];
      if (audit) telemetryData.audit = audit || [];
      if (sources) telemetryData.sources = sources || [];
      if (rollup) telemetryData.rollup = rollup || [];
      if (uninspected) telemetryData.uninspected = uninspected || [];
      if (notifyCfg) telemetryData.notifyCfg = notifyCfg;
    }

    telemetryData.flagsView = telemetryData.flags;
    telemetryData.eventsView = telemetryData.events;
    sparkIngestEvents(telemetryData.events);
    if (isFlagsFiltered()) {
      const v = await grab('flags', flagsQuery());
      if (v) telemetryData.flagsView = (v || []).filter(f => !f.acknowledged);
    }
    if (isEventsFiltered()) {
      const v = await grab('events', eventsQuery());
      if (v) telemetryData.eventsView = v || [];
    }

    reconcileRetriage();

    telemetryData.connected = !!(snap && snap.status);
    setConnState(telemetryData.connected ? 'ok' : (sawAuth ? 'auth-expired' : 'unreachable'));

    renderAll();
  }

  function renderAll() {
    // Crash isolation: one panel's bad data must never take the whole page
    // down with it. The /fleet shape mismatch (object, not array) threw in
    // renderFleet and silently killed every panel after it — flags, events,
    // activity — on every single poll.
    const panels = [
      ['posture', renderPosture], ['status', renderStatus], ['sessions', renderSessionBoard],
      ['agents', renderAgents],
      ['firewall', renderFirewall], ['incidents', renderIncidents], ['fleet', renderFleet],
      ['audit', renderAudit], ['sources', renderSources], ['flags', renderFlags],
      ['events', renderEvents], ['activity', renderActivity]
    ];
    for (const [name, fn] of panels) {
      try { fn(); } catch (err) { console.error(`render panel "${name}" failed:`, err); }
    }
  }

  // Activity rollup chart: hourly event bars with rose flag markers — the
  // "is this normal for this machine?" answer at a glance. The 24h/7d toggle
  // re-slices the same 7d fetch locally (no refetch).
  function renderActivity() {
    const svg = document.getElementById('activity-chart');
    if (!svg) return;
    const hours = Number(document.getElementById('activity-window')?.value || 24);
    const s = rollupSeries(telemetryData.rollup, hours, Date.now()); // lib.js
    const max = Math.max(1, ...s.events.map((v, i) => v + s.flags[i]));
    const W = 1200, H = 96, bw = W / hours;
    let bars = '';
    for (let i = 0; i < hours; i++) {
      const evH = (s.events[i] / max) * (H - 14);
      const flH = (s.flags[i] / max) * (H - 14);
      const x = (i * bw).toFixed(1);
      if (s.events[i] > 0) {
        bars += `<rect x="${x}" y="${(H - evH).toFixed(1)}" width="${(bw - 1).toFixed(1)}" height="${evH.toFixed(1)}" rx="1.5" class="act-ev"><title>${s.labels[i]} — ${s.events[i]} events${s.flags[i] ? `, ${s.flags[i]} flags` : ''}</title></rect>`;
      }
      if (s.flags[i] > 0) {
        bars += `<rect x="${x}" y="${(H - evH - flH).toFixed(1)}" width="${(bw - 1).toFixed(1)}" height="${flH.toFixed(1)}" rx="1.5" class="act-fl"/>`;
      }
      if (s.events[i] === 0 && s.flags[i] === 0) {
        bars += `<rect x="${x}" y="${H - 2}" width="${(bw - 1).toFixed(1)}" height="2" class="act-zero"/>`;
      }
    }
    svg.innerHTML = bars;
  }
  document.getElementById('activity-window')?.addEventListener('change', renderActivity);

  function renderStatus() {
    const chip = document.getElementById('system-status');
    if (!telemetryData.connected) {
      if (chip) chip.className = 'status-chip down';
      document.getElementById('status-text').textContent =
        connState === 'auth-expired' ? 'Session expired' : 'Disconnected';
      return; // keep last-known metrics visible
    }

    const s = telemetryData.status;
    if (!s) return;

    document.getElementById('status-text').textContent = s.running ? 'Daemon Active' : 'Disconnected';
    if (chip) chip.className = 'status-chip ' + (s.running ? 'active' : 'down');
    if (s.version) document.getElementById('app-version').textContent = s.version;
    document.getElementById('uptime-val').textContent = s.uptime || '--';
    document.getElementById('proxy-status').textContent = s.proxy_enabled ? `127.0.0.1:${s.proxy_port || 8443}` : 'Disabled';

    const agentList = s.agents || [];
    setKpi('count-agents', s.active_agents || agentList.length);
    const families = groupAgents(agentList);
    const hint = document.getElementById('hint-agents');
    if (hint) {
      hint.textContent = families.length
        ? `${families.length} ${families.length === 1 ? 'family' : 'families'} · ${agentList.length} ${agentList.length === 1 ? 'process' : 'processes'}`
        : 'Tagged in the process tree';
    }
    setKpi('count-flags', s.unacted_flags_24h != null
      ? s.unacted_flags_24h
      : unactedLast24h(telemetryData.flags, Date.now()).length);
    const openInc = (telemetryData.incidents || []).filter(inc => !inc.workflow || inc.workflow.status !== 'resolved');
    const inc24 = openInc.filter(inc => {
      const t = Date.parse(inc.timestamp);
      return !Number.isFinite(t) || t >= Date.now() - 24 * 3600e3;
    });
    setKpi('count-incidents', inc24.length);

    const proxyEvents = telemetryData.events.filter(e => e.kind === 9 || (e.detail && e.detail.includes('proxy')));
    setKpi('count-proxy', proxyEvents.length);
    if (chip && s.bus_drops) chip.title = s.bus_drops + ' event bus drops';
  }

  const sessionHelpOpen = {};

  function renderSessionBoard() {
    const container = document.getElementById('session-board');
    const badge = document.getElementById('badge-session-count');
    if (!container) return;
    const agents = (telemetryData.status && telemetryData.status.agents) ? telemetryData.status.agents : [];
    const trees = telemetryData.status && telemetryData.status.trees;
    const rows = sessionRows(agents, trees);
    if (badge) badge.textContent = rows.length;
    if (rows.length === 0) {
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No agents running yet — start Claude Code, Cursor, or Codex and they'll appear here</span></div>`;
      return;
    }
    const now = Date.now();
    container.innerHTML = sessionBoardHTML(rows, now, sessionHelpOpen);
    container.querySelectorAll('details.session-helpers').forEach(el => {
      el.addEventListener('toggle', () => {
        sessionHelpOpen[el.dataset.pid] = el.open;
      });
    });
  }

  const agentGroupOpen = {};

  function renderAgents() {
    const container = document.getElementById('agents-container');
    const badge = document.getElementById('badge-agents-count');
    const agents = (telemetryData.status && telemetryData.status.agents) ? telemetryData.status.agents : [];
    const families = groupAgents(agents);

    badge.textContent = families.length;
    setTabBadge('agents', families.length); // informative count, neutral styling

    if (agents.length === 0) {
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-agent"/></svg><span>No agents running yet — start Claude Code, Cursor, or Codex and they'll appear here</span></div>`;
      return;
    }

    const now = Date.now();
    const totalInstances = families.reduce((n, fam) => n + fam.roots.length, 0);
    container.innerHTML = families.map(f => {
      const open = familyShouldExpand(f, families.length, totalInstances, agentGroupOpen);
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
        agentGroupOpen[el.dataset.family] = el.open;
      });
    });
  }

  function renderInstance(root, members, now) {
    const kids = childrenOf(root, members);
    return `${renderProcessRow(root, now, false)}${kids.map(c => renderProcessRow(c, now, true)).join('')}`;
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
    setTabBadge('egress', uninspected);

    if (rules.length === 0 && uninspected === 0) {
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-shield"/></svg><span>No egress inspected yet — traffic is scanned as your agents run</span></div>`;
      prevFwStats = stats;
      return;
    }

    let html = '';
    if (uninspected > 0) {
      html += `<button type="button" class="fw-uninspected fw-drill" data-action="open-uninspected"><svg class="icon"><use href="#i-globe"/></svg><span>${uninspected} endpoint${uninspected === 1 ? '' : 's'} reached without inspection in the last 24h (pinned or unrouted)</span><span class="fw-drill-hint">view endpoints</span></button>`;
    }
    html += vendorKeyPromoteHTML(monitorVendorKeyIDs(stats));
    // Egress suggestions: recurring uninspected endpoints the user can approve
    // into the vendor allowlist with one click (drives the blind spot to zero).
    const suggestions = telemetryData.suggestions || [];
    if (suggestions.length > 0) {
      const vis = inspectionVisible(telemetryData.status, telemetryData.audit);
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
      if (it.kind === 'flag') link = `<a href="#" data-action="goto-tab" data-tab="findings">view evidence</a>`;
      if (it.kind === 'incident') link = `<a href="#" data-action="open-incident" data-id="${escapeHTML(it.id)}">view report</a>`;
      if (it.kind === 'guard_pending') link = `<span>resolve it in the menu bar app</span>`;
      if (it.kind === 'collector_down') link = `<span>— ${escapeHTML(it.detail || 'collector stopped')} <a href="#" data-action="open-fda">open Full Disk Access settings</a></span>`;
      if (it.kind === 'uninspected_egress') link = `<a href="#" data-action="open-uninspected">see endpoints</a>`;
      return `<li><span class="sev ${sev}">●</span><span>${escapeHTML(it.title)} ${link}</span></li>`;
    });
    // The fatigue reducer: when the local advisor has triaged the critical
    // flags and some read benign, say so at the one-glance level.
    const vis = inspectionVisible(telemetryData.status, telemetryData.audit);
    const criticals = vis.advisor
      ? (telemetryData.flags || []).filter(f => f.severity >= 3 && f.advisor && f.advisor.assessment)
      : [];
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
    const incidents = scopedBySession(telemetryData.incidents || [], timelineSession, timelinePids);

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
          <span class="kpi-hint">${inc.agent ? escapeHTML(inc.agent) + ' · ' : ''}${escapeHTML(inc.rule)} — PID ${inc.pid}</span>
          ${statusChip}
        </div>
        <div class="incident-summary">${escapeHTML(inc.summary)}</div>
        ${inspectionVisible(telemetryData.status, telemetryData.audit).advisor && inc.advisor_narrative ? `<div class="advisor-narrative"><svg class="icon"><use href="#i-agent"/></svg><span>${escapeHTML(inc.advisor_narrative)}</span></div>` : ''}
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
    const vis = inspectionVisible(telemetryData.status, telemetryData.audit);
    const fleetCol = document.getElementById('fleet-col');
    if (fleetCol) fleetCol.hidden = !vis.fleet;
    if (!vis.fleet) return;

    const container = document.getElementById('fleet-container');
    const badge = document.getElementById('badge-fleet-count');
    // /fleet returns THIS node's status OBJECT (hostname/os/agents/…), not an
    // array of remote nodes. Older console builds did fleet.map on it and
    // crashed renderAll — killing every panel below fleet on every poll.
    // Accept both shapes: object → one local node card; array → remote list.
    const raw = telemetryData.fleet;
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

  function renderAudit() {
    const vis = inspectionVisible(telemetryData.status, telemetryData.audit);
    const panel = document.getElementById('audit-panel');
    if (panel) panel.hidden = !vis.audit;
    if (!vis.audit) return;

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

  // ---------- advisor re-triage lifecycle ----------
  // id → { baseline, at }. Pending means "we asked, the model hasn't
  // answered yet" — the card shows a spinner, never a dead button. Mirrors
  // the menubar's flow.
  const pendingRetriage = new Map();
  const RETRIAGE_TIMEOUT_MS = 90000;
  const advisorSig = (v) => v ? `${v.assessment || ''}|${v.suggested_action || ''}|${v.rationale || ''}` : '';

  function reconcileRetriage() {
    if (!pendingRetriage.size) return;
    const health = telemetryData.status && telemetryData.status.advisor_health;
    for (const [id, p] of pendingRetriage) {
      const f = (telemetryData.flags || []).find(x => x.id === id);
      if (f && advisorSig(f.advisor) !== p.baseline) {
        pendingRetriage.delete(id);
        showToast(`Advisor verdict updated for ${f.rule}`, 'success');
      } else if (Date.now() - p.at > RETRIAGE_TIMEOUT_MS) {
        pendingRetriage.delete(id);
        showToast(health && health.circuit_open
          ? 'Advisor is offline (verdicts paused) — check the local model server'
          : "Advisor didn't answer within 90s — the model server may be busy or down", 'danger');
      }
    }
  }

  window.retriageFlag = async function(id) {
    const f = (telemetryData.flags || []).find(x => x.id === id);
    try {
      const res = await apiFetch('/advisor/retriage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flag_id: id })
      });
      if (!res.ok) throw new Error(await res.text());
      pendingRetriage.set(id, { baseline: advisorSig(f && f.advisor), at: Date.now() });
      renderFlags();
      fetchTelemetry();
    } catch (err) {
      showToast(`Advisor re-run failed: ${err.message || err}`, 'danger');
    }
  };

  // Dismiss ONE flag (acknowledge): reviewed-and-done — the flag leaves the
  // list, the rule keeps watching. The missing middle ground between "kill
  // the agent" and "suppress the class".
  window.dismissFlag = async function(id) {
    try {
      const res = await apiFetch('/flags/acknowledge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flag_id: id })
      });
      if (!res.ok) throw new Error(await res.text());
      telemetryData.flags = (telemetryData.flags || []).filter(x => x.id !== id);
      telemetryData.flagsView = (telemetryData.flagsView || []).filter(x => x.id !== id);
      showToast('Flag dismissed — the rule keeps watching', 'info');
      renderFlags();
      renderStatus();
      fetchTelemetry();
    } catch (err) {
      showToast(`Failed to dismiss flag: ${err.message || err}`, 'danger');
    }
  };

  // pid → agent name for human-readable timeline rows (a bare PID is the
  // ambiguous-process complaint; the name is what the operator recognizes).
  function agentNameFor(pid) {
    const list = (telemetryData.status && telemetryData.status.agents) || [];
    for (const a of list) {
      if (Number(a.pid) === Number(pid)) return a.name || '';
    }
    return '';
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

    const flags = scopedBySession(telemetryData.flagsView || [], timelineSession, timelinePids);
    const scopedInc = scopedBySession(telemetryData.incidents || [], timelineSession, timelinePids);
    paintSessionChip('flags-session-filter', 'flags-session-filter-id', flags.length);
    badge.textContent = flags.length;
    setTabBadge('findings', flags.length + scopedInc.length);

    if (flags.length === 0) {
      const msg = sessionScopeOn()
        ? `No flags for ${sessionScopeTag()} in the loaded window`
        : isFlagsFiltered() ? 'No flags match the current filter' : 'No security flags — agent egress looks clean';
      container.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-alert"/></svg><span>${msg}</span></div>`;
      return;
    }

    const advisorHealth = (telemetryData.status && telemetryData.status.advisor_health) || null;
    const advisorOffline = !!(advisorHealth && advisorHealth.circuit_open);
    const vis = inspectionVisible(telemetryData.status, telemetryData.audit);

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
      const isKeychain = f.rule === 'keychain-access' || f.rule === 'keychain-security-cli';
      const retriageBtn = !vis.advisor ? ''
        : pendingRetriage.has(f.id)
        ? `<span class="advisor-pending" title="The model is re-reading this flag — the fresh verdict lands here"><span class="spinner" aria-hidden="true"></span>advisor re-reading…</span>`
        : advisorOffline
          ? `<button class="btn btn-ghost btn-sm" disabled title="Advisor offline — verdicts paused (${escapeHTML(advisorHealth.last_error || 'model server unreachable')})"><svg class="icon"><use href="#i-refresh"/></svg><span>Advisor offline</span></button>`
          : `<button class="btn btn-ghost btn-sm" data-action="retriage" data-id="${escapeHTML(f.id)}" title="Ask the local model to re-read this flag"><svg class="icon"><use href="#i-refresh"/></svg><span>Re-run advisor</span></button>`;
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
            ${f.session_id ? `<button class="btn btn-ghost btn-sm" data-action="filter-session" data-session="${escapeHTML(f.session_id)}"><svg class="icon"><use href="#i-activity"/></svg><span>View session in timeline</span></button>` : ''}
            ${f.advisor && f.advisor.assessment === 'benign' && flagHost(f) ? `<button class="btn btn-ghost btn-sm" data-action="mute-flag" data-rule="${escapeHTML(f.rule)}" data-host="${escapeHTML(flagHost(f))}" title="Stop flagging ${escapeHTML(f.rule)} for ${escapeHTML(flagHost(f))} — reversible"><svg class="icon"><use href="#i-close"/></svg><span>Mute rule+host</span></button>` : ''}
            ${isKeychain ? `<button class="btn btn-ghost btn-sm" data-action="mute-rule" data-rule="${escapeHTML(f.rule)}" title="Stop flagging ${escapeHTML(f.rule)} entirely — reversible from the muted list below"><svg class="icon"><use href="#i-close"/></svg><span>Dismiss this flag class</span></button>` : ''}
            <button class="btn btn-danger btn-sm" data-action="kill" data-pid="${f.pid}" title="Terminate the agent process tree (pid ${f.pid})"><svg class="icon"><use href="#i-power"/></svg><span>Kill ${escapeHTML(f.agent)}</span></button>
          </div>
          <div class="flag-evidence">
            ${(f.evidence || []).map(ev => `<div>${escapeHTML(ev)}</div>`).join('')}
          </div>
        </div></div>
      </div>`;
    }).join('');

    // Dispositions: muted (rule, host) pairs, visible so the quiet is
    // deliberate and reversible.
    const mutes = telemetryData.mutes || [];
    if (mutes.length > 0) {
      container.innerHTML += `<div class="mute-list"><div class="mute-head">Muted</div>` + mutes.map(m => `
        <div class="mute-row">
          <span class="mute-pair">${escapeHTML(m.rule)} · ${m.host === '*' ? 'all hosts' : escapeHTML(m.host)}</span>
          <button class="source-remove" title="Unmute" data-action="unmute" data-rule="${escapeHTML(m.rule)}" data-host="${escapeHTML(m.host)}"><svg class="icon"><use href="#i-close"/></svg></button>
        </div>`).join('') + `</div>`;
    }
  }

  function renderEvents() {
    const container = document.getElementById('events-container');
    const allEvents = telemetryData.eventsView || [];
    let events = allEvents;
    if (timelineSession) events = filterEventsBySession(allEvents, timelineSession);
    else if (timelinePids && timelinePids.length) events = filterEventsByPids(allEvents, timelinePids);

    const chip = document.getElementById('session-filter');
    if (chip) paintSessionChip('session-filter', 'session-filter-id', events.length);

    if (events.length === 0) {
      const msg = timelineSession
        ? `No events for session ${sessionShort(timelineSession)} in the loaded window`
        : (timelinePids && timelinePids.length)
          ? `No events for ${timelinePidLabel || 'this session'} in the loaded window`
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
      // A bare PID is the ambiguous-process complaint — prefix the agent
      // name when the tagged tree can supply one.
      const agentName = agentNameFor(e.pid);
      const pidLabel = agentName ? `${agentName} · PID ${e.pid}` : `PID ${e.pid}`;

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
          <span class="pid" title="PID ${e.pid}">${escapeHTML(pidLabel)}</span>
          <span class="dtl">${escapeHTML(detailStr)}</span>
        </div>
      `;
    }).join('');

    prevEventKeys = new Set(events.map(eventKey));
    firstEventRender = false;
    suppressFreshOnce = false;
  }

  // The report modal is shared by two views: the incident report (markdown,
  // with a Copy button) and the uninspected-egress drill-down (row actions,
  // no Copy). modalMode tracks which one is open so action handlers can
  // re-render the right content after a mutation.
  let modalMode = null; // 'incident' | 'uninspected' | null

  window.openIncidentReport = async function(incidentId) {
    if (!reportModal) return;
    modalMode = 'incident';
    const bodyEl = document.getElementById('modal-report-body');
    const titleEl = document.getElementById('modal-title');
    if (btnCopyReport) btnCopyReport.style.display = '';
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

  // Uninspected-egress drill-down: the count in the firewall panel becomes a
  // list the operator can act on (allow the endpoint, read the advisor's
  // verdict) instead of a dead end.
  function fillUninspected(bodyEl) {
    const rows = telemetryData.uninspected || [];
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
            ${inspectionVisible(telemetryData.status, telemetryData.audit).advisor && e.assessment ? `<span class="advisor-chip adv-${escapeHTML(e.assessment)}" title="${escapeHTML(e.rationale)}">advisor: ${escapeHTML(e.assessment)}</span>` : ''}
          </div>
        </div>
        <button class="btn btn-ghost btn-sm" data-action="allow-host" data-agent="${escapeHTML(e.agent)}" data-host="${escapeHTML(e.host)}"><svg class="icon"><use href="#i-shield"/></svg><span>Allow for ${escapeHTML(e.agent)}</span></button>
      </div>`).join('');
  }

  window.openUninspected = function() {
    if (!reportModal) return;
    modalMode = 'uninspected';
    const bodyEl = document.getElementById('modal-report-body');
    const titleEl = document.getElementById('modal-title');
    if (btnCopyReport) btnCopyReport.style.display = 'none';
    titleEl.innerHTML = `<svg class="icon"><use href="#i-globe"/></svg>Uninspected egress — last 24h`;
    fillUninspected(bodyEl);
    if (!reportModal.open) reportModal.showModal();
  };

  window.killProcess = async function(pid, startedAt, family) {
    const when = startedAt ? ` started ${startedAt}` : '';
    const who = family ? `${family} ` : '';
    if (!confirm(`Terminate process tree ${who}PID ${pid}${when}?`)) return;
    const body = { pid };
    if (startedAt) body.started_at = startedAt;
    try {
      const res = await apiFetch('/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (res.ok) {
        showToast(`Process tree PID ${pid} terminated.`, 'success');
        fetchTelemetry();
      } else {
        showToast(`Failed to terminate PID ${pid}.`, 'danger');
      }
    } catch (err) {
      showToast(`Error terminating PID ${pid}: ${err}`, 'danger');
    }
  };

  window.killOrphans = async function(family) {
    const agents = (telemetryData.status && telemetryData.status.agents) ? telemetryData.status.agents : [];
    const orphans = agents.filter(a => a.name === family && a.is_orphan);
    if (orphans.length === 0) return;
    if (!confirm(`Terminate ${orphans.length} leftover ${family} process${orphans.length === 1 ? '' : 'es'}?`)) return;
    for (const a of orphans) {
      const body = { pid: a.pid };
      if (a.started_at) body.started_at = a.started_at;
      try {
        const res = await apiFetch('/kill', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        if (!res.ok) showToast(`Failed to terminate PID ${a.pid}.`, 'danger');
      } catch (err) {
        showToast(`Error terminating PID ${a.pid}: ${err}`, 'danger');
      }
    }
    showToast(`Leftover ${family} processes terminated.`, 'success');
    fetchTelemetry();
  };

  window.allowHost = async function(agent, host) {
    try {
      const res = await apiFetch('/allowlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent, host })
      });
      if (res.ok) {
        showToast(`Allowlisted ${host} for ${agent}`, 'success');
        await fetchTelemetry();
        // Refresh the drill-down in place: the allowed pair should disappear.
        if (modalMode === 'uninspected' && reportModal && reportModal.open) {
          fillUninspected(document.getElementById('modal-report-body'));
        }
      } else {
        showToast(`Failed to allowlist ${host}.`, 'danger');
      }
    } catch (err) {
      showToast(`Error allowlisting ${host}: ${err}`, 'danger');
    }
  };

  window.openFDASettings = async function() {
    try {
      const res = await apiFetch('/ui/open-fda', { method: 'POST' });
      if (res.ok) {
        showToast('Opening System Settings → Full Disk Access', 'info');
      } else {
        showToast('Could not open settings — open Setup & Permissions from the menu bar instead.', 'danger');
      }
    } catch (err) {
      showToast(`Could not open settings: ${err}`, 'danger');
    }
  };

  window.muteFlag = async function(rule, host) {
    try {
      const res = await apiFetch('/mute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, host })
      });
      if (res.ok) {
        showToast(host === '*'
          ? `Dismissed ${rule} — future flags of this class are suppressed`
          : `Muted ${rule} for ${host} — future flags suppressed`, 'success');
        fetchTelemetry();
      } else {
        showToast(`Failed to mute: ${await res.text()}`, 'danger');
      }
    } catch (err) {
      showToast(`Error muting: ${err}`, 'danger');
    }
  };

  window.unmuteFlag = async function(rule, host) {
    try {
      const res = await apiFetch(`/mute?rule=${encodeURIComponent(rule)}&host=${encodeURIComponent(host)}`, { method: 'DELETE' });
      if (res.ok) {
        showToast(`Unmuted ${rule} for ${host}`, 'info');
        fetchTelemetry();
      } else {
        showToast(`Failed to unmute.`, 'danger');
      }
    } catch (err) {
      showToast(`Error unmuting: ${err}`, 'danger');
    }
  };

  window.promoteVendorKeys = async function() {
    try {
      const res = await apiFetch('/firewall/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'vendor-key', mode: 'block' })
      });
      if (res.ok) {
        const body = await res.json().catch(() => ({}));
        const n = (body.promoted || []).length;
        showToast(n ? `Promoted ${n} vendor-key rule${n === 1 ? '' : 's'} to block.` : 'Vendor-key rules already blocking.', 'success');
        fetchTelemetry();
      } else {
        showToast('Failed to promote vendor-key rules.', 'danger');
      }
    } catch (err) {
      showToast(`Error promoting vendor-key rules: ${err}`, 'danger');
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
    timelinePids = null;
    timelinePidLabel = '';
    suppressFreshOnce = true;
    renderEvents();
    renderFlags();
    renderIncidents();
    switchTab('overview');
    const el = document.getElementById('events-container');
    if (el && el.scrollIntoView) {
      el.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'nearest' });
    }
  };

  window.filterTimelineToPids = function(pids, label) {
    timelineSession = null;
    timelinePids = (pids || []).map(Number).filter(n => n > 0);
    timelinePidLabel = label || '';
    suppressFreshOnce = true;
    renderEvents();
    renderFlags();
    renderIncidents();
    switchTab('overview');
    const el = document.getElementById('events-container');
    if (el && el.scrollIntoView) {
      el.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'nearest' });
    }
  };

  window.clearTimelineSession = function() {
    timelineSession = null;
    timelinePids = null;
    timelinePidLabel = '';
    suppressFreshOnce = true;
    renderEvents();
    renderFlags();
    renderIncidents();
  };

  const btnSessionClear = document.getElementById('session-clear');
  if (btnSessionClear) btnSessionClear.addEventListener('click', () => window.clearTimelineSession());
  const btnFlagsSessionClear = document.getElementById('flags-session-clear');
  if (btnFlagsSessionClear) btnFlagsSessionClear.addEventListener('click', () => window.clearTimelineSession());

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
        e.preventDefault();
        e.stopPropagation();
        window.killProcess(Number(d.pid), d.started, d.family);
        break;
      case 'kill-orphans':
        e.preventDefault();
        e.stopPropagation();
        window.killOrphans(d.family);
        break;
      case 'promote':
        window.promoteRule(d.rule);
        break;
      case 'promote-vendor-keys':
        window.promoteVendorKeys();
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
      case 'filter-pids':
        e.preventDefault();
        window.filterTimelineToPids((d.pids || '').split(','), d.label);
        break;
      case 'allow-host':
        window.allowHost(d.agent, d.host);
        break;
      case 'mute-flag':
        window.muteFlag(d.rule, d.host);
        break;
      case 'mute-rule':
        window.muteFlag(d.rule, '*');
        break;
      case 'dismiss-flag':
        window.dismissFlag(d.id);
        break;
      case 'retriage':
        window.retriageFlag(d.id);
        break;
      case 'open-uninspected':
        e.preventDefault();
        window.openUninspected();
        break;
      case 'goto-tab':
        e.preventDefault();
        switchTab(d.tab);
        break;
      case 'unmute':
        window.unmuteFlag(d.rule, d.host);
        break;
      case 'open-fda':
        e.preventDefault();
        window.openFDASettings();
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

  // ---------- notification preferences ----------
  // Per-rule overrides over the daemon's default policy (severity >= 3
  // notifies). Each rule gets Default / Always / Never; the menubar reads the
  // same store, so one choice silences both surfaces.
  const NOTIFY_RULES = [
    ['proxy-secret-leak', 'Secret leaving in agent traffic'],
    ['sensitive-read-then-connect', 'Secret read, then connected out'],
    ['keychain-access', 'Keychain file access'],
    ['keychain-security-cli', 'Keychain CLI (security tool)'],
    ['tcc-tamper', 'Privacy permissions (TCC) tamper'],
    ['proxy-prompt-injection', 'Prompt injection in a response']
  ];

  function renderNotifyRules() {
    const list = document.getElementById('notify-rules-list');
    if (!list) return;
    const overrides = (telemetryData.notifyCfg && telemetryData.notifyCfg.overrides) || {};
    list.innerHTML = NOTIFY_RULES.map(([rule, label]) => {
      const cur = rule in overrides ? (overrides[rule] ? 'always' : 'never') : 'default';
      return `<div class="notify-rule-row">
        <span class="notify-rule-name" title="${escapeHTML(rule)}">${escapeHTML(label)}</span>
        <select class="select select-sm" data-notify-rule="${escapeHTML(rule)}" aria-label="Notifications for ${escapeHTML(label)}">
          <option value="default"${cur === 'default' ? ' selected' : ''}>Default</option>
          <option value="always"${cur === 'always' ? ' selected' : ''}>Always</option>
          <option value="never"${cur === 'never' ? ' selected' : ''}>Never</option>
        </select>
      </div>`;
    }).join('');
  }

  const btnNotify = document.getElementById('btn-notify');
  const notifyPop = document.getElementById('notify-pop');
  if (btnNotify && notifyPop) {
    btnNotify.addEventListener('click', (e) => {
      e.stopPropagation();
      renderNotifyRules();
      notifyPop.hidden = !notifyPop.hidden;
    });
    document.addEventListener('click', (e) => {
      if (!notifyPop.hidden && !e.target.closest('.notify-wrap')) notifyPop.hidden = true;
    });
    notifyPop.addEventListener('change', async (e) => {
      const sel = e.target.closest('select[data-notify-rule]');
      if (!sel) return;
      const rule = sel.dataset.notifyRule;
      const v = sel.value;
      const body = v === 'default' ? { rule, notify: null } : { rule, notify: v === 'always' };
      try {
        const res = await apiFetch('/notify/rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        if (!res.ok) throw new Error(await res.text());
        showToast(v === 'default' ? `${rule}: back to the default policy`
          : v === 'always' ? `${rule}: will always notify`
          : `${rule}: notifications off`, 'success');
        fetchTelemetry();
      } catch (err) {
        showToast(`Failed to update notification rule: ${err.message || err}`, 'danger');
      }
    });
  }

  // Live updates: SSE push when the endpoint is available, with a 2s poll as
  // the fallback (older daemon, or a stream that keeps failing). The stream
  // carries the guard lifecycle (guard-prompt/guard-resolved), so pending
  // prompts surface immediately instead of up to 2s late. A slow 30s refresh
  // always runs for status/uptime, which change without any bus event.
  fetchTelemetry();
  setInterval(fetchTelemetry, 30000);

  let pollTimer = null;
  const startPolling = () => {
    // Auth-expired sessions retry on the slow 30s cadence only — a dead token
    // doesn't deserve a 2s hammer against a wall of 403s.
    if (connState === 'auth-expired') return;
    if (!pollTimer) pollTimer = setInterval(fetchTelemetry, 2000);
  };
  const stopPolling = () => { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } };

  // Testability hook: ?nosse skips the push stream (headless E2E can then
  // use virtual time — a pending SSE response stalls the virtual clock).
  const noSSE = new URLSearchParams(location.search).has('nosse');

  if (window.EventSource && !noSSE) {
    const streamURL = '/events/stream' + (consoleToken ? '?ct=' + encodeURIComponent(consoleToken) : '');
    let esFailures = 0;
    let refreshPending = false;
    const scheduleRefresh = () => {
      if (refreshPending) return;
      refreshPending = true;
      setTimeout(() => { refreshPending = false; fetchTelemetry({ slow: false }); }, 400);
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
