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
  const hashParams = new URLSearchParams(location.hash.slice(1));
  let consoleToken = hashParams.get('ct') || '';
  if (consoleToken) {
    try { sessionStorage.setItem(SS_TOKEN_KEY, consoleToken); } catch { /* private mode: memory only */ }
    if (window.history.replaceState) {
      // Strip the token from the address bar but PRESERVE a tab deep-link
      // (#ct=…&tab=egress → #egress) — the hero's "open the drill-down"
      // depends on it surviving the handoff.
      const tab = hashParams.get('tab');
      history.replaceState(null, '', location.pathname + location.search + (tab ? '#' + tab : ''));
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
  const drawer = document.getElementById('drawer');
  const drawerBody = document.getElementById('drawer-body');
  const drawerFoot = document.getElementById('drawer-foot');
  const drawerTitle = document.getElementById('drawer-title-text');
  const drawerTitleIcon = document.querySelector('#drawer-title use');
  const btnDrawerClose = document.getElementById('btn-drawer-close');
  const btnDrawerCopy = document.getElementById('btn-drawer-copy');

  // Screen-reader announcements for state the eye would catch on its own.
  const liveRegion = document.getElementById('a11y-live');
  window.saAnnounce = function(text) {
    if (!liveRegion || !text) return;
    liveRegion.textContent = '';
    // A tick later so repeated identical strings re-announce.
    setTimeout(() => { liveRegion.textContent = text; }, 30);
  };

  // ---------- drawer ----------
  // One slide-over replaces every native <dialog>. A native modal's backdrop
  // is painted by the UA from the SYSTEM color-scheme, which inverted fg/bg
  // when the page theme was pinned to the other scheme. This surface is plain
  // DOM styled only from our tokens, so it always matches the page.
  //
  // The drawer is a single reusable surface: title + body + optional footer
  // actions. Only one is open at a time; closing restores focus to the opener.
  let drawerOpener = null;
  let drawerOnClose = null;

  function openDrawer({ title, icon, body, foot, variant, onClose }) {
    if (!drawer) return false;
    drawerOpener = document.activeElement;
    drawerOnClose = onClose || null;
    drawerTitle.textContent = title || 'Details';
    if (icon && drawerTitleIcon) drawerTitleIcon.setAttribute('href', '#i-' + icon);
    drawerBody.innerHTML = body || '';
    drawerFoot.innerHTML = foot || '';
    drawerFoot.hidden = !foot;
    drawer.className = 'drawer' + (variant ? ' ' + variant : '');
    drawer.hidden = false;
    // Reserve room so the panel docks beside the content instead of covering
    // it — this is an inspector, not a modal.
    const app = document.querySelector('.app');
    if (app) {
      app.classList.add('drawer-open');
      app.classList.toggle('drawer-wide', !!variant);
    }
    return true;
  }

  function closeDrawer() {
    if (!drawer || drawer.hidden) return;
    drawer.hidden = true;
    drawerBody.innerHTML = '';
    drawerFoot.innerHTML = '';
    drawerFoot.hidden = true;
    const app = document.querySelector('.app');
    if (app) app.classList.remove('drawer-open', 'drawer-wide');
    const fn = drawerOnClose;
    drawerOnClose = null;
    if (drawerOpener && typeof drawerOpener.focus === 'function') drawerOpener.focus();
    drawerOpener = null;
    if (fn) fn();
  }
  window.saCloseDrawer = closeDrawer;

  if (btnDrawerClose) btnDrawerClose.addEventListener('click', closeDrawer);
  if (drawer) {
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && drawer && !drawer.hidden) closeDrawer();
    });
  }

  // Confirmation / prompt. A small stacked card (z-index above the drawer),
  // NOT the drawer itself: a confirm raised from inside the policy editor must
  // not blow away the editor behind it. Returns a Promise so call sites read
  // like the native confirm()/prompt() they replaced.
  const confirmLayer = document.getElementById('confirm-layer');
  const confirmTitleEl = document.getElementById('confirm-title');
  const confirmMessageEl = document.getElementById('confirm-message');
  const confirmInputEl = document.getElementById('confirm-input');
  const confirmOkEl = document.getElementById('confirm-ok');
  const confirmCancelEl = document.getElementById('confirm-cancel');

  function saDialog({ title, message, okLabel, withInput, placeholder, danger }) {
    if (!confirmLayer) {
      const text = withInput ? window.prompt(message, '') : null;
      return Promise.resolve(withInput ? text : window.confirm(message));
    }
    confirmTitleEl.textContent = title || 'Confirm';
    confirmMessageEl.textContent = message || '';
    confirmOkEl.textContent = okLabel || 'Confirm';
    confirmOkEl.className = 'btn ' + (danger === false ? 'btn-primary' : 'btn-danger');
    confirmInputEl.hidden = !withInput;
    confirmInputEl.value = '';
    if (withInput) confirmInputEl.placeholder = placeholder || '';
    confirmLayer.hidden = false;
    (withInput ? confirmInputEl : confirmOkEl).focus();

    return new Promise((resolve) => {
      const finish = (value) => {
        confirmOkEl.removeEventListener('click', okHandler);
        confirmCancelEl.removeEventListener('click', cancelHandler);
        confirmLayer.hidden = true;
        resolve(value);
      };
      const okHandler = () => finish(withInput ? (confirmInputEl.value || '') : true);
      const cancelHandler = () => finish(withInput ? null : false);
      confirmOkEl.addEventListener('click', okHandler, { once: true });
      confirmCancelEl.addEventListener('click', cancelHandler, { once: true });
    });
  }
  window.saConfirm = (message, opts = {}) => saDialog({ message, danger: true, ...opts });
  window.saPrompt = (message, opts = {}) => saDialog({ message, withInput: true, danger: false, ...opts });

  // Theme: explicit pin (persisted) or follow the system. The pre-paint
  // inline script already applied the initial choice; this wires the toggle.
  (function initTheme() {
    const mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;
    const apply = (mode) => {
      const theme = mode === 'system'
        ? (mq && mq.matches ? 'light' : 'dark')
        : mode;
      document.documentElement.dataset.theme = theme;
      for (const m of ['system', 'light', 'dark']) {
        const b = document.getElementById('theme-' + m);
        if (b) b.setAttribute('aria-pressed', m === mode ? 'true' : 'false');
      }
    };
    let mode = 'system';
    try { mode = localStorage.getItem('sa-theme') || 'system'; } catch { /* memory only */ }
    apply(mode);
    for (const m of ['system', 'light', 'dark']) {
      const b = document.getElementById('theme-' + m);
      if (b) b.addEventListener('click', () => {
        mode = m;
        try { m === 'system' ? localStorage.removeItem('sa-theme') : localStorage.setItem('sa-theme', m); } catch { /* ok */ }
        apply(m);
      });
    }
    if (mq && mq.addEventListener) mq.addEventListener('change', () => { if (mode === 'system') apply('system'); });
  })();

  let currentRawMarkdown = '';

  btnRefresh.addEventListener('click', () => {
    fetchTelemetry();
    showToast('Refreshing telemetry data...', 'info');
  });

  const btnAddSource = document.getElementById('btn-add-source');
  const sourceInput = document.getElementById('source-input');
  if (btnAddSource) btnAddSource.addEventListener('click', () => window.addSource());
  if (sourceInput) sourceInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') window.addSource(); });

  if (btnDrawerCopy) {
    btnDrawerCopy.addEventListener('click', async () => {
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
    resources: null,
    flags: [],       // unfiltered — feeds KPIs
    flagsView: [],   // filtered — feeds the flags panel
    incidents: [],
    events: [],       // unfiltered — feeds KPIs
    eventsView: [],   // filtered — feeds the event timeline
    fleet: [],
    audit: [],
    sources: [],
    uninspected: [],  // /egress/uninspected rows — the drill-down list
    guardPending: [], // blocked tool calls waiting for an operator decision
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
  // markZero flags an element whose numeric value is zero, so CSS can drop
  // its severity colour (a red "0 flags" is noise, not a warning). A CLASS,
  // not a data attribute: the class sits before the id in the markup, so the
  // exact `id="count-flags">N<` shape stays intact for tests and tooling.
  function markZero(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle('is-zero', String(el.textContent).trim() === '0');
  }

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
  let selectedResourceKey = '';

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

  // ---------- saved views ----------
  // A view is a named snapshot of what the operator is looking at: the tab,
  // the flag/event filters, and the free-text search. Persisted in
  // localStorage (per browser, not per daemon — a view is a UI convenience,
  // not a fleet policy). No secrets are stored; only filter values.
  const VIEWS_KEY = 'sa.views';
  function loadViews() {
    try { return JSON.parse(localStorage.getItem(VIEWS_KEY) || '[]') || []; } catch { return []; }
  }
  function persistViews(views) {
    try { localStorage.setItem(VIEWS_KEY, JSON.stringify(views)); } catch { /* private mode */ }
  }
  function currentViewSnapshot(name) {
    return {
      name,
      tab: activeTab,
      search: (document.getElementById('global-search') || {}).value || '',
      flags: { ...filters.flags },
      events: { ...filters.events },
    };
  }
  window.saveCurrentView = function() {
    const nameEl = document.getElementById('view-name');
    const name = ((nameEl && nameEl.value) || '').trim();
    if (!name) { showToast('Give the view a name.', 'info'); return; }
    const views = loadViews().filter(v => v.name !== name);
    views.push(currentViewSnapshot(name));
    persistViews(views);
    if (nameEl) nameEl.value = '';
    renderViews();
    showToast(`View saved: ${name}`, 'success');
  };
  window.applyView = function(name) {
    const view = loadViews().find(v => v.name === name);
    if (!view) return;
    filters.flags = { ...filters.flags, ...(view.flags || {}) };
    filters.events = { ...filters.events, ...(view.events || {}) };
    const search = document.getElementById('global-search');
    if (search) search.value = view.search || '';
    syncFilterControls();
    const pop = document.getElementById('views-pop');
    if (pop) pop.hidden = true;
    if (view.tab && TABS.includes(view.tab)) switchTab(view.tab);
    suppressFreshOnce = true;
    fetchTelemetry();
    showToast(`View applied: ${name}`, 'info');
  };
  window.removeView = function(name) {
    persistViews(loadViews().filter(v => v.name !== name));
    renderViews();
  };
  function renderViews() {
    const list = document.getElementById('views-list');
    if (!list) return;
    const views = loadViews();
    list.innerHTML = views.length
      ? views.map(v => `<div class="view-row">
          <button class="view-load" data-action="apply-view" data-name="${escapeHTML(v.name)}" title="Apply ${escapeHTML(v.name)}">${escapeHTML(v.name)}</button>
          <span class="view-tab">${escapeHTML(v.tab || 'overview')}</span>
          <button class="source-remove" data-action="remove-view" data-name="${escapeHTML(v.name)}" title="Delete view"><svg class="icon"><use href="#i-close"/></svg></button>
        </div>`).join('')
      : '<div class="notify-scope-empty">No saved views yet</div>';
  }
  // Push the filter model back into the <select> controls after applying a view.
  function syncFilterControls() {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val; };
    set('flags-agent', filters.flags.agent);
    set('flags-rule', filters.flags.rule);
    set('flags-severity', filters.flags.minsev);
    set('flags-window', filters.flags.since);
    set('event-filter', filters.events.kind);
    set('event-window', filters.events.since);
  }
  {
    const btnViews = document.getElementById('btn-views');
    const viewsPop = document.getElementById('views-pop');
    if (btnViews && viewsPop) {
      btnViews.addEventListener('click', (e) => {
        e.stopPropagation();
        renderViews();
        viewsPop.hidden = !viewsPop.hidden;
      });
      document.addEventListener('click', (e) => {
        if (!viewsPop.hidden && !e.target.closest('.views-wrap')) viewsPop.hidden = true;
      });
    }
  }

  // ---------- global search ----------
  // One box that narrows the panels by free text. It matches agent, rule,
  // host, and evidence across the rendered lists — a client-side lens over
  // data already in hand, not a new query surface (the filters do that).
  let globalSearch = '';
  {
    const el = document.getElementById('global-search');
    if (el) el.addEventListener('input', () => {
      globalSearch = el.value.trim().toLowerCase();
      suppressFreshOnce = true;
      renderAll();
    });
  }
  window.globalSearchTerm = () => globalSearch;

  // ---------- export ----------
  // Download the current panel data as a file. Pure client-side: the console
  // already holds the rows; no new endpoint, no server round-trip, and the
  // file lands where the operator chose.
  window.exportData = function(which) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    let rows, filename;
    if (which === 'flags') { rows = telemetryData.flags || []; filename = `secure-agent-flags-${stamp}.json`; }
    else if (which === 'incidents') { rows = telemetryData.incidents || []; filename = `secure-agent-incidents-${stamp}.json`; }
    else { rows = telemetryData.events || []; filename = `secure-agent-events-${stamp}.json`; }
    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast(`Exported ${rows.length} ${which} → ${filename}`, 'success');
  };

  // ---------- tabs ----------
  // The console is organized by question (Overview / Agents / Egress /
  // Findings), not by data source. State persists per tab-session; the hash
  // carries the tab for deep links (#ct is lifted and stripped BEFORE this
  // runs, so the two never collide). "Telemetry" holds the per-source detail
  // (resource control + raw event timeline) split out of Overview.
  const TABS = ['overview', 'sessions', 'agents', 'resources', 'history', 'events', 'egress', 'findings'];
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

    const requests = [grab('snapshot', '/snapshot'), grab('guard decisions', '/guard/pending')];
    if (slow) requests.push(grab('resources', '/resources'));
    const [snap, guardPending, resources] = await Promise.all(requests);
    if (guardPending) telemetryData.guardPending = guardPending || [];
    if (resources) telemetryData.resources = resources;
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
      if (snap.sessions) telemetryData.sessions = snap.sessions || [];
    }

    if (slow) {
      const [fleet, audit, sources, rollup, uninspected, notifyCfg, allowlist, episodes] = await Promise.all([
        grab('fleet', '/fleet'),
        grab('audit', '/audit?limit=50'),
        grab('firewall sources', '/firewall/sources'),
        grab('activity rollup', '/stats/rollup?hours=168'),
        grab('uninspected egress', '/egress/uninspected?hours=24&limit=200'),
        grab('notification rules', '/notify/rules'),
        grab('allowlist', '/allowlist'),
        grab('resource episodes', '/resources/episodes')
      ]);
      if (fleet) telemetryData.fleet = fleet || [];
      if (audit) telemetryData.audit = audit || [];
      if (sources) telemetryData.sources = sources || [];
      if (rollup) telemetryData.rollup = rollup || [];
      if (uninspected) telemetryData.uninspected = uninspected || [];
      if (episodes) telemetryData.episodes = episodes || [];
      if (notifyCfg) telemetryData.notifyCfg = notifyCfg;
      if (allowlist) telemetryData.allowlist = allowlist || [];
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
      ['posture', renderPosture], ['status', renderStatus], ['resources', renderResourceMissionControl], ['history', renderResourceHistory], ['sessions', renderSessionBoard],
      ['chart-flags', renderChartFlags], ['chart-memory', renderChartMemory],
      ['agents', renderAgents],
      ['firewall', renderFirewall], ['incidents', renderIncidents], ['fleet', renderFleet],
      ['audit', renderAudit], ['sources', renderSources], ['flags', renderFlags], ['attention', renderAttention],
      ['events', renderEvents], ['activity', renderActivity]
    ];
    for (const [name, fn] of panels) {
      try { fn(); } catch (err) { console.error(`render panel "${name}" failed:`, err); }
    }
  }

  // Activity rollup chart: hourly event bars with rose flag markers — the
  // "is this normal for this machine?" answer at a glance. The 24h/7d toggle
  // re-slices the same 7d fetch locally (no refetch).
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

    // "Daemon Active" alone hid dead telemetry; the coverage suffix is the
    // monitor saying how many running harnesses it is actually seeing.
    let statusLine = s.running ? 'Daemon Active' : 'Disconnected';
    if (s.running && s.coverage && s.coverage.harnesses_active > 0) {
      statusLine += ` — seeing ${s.coverage.harnesses_seen}/${s.coverage.harnesses_active} harnesses`;
    }
    document.getElementById('status-text').textContent = statusLine;
    if (chip) chip.className = 'status-chip ' + (s.running ? 'active' : 'down');
    if (s.version) document.getElementById('app-version').textContent = s.version;
    document.getElementById('uptime-val').textContent = s.uptime || '--';
    document.getElementById('proxy-status').textContent = s.proxy_enabled ? `127.0.0.1:${s.proxy_port || 8443}` : 'Disabled';
    // The status chip's tooltip carries what the header used to spell out, so
    // uptime/proxy stay available without their own stat blocks.
    if (chip) {
      const up = document.getElementById('uptime-val')?.textContent || '--';
      const px = document.getElementById('proxy-status')?.textContent || '';
      chip.title = `uptime ${up}${s.proxy_enabled ? ` · proxy ${px}` : ''}`;
    }
    const uptimeMeta = document.getElementById('uptime-meta');
    if (uptimeMeta) uptimeMeta.textContent = 'up ' + (s.uptime || '--');
    // Coverage light: how many running harnesses the daemon is actually
    // seeing. Red only when it is provably blind (0 of a live count).
    const cov = document.getElementById('coverage-chip');
    if (cov) {
      if (s.coverage && s.coverage.harnesses_active > 0) {
        const seen = s.coverage.harnesses_seen, act = s.coverage.harnesses_active;
        cov.hidden = false;
        cov.textContent = `seeing ${seen}/${act}`;
        cov.className = 'ss-chip ' + (seen === 0 ? 'blind' : seen < act ? 'partial' : 'ok');
        cov.title = seen === 0
          ? 'The daemon is running but seeing no harness activity — hooks may not be registered'
          : `${seen} of ${act} running harnesses have attributed activity`;
      } else {
        cov.hidden = true;
      }
    }

    const agentList = s.agents || [];
    setKpi('count-agents', s.active_agents || agentList.length);
    const hint = document.getElementById('hint-agents');
    if (hint) {
      // Infra (IDEs, model servers) is tracked but never counted as agents.
      // Inline in the stat strip, so keep it to one short phrase.
      hint.textContent = s.infra_count ? `+${s.infra_count} infra` : '';
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
    // Severity colour only when the count is real: a red 0 reads as a bug.
    markZero('count-flags');
    markZero('count-incidents');
    if (chip && s.bus_drops) chip.title = s.bus_drops + ' event bus drops';
  }

  const sessionHelpOpen = {};
  const sessionGroupOpen = {};
  const endedSessionsOpen = {}; // harness key → ended tail expanded
  const agentGroupOpen = {};
  const agentTreeOpen = {}; // instance root pid → helper disclosure open

  // Harness filter shared by the Sessions and Agents tabs: pill states
  // (harness key → false when switched off), the text filter, and the
  // Sessions "live only" switch. Kept for the life of the tab, like the
  // selected console tab.
  const HARNESS_FILTER_KEY = 'sa.harness-filter';
  const harnessFilter = { harnesses: {}, text: '', liveOnly: true };
  try {
    const saved = JSON.parse(sessionStorage.getItem(HARNESS_FILTER_KEY) || '{}') || {};
    if (saved.harnesses && typeof saved.harnesses === 'object') harnessFilter.harnesses = saved.harnesses;
    if (typeof saved.text === 'string') harnessFilter.text = saved.text;
    if (typeof saved.liveOnly === 'boolean') harnessFilter.liveOnly = saved.liveOnly;
  } catch { /* private mode or unreadable: defaults */ }
  const harnessTextInputs = ['session-cwd-filter', 'agent-filter-text'].map(id => document.getElementById(id)).filter(Boolean);
  const liveOnlySwitch = document.getElementById('session-live-only');
  function syncHarnessFilterControls() {
    for (const el of harnessTextInputs) if (el.value !== harnessFilter.text) el.value = harnessFilter.text;
    if (liveOnlySwitch) liveOnlySwitch.checked = harnessFilter.liveOnly;
  }
  function harnessFilterChanged() {
    try { sessionStorage.setItem(HARNESS_FILTER_KEY, JSON.stringify(harnessFilter)); } catch { /* private mode */ }
    syncHarnessFilterControls();
    renderSessionBoard();
    renderAgents();
  }
  syncHarnessFilterControls();
  for (const el of harnessTextInputs) {
    el.addEventListener('input', () => { harnessFilter.text = el.value; harnessFilterChanged(); });
  }
  liveOnlySwitch?.addEventListener('change', () => { harnessFilter.liveOnly = liveOnlySwitch.checked; harnessFilterChanged(); });


  // Posture headline: the one-glance answer, plus clickable jump-off points
  // into the panels below (drill-down without leaving the page).

  // Incident workflow: acknowledge keeps it visible but marked seen; resolve
  // closes it with a note. Both hit /incidents/status and refresh.
  window.setIncidentStatus = async function(id, status) {
    const body = { id, status };
    if (status === 'resolved') {
      const note = await saPrompt('Resolve this incident. What did you do?', {
        title: 'Resolve incident', okLabel: 'Resolve', danger: false, placeholder: 'rotated the key, removed the file…'
      });
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

  // Tab renderers (tab-*.js) read this bag at call time so they stay outside
  // the DOMContentLoaded closure. Lets that are reassigned use accessors.
  window.SA = {
    t: telemetryData,
    sessionHelpOpen,
    sessionGroupOpen,
    endedSessionsOpen,
    agentGroupOpen,
    agentTreeOpen,
    harnessFilter,
    setTabBadge,
    paintSessionChip,
    sessionScopeOn,
    sessionScopeTag,
    reducedMotion,
    seenAgents,
    seenRules,
    syncSelect,
    agentNameFor,
    pendingRetriage,
    isFlagsFiltered,
    isEventsFiltered,
    globalSearchTerm,
  };
  Object.defineProperties(window.SA, {
    timelineSession: { get() { return timelineSession; }, set(v) { timelineSession = v; } },
    timelinePids: { get() { return timelinePids; }, set(v) { timelinePids = v; } },
    timelinePidLabel: { get() { return timelinePidLabel; }, set(v) { timelinePidLabel = v; } },
    prevFwStats: { get() { return prevFwStats; }, set(v) { prevFwStats = v; } },
    prevEventKeys: { get() { return prevEventKeys; }, set(v) { prevEventKeys = v; } },
    firstEventRender: { get() { return firstEventRender; }, set(v) { firstEventRender = v; } },
    suppressFreshOnce: { get() { return suppressFreshOnce; }, set(v) { suppressFreshOnce = v; } },
    selectedResourceKey: { get() { return selectedResourceKey; }, set(v) { selectedResourceKey = v; } },
    selectedSessionId: { get() { return selectedSessionId; }, set(v) { selectedSessionId = v; } },
    sessionTimeline: { get() { return sessionTimeline; }, set(v) { sessionTimeline = v; } },
  });

  // Session-first tab: selection + its trace. The timeline refetches on
  // select and when an event delta lands for the selected session.
  let selectedSessionId = '';
  let sessionTimeline = [];
  let sessionTimelineAt = 0;
  async function loadSessionTimeline(id, force) {
    if (!id) { sessionTimeline = []; return; }
    // Throttle refetches: deltas for the selected session arrive per event.
    if (!force && Date.now() - sessionTimelineAt < 2000) return;
    sessionTimelineAt = Date.now();
    const r = await apiFetch('/sessions/' + encodeURIComponent(id) + '/timeline?limit=500');
    if (r.ok) sessionTimeline = (await r.json()) || [];
  }
  window.selectSession = async function(id) {
    selectedSessionId = (selectedSessionId === id) ? '' : id;
    if (selectedSessionId) await loadSessionTimeline(selectedSessionId, true);
    renderAll();
  };

  // The drawer is shared by two views: the incident report (markdown, with a
  // Copy button) and the uninspected-egress drill-down (row actions, no
  // Copy). drawerMode tracks which one is open so action handlers can
  // re-render the right content after a mutation.
  let drawerMode = null; // 'incident' | 'uninspected' | null

  window.openIncidentReport = async function(incidentId) {
    if (!drawer) return;
    drawerMode = 'incident';
    if (btnDrawerCopy) btnDrawerCopy.hidden = false;
    openDrawer({
      title: `Incident report — ${incidentId}`,
      icon: 'doc',
      body: `<div class="loading-spinner">Fetching incident report…</div>`,
      onClose: () => { drawerMode = null; },
    });

    try {
      const res = await apiFetch(`/incidents?id=${encodeURIComponent(incidentId)}&format=markdown`);
      if (res.ok) {
        const text = await res.text();
        currentRawMarkdown = text;
        drawerBody.innerHTML = parseMarkdownToHTML(text);
      } else {
        drawerBody.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Failed to load the incident report.</span></div>`;
      }
    } catch (err) {
      drawerBody.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Error: ${escapeHTML(err.message)}</span></div>`;
    }
  };

  // Endpoint detail: "what IS this address?" The Evidence action opens this so
  // an unknown IPv6 is explained (owner org, PTR name, which agents/sessions
  // reached it, recent connections) instead of being a bare address that looks
  // safe to block.
  window.openEndpointDetail = async function(host, agent) {
    if (!drawer) return;
    drawerMode = 'endpoint';
    if (btnDrawerCopy) btnDrawerCopy.hidden = true;
    openDrawer({
      title: 'Endpoint detail',
      icon: 'globe',
      onClose: () => { drawerMode = null; },
    });
    drawerBody.innerHTML = `<div class="loading-spinner">Identifying ${escapeHTML(host)}…</div>`;
    try {
      const res = await apiFetch(`/egress/endpoint?host=${encodeURIComponent(host)}`);
      if (!res.ok) throw new Error((await res.text()).trim() || 'lookup failed');
      const detail = await res.json();
      drawerBody.innerHTML = endpointDetailHTML(detail, agent);
    } catch (err) {
      drawerBody.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>Could not identify this endpoint: ${escapeHTML(err.message || err)}</span></div>`;
    }
  };

  // Uninspected-egress drill-down: the count in the firewall panel becomes a
  // list the operator can act on (allow the endpoint, read the advisor's
  // verdict) instead of a dead end.

  window.openUninspected = function() {
    if (!drawer) return;
    drawerMode = 'uninspected';
    if (btnDrawerCopy) btnDrawerCopy.hidden = true;
    openDrawer({
      title: 'Uninspected egress — last 24h',
      icon: 'globe',
      onClose: () => { drawerMode = null; },
    });
    fillUninspected(drawerBody);
  };

  window.killProcess = async function(pid, startedAt, family) {
    const when = startedAt ? ` started ${startedAt}` : '';
    const who = family ? `${family} ` : '';
    if (!await saConfirm(`Terminate the ${who || ''}process tree at PID ${pid}${when || ''}?`, { title: 'Terminate process tree', okLabel: 'Terminate' })) return;
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

  window.resolveResourceControl = async function(id, decision, sessionKey, actionName) {
    const verb = decision === 'dismiss' ? 'keep this session running' : decision === 'resume' ? 'resume this entire session' : `apply ${String(actionName || 'this intervention').replaceAll('_', ' ')}`;
    if (!await saConfirm(`Save this resource policy change: ${verb}?`, { title: 'Resource policy', okLabel: 'Save' })) return;
    try {
      const res = await apiFetch('/resources/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ id, decision, session_key: sessionKey || '' })
      });
      if (!res.ok) throw new Error(await res.text());
      showToast(decision === 'dismiss' ? 'Session kept running for the cooldown window.' : decision === 'resume' ? 'Session resumed.' : 'Intervention applied.', 'success');
      fetchTelemetry({ slow: true });
    } catch (err) {
      showToast(`Resource decision failed: ${err}`, 'danger');
    }
  };

  window.resolveGuardPrompt = async function(id, verdict, scope) {
    const action = verdict === 'allow'
      ? (scope === 'always' ? 'allow every future path matched by this rule' : 'allow this request once')
      : 'deny this request and remember the rule';
    if (!await saConfirm(`Apply guard decision: ${action}?`, { title: 'Guard decision', okLabel: 'Apply' })) return;
    try {
      const res = await apiFetch('/guard/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, verdict, scope })
      });
      if (!res.ok) throw new Error(await res.text());
      showToast(`Guard request ${verdict === 'allow' ? 'allowed' : 'denied'}${scope === 'always' ? ' for this rule' : ' once'}.`, 'success');
      fetchTelemetry({ slow: false });
    } catch (err) {
      showToast(`Guard decision failed: ${err}`, 'danger');
    }
  };

  let resourcePolicyDraft = null;

  function resourcePolicyFromSnapshot(policy) {
    return {
      cwd_prefix: policy.cwd_prefix || '',
      mode: policy.mode || 'observe',
      max_rss_mb: Math.round(Number(policy.max_rss_bytes || 0) / (1024 * 1024)),
      max_cpu_percent: Number(policy.max_cpu_percent || 0),
      sustain_seconds: Number(policy.sustain_seconds || 0),
	  cooldown_seconds: Number(policy.cooldown_seconds || 0),
	  interventions: (policy.interventions || []).map(step => ({
		action: step.action, after_seconds: Number(step.after_seconds || 0), nice: Number(step.nice || 0)
	  }))
    };
  }

  function resourcePolicyFields(policy, index, isDefault) {
    const selected = (mode) => policy.mode === mode ? ' selected' : '';
	const step = (action) => (policy.interventions || []).find(item => item.action === action);
	const intervention = (action, label, defaultAfter, extra = '') => {
	  const current = step(action);
	  return `<label class="resource-policy-step"><input type="checkbox" data-step-enabled data-step-action="${action}"${current ? ' checked' : ''}><span>${label}</span><input class="input" type="number" min="0" step="1" data-step-after value="${Number(current?.after_seconds ?? defaultAfter)}" aria-label="${label} delay in seconds">${extra}</label>`;
	};
    return `<div class="resource-policy-editor-row${isDefault ? ' default' : ''}" data-policy-row data-policy-index="${index}" data-policy-default="${isDefault ? 'true' : 'false'}">
      ${isDefault ? '' : `<label class="resource-policy-field resource-policy-path">Workspace path<input class="input" data-policy-field="cwd_prefix" value="${escapeHTML(policy.cwd_prefix || '')}" placeholder="Absolute project path" spellcheck="false"></label>`}
      <label class="resource-policy-field">Action<select class="select" data-policy-field="mode"><option value="observe"${selected('observe')}>Observe</option><option value="prompt"${selected('prompt')}>Ask first</option><option value="terminate"${selected('terminate')}>Terminate</option></select></label>
      <label class="resource-policy-field">Memory (MiB)<input class="input" type="number" min="0" step="1" data-policy-field="max_rss_mb" value="${Number(policy.max_rss_mb || 0)}"></label>
      <label class="resource-policy-field">CPU (%)<input class="input" type="number" min="0" step="1" data-policy-field="max_cpu_percent" value="${Number(policy.max_cpu_percent || 0)}"></label>
      <label class="resource-policy-field">Grace (sec)<input class="input" type="number" min="0" step="1" data-policy-field="sustain_seconds" value="${Number(policy.sustain_seconds || 0)}"></label>
      <label class="resource-policy-field">Cooldown (sec)<input class="input" type="number" min="0" step="1" data-policy-field="cooldown_seconds" value="${Number(policy.cooldown_seconds || 0)}"></label>
	  <div class="resource-policy-ladder"><span class="resource-policy-ladder-title">Intervention ladder <small>seconds after grace</small></span>
		${intervention('notify', 'Notify', 0)}
		${intervention('lower_priority', 'Lower priority', 30, `<input class="input resource-policy-nice" type="number" min="1" max="19" step="1" data-step-nice value="${Number(step('lower_priority')?.nice || 10)}" aria-label="Nice value">`)}
		${intervention('pause', 'Pause', 60)}
		${intervention('terminate', 'Terminate', 120)}
	  </div>
      ${isDefault ? '' : `<button type="button" class="btn btn-ghost btn-sm" data-action="remove-resource-override" data-index="${index}">Remove</button>`}
    </div>`;
  }

  function renderResourcePolicyEditor() {
    if (!drawerBody || !resourcePolicyDraft) return;
    drawerBody.innerHTML = `<p class="resource-policy-intro">Set machine-wide budgets, then add complete policies for specific workspace trees. The most specific matching path wins.</p>
      <section class="resource-policy-section"><div class="resource-policy-section-head"><h4>Machine default</h4></div>${resourcePolicyFields(resourcePolicyDraft.default, -1, true)}</section>
      <section class="resource-policy-section"><div class="resource-policy-section-head"><h4>Workspace overrides</h4><span><button type="button" class="btn btn-ghost btn-sm" data-action="add-resource-override" data-source="current">Add current workspace</button><button type="button" class="btn btn-ghost btn-sm" data-action="add-resource-override" data-source="manual">Add path</button></span></div>
      <div id="resource-policy-overrides">${resourcePolicyDraft.overrides.map((p, i) => resourcePolicyFields(p, i, false)).join('') || '<div class="resource-detail-empty">No workspace overrides. Every session uses the machine default.</div>'}</div></section>
	  <p class="resource-policy-danger">Terminate mode applies every enabled intervention automatically. Pause stops the full attributed session until resumed; terminate ends it.</p>`;
  }

  function readResourcePolicyEditor() {
    if (!drawerBody || !resourcePolicyDraft) return resourcePolicyDraft;
    const read = (row) => {
      const value = (name) => row.querySelector(`[data-policy-field="${name}"]`)?.value || '';
      return {
        ...(row.dataset.policyDefault === 'true' ? {} : { cwd_prefix: value('cwd_prefix').trim() }),
        mode: value('mode'), max_rss_mb: Number(value('max_rss_mb')),
        max_cpu_percent: Number(value('max_cpu_percent')), sustain_seconds: Number(value('sustain_seconds')),
		cooldown_seconds: Number(value('cooldown_seconds')),
		interventions: Array.from(row.querySelectorAll('[data-step-enabled]:checked')).map(enabled => {
		  const stepRow = enabled.closest('.resource-policy-step');
		  return { action: enabled.dataset.stepAction, after_seconds: Number(stepRow.querySelector('[data-step-after]').value),
			...(enabled.dataset.stepAction === 'lower_priority' ? { nice: Number(stepRow.querySelector('[data-step-nice]').value) } : {}) };
		})
      };
    };
    const rows = Array.from(drawerBody.querySelectorAll('[data-policy-row]'));
    return { default: read(rows[0]), overrides: rows.slice(1).map(read) };
  }

  window.openResourcePolicyEditor = function() {
    const control = (telemetryData.resources && telemetryData.resources.control) || {};
    resourcePolicyDraft = {
      default: resourcePolicyFromSnapshot(control),
      overrides: (control.workspace_overrides || []).map(resourcePolicyFromSnapshot)
    };
    openDrawer({
      title: 'Resource policy editor',
      icon: 'activity',
      variant: 'resource-policy',
      foot: `<button type="button" class="btn btn-ghost" data-action="policy-cancel">Cancel</button>`
        + `<button type="button" class="btn btn-primary" data-action="policy-save">Save and apply</button>`,
      onClose: () => { resourcePolicyDraft = null; },
    });
    renderResourcePolicyEditor();
    drawerFoot.querySelector('[data-action="policy-cancel"]')?.addEventListener('click', closeDrawer);
    drawerFoot.querySelector('[data-action="policy-save"]')?.addEventListener('click', saveResourcePolicy);
  };

  window.addResourceOverride = function(source) {
    resourcePolicyDraft = readResourcePolicyEditor();
    const selected = (telemetryData.resources?.sessions || []).find(s => s.key === selectedResourceKey);
    const path = source === 'current' && selected ? (selected.workspace || '') : '';
    if (source === 'current' && !path) {
      showToast('Select a session with a workspace first.', 'info');
      return;
    }
    if (path && resourcePolicyDraft.overrides.some(p => p.cwd_prefix === path)) {
      showToast('That workspace already has an override.', 'info');
      return;
    }
    resourcePolicyDraft.overrides.push({ ...resourcePolicyDraft.default, cwd_prefix: path });
    renderResourcePolicyEditor();
    const paths = drawerBody.querySelectorAll('[data-policy-field="cwd_prefix"]');
    if (paths.length) paths[paths.length - 1].focus();
  };

  window.removeResourceOverride = function(index) {
    resourcePolicyDraft = readResourcePolicyEditor();
    resourcePolicyDraft.overrides.splice(Number(index), 1);
    renderResourcePolicyEditor();
  };

  async function saveResourcePolicy() {
    const draft = readResourcePolicyEditor();
    if (!draft) return;
    const invalid = draft.overrides.find(p => !p.cwd_prefix.startsWith('/'));
    if (invalid) {
      showToast('Workspace paths must be absolute.', 'danger');
      return;
    }
    const body = { ...draft.default, workspace_overrides: draft.overrides };
    if ([body, ...body.workspace_overrides].some(p => p.mode === 'terminate') &&
		!await saConfirm('Terminate mode will automatically apply the enabled intervention ladder to entire agent sessions. Save this policy?', { title: 'Enable terminate mode', okLabel: 'Save policy' })) return;
    const saveBtn = drawerFoot.querySelector('[data-action="policy-save"]');
    if (saveBtn) saveBtn.disabled = true;
    try {
      const res = await apiFetch('/resources/policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!res.ok) throw new Error((await res.text()).trim() || 'save failed');
      closeDrawer();
      showToast('Resource policy saved and applied.', 'success');
      fetchTelemetry({ slow: true });
    } catch (err) {
      showToast(`Resource policy save failed: ${err.message || err}`, 'danger');
    } finally {
      const b = drawerFoot.querySelector('[data-action="policy-save"]');
      if (b) b.disabled = false;
    }
  }

  window.killOrphans = async function(family) {
    const agents = (telemetryData.status && telemetryData.status.agents) ? telemetryData.status.agents : [];
    const orphans = agents.filter(a => harnessMeta(a.name).key === family && a.is_orphan);
    if (orphans.length === 0) return;
    if (!await saConfirm(`Terminate ${orphans.length} leftover ${family} process${orphans.length === 1 ? '' : 'es'}?`, { title: 'Clean up leftovers', okLabel: 'Terminate' })) return;
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

  // Bulk allow: one click for a group the operator has already judged (all
  // hosts under one suffix for one agent). Sequential and bounded — the
  // allowlist is a user-owned file, not a bulk-import target.
  window.bulkAllowHosts = async function(agent, hosts) {
    const list = String(hosts || '').split(',').filter(Boolean);
    let ok = 0;
    for (const host of list) {
      try {
        const res = await apiFetch('/allowlist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ agent, host })
        });
        if (res.ok) ok++;
      } catch { /* continue; the toast reports the tally */ }
    }
    showToast(`Allowlisted ${ok} of ${list.length} hosts for ${agent}`, ok === list.length ? 'success' : 'warn');
    await fetchTelemetry();
    if (drawerMode === 'uninspected' && drawer && !drawer.hidden) {
      fillUninspected(drawerBody);
    }
  };

  // Ask the advisor what an endpoint is — the functionality that turns a raw
  // IP into a decision. The daemon answers with a cached verdict immediately
  // and queues a fresh assessment; the console polls a few times for the
  // verdict to land, then re-renders the row.
  window.assessHost = async function(agent, host) {
    try {
      const res = await apiFetch('/advisor/assess-host', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent, host })
      });
      if (res.status === 503) {
        showToast('Advisor is off — enable it in Settings for endpoint guidance.', 'info');
        return;
      }
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json().catch(() => ({}));
      showToast(data.verdict ? 'Advisor verdict loaded' : 'Asking the advisor…', 'info');
      await pollHostVerdict(agent, host, !!data.verdict);
    } catch (err) {
      showToast(`Advisor assessment failed: ${err.message || err}`, 'danger');
    }
  };

  // Poll for a fresh host verdict (bounded): the model answers in seconds, and
  // /egress/uninspected carries the stored verdict once it lands.
  async function pollHostVerdict(agent, host, hadVerdict) {
    const rounds = hadVerdict ? 1 : 8;
    for (let i = 0; i < rounds; i++) {
      await fetchTelemetry({ slow: true });
      const row = (telemetryData.uninspected || []).find(e => e.agent === agent && e.host === host);
      if (row && row.assessment) break;
      await new Promise(r => setTimeout(r, 1500));
    }
    if (drawerMode === 'uninspected' && drawer && !drawer.hidden) {
      fillUninspected(drawerBody);
    }
  }

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
        if (drawerMode === 'uninspected' && drawer && !drawer.hidden) {
          fillUninspected(drawerBody);
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

  // Blocking must be reversible — a rule you can only tighten is a ratchet.
  window.demoteRule = async function(rule) {
    try {
      const res = await apiFetch('/firewall/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, mode: 'monitor' })
      });
      if (res.ok) {
        showToast(`Rule “${rule}” back to monitor.`, 'success');
        fetchTelemetry();
      } else {
        showToast(`Failed to demote “${rule}”.`, 'danger');
      }
    } catch (err) {
      showToast(`Error demoting “${rule}”: ${err}`, 'danger');
    }
  };

  window.removeAllowlistEntry = async function(agent, host) {
    try {
      const res = await apiFetch('/allowlist', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent, host })
      });
      if (res.ok) {
        telemetryData.allowlist = (telemetryData.allowlist || []).filter(p => !(p.agent === agent && p.host === host));
        showToast(`Removed ${host} for ${agent}.`, 'info');
        renderFirewall();
      } else {
        showToast(`Failed to remove ${host}.`, 'danger');
      }
    } catch (err) {
      showToast(`Error removing ${host}: ${err}`, 'danger');
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
      case 'demote':
        window.demoteRule(d.rule);
        break;
      case 'allowlist-remove':
        window.removeAllowlistEntry(d.agent, d.host);
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
      case 'resource-session':
        selectedResourceKey = d.key || '';
        renderResourceMissionControl();
        break;
      case 'resource-control':
        e.preventDefault();
        e.stopPropagation();
		window.resolveResourceControl(d.id, d.decision, d.session, d.intervention);
        break;
      case 'guard-resolve':
        e.preventDefault();
        window.resolveGuardPrompt(d.id, d.verdict, d.scope);
        break;
      case 'edit-resource-policy':
        window.openResourcePolicyEditor();
        break;
      case 'add-resource-override':
        window.addResourceOverride(d.source);
        break;
      case 'remove-resource-override':
        window.removeResourceOverride(d.index);
        break;
      case 'allow-host':
        window.allowHost(d.agent, d.host);
        break;
      case 'bulk-allow':
        window.bulkAllowHosts(d.agent, d.hosts);
        break;
      case 'assess-host':
        window.assessHost(d.agent, d.host);
        break;
      case 'endpoint-detail':
        e.preventDefault();
        window.openEndpointDetail(d.host, d.agent);
        break;
      case 'notify-scope-add':
        window.addNotifyScope();
        break;
      case 'notify-scope-remove':
        window.removeNotifyScope(d.rule, d.workspace);
        break;
      case 'save-view':
        window.saveCurrentView();
        break;
      case 'apply-view':
        window.applyView(d.name);
        break;
      case 'remove-view':
        window.removeView(d.name);
        break;
      case 'export':
        window.exportData(d.what);
        break;
      case 'select-session':
        window.selectSession(d.id);
        break;
      case 'toggle-ended-sessions':
        endedSessionsOpen[d.harness] = !endedSessionsOpen[d.harness];
        renderSessionBoard();
        break;
      case 'toggle-harness':
        if (harnessFilter.harnesses[d.harness] === false) delete harnessFilter.harnesses[d.harness];
        else harnessFilter.harnesses[d.harness] = false;
        harnessFilterChanged();
        break;
      case 'clear-harness-filter':
        harnessFilter.harnesses = {};
        harnessFilter.text = '';
        harnessFilterChanged();
        break;
      case 'copy-path':
        (navigator.clipboard ? navigator.clipboard.writeText(d.path || '') : Promise.reject(new Error('no clipboard'))).then(
          () => showToast('Path copied', 'success'),
          () => showToast('Copy failed — select the path from its tooltip', 'danger'));
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
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = msg;

    // The drawer is ordinary DOM (z-index 200), and the toast container is a
    // top-layer popover — so toasts already paint above an open drawer without
    // the old "append inside the <dialog>" dance that native modals required.
    const host = document.getElementById('toast-container');
    if (!host) return;
    if (typeof host.showPopover === 'function') {
      try {
        if (host.matches(':popover-open')) host.hidePopover();
        host.showPopover();
      } catch { /* unsupported */ }
    }

    host.appendChild(toast);
    // Keep the stack short: an endpoint-failure burst must not build a toast
    // column taller than the viewport (which pushes the oldest ones off-screen).
    while (host.childElementCount > 4) host.firstElementChild.remove();

    setTimeout(() => {
      toast.remove();
      if (host.classList.contains('toast-host') && !host.childElementCount) {
        host.remove();
      } else if (host.id === 'toast-container' && !host.childElementCount &&
                 typeof host.hidePopover === 'function' && host.matches(':popover-open')) {
        try { host.hidePopover(); } catch { /* ok */ }
      }
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
    renderNotifyScopes();
  }

  // Per-workspace scopes: existing ones with a remove button, plus a compact
  // add form (rule + path prefix + page/silence). The daemon matches by path
  // prefix, longest first.
  function renderNotifyScopes() {
    const list = document.getElementById('notify-scopes-list');
    if (!list) return;
    const scopes = (telemetryData.notifyCfg && telemetryData.notifyCfg.scopes) || [];
    const rows = scopes.map(s => `<div class="notify-rule-row">
        <span class="notify-rule-name" title="${escapeHTML(s.workspace)}">${escapeHTML(s.rule)} <span class="notify-scope-path">${escapeHTML(s.workspace)}</span></span>
        <span class="notify-scope-mode ${s.notify ? 'on' : 'off'}">${s.notify ? 'page' : 'quiet'}</span>
        <button class="source-remove" title="Remove this scope" data-action="notify-scope-remove" data-rule="${escapeHTML(s.rule)}" data-workspace="${escapeHTML(s.workspace)}"><svg class="icon"><use href="#i-close"/></svg></button>
      </div>`).join('');
    list.innerHTML = (rows || '<div class="notify-scope-empty">No workspace scopes yet</div>') + `
      <div class="notify-scope-add">
        <select class="select select-sm" id="notify-scope-rule" aria-label="Rule for the workspace scope">
          ${NOTIFY_RULES.map(([rule, label]) => `<option value="${escapeHTML(rule)}">${escapeHTML(label)}</option>`).join('')}
        </select>
        <input class="input input-sm" id="notify-scope-path" placeholder="repo path, e.g. ~/work/prod" autocomplete="off" spellcheck="false">
        <select class="select select-sm" id="notify-scope-mode" aria-label="Scope action">
          <option value="always">Page</option>
          <option value="never">Quiet</option>
        </select>
        <button class="btn btn-ghost btn-sm" data-action="notify-scope-add" title="Add this workspace scope"><svg class="icon"><use href="#i-arrow"/></svg><span>Add</span></button>
      </div>`;
  }

  window.addNotifyScope = async function() {
    const rule = (document.getElementById('notify-scope-rule') || {}).value;
    const workspace = ((document.getElementById('notify-scope-path') || {}).value || '').trim();
    const mode = (document.getElementById('notify-scope-mode') || {}).value;
    if (!rule || !workspace) { showToast('Pick a rule and enter a workspace path.', 'info'); return; }
    await setNotifyScope(rule, workspace, mode === 'always');
  };

  window.removeNotifyScope = async function(rule, workspace) {
    await setNotifyScope(rule, workspace, null);
  };

  async function setNotifyScope(rule, workspace, notify) {
    try {
      const res = await apiFetch('/notify/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, workspace, notify })
      });
      if (!res.ok) throw new Error(await res.text());
      showToast(notify === null ? `Scope removed: ${rule} in ${workspace}`
        : notify ? `${rule}: always pages in ${workspace}`
        : `${rule}: quiet in ${workspace}`, 'success');
      fetchTelemetry();
    } catch (err) {
      showToast(`Failed to update workspace scope: ${err.message || err}`, 'danger');
    }
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

    // Typed deltas: patch local state, then one debounced render. The
    // full-snapshot refetch per raw bus event is over — /snapshot remains
    // for initial load and the 30s reconcile.
    let renderPending = false;
    const scheduleRender = () => {
      if (renderPending) return;
      renderPending = true;
      setTimeout(() => { renderPending = false; renderAll(); }, 120);
    };
    const upsertById = (list, item) => {
      list = list || [];
      const i = list.findIndex(x => x && x.id === item.id);
      if (i >= 0) list[i] = item; else list.unshift(item);
      return list;
    };
    es.addEventListener('event', (msg) => {
      // Push path: count the event immediately so the sparkline reflects
      // bursts between fetches. Record its key so sparkIngestEvents won't
      // double-count it when the reconcile fetch lands.
      try {
        const e = JSON.parse(msg.data);
        countedEventKeys.add(eventKey(e));
        sparkBump(1, Date.parse(e.ts) || 0);
        telemetryData.events = [e, ...(telemetryData.events || [])].slice(0, 200);
        if (e.kind === 9) flashFirewallPanel(); // proxy-hit
        // The open session's waterfall follows its own trace live.
        if (selectedSessionId && e.session_id === selectedSessionId) {
          loadSessionTimeline(selectedSessionId).then(scheduleRender);
        }
      } catch { sparkBump(1, 0); /* unparseable frame still counts */ }
      scheduleRender();
    });
    es.addEventListener('flag', (msg) => {
      try { telemetryData.flags = upsertById(telemetryData.flags, JSON.parse(msg.data)); } catch { /* next reconcile repairs */ }
      scheduleRender();
    });
    es.addEventListener('incident', (msg) => {
      // Delta incidents are the bare report (no workflow join); the 30s
      // reconcile supplies workflow state.
      try { telemetryData.incidents = upsertById(telemetryData.incidents, JSON.parse(msg.data)); } catch { /* next reconcile repairs */ }
      scheduleRender();
    });
    es.addEventListener('session', (msg) => {
      try { telemetryData.sessions = upsertById(telemetryData.sessions, JSON.parse(msg.data)); } catch { /* next reconcile repairs */ }
      scheduleRender();
    });
    es.addEventListener('posture', (msg) => {
      try { telemetryData.posture = JSON.parse(msg.data); } catch { /* next reconcile repairs */ }
      scheduleRender();
    });
    // Guard lifecycle: a waiting operator decision must not wait for a
    // reconcile — keep the instant refetch for these two.
    ['guard-prompt', 'guard-resolved']
      .forEach(kind => es.addEventListener(kind, scheduleRefresh));
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
