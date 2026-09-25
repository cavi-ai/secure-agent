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
  // The menu bar loads a fresh #ct= into an existing console tab (a tab
  // whose session ended included): keep the new token and start over.
  window.addEventListener('hashchange', () => {
    const fresh = new URLSearchParams(location.hash.slice(1)).get('ct');
    if (!fresh) return;
    try { sessionStorage.setItem(SS_TOKEN_KEY, fresh); } catch { /* private mode: the reload reads the hash */ }
    location.reload();
  });
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
  // Honest ended state: without a token nothing else paints — no posture,
  // no counts, no panels, no fetches, no stream. Only the menu bar can mint
  // a session.
  function showSessionEnded() {
    document.body.classList.add('is-ended');
    const ended = document.getElementById('session-ended');
    document.querySelectorAll('.app > *, .masthead-right, #drawer, #confirm-layer').forEach(el => {
      if (el !== ended && !el.classList.contains('masthead')) el.hidden = true;
    });
    if (ended) ended.hidden = false;
  }
  if (consoleBootState(hashParams.get('ct'), consoleToken) === 'ended') {
    showSessionEnded();
    return;
  }
  const authHeaders = consoleToken ? { 'X-SecureAgent-Console-Token': consoleToken } : {};

  // Every request carries a timeout: a hung endpoint must not wedge the whole
  // refresh cycle (Promise.all resolves only as fast as its slowest member).
  const FETCH_TIMEOUT_MS = 5000;
  // opts.timeoutMs raises it for the few calls that do real work on request
  // (a worktree scan reads every repository).
  const apiFetch = (path, opts = {}) => {
    const { timeoutMs, ...init } = opts;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs || FETCH_TIMEOUT_MS);
    return fetch(path, { ...init, signal: ctl.signal, headers: { ...authHeaders, ...(init.headers || {}) } })
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
  let drawerBack = null;
  // Bumped on every open: an async opener writes its body only while its
  // drawer is still the one showing.
  let drawerSeq = 0;
  const drawerHead = drawer && drawer.querySelector('.drawer-head');
  const drawerTitleEl = document.getElementById('drawer-title');

  function openDrawer({ title, icon, body, foot, variant, onClose, back }) {
    if (!drawer) return false;
    // A drawer opened from inside the open one keeps the original opener, so
    // closing still returns focus to the page.
    if (drawer.hidden) drawerOpener = document.activeElement;
    drawerOnClose = onClose || null;
    drawerBack = back || null;
    drawerSeq++;
    if (drawerHead && drawerTitleEl) paintDrawerBack(drawerHead, drawerTitleEl, drawerBack);
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
    drawerBack = null;
    if (drawerHead && drawerTitleEl) paintDrawerBack(drawerHead, drawerTitleEl, null);
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
    fetchTelemetry({ full: true });
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
    patterns: [],    // /snapshot patterns: repeating findings, one card each
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
    costs: null,      // /costs report (24h, by repo) — the spend tile
    costsCard: null,  // /costs report for the Spend card's saved view
    costPlans: null,  // /costs/plans — plan headroom per harness home
    connected: true
  };
  // Last-seen /notify/rules payload hash — gates 'notify' dirty-marking on
  // the reconcile poll so a config that hasn't changed never re-renders the
  // panel (and erases an in-progress edit); see fetchTelemetry.
  let notifyCfgHash = '';

  // Spend card view: dimension and window, kept for the tab in
  // sessionStorage. The tile keeps its own 24h/by-repo fetch.
  const SPEND_VIEW_KEY = 'sa.spend-view';
  const SPEND_BY = ['repo', 'provider', 'model', 'day'];
  const SPEND_SINCE = ['24h', '7d', '30d'];
  let spendView = { by: 'repo', since: '24h' };
  try {
    const saved = JSON.parse(sessionStorage.getItem(SPEND_VIEW_KEY) || '{}') || {};
    if (SPEND_BY.includes(saved.by)) spendView.by = saved.by;
    if (SPEND_SINCE.includes(saved.since)) spendView.since = saved.since;
  } catch { /* private mode or a corrupt entry: the default view */ }
  const spendCardPath = () =>
    `/costs?since=${spendView.since}&by=${spendView.by}&tz=${-(new Date()).getTimezoneOffset()}`;

  // ---------- connectivity ----------
  // Two honest live states, never conflated:
  //  - 'ok':           fetches succeed.
  //  - 'unreachable':  network-level failure — the daemon or its proxy
  //                    listener is gone; the last known state stays visible.
  // A 403 is neither: the token is missing or rotated, only the menu bar can
  // mint a fresh session, and the page switches to the ended state
  // (endSession).
  let connState = 'ok';
  let sessionEnded = false;
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
    if (text) text.textContent = "Can't reach the Secure Agent daemon — showing the last known state and retrying…";
  }

  // endSession: a 403 means the token is dead. Drop it, stop every timer and
  // the stream, and show only the ended state; nothing retries.
  function endSession() {
    if (sessionEnded) return;
    sessionEnded = true;
    try { sessionStorage.removeItem(SS_TOKEN_KEY); } catch { /* private mode */ }
    clearInterval(slowTimer);
    clearInterval(sparkTimer);
    stopPolling();
    if (es) es.close();
    showSessionEnded();
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

  const sparkTimer = setInterval(() => { sparkAdvance(); drawSpark(); }, 1000);

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

  // Scope bar under the tabs: visible on every tab while Events, Flags and
  // Incidents are narrowed; Clear drops the scope everywhere.
  function paintScopeBar() {
    const bar = document.getElementById('scope-bar');
    if (!bar) return;
    const t = telemetryData;
    const html = sessionScopeOn() ? scopeBarHTML({
      session: timelineSession, pids: timelinePids, pidLabel: timelinePidLabel,
      events: scopedBySession(t.eventsView || [], timelineSession, timelinePids).length,
      flags: scopedBySession(t.flagsView || [], timelineSession, timelinePids).length,
    }) : '';
    bar.hidden = !html;
    if (bar._saHTML !== html) {
      bar.innerHTML = html;
      bar._saHTML = html;
    }
  }

  // Posture pill on the stuck tab bar: the hero's count; a click goes back
  // to the top.
  function paintTabsPosture() {
    const pill = document.getElementById('tabs-posture');
    const text = document.getElementById('tabs-posture-text');
    if (!pill || !text) return;
    const p = telemetryData.posture;
    const n = attentionCount(p);
    pill.dataset.state = (p && p.state) || 'all-clear';
    text.textContent = n ? `${n} need${n === 1 ? 's' : ''} you` : 'All clear';
  }
  const tabsBar = document.getElementById('tabs-bar');
  function syncTabsStuck() {
    if (!tabsBar) return;
    const stuck = window.scrollY > 0 && tabsBar.getBoundingClientRect().top <= 0;
    tabsBar.classList.toggle('is-stuck', stuck);
    const pill = document.getElementById('tabs-posture');
    if (pill) pill.hidden = !stuck;
  }
  window.addEventListener('scroll', syncTabsStuck, { passive: true });
  window.addEventListener('resize', syncTabsStuck);

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
      tab: routeKey({ tab: activeTab, sub: activeSub }),
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
    if (view.tab && isConsoleRoute(view.tab)) switchTab(view.tab);
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
  // The console is organized by question (Home / Sessions / Egress /
  // Policy / Agent), not by data source. State persists per tab-session; the hash
  // carries the tab (and the Sessions sub-view) for deep links (#ct is lifted
  // and stripped BEFORE this runs, so the two never collide).
  // ---------- render scheduler ----------
  // A panel renders only when the telemetryData slice it reads changed
  // (dirty) and only when it is on screen: the active tab's panels plus the
  // globals. A hidden panel keeps its dirty bit and renders on switchTab.
  // Renders coalesce into one frame; a panel renders at most every 250ms
  // (later marks wait for one trailing timer, nothing is dropped). While the
  // pointer is down in <main>, or a control inside a panel has focus (up to
  // 3s), that panel waits: the node under the cursor or the caret survives.
  const PANELS = [
    ['posture', renderPosture], ['status', renderStatus], ['resources', renderResourceMissionControl], ['history', renderResourceHistory], ['sessions', renderSessionBoard],
    ['chart-flags', renderChartFlags], ['chart-memory', renderChartMemory], ['spend', renderSpend],
    ['agents', renderAgents],
    ['endpoints', renderEndpoints], ['firewall', renderFirewall], ['incidents', renderIncidents], ['fleet', renderFleet],
    ['audit', renderAudit], ['sources', renderSources], ['flags', renderFlags], ['attention', renderAttention],
    ['events', renderEvents], ['activity', renderActivity], ['worktrees', renderWorktrees], ['clutter', renderClutter], ['tab-badges', renderTabBadges],
    ['notify', renderNotifyRules], ['policy', renderPolicyLists], ['agent', renderAgent]
  ];
  // Panel → where it lives: tab, tab/sub-view, or tab:group (a Home
  // <details> group). A panel absent here is global (always on screen).
  const PANEL_VIEW = {
    attention: 'home', spend: 'home',
    flags: 'home:findings', incidents: 'home:findings',
    activity: 'home:trends', 'chart-flags': 'home:trends', 'chart-memory': 'home:trends',
    sessions: 'sessions/board', agents: 'sessions/processes', fleet: 'sessions/processes',
    resources: 'sessions/resources', history: 'sessions/resources',
    worktrees: 'sessions/worktrees', clutter: 'sessions/worktrees', events: 'sessions/events',
    endpoints: 'egress', firewall: 'egress', sources: 'egress',
    notify: 'policy', policy: 'policy', audit: 'policy', agent: 'agent'
  };
  // A panel is on screen when its tab is active, its sub-view is the open
  // one, and its Home group is expanded.
  function panelOnScreen(name) {
    const v = PANEL_VIEW[name];
    if (!v) return true;
    const [route, group] = v.split(':');
    const [tab, sub] = route.split('/');
    if (tab !== activeTab || (sub && sub !== activeSub)) return false;
    return !group || homeGroupOpen(group);
  }
  // Panel → the element whose focused control holds its render.
  const PANEL_EL = {
    resources: 'resource-board', history: 'history-board', sessions: 'session-rail', agents: 'agents-container',
    fleet: 'fleet-container', endpoints: 'endpoints-container', firewall: 'firewall-container', sources: 'sources-list', incidents: 'incidents-container',
    audit: 'audit-container', flags: 'flags-list', attention: 'attention-list', events: 'events-container',
    worktrees: 'worktrees-container', clutter: 'clutter-container', notify: 'notify-pop', agent: 'agent-side'
  };
  const SLOW_ONLY = new Set(['resources', 'history', 'fleet', 'audit', 'sources', 'activity', 'spend']);
  const PANEL_MIN_MS = 250;
  const FOCUS_HOLD_MS = 3000;
  const dirtyPanels = new Set();
  const renderCounts = {};
  const lastRenderAt = {};
  let booted = false; // nothing renders before the first telemetry lands
  let renderQueued = false;
  let trailingTimer = null;
  let interacting = false;
  let focusAt = 0;

  function renderPanel(name, fn) {
    lastRenderAt[name] = Date.now();
    renderCounts[name] = (renderCounts[name] || 0) + 1;
    try { fn(); } catch (err) { console.error(`render panel "${name}" failed:`, err); }
  }
  function markDirty(...names) {
    names.forEach(n => dirtyPanels.add(n));
    scheduleDirty();
  }
  function scheduleDirty() {
    if (renderQueued) return;
    renderQueued = true;
    let done = false;
    const run = () => { if (done) return; done = true; renderQueued = false; renderDirty(); };
    // A frame when the page paints; the timer backstops a page that does not
    // (background tab, headless).
    if (window.requestAnimationFrame) requestAnimationFrame(run);
    setTimeout(run, window.requestAnimationFrame ? 100 : 16);
  }
  // ms this panel must still wait, -1 for "until the pointer is up", 0 = go.
  function panelHold(name) {
    if (!PANEL_VIEW[name]) return 0;
    if (interacting) return -1;
    const el = PANEL_EL[name] && document.getElementById(PANEL_EL[name]);
    const a = document.activeElement;
    if (el && a && el.contains(a) && a.matches('button, select, input, textarea, summary')) {
      const left = FOCUS_HOLD_MS - (Date.now() - focusAt);
      if (left > 0) return left;
    }
    return 0;
  }
  function renderDirty() {
    if (!booted || sessionEnded) return;
    const now = Date.now();
    let wait = Infinity;
    for (const [name, fn] of PANELS) {
      if (!dirtyPanels.has(name)) continue;
      if (!panelOnScreen(name)) continue;
      const hold = panelHold(name);
      if (hold) { if (hold > 0) wait = Math.min(wait, hold); continue; }
      const since = now - (lastRenderAt[name] || 0);
      if (since < PANEL_MIN_MS) { wait = Math.min(wait, PANEL_MIN_MS - since); continue; }
      dirtyPanels.delete(name);
      renderPanel(name, fn);
    }
    if (wait !== Infinity && !trailingTimer) {
      trailingTimer = setTimeout(() => { trailingTimer = null; renderDirty(); }, wait);
    }
  }
  // User-initiated: render these panels now, visible or not.
  function renderNow(names) {
    for (const [name, fn] of PANELS) if (names.includes(name)) { dirtyPanels.delete(name); renderPanel(name, fn); }
  }
  document.querySelector('main')?.addEventListener('pointerdown', () => { interacting = true; });
  const releasePointer = () => { if (interacting) { interacting = false; scheduleDirty(); } };
  document.addEventListener('pointerup', releasePointer);
  document.addEventListener('pointercancel', releasePointer);
  window.addEventListener('blur', releasePointer);
  document.addEventListener('focusin', () => { focusAt = Date.now(); });
  document.addEventListener('focusout', () => scheduleDirty());

  // Tab badges are the signal for HIDDEN tabs, so they cannot wait for their
  // tab's panels: a cheap global recount of the four badges.
  function renderTabBadges() {
    const t = telemetryData;
    const agents = (t.status && t.status.agents) || [];
    const trees = t.status && t.status.trees;
    setTabBadge('home', attentionCount(t.posture));
    setTabBadge('egress', (t.status && t.status.uninspected_egress) || 0);
    setTabBadge('processes', groupAgentsByHarness(agents).filter(g => !g.infra).length);
    setTabBadge('sessions', t.sessions && t.sessions.length
      ? groupSessionsByHarness(t.sessions, trees, agents).reduce((n, g) => n + (g.infra ? 0 : familySize(g.live)), 0)
      : sessionRows(agents, trees).length);
    paintTabsPosture();
    paintScopeBar();
  }

  let activeTab = 'home';
  let activeSub = 'board';

  // Worktrees are not telemetry: the tab fetches its report when opened
  // (the daemon caches a scan for 10 minutes) and on Rescan, never on the
  // refresh cycle.
  const WORKTREE_TIMEOUT_MS = 200000;
  const WORKTREE_STALE_MS = 60000;
  const worktreesState = { report: null, loading: false, error: '', loadedAt: 0, filter: { state: '', stale: false } };
  // While the daemon is still measuring sizes, the open tab re-reads the
  // cached report (cheap: no rescan) until the sizes land.
  const WORKTREE_SIZING_POLL_MS = 5000;
  const WORKTREE_SIZING_POLLS = 60;
  let worktreeSizingTimer = null;
  let worktreeSizingPolls = 0;
  // Also while an agent ask runs: its answer lands in the report's asks.
  // While a removal runs, every 1.5 s and without a cap: the daemon bounds
  // a removal at 10 minutes.
  const WORKTREE_REMOVAL_POLL_MS = 1500;
  const removalRunning = rep => rep && Object.values(rep.removals || {}).some(r => r.state === 'running');
  function followWorktreeSizing() {
    const rep = worktreesState.report;
    const asking = rep && Object.values(rep.asks || {}).some(a => a.status === 'running');
    const removing = removalRunning(rep);
    if (!rep || !(rep.sizing || rep.refreshing || asking || removing) || !(activeTab === 'sessions' && activeSub === 'worktrees') || worktreeSizingTimer) return;
    if (!removing) {
      if (worktreeSizingPolls >= WORKTREE_SIZING_POLLS) return;
      worktreeSizingPolls++;
    }
    worktreeSizingTimer = setTimeout(() => { worktreeSizingTimer = null; loadWorktrees(false); }, removing ? WORKTREE_REMOVAL_POLL_MS : WORKTREE_SIZING_POLL_MS);
  }
  // announceRemovals toasts each removal this page saw running that has
  // since finished; a Remove all batch gets one line when its last
  // removal ends.
  const removalBatches = [];
  function announceRemovals(before, after) {
    const batched = new Set(removalBatches.flatMap(b => b.paths));
    for (let i = removalBatches.length - 1; i >= 0; i--) {
      const text = removalBatchSummary(removalBatches[i].paths, after && after.removals);
      if (!text) continue;
      showToast(text, text.includes('not removed') ? 'info' : 'success');
      removalBatches.splice(i, 1);
    }
    for (const [path, was] of Object.entries((before && before.removals) || {})) {
      const now = ((after && after.removals) || {})[path];
      if (batched.has(path) || was.state !== 'running' || !now || now.state === 'running') continue;
      if (now.state === 'removed') {
        showToast(now.bytes ? `Removed ${path} — ${fmtDisk(now.bytes)} reclaimed` : `Removed ${path}`, 'success');
      } else if (now.row_state) {
        showToast(`Not removed — ${path} is now ${now.row_state}: ${(now.reasons || []).join('; ')}`, 'info');
      } else {
        showToast(`Could not remove ${path}: ${now.error || 'unknown error'}`, 'danger');
      }
    }
  }
  async function loadWorktrees(refresh) {
    if (worktreesState.loading) return;
    worktreesState.loading = true;
    worktreesState.error = '';
    markDirty('worktrees');
    try {
      const r = await apiFetch('/worktrees' + (refresh ? '?refresh=1' : ''), { timeoutMs: WORKTREE_TIMEOUT_MS });
      if (!r.ok) throw new Error((await r.text()).trim() || String(r.status));
      const before = worktreesState.report;
      worktreesState.report = await r.json();
      worktreesState.loadedAt = Date.now();
      announceRemovals(before, worktreesState.report);
      if (!worktreesState.report.sizing && !worktreesState.report.refreshing && !Object.values(worktreesState.report.asks || {}).some(a => a.status === 'running')) worktreeSizingPolls = 0;
    } catch (err) {
      worktreesState.error = 'Worktree scan failed: ' + (err.message || err);
      if (worktreesState.report) showToast(worktreesState.error, 'danger');
    } finally {
      worktreesState.loading = false;
      markDirty('worktrees');
      followWorktreeSizing();
    }
  }
  // Clutter: loaded with the tab like worktrees; re-read while sizes land.
  const clutterState = { report: null, loading: false, error: '', loadedAt: 0, filter: { kind: '' }, expanded: new Set() };
  let clutterSizingTimer = null;
  let clutterSizingPolls = 0;
  async function loadClutter(refresh) {
    if (clutterState.loading) return;
    clutterState.loading = true;
    clutterState.error = '';
    markDirty('clutter');
    try {
      const r = await apiFetch('/cleanup' + (refresh ? '?refresh=1' : ''), { timeoutMs: WORKTREE_TIMEOUT_MS });
      if (!r.ok) throw new Error((await r.text()).trim() || String(r.status));
      clutterState.report = await r.json();
      clutterState.loadedAt = Date.now();
      if (!clutterState.report.sizing && !clutterState.report.refreshing) clutterSizingPolls = 0;
    } catch (err) {
      clutterState.error = 'Clutter scan failed: ' + (err.message || err);
      if (clutterState.report) showToast(clutterState.error, 'danger');
    } finally {
      clutterState.loading = false;
      markDirty('clutter');
      const rep = clutterState.report;
      if (rep && (rep.sizing || rep.refreshing) && activeTab === 'sessions' && activeSub === 'worktrees' && !clutterSizingTimer && clutterSizingPolls < WORKTREE_SIZING_POLLS) {
        clutterSizingPolls++;
        clutterSizingTimer = setTimeout(() => { clutterSizingTimer = null; loadClutter(false); }, WORKTREE_SIZING_POLL_MS);
      }
    }
  }

  // Policy lists are not telemetry either: they load when the Policy tab
  // opens and on its Refresh, never on the refresh cycle.
  const policyState = { guardRules: null, pathAllows: null, mutes: null, loading: false, error: '' };
  async function loadPolicy() {
    if (policyState.loading) return;
    policyState.loading = true;
    policyState.error = '';
    markDirty('policy');
    const get = async (path) => {
      const r = await apiFetch(path);
      if (r.status === 403) { endSession(); throw new Error('session ended'); }
      if (!r.ok) throw new Error((await r.text()).trim() || String(r.status));
      return (await r.json()) || [];
    };
    try {
      const [rules, paths, mutes] = await Promise.all([get('/guard/rules'), get('/guard/path-allow'), get('/mute')]);
      Object.assign(policyState, { guardRules: rules, pathAllows: paths, mutes });
    } catch (err) {
      policyState.error = "Couldn't load the policy lists: " + (err.message || err);
    } finally {
      policyState.loading = false;
      markDirty('policy');
    }
  }
  function renderPolicyLists() {
    const put = (id, badge, rows, html) => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = html;
      const b = document.getElementById(badge);
      if (b) b.textContent = rows ? rows.length : 0;
    };
    const st = policyState;
    put('policy-guard-rules', 'badge-guard-rules', st.guardRules, policyListHTML('guard', st.guardRules, st));
    put('policy-path-allows', 'badge-path-allows', st.pathAllows, policyListHTML('path', st.pathAllows, st));
    put('policy-mutes', 'badge-mutes', st.mutes, policyListHTML('mute', st.mutes, st));
  }

  // Agent tab: the system agent's status, chat, plans and runs load when
  // the tab opens and after each action. While the model answers or a
  // headless run is in flight, the busy part is re-read every
  // AGENT_POLL_MS (tab open only); when it settles, everything once more.
  const AGENT_POLL_MS = 1500;
  const AGENT_POLL_LIMIT = 1200;
  const AGENT_TIMEOUT_MS = 15000;
  const agentState = { status: null, chat: null, plans: null, runs: null, skills: null, error: '', polls: 0, lastCount: 0 };
  // Literal paths: the proxy's console allow-list test reads them from here.
  const AGENT_PATHS = { status: '/agent/status', chat: '/agent/chat', plans: '/agent/plans', runs: '/agent/runs' };
  let agentPollTimer = null;
  const agentComposer = document.getElementById('agent-composer');
  const agentInput = document.getElementById('agent-input');
  const agentHarnessSelect = document.getElementById('agent-harness');
  const agentWorkdirInput = document.getElementById('agent-workdir');
  try { if (agentWorkdirInput) agentWorkdirInput.value = sessionStorage.getItem('sa.agent-workdir') || ''; } catch { /* private mode */ }
  async function agentFetch(path, opts = {}) {
    const init = { timeoutMs: AGENT_TIMEOUT_MS, method: opts.method || 'GET' };
    if (opts.body !== undefined) {
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(opts.body);
    }
    const r = await apiFetch(path, init);
    if (r.status === 403) { endSession(); throw new Error('session ended'); }
    const text = await r.text();
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    try { return JSON.parse(text); } catch { return null; }
  }
  function agentBusy() {
    return !!((agentState.chat && agentState.chat.chatting) || (agentState.runs || []).some(r => r.status === 'running'));
  }
  async function loadAgent(parts) {
    const want = parts || ['status', 'chat', 'plans', 'runs'];
    const wasBusy = agentBusy();
    try {
      const got = await Promise.all(want.map(p => agentFetch(AGENT_PATHS[p])));
      want.forEach((p, i) => { agentState[p] = got[i]; });
      agentState.error = '';
      if (want.includes('status')) fillAgentHarnesses();
    } catch (err) {
      agentState.error = "Couldn't load the system agent: " + (err.message || err);
    }
    markDirty('agent');
    followAgent(wasBusy);
  }
  function followAgent(wasBusy) {
    if (!agentBusy()) {
      agentState.polls = 0;
      if (wasBusy) loadAgent(['chat', 'plans', 'runs']);
      return;
    }
    if (agentPollTimer || activeTab !== 'agent' || agentState.polls >= AGENT_POLL_LIMIT) return;
    agentState.polls++;
    agentPollTimer = setTimeout(() => {
      agentPollTimer = null;
      loadAgent(agentState.chat && agentState.chat.chatting ? ['chat'] : ['runs']);
    }, AGENT_POLL_MS);
  }
  // The route-to dropdown follows /agent/status; the pick is kept per tab.
  function fillAgentHarnesses() {
    if (!agentHarnessSelect || !agentState.status) return;
    let pick = agentHarnessSelect.value;
    try { pick = pick || sessionStorage.getItem('sa.agent-harness') || ''; } catch { /* private mode */ }
    const hs = agentState.status.harnesses || [];
    if (!hs.some(h => h.id === pick)) pick = (hs.find(h => h.ready) || hs[0] || {}).id || '';
    agentHarnessSelect.innerHTML = agentHarnessOptionsHTML(agentState.status, pick);
  }
  function renderAgent() {
    const st = agentState.status;
    const enabled = !!(st && st.enabled);
    const stateEl = document.getElementById('agent-state');
    if (stateEl) stateEl.textContent = agentState.error || agentStateText(st);
    if (agentComposer) {
      agentComposer.classList.toggle('off', !enabled);
      agentComposer.querySelectorAll('textarea, select, input, button').forEach(el => { el.disabled = !enabled; });
    }
    const thread = document.getElementById('agent-thread');
    if (thread && st && !enabled) {
      if (thread._saEmpty !== 'off') { thread.innerHTML = agentOffHTML(); thread._saEmpty = 'off'; }
    } else if (thread) {
      const items = agentThreadItems(agentState.chat, st);
      patchList(thread, items, { key: i => i.key, html: i => i.html, empty: agentEmptyThreadHTML(st) });
      if (items.length !== agentState.lastCount) {
        agentState.lastCount = items.length;
        thread.scrollTop = thread.scrollHeight;
      }
    }
    const plans = agentState.plans;
    const plansEl = document.getElementById('agent-plans');
    if (plansEl && plans) {
      patchList(plansEl, plans, { key: p => p.id, html: p => agentPlanHTML(p, st),
        empty: '<div class="empty"><span>No plans yet. A proposal whose harness cannot run now is saved here; Save as plan keeps any request for later.</span></div>' });
    }
    const badge = document.getElementById('badge-agent-plans');
    if (badge) badge.textContent = plans ? plans.length : 0;
    const runsEl = document.getElementById('agent-runs');
    if (runsEl && agentState.runs) {
      const now = Date.now();
      patchList(runsEl, agentState.runs, { key: r => r.id, html: r => agentRunHTML(r, st, now),
        empty: '<div class="empty"><span>No dispatches yet. Run a plan headless or open it in a terminal.</span></div>' });
    }
    const hEl = document.getElementById('agent-harnesses');
    if (hEl) hEl.innerHTML = agentHarnessesHTML(st);
    const sEl = document.getElementById('agent-skills');
    if (sEl) sEl.innerHTML = agentSkillsHTML(st);
  }
  window.sendAgentMessage = async function() {
    const text = agentInput ? agentInput.value.trim() : '';
    if (!text) return;
    try {
      const res = await agentFetch('/agent/chat', { method: 'POST',
        body: { message: text, harness: agentHarnessSelect.value, workdir: agentWorkdirInput.value.trim() } });
      agentInput.value = '';
      const chat = agentState.chat || (agentState.chat = { messages: [] });
      if (res && res.message) chat.messages = [...(chat.messages || []), res.message];
      chat.chatting = true;
      renderNow(['agent']);
      followAgent(false);
    } catch (err) {
      showToast('Not sent: ' + (err.message || err), 'danger');
    }
  };
  window.saveAgentRequest = async function() {
    const text = agentInput ? agentInput.value.trim() : '';
    if (!text) { showToast("Write the request first — it becomes the plan's task", 'info'); return; }
    const workdir = agentWorkdirInput.value.trim() || (agentState.status && agentState.status.home) || '';
    try {
      const res = await agentFetch('/agent/plans', { method: 'POST',
        body: { harness: agentHarnessSelect.value, mode: 'terminal', workdir, task: text } });
      agentInput.value = '';
      showToast(`Saved as plan #${res.plan.id} — dispatch it from Plans`, 'success');
      loadAgent(['plans']);
    } catch (err) {
      showToast('Not saved: ' + (err.message || err), 'danger');
    }
  };
  window.saveAgentProposal = async function(messageId) {
    try {
      const res = await agentFetch('/agent/plans', { method: 'POST', body: { message_id: messageId } });
      showToast(`Saved as plan #${res.plan.id}`, 'success');
      loadAgent(['chat', 'plans']);
    } catch (err) {
      showToast('Not saved: ' + (err.message || err), 'danger');
    }
  };
  // dispatchAgent confirms, then (for a reply's proposal) saves it as a
  // plan, then dispatches it.
  window.dispatchAgent = async function({ planId, messageId, mode }) {
    let plan = planId ? (agentState.plans || []).find(p => p.id === planId) : null;
    if (!plan && messageId) {
      const m = ((agentState.chat && agentState.chat.messages) || []).find(x => x.id === messageId);
      plan = m && m.proposal ? { ...m.proposal } : null;
    }
    if (!plan) return;
    const ok = await window.saConfirm(agentDispatchMessage(plan, mode, agentState.status),
      { title: mode === 'terminal' ? 'Open in terminal' : 'Run headless', okLabel: mode === 'terminal' ? 'Open' : 'Run', danger: false });
    if (!ok) return;
    try {
      if (!planId) {
        const saved = await agentFetch('/agent/plans', { method: 'POST', body: { message_id: messageId } });
        planId = saved.plan.id;
      }
      const res = await agentFetch('/agent/dispatch', { method: 'POST', body: { plan_id: planId, mode } });
      const run = (res && res.run) || {};
      const label = agentHarnessLabel(agentState.status, run.harness);
      const said = { running: `${label} is running headless — its answer shows under Runs`, opened: `${label} opened in Terminal`,
        manual: 'Run the command under Runs in a terminal' };
      showToast(said[run.status] || 'Dispatched', run.status === 'manual' ? 'info' : 'success');
    } catch (err) {
      showToast('Not dispatched: ' + (err.message || err), 'danger');
    }
    loadAgent(['chat', 'plans', 'runs']);
  };
  window.deleteAgentPlan = async function(planId) {
    const ok = await window.saConfirm(`Delete plan #${planId}? Its runs stay listed.`, { title: 'Delete plan', okLabel: 'Delete' });
    if (!ok) return;
    try {
      await agentFetch('/agent/plans?id=' + encodeURIComponent(planId), { method: 'DELETE' });
      loadAgent(['plans']);
    } catch (err) {
      showToast('Not deleted: ' + (err.message || err), 'danger');
    }
  };
  window.clearAgentChat = async function() {
    const ok = await window.saConfirm('Delete the conversation? Plans and runs stay.', { title: 'Clear conversation', okLabel: 'Clear' });
    if (!ok) return;
    try {
      await agentFetch('/agent/chat', { method: 'DELETE' });
      loadAgent(['chat']);
    } catch (err) {
      showToast('Not cleared: ' + (err.message || err), 'danger');
    }
  };
  window.showAgentSkill = async function(id) {
    try {
      if (!agentState.skills) agentState.skills = await agentFetch('/agent/skills');
      const s = (agentState.skills || []).find(x => x.id === id);
      if (!s) return;
      openDrawer({ title: s.title, icon: 'doc',
        body: `<div class="panel-body"><p>${escapeHTML(s.summary)}</p><pre class="agent-skill-body">${escapeHTML(s.body)}</pre></div>` });
    } catch (err) {
      showToast("Couldn't load the skill: " + (err.message || err), 'danger');
    }
  };
  if (agentComposer) {
    agentComposer.addEventListener('submit', (e) => { e.preventDefault(); window.sendAgentMessage(); });
    agentInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); window.sendAgentMessage(); }
    });
    agentHarnessSelect.addEventListener('change', () => {
      try { sessionStorage.setItem('sa.agent-harness', agentHarnessSelect.value); } catch { /* private mode */ }
    });
    agentWorkdirInput.addEventListener('change', () => {
      try { sessionStorage.setItem('sa.agent-workdir', agentWorkdirInput.value.trim()); } catch { /* private mode */ }
    });
  }

  // dropWorktreeRows removes rows the daemon just pruned or moved to the
  // Trash, so the tab updates without a rescan.
  function dropWorktreeRows(paths) {
    const rep = worktreesState.report;
    if (!rep) return;
    const gone = new Set(paths);
    for (const repo of rep.repos || []) {
      const dropped = (repo.worktrees || []).filter(w => gone.has(w.path));
      if (!dropped.length) continue;
      repo.worktrees = repo.worktrees.filter(w => !gone.has(w.path));
      for (const w of dropped) {
        const size = Number(w.size_bytes) || 0;
        repo.size_bytes = Math.max(0, (Number(repo.size_bytes) || 0) - size);
        if (rep.summary) {
          rep.summary.worktrees = Math.max(0, (rep.summary.worktrees || 0) - 1);
          rep.summary.size_bytes = Math.max(0, (Number(rep.summary.size_bytes) || 0) - size);
          if (w.state === 'remove') rep.summary.removable_bytes = Math.max(0, (Number(rep.summary.removable_bytes) || 0) - size);
        }
      }
    }
  }

  // Home groups: closed by default, open state kept for the tab. A panel
  // in a closed group does not render; opening the group renders it.
  const HOME_GROUPS_KEY = 'sa.home-groups';
  function homeGroupOpen(group) {
    const el = document.getElementById('home-' + group);
    return !!(el && el.open);
  }
  function persistHomeGroups() {
    const state = {};
    document.querySelectorAll('details.home-group').forEach(d => { state[d.dataset.group] = d.open; });
    try { sessionStorage.setItem(HOME_GROUPS_KEY, JSON.stringify(state)); } catch { /* private mode */ }
  }
  try {
    const saved = JSON.parse(sessionStorage.getItem(HOME_GROUPS_KEY) || '{}') || {};
    document.querySelectorAll('details.home-group').forEach(d => { if (saved[d.dataset.group]) d.open = true; });
  } catch { /* private mode or corrupt value: groups stay closed */ }
  document.querySelectorAll('details.home-group').forEach(d => d.addEventListener('toggle', () => {
    persistHomeGroups();
    if (!d.open) return;
    PANELS.forEach(([name]) => { if (PANEL_VIEW[name] === 'home:' + d.dataset.group) dirtyPanels.add(name); });
    renderDirty();
  }));

  // switchTab takes any route: a tab, "sessions/<sub>", or an old tab id
  // (menu bar deep link, saved view, stored tab, in-page link) through the
  // alias table. opts.group expands that Home group.
  function switchTab(id, opts = {}) {
    const r = resolveConsoleRoute(id);
    const from = activeTab;
    activeTab = r.tab;
    if (r.tab === 'sessions') activeSub = r.sub;
    document.querySelectorAll('.tab-btn').forEach(b => {
      const on = b.dataset.tab === activeTab;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.tabpanel').forEach(p => { p.hidden = p.id !== 'tab-' + activeTab; });
    document.querySelectorAll('.subtab-btn').forEach(b => {
      const on = b.dataset.subtab === activeSub;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.subview').forEach(v => { v.hidden = v.id !== 'sub-' + activeSub; });
    const group = opts.group && document.getElementById('home-' + opts.group);
    if (group && activeTab === 'home' && !group.open) group.open = true;
    const key = routeKey({ tab: activeTab, sub: activeSub });
    try { sessionStorage.setItem('sa.console-tab', key); } catch { /* private mode */ }
    if (!opts.skipHash && window.history.replaceState) {
      history.replaceState(null, '', location.pathname + location.search + consoleRouteHash({ tab: activeTab, sub: activeSub }));
    }
    PANELS.forEach(([name]) => { if (panelOnScreen(name)) dirtyPanels.add(name); });
    renderDirty();
    if (activeTab === 'sessions' && activeSub === 'worktrees'
      && (!worktreesState.report || Date.now() - worktreesState.loadedAt > WORKTREE_STALE_MS)) {
      loadWorktrees(false);
    }
    if (activeTab === 'sessions' && activeSub === 'worktrees'
      && (!clutterState.report || Date.now() - clutterState.loadedAt > WORKTREE_STALE_MS)) {
      loadClutter(false);
    }
    if (activeTab === 'policy' && from !== 'policy') loadPolicy();
    if (activeTab === 'agent' && from !== 'agent') loadAgent();
    const focus = r.focus === 'attention' ? document.getElementById('attention-center') : group;
    if (focus && focus.scrollIntoView) focus.scrollIntoView({ behavior: 'auto', block: 'start' });
  }

  // The Sessions tab reopens its last sub-view.
  document.querySelectorAll('.tab-btn').forEach(b =>
    b.addEventListener('click', () => switchTab(b.dataset.tab === 'sessions' ? 'sessions/' + activeSub : b.dataset.tab)));
  document.querySelectorAll('.subtab-btn').forEach(b =>
    b.addEventListener('click', () => switchTab('sessions/' + b.dataset.subtab)));

  // Tab badges: the "something needs you here" signal for hidden panels.
  // home, sessions, egress are tab badges; the sessions and processes
  // counts also sit on their sub-view buttons.
  const BADGE_ELS = {
    home: ['tab-badge-home'], egress: ['tab-badge-egress'],
    sessions: ['tab-badge-sessions', 'subtab-badge-board'], processes: ['subtab-badge-processes']
  };
  function setTabBadge(id, n) {
    for (const elId of BADGE_ELS[id] || []) {
      const el = document.getElementById(elId);
      if (!el) continue;
      el.hidden = !(n > 0);
      el.textContent = n > 0 ? n : '';
    }
  }

  // Initial tab: hash (deep link, old ids included) > session memory > Home.
  let initialTab = (location.hash || '').replace('#', '');
  if (!isConsoleRoute(initialTab)) {
    try { initialTab = sessionStorage.getItem('sa.console-tab') || 'home'; }
    catch { initialTab = 'home'; }
  }
  switchTab(initialTab, { skipHash: true });

  async function fetchTelemetry(opts) {
    // grab(): one fetch with honest failure semantics. 403 = the session is
    // dead (drives the ended state); other HTTP errors mark just that
    // endpoint failed; network errors drive the unreachable state. A failed
    // endpoint NEVER overwrites the panel's last good data.
    if (sessionEnded) return;
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
      if (snap.patterns) telemetryData.patterns = snap.patterns || [];
      if (snap.incidents) telemetryData.incidents = snap.incidents || [];
      if (snap.events) telemetryData.events = snap.events || [];
      if (snap.posture) telemetryData.posture = snap.posture;
      if (snap.suggestions) telemetryData.suggestions = snap.suggestions || [];
      if (snap.mutes) telemetryData.mutes = snap.mutes || [];
      if (snap.sessions) telemetryData.sessions = snap.sessions || [];
    }

    const cardPath = spendCardPath();
    if (slow) {
      const [fleet, audit, sources, rollup, uninspected, notifyCfg, allowlist, episodes, costs, costsCard, costPlans] = await Promise.all([
        grab('fleet', '/fleet'),
        grab('audit', '/audit?limit=50'),
        grab('firewall sources', '/firewall/sources'),
        grab('activity rollup', '/stats/rollup?hours=168'),
        grab('uninspected egress', '/egress/uninspected?hours=24&limit=200'),
        grab('notification rules', '/notify/rules'),
        grab('allowlist', '/allowlist'),
        grab('resource episodes', '/resources/episodes'),
        grab('spend', '/costs?since=24h&by=repo'),
        grab('spend card', cardPath),
        grab('spend plans', '/costs/plans')
      ]);
      if (fleet) telemetryData.fleet = fleet || [];
      if (audit) telemetryData.audit = audit || [];
      if (sources) telemetryData.sources = sources || [];
      if (rollup) telemetryData.rollup = rollup || [];
      if (uninspected) telemetryData.uninspected = uninspected || [];
      if (episodes) telemetryData.episodes = episodes || [];
      if (notifyCfg) {
        // A reconcile while the operator is typing a workspace path must not
        // dirty (and re-render) the notify panel unless the served config
        // actually changed — a stable hash, not the poll cadence, decides.
        const h = JSON.stringify(notifyCfg);
        if (h !== notifyCfgHash) { notifyCfgHash = h; telemetryData.notifyCfg = notifyCfg; markDirty('notify'); }
      }
      if (allowlist) telemetryData.allowlist = allowlist || [];
      if (costs) telemetryData.costs = costs;
      if (costPlans) telemetryData.costPlans = costPlans;
      if (costsCard && cardPath === spendCardPath()) telemetryData.costsCard = costsCard;
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
    if (!telemetryData.connected && sawAuth) { endSession(); return; }
    setConnState(telemetryData.connected ? 'ok' : 'unreachable');

    if (!booted || (opts && opts.full)) renderAll();
    // 'notify' is excluded here: it dirties itself above, only when its
    // fetched config actually changed, so an unrelated poll tick never
    // erases an in-progress workspace-scope edit.
    else markDirty(...PANELS.map(p => p[0]).filter(n => (slow || !SLOW_ONLY.has(n)) && n !== 'notify'));
    if (resources) fillFamilyDrawer();
  }

  // Every panel is a candidate: initial load, Refresh, and actions that
  // reshape every list (search, session select). "Candidate" does not mean
  // "rendered" — renderDirty() still runs each through panelOnScreen, so a
  // closed Home group or a hidden Sessions sub-view stays dirty instead of
  // painting off-screen DOM, and picks up its render the moment it is shown
  // (switchTab/openHomeGroup mark it dirty again, or it is already dirty
  // here). Crash isolation is unchanged: renderDirty still renders each
  // panel through renderPanel, so one panel's bad data never takes the whole
  // page down with it (the /fleet shape mismatch once killed every panel
  // after it on every poll).
  function renderAll() {
    booted = true;
    for (const [name] of PANELS) dirtyPanels.add(name);
    renderDirty();
  }

  // Activity rollup chart: hourly event bars with rose flag markers — the
  // "is this normal for this machine?" answer at a glance. The 24h/7d toggle
  // re-slices the same 7d fetch locally (no refetch).
  document.getElementById('activity-window')?.addEventListener('change', renderActivity);

  // Spend card controls: a change saves the view, clears the card and fetches
  // the new report; a response for a view since replaced is dropped.
  const spendBySel = document.getElementById('spend-by');
  const spendSinceSel = document.getElementById('spend-since');
  if (spendBySel) spendBySel.value = spendView.by;
  if (spendSinceSel) spendSinceSel.value = spendView.since;
  async function loadSpendCard() {
    const path = spendCardPath();
    try {
      const r = await apiFetch(path);
      if (!r.ok) { noteEndpointFailure('spend card'); return; }
      const rep = await r.json();
      if (path !== spendCardPath()) return;
      failedEndpoints.delete('spend card');
      telemetryData.costsCard = rep;
      renderNow(['spend']);
    } catch { /* network error: the next slow refresh retries */ }
  }
  const onSpendView = () => {
    const by = spendBySel && spendBySel.value, since = spendSinceSel && spendSinceSel.value;
    spendView = { by: SPEND_BY.includes(by) ? by : 'repo', since: SPEND_SINCE.includes(since) ? since : '24h' };
    try { sessionStorage.setItem(SPEND_VIEW_KEY, JSON.stringify(spendView)); } catch { /* private mode */ }
    telemetryData.costsCard = null;
    renderNow(['spend']);
    loadSpendCard();
  };
  spendBySel?.addEventListener('change', onSpendView);
  spendSinceSel?.addEventListener('change', onSpendView);

  function renderStatus() {
    const chip = document.getElementById('system-status');
    if (!telemetryData.connected) {
      if (chip) chip.className = 'status-chip down';
      document.getElementById('status-text').textContent = 'Disconnected';
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
  const endedSessionsOpen = {}; // harness key → ended tail expanded
  const sessionDupOpen = {}; // '<live|ended>|<folded rail row key>' → expanded
  const familyDupOpen = {}; // folded Resources family row key → expanded
  const agentGroupOpen = {};
  const agentTreeOpen = {}; // instance root pid → helper disclosure open
  // cappedList keys the operator expanded ("events", "agents:<harness>",
  // "family-procs:<family key>"); re-renders keep those lists whole.
  const expandedLists = new Set();

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


  // ---------- act in place ----------
  // A mutating action applies its expected result to telemetryData and
  // renders the affected panels BEFORE the request; the card changes under
  // the click. stage() snapshots the top-level keys the mutation replaces
  // (mutations assign new values, never edit in place) and returns revert(),
  // which restores a key only if nothing (SSE, reconcile) replaced it since.
  function stage(keys, panels, mutate) {
    const before = keys.map(k => telemetryData[k]);
    mutate();
    const after = keys.map(k => telemetryData[k]);
    renderNow(panels);
    return () => {
      keys.forEach((k, i) => { if (telemetryData[k] === after[i]) telemetryData[k] = before[i]; });
      renderNow(panels);
    };
  }
  // posture.groups is the attention queue: map its items, drop empty groups;
  // a dropped item leaves posture.items and needs_you with it.
  function mapAttentionItems(fn) {
    const p = telemetryData.posture;
    if (!p || !p.groups) return;
    telemetryData.posture = mapPostureAttention(p, fn);
  }
  const withMode = (rules, mode) => {
    const s = telemetryData.status;
    if (!s || !s.firewall_stats) return;
    const stats = { ...s.firewall_stats };
    rules.forEach(r => { if (stats[r]) stats[r] = { ...stats[r], mode }; });
    telemetryData.status = { ...s, firewall_stats: stats };
  };
  const cssq = v => CSS.escape(String(v));
  // One-line confirmation on the card the action changed, for 4s. When the
  // action removed the card, the note sits on its panel's head.
  function cardNote(selector, cardSel, panelId, text) {
    const hit = selector && document.querySelector(selector);
    let at = hit && hit.closest(cardSel);
    if (!at) {
      const panel = document.getElementById(panelId)?.closest('.panel');
      at = panel && panel.querySelector('.panel-head');
    }
    if (!at) return;
    const note = document.createElement('span');
    note.className = 'card-note';
    note.textContent = text;
    at.appendChild(note);
    setTimeout(() => note.remove(), 4000);
  }
  const allowRowSel = (agent, host) => `#firewall-container [data-action="allowlist-remove"][data-agent="${cssq(agent)}"][data-host="${cssq(host)}"]`;
  function stageAllow(agent, hosts) {
    const hit = x => x.agent === agent && hosts.includes(x.host);
    return stage(['allowlist', 'suggestions', 'uninspected'], ['firewall', 'endpoints'], () => {
      const have = telemetryData.allowlist || [];
      telemetryData.allowlist = have.concat(hosts.filter(h => !have.some(p => p.agent === agent && p.host === h)).map(host => ({ agent, host })));
      telemetryData.suggestions = (telemetryData.suggestions || []).filter(x => !hit(x));
      telemetryData.uninspected = (telemetryData.uninspected || []).filter(x => !hit(x));
    });
  }
  function refillUninspected() {
    markDirty('endpoints');
    if (drawerMode === 'uninspected' && drawer && !drawer.hidden) fillUninspected(drawerBody);
  }

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
    const revert = stage(['incidents', 'posture'], ['incidents', 'attention', 'status'], () => {
      telemetryData.incidents = (telemetryData.incidents || []).map(inc => inc.id !== id ? inc
        : { ...inc, workflow: { ...(inc.workflow || {}), status, ...(body.note ? { resolution_note: body.note } : {}) } });
      // resolved leaves the queue; acknowledged stays, marked seen.
      mapAttentionItems(it => (it.kind !== 'incident' || it.id !== id ? it : status === 'resolved' ? null : { ...it, status }));
    });
    try {
      const r = await apiFetch('/incidents/status', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (!r.ok) throw new Error(await r.text());
      showToast(status === 'resolved' ? 'Incident resolved' : 'Incident acknowledged', 'success');
      cardNote(`#incidents-container [data-action="open-incident"][data-id="${cssq(id)}"]`, '.incident-card', 'incidents-container', status);
      fetchTelemetry();
    } catch (err) {
      revert();
      showToast('Failed to update incident: ' + err.message, 'danger');
    }
  };

  // Worktree actions. The daemon re-inspects before removing and answers 409
  // with the fresh verdict when the worktree is no longer removable.
  async function postWorktree(path, body) {
    const r = await apiFetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), timeoutMs: WORKTREE_TIMEOUT_MS
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* http.Error text */ }
    return { r, text, json };
  }

  window.removeWorktree = async function(path, branch) {
    const ok = await window.saConfirm(
      `git deletes ${path} and its ignored files. ${branch ? `Branch ${branch} and its commits stay.` : 'Its commits stay reachable from other refs.'}`,
      { title: 'Remove worktree', okLabel: 'Remove' });
    if (!ok) return;
    // The daemon removes in the background; the row shows each step and the
    // outcome, which the re-reads pick up.
    try {
      const { r, text, json } = await postWorktree('/worktrees/remove', { path, async: true });
      if (!r.ok || !json || !json.removal) throw new Error(text.trim() || String(r.status));
      const rep = worktreesState.report;
      if (rep) (rep.removals || (rep.removals = {}))[path] = json.removal;
      renderNow(['worktrees']);
      followWorktreeSizing();
    } catch (err) {
      showToast('Could not start the removal: ' + (err.message || err), 'danger');
    }
  };

  // Remove all: every removable row of one repository, each checked again
  // by the daemon before it goes; one line when the batch ends.
  window.removeAllWorktrees = async function(repoPath) {
    const rep = worktreesState.report;
    const repo = rep && (rep.repos || []).find(r => r.path === repoPath);
    const rows = removableRows(repo, rep && rep.removals);
    if (!rows.length) return;
    const bytes = rows.reduce((n, w) => n + (Number(w.size_bytes) || 0), 0);
    const ok = await window.saConfirm(
      `git deletes ${rows.length} worktrees of ${repoPath}${bytes ? ` (${fmtDisk(bytes)})` : ''} and their ignored files. Their branches and commits stay; each is checked again before it goes.`,
      { title: 'Remove all', okLabel: `Remove ${rows.length}` });
    if (!ok) return;
    const started = [];
    for (const w of rows) {
      try {
        const { r, text, json } = await postWorktree('/worktrees/remove', { path: w.path, async: true });
        if (!r.ok || !json || !json.removal) throw new Error(text.trim() || String(r.status));
        (rep.removals || (rep.removals = {}))[w.path] = json.removal;
        started.push(w.path);
      } catch (err) {
        showToast(`Could not start removing ${w.path}: ${err.message || err}`, 'danger');
      }
    }
    if (started.length) removalBatches.push({ paths: started });
    renderNow(['worktrees']);
    followWorktreeSizing();
  };

  // Folders git no longer records: open in Finder, link again to the
  // repository that still records them, or move to the Trash.
  window.revealWorktree = async function(path) {
    try {
      const { r, text } = await postWorktree('/worktrees/reveal', { path });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
    } catch (err) {
      showToast('Could not open the folder: ' + (err.message || err), 'danger');
    }
  };
  window.reconnectWorktree = async function(path, repo) {
    const ok = await window.saConfirm(`git worktree repair links ${path} to ${repo} again. Nothing is deleted.`,
      { title: 'Reconnect worktree', okLabel: 'Reconnect' });
    if (!ok) return;
    try {
      const { r, text } = await postWorktree('/worktrees/reconnect', { path });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      showToast(`Reconnected ${path} to ${repo}`, 'success');
      loadWorktrees(false);
    } catch (err) {
      showToast('Could not reconnect: ' + (err.message || err), 'danger');
    }
  };
  window.trashOrphanWorktree = async function(path) {
    const ok = await window.saConfirm(`Move ${path} to the Trash? Git no longer records it, so its files are the only copy; you can put it back from the Trash until you empty it.`,
      { title: 'Move to Trash', okLabel: 'Move to Trash' });
    if (!ok) return;
    try {
      const { r, text, json } = await postWorktree('/worktrees/trash', { path });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      const bytes = Number(json && json.result && json.result.bytes) || 0;
      dropWorktreeRows([path]);
      renderNow(['worktrees']);
      showToast(bytes ? `Moved ${path} to the Trash — ${fmtDisk(bytes)}` : `Moved ${path} to the Trash`, 'success');
      loadWorktrees(false);
    } catch (err) {
      showToast('Could not move it to the Trash: ' + (err.message || err), 'danger');
    }
  };

  // Ask the local advisor for a note. The note is looked up on every GET, so
  // a few cheap re-reads of the cached report pick it up when the model
  // answers; no rescan.
  const WORKTREE_NOTE_POLLS = 6;
  const WORKTREE_NOTE_EVERY_MS = 10000;
  window.adviseWorktree = async function(path) {
    try {
      const { r, text, json } = await postWorktree('/worktrees/advise', { path });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      if (!json || !json.queued) {
        showToast('The advisor is off or busy — no note queued', 'info');
        return;
      }
      showToast('Asked the local advisor — the note appears under the row when it answers', 'info');
      for (let i = 0; i < WORKTREE_NOTE_POLLS; i++) {
        await new Promise(res => setTimeout(res, WORKTREE_NOTE_EVERY_MS));
        const g = await apiFetch('/worktrees', { timeoutMs: WORKTREE_TIMEOUT_MS });
        if (!g.ok) break;
        const rep = await g.json();
        worktreesState.report = rep;
        markDirty('worktrees');
        if (rep.advice && rep.advice[path]) break;
      }
    } catch (err) {
      showToast('Failed to ask the advisor: ' + (err.message || err), 'danger');
    }
  };

  window.trashClutter = async function(path) {
    const ok = await window.saConfirm(`Move ${path} to the Trash? You can put it back from the Trash until you empty it.`,
      { title: 'Move to Trash', okLabel: 'Move to Trash' });
    if (!ok) return;
    try {
      const { r, text, json } = await postWorktree('/cleanup/trash', { path });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      const bytes = Number(json && json.result && json.result.bytes) || 0;
      const rep = clutterState.report;
      if (rep) {
        rep.items = (rep.items || []).filter(it => it.path !== path);
        const t = rep.reclaimed || (rep.reclaimed = { bytes: 0, count: 0, bytes_30d: 0, count_30d: 0, trashed_bytes: 0, trashed_count: 0 });
        t.trashed_bytes = (Number(t.trashed_bytes) || 0) + bytes;
        t.trashed_count = (Number(t.trashed_count) || 0) + 1;
      }
      renderNow(['clutter']);
      showToast(`Moved ${path} to the Trash — ${fmtDisk(bytes)} frees when you empty it`, 'success');
    } catch (err) {
      showToast('Failed to move to the Trash: ' + (err.message || err), 'danger');
    }
  };

  // Ask the local advisor for a project's cleanup plan; the plan arrives in
  // GET /cleanup's advice, re-read every 5 s for up to a minute.
  const CLUTTER_PLAN_POLLS = 12;
  const CLUTTER_PLAN_EVERY_MS = 5000;
  window.adviseClutterProject = async function(project) {
    try {
      const { r, text, json } = await postWorktree('/cleanup/advise', { project });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      if (!json || !json.queued) {
        showToast('The advisor is off or busy — no plan queued', 'info');
        return;
      }
      showToast('Asked the local advisor for a plan — it appears under the project when it answers', 'info');
      for (let i = 0; i < CLUTTER_PLAN_POLLS; i++) {
        await new Promise(res => setTimeout(res, CLUTTER_PLAN_EVERY_MS));
        const g = await apiFetch('/cleanup', { timeoutMs: WORKTREE_TIMEOUT_MS });
        if (!g.ok) break;
        const rep = await g.json();
        clutterState.report = rep;
        markDirty('clutter');
        if (rep.advice && rep.advice[project]) break;
      }
    } catch (err) {
      showToast('Failed to ask the advisor: ' + (err.message || err), 'danger');
    }
  };

  window.cleanClutter = async function(name) {
    const it = ((clutterState.report && clutterState.report.items) || []).find(x => x.name === name && x.action === 'clean');
    const ok = await window.saConfirm(`Run \`${(it && it.command) || name}\`? The tool clears its own cache; it may take a few minutes.`,
      { title: 'Clean cache', okLabel: 'Run', danger: false });
    if (!ok) return;
    showToast(`Running ${(it && it.command) || name}…`, 'info');
    try {
      const { r, text, json } = await postWorktree('/cleanup/clean', { name });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      const bytes = Number(json && json.result && json.result.bytes) || 0;
      showToast(`${name}: ${fmtDisk(bytes)} reclaimed`, 'success');
      loadClutter(false);
    } catch (err) {
      showToast('Clean failed: ' + (err.message || err), 'danger');
    }
  };

  // Resume the agent that worked in the worktree with the cleanup request;
  // its answer arrives in the report's asks (the tab re-reads meanwhile).
  window.askWorktreeAgent = async function(path) {
    const ok = await window.saConfirm(
      `Resume the agent that worked in ${path}? It gets a fixed request: open a pull request for work worth keeping, or say the worktree can go. It runs with your agent settings (it may commit and push), capped at $1.00 for Claude Code and 15 minutes.`,
      { title: 'Ask the agent', okLabel: 'Ask', danger: false });
    if (!ok) return;
    try {
      const { r, text, json } = await postWorktree('/worktrees/ask', { path });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      const ask = json && json.ask;
      const rep = worktreesState.report;
      if (rep && ask) (rep.asks || (rep.asks = {}))[path] = ask;
      renderNow(['worktrees']);
      showToast(`Asked ${ask ? ask.harness : 'the agent'} — its answer shows under the row`, 'info');
      worktreeSizingPolls = 0;
      followWorktreeSizing();
    } catch (err) {
      showToast('Could not ask the agent: ' + (err.message || err), 'danger');
    }
  };

  window.pruneWorktrees = async function(repo) {
    const ok = await window.saConfirm(`Drop git's entries for worktrees of ${repo} whose directory is gone?`,
      { title: 'Prune worktrees', okLabel: 'Prune', danger: false });
    if (!ok) return;
    try {
      const { r, text, json } = await postWorktree('/worktrees/remove', { repo, prune: true });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      const pruned = (json && json.pruned) || [];
      dropWorktreeRows(pruned);
      renderNow(['worktrees']);
      showToast(`Pruned ${pruned.length} worktree entr${pruned.length === 1 ? 'y' : 'ies'}`, 'success');
    } catch (err) {
      showToast('Failed to prune: ' + (err.message || err), 'danger');
    }
  };

  window.hideWorktreeRepo = async function(repo) {
    try {
      const { r, text } = await postWorktree('/worktrees/repos', { path: repo, hidden: true });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      const rep = worktreesState.report;
      if (rep) rep.repos = (rep.repos || []).filter(x => x.path !== repo);
      renderNow(['worktrees']);
      showToast(`Hidden ${repo} — adding it again brings it back`, 'info');
    } catch (err) {
      showToast('Failed to hide the repository: ' + (err.message || err), 'danger');
    }
  };

  const worktreeAddForm = document.getElementById('worktree-add-form');
  if (worktreeAddForm) worktreeAddForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('worktree-add-input');
    const path = (input.value || '').trim();
    if (!path) return;
    try {
      const { r, text, json } = await postWorktree('/worktrees/repos', { path });
      if (!r.ok) throw new Error(text.trim() || String(r.status));
      input.value = '';
      showToast(`Added ${(json && json.path) || path}`, 'success');
      loadWorktrees(false);
    } catch (err) {
      showToast('Failed to add the repository: ' + (err.message || err), 'danger');
    }
  });

  window.addSource = async function() {
    const input = document.getElementById('source-input');
    const value = (input.value || '').trim();
    if (!value) return;
    const revert = stage(['sources'], ['sources'], () => {
      telemetryData.sources = [...(telemetryData.sources || []), { source: value, origin: 'user' }];
    });
    try {
      const res = await apiFetch('/firewall/sources', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: value, op: 'add' })
      });
      if (!res.ok) { revert(); showToast('Failed to add source: ' + (await res.text()), 'danger'); return; }
      const data = await res.json();
      input.value = '';
      showToast(`Watching ${value} — ${data.registered} secret(s) registered`, 'success');
      cardNote(`#sources-list [data-action="remove-source"][data-source="${cssq(value)}"]`, '.source-item', 'sources-list', 'watching');
      fetchTelemetry();
    } catch (err) {
      revert();
      showToast('Failed to add source: ' + err, 'danger');
    }
  };

  window.removeSource = async function(source) {
    const revert = stage(['sources'], ['sources'], () => {
      telemetryData.sources = (telemetryData.sources || []).filter(x => x.source !== source);
    });
    try {
      const res = await apiFetch('/firewall/sources', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, op: 'remove' })
      });
      if (!res.ok) { revert(); showToast('Failed to remove source: ' + (await res.text()), 'danger'); return; }
      showToast(`Stopped watching ${source}`, 'info');
      cardNote('', '', 'sources-list', 'stopped watching');
      fetchTelemetry();
    } catch (err) {
      revert();
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
  // The flag leaves flags, flagsView and the attention queue; revert() puts
  // it back.
  function stageDropFlag(id) {
    return stage(['flags', 'flagsView', 'posture'], ['flags', 'attention', 'chart-flags', 'status', 'tab-badges'], () => {
      telemetryData.flags = (telemetryData.flags || []).filter(x => x.id !== id);
      telemetryData.flagsView = (telemetryData.flagsView || []).filter(x => x.id !== id);
      mapAttentionItems(it => (it.kind === 'flag' && it.id === id ? null : it));
    });
  }
  window.dismissFlag = async function(id) {
    const revert = stageDropFlag(id);
    try {
      const res = await apiFetch('/flags/acknowledge', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flag_id: id })
      });
      if (!res.ok) throw new Error(await res.text());
      showToast('Flag dismissed — the rule keeps watching', 'info');
      cardNote('', '', 'flags-list', 'dismissed');
      fetchTelemetry();
    } catch (err) {
      revert();
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
    endedSessionsOpen,
    sessionDupOpen,
    familyDupOpen,
    agentGroupOpen,
    agentTreeOpen,
    expanded: expandedLists,
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
    renderCounts,
    worktrees: worktreesState,
    clutter: clutterState,
    flushRender() {
      for (const [name, fn] of PANELS) if (dirtyPanels.has(name)) { dirtyPanels.delete(name); renderPanel(name, fn); }
    },
  };
  // toggle does not bubble: one capture listener records agent group and
  // helper-tree disclosure state for the next rebuild of that group.
  document.getElementById('agents-container')?.addEventListener('toggle', (e) => {
    const el = e.target;
    if (el.matches('details.agent-group')) agentGroupOpen[el.dataset.harness] = el.open;
    else if (el.matches('details.agent-tree')) agentTreeOpen[el.dataset.pid] = el.open;
  }, true);
  Object.defineProperties(window.SA, {
    activeTab: { get() { return activeTab; } },
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
  // Export: copy the session's markdown report. Safari only honours a
  // clipboard write started inside the click, so where ClipboardItem exists
  // the write starts now with the report body still loading.
  window.copySessionReport = function(id) {
    const text = apiFetch('/sessions/' + encodeURIComponent(id) + '/report?format=md').then(async r => {
      const body = await r.text();
      if (!r.ok) throw new Error((body || '').trim() || 'HTTP ' + r.status);
      return body;
    });
    const clip = navigator.clipboard;
    let write;
    if (clip && typeof clip.write === 'function' && typeof window.ClipboardItem === 'function') {
      write = clip.write([new ClipboardItem({ 'text/plain': text.then(t => new Blob([t], { type: 'text/plain' })) })]);
    } else if (clip) {
      write = text.then(t => clip.writeText(t));
    } else {
      write = Promise.reject(new Error('no clipboard'));
    }
    Promise.all([text, write]).then(
      () => showToast('Session report copied (markdown)', 'success'),
      err => showToast('Export failed: ' + ((err && err.message) || err), 'danger'));
  };
  window.selectSession = async function(id) {
    selectedSessionId = (selectedSessionId === id) ? '' : id;
    if (selectedSessionId) await loadSessionTimeline(selectedSessionId, true);
    renderAll();
  };

  // The drawer is shared by two views: the incident report (markdown, with a
  // Copy button) and the uninspected-egress drill-down (row actions, no
  // Copy). drawerMode tracks which one is open so action handlers can
  // re-render the right content after a mutation.
  let drawerMode = null; // 'incident' | 'endpoint' | 'file' | 'plan' | 'uninspected' | 'family' | 'policy' | null
  let drawerFile = '';
  let drawerPlan = '';

  let drawerIncident = '';
  let drawerEndpoint = null;
  window.openIncidentReport = async function(incidentId, { back } = {}) {
    if (!drawer) return;
    drawerMode = 'incident';
    drawerIncident = incidentId;
    if (btnDrawerCopy) btnDrawerCopy.hidden = false;
    openDrawer({
      title: `Incident report — ${incidentId}`,
      icon: 'doc',
      body: `<div class="loading-spinner">Fetching incident report…</div>`,
      onClose: () => { drawerMode = null; },
      back,
    });
    const seq = drawerSeq;

    try {
      const res = await apiFetch(`/incidents?id=${encodeURIComponent(incidentId)}&format=markdown`);
      if (seq !== drawerSeq) return;
      if (res.ok) {
        const text = await res.text();
        if (seq !== drawerSeq) return;
        currentRawMarkdown = text;
        drawerBody.innerHTML = linkEvidencePaths(parseMarkdownToHTML(text)) + planSlotHTML('incident:' + incidentId);
        loadPlanSlot('incident:' + incidentId);
      } else {
        drawerBody.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Failed to load the incident report.</span></div>`;
      }
    } catch (err) {
      if (seq !== drawerSeq) return;
      drawerBody.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Error: ${escapeHTML(err.message)}</span></div>`;
    }
  };

  // Endpoint detail: "what IS this address?" The Evidence action opens this so
  // an unknown IPv6 is explained (owner org, PTR name, which agents/sessions
  // reached it, recent connections) instead of being a bare address that looks
  // safe to block.
  window.openEndpointDetail = async function(host, agent, { back } = {}) {
    if (!drawer) return;
    drawerMode = 'endpoint';
    drawerEndpoint = { host, agent };
    if (btnDrawerCopy) btnDrawerCopy.hidden = true;
    openDrawer({
      title: 'Endpoint detail',
      icon: 'globe',
      onClose: () => { drawerMode = null; },
      back,
    });
    const seq = drawerSeq;
    drawerBody.innerHTML = `<div class="loading-spinner">Identifying ${escapeHTML(host)}…</div>`;
    try {
      const res = await apiFetch(`/egress/endpoint?host=${encodeURIComponent(host)}`);
      if (!res.ok) throw new Error((await res.text()).trim() || 'lookup failed');
      const detail = await res.json();
      if (seq !== drawerSeq) return;
      drawerBody.innerHTML = endpointDetailHTML(detail, agent);
    } catch (err) {
      if (seq !== drawerSeq) return;
      drawerBody.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>Could not identify this endpoint: ${escapeHTML(err.message || err)}</span></div>`;
    }
  };

  // File detail: an evidence path opens what the daemon knows about the file —
  // facts, the masked excerpt around each secret, findings and agent access —
  // with Reveal in Finder and Open in editor.
  window.openFileDetail = async function(path, { back } = {}) {
    if (!drawer) return;
    drawerMode = 'file';
    drawerFile = path;
    if (btnDrawerCopy) btnDrawerCopy.hidden = true;
    openDrawer({
      title: 'File',
      icon: 'doc',
      onClose: () => { drawerMode = null; },
      back,
    });
    const seq = drawerSeq;
    drawerBody.innerHTML = `<div class="loading-spinner">Reading ${escapeHTML(path)}…</div>`;
    try {
      const res = await apiFetch(`/files/detail?path=${encodeURIComponent(path)}`);
      if (!res.ok) throw new Error((await res.text()).trim() || 'lookup failed');
      const detail = await res.json();
      if (seq !== drawerSeq) return;
      drawerBody.innerHTML = fileDetailHTML(detail) + planSlotHTML('file:' + path);
      loadPlanSlot('file:' + path);
    } catch (err) {
      if (seq !== drawerSeq) return;
      drawerBody.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Could not read this file: ${escapeHTML(err.message || err)}</span></div>`;
    }
  };

  window.fileAction = async function(action, path) {
    try {
      const r = await apiFetch(action === 'reveal' ? '/files/reveal' : '/files/open', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path })
      });
      if (!r.ok) throw new Error((await r.text()).trim());
      showToast(action === 'reveal' ? 'Shown in Finder' : 'Opened in your editor', 'success');
    } catch (err) {
      showToast(`Could not ${action === 'reveal' ? 'reveal' : 'open'} the file: ${err.message || err}`, 'error');
    }
  };

  // Playbook and advisor plan. A slot (.plan-slot[data-plan-subject]) on any
  // surface shows GET /advisor/plan; asking POSTs and polls every 3 s while
  // the plan is pending (at most 90 s, and only while a slot for it is open).
  // Flags that come with a plan are kept so its action buttons work even when
  // the flag is outside the loaded list.
  const planFlagCache = new Map();
  const planPolls = new Map();
  const planSlots = subject => Array.from(document.querySelectorAll('.plan-slot'))
    .filter(el => el.dataset.planSubject === subject);
  function paintPlanSlots(subject, resp) {
    if (resp && resp.flag) planFlagCache.set(resp.flag.id, resp.flag);
    planSlots(subject).forEach(el => { el.innerHTML = planHTML(resp); });
  }
  async function fetchPlan(subject) {
    const res = await apiFetch(`/advisor/plan?subject=${encodeURIComponent(subject)}`);
    if (!res.ok) throw new Error((await res.text()).trim() || 'no playbook');
    return res.json();
  }
  function pollPlan(subject, tries = 0) {
    clearTimeout(planPolls.get(subject));
    if (tries >= 30) return;
    planPolls.set(subject, setTimeout(async () => {
      if (!planSlots(subject).length) return;
      try {
        const resp = await fetchPlan(subject);
        paintPlanSlots(subject, resp);
        if (resp.status === 'pending') pollPlan(subject, tries + 1);
      } catch {
        pollPlan(subject, tries + 1);
      }
    }, 3000));
  }
  async function loadPlanSlot(subject) {
    try {
      const resp = await fetchPlan(subject);
      paintPlanSlots(subject, resp);
      if (resp.status === 'pending') pollPlan(subject);
    } catch (err) {
      planSlots(subject).forEach(el => { el.innerHTML = `<p class="plan-status">No playbook: ${escapeHTML(err.message || err)}</p>`; });
    }
  }
  window.askAdvisorPlan = async function(subject) {
    try {
      const res = await apiFetch('/advisor/plan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject })
      });
      const resp = await res.json().catch(() => null);
      if (resp) paintPlanSlots(subject, resp);
      if (res.status === 202) pollPlan(subject);
      else if (!res.ok) showToast((resp && resp.reason) || 'The advisor could not take the request', 'info');
    } catch (err) {
      showToast(`Could not ask the advisor: ${err.message || err}`, 'error');
    }
  };
  // Operator labels: Mark as routine / Mark as not ok, and the kill record.
  // The advisor reads them on the next triage and plan.
  window.markLabel = async function(subject, label, source, { quiet } = {}) {
    try {
      const res = await apiFetch('/labels', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject, label, source: source || 'mark' })
      });
      if (!res.ok) throw new Error((await res.text()).trim());
      if (!quiet) showToast(label === 'ok' ? 'Marked as routine. The advisor will use it.' : 'Marked as not ok. The advisor will use it.', 'success');
      fetchTelemetry();
      if (planSlots(subject).length) loadPlanSlot(subject);
    } catch (err) {
      if (!quiet) showToast(`Could not save the mark: ${err.message || err}`, 'error');
    }
  };

  window.openPlanDrawer = function(subject, { back } = {}) {
    if (!drawer) return;
    drawerMode = 'plan';
    drawerPlan = subject;
    if (btnDrawerCopy) btnDrawerCopy.hidden = true;
    openDrawer({ title: 'What to do', icon: 'doc', onClose: () => { drawerMode = null; }, back });
    drawerBody.innerHTML = `<div class="plan-slot" data-plan-subject="${escapeHTML(subject)}"><div class="loading-spinner">Loading the playbook…</div></div>`;
    loadPlanSlot(subject);
  };

  // Deep link from the menubar: #ct=…&file=<path> opens that file's drawer.
  const deepFile = hashParams.get('file');
  if (deepFile) window.openFileDetail(deepFile);

  // Uninspected-egress drill-down: the count in the firewall panel becomes a
  // list the operator can act on (allow the endpoint, read the advisor's
  // verdict) instead of a dead end.

  window.openUninspected = function({ back } = {}) {
    if (!drawer) return;
    drawerMode = 'uninspected';
    if (btnDrawerCopy) btnDrawerCopy.hidden = true;
    openDrawer({
      title: 'Uninspected egress — last 24h',
      icon: 'globe',
      onClose: () => { drawerMode = null; },
      back,
    });
    fillUninspected(drawerBody);
  };

  // Family drawer: View family on the Resources board opens the docked
  // inspector for one process family — no tab switch. The 30s reconcile
  // refills it in place (fetchTelemetry); the process table's Show more
  // state lives in expandedLists. Open in Events is the way out to the full
  // timeline.
  let familyDrawerKey = '';
  const familyByKey = key => ((telemetryData.resources && telemetryData.resources.sessions) || []).find(f => f.key === key);
  window.openFamilyDrawer = function(key, { back } = {}) {
    const fam = familyByKey(key);
    if (!drawer || !fam) return;
    // View family on the family already showing keeps its own way back.
    if (drawerMode === 'family' && familyDrawerKey === key && !drawer.hidden) back = drawerBack;
    drawerMode = 'family';
    familyDrawerKey = key;
    selectedResourceKey = key;
    if (btnDrawerCopy) btnDrawerCopy.hidden = true;
    openDrawer({
      title: familyLabel(fam, telemetryData.sessions),
      icon: 'activity',
      onClose: () => { drawerMode = null; familyDrawerKey = ''; },
      back,
    });
    drawerFoot._saFoot = undefined;
    fillFamilyDrawer();
  };

  // The open drawer as a way back to it. reopen re-runs its opener (with the
  // back it had), so the previous drawer renders from live data, never from
  // stale HTML. The policy editor has none: reopening would drop its draft.
  function currentDrawerBack() {
    if (!drawer || drawer.hidden) return null;
    const back = drawerBack || undefined;
    switch (drawerMode) {
      case 'uninspected':
        return { label: 'Uninspected egress', reopen: () => window.openUninspected({ back }) };
      case 'endpoint': {
        const { host, agent } = drawerEndpoint;
        return { label: 'Endpoint detail', reopen: () => window.openEndpointDetail(host, agent, { back }) };
      }
      case 'incident': {
        const id = drawerIncident;
        return { label: 'Incident report', reopen: () => window.openIncidentReport(id, { back }) };
      }
      case 'file': {
        const p = drawerFile;
        return { label: 'File', reopen: () => window.openFileDetail(p, { back }) };
      }
      case 'plan': {
        const s = drawerPlan;
        return { label: 'What to do', reopen: () => window.openPlanDrawer(s, { back }) };
      }
      case 'family': {
        const key = familyDrawerKey;
        const fam = familyByKey(key);
        return { label: fam ? familyLabel(fam, telemetryData.sessions) : 'Process family', reopen: () => window.openFamilyDrawer(key, { back }) };
      }
    }
    return null;
  }
  function fillFamilyDrawer() {
    if (drawerMode !== 'family' || !drawer || drawer.hidden) return;
    const fam = familyByKey(familyDrawerKey);
    if (!fam) {
      drawerBody.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>This family is no longer running.</span></div>`;
      drawerFoot.innerHTML = '';
      drawerFoot._saFoot = undefined;
      drawerFoot.hidden = true;
      return;
    }
    const label = familyLabel(fam, telemetryData.sessions);
    drawerTitle.textContent = label;
    patchList(drawerBody, familyDrawerSections(fam, {
      sessions: telemetryData.sessions, events: telemetryData.events, flags: telemetryData.flags,
      expanded: expandedLists, now: Date.now(),
    }), { key: p => p.key, html: p => p.html });
    const foot = familyDrawerFootHTML(fam, label);
    if (drawerFoot._saFoot !== foot) {
      drawerFoot.innerHTML = foot;
      drawerFoot._saFoot = foot;
    }
    drawerFoot.hidden = false;
  }

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
        return true;
      }
      showToast(`Failed to terminate PID ${pid}.`, 'danger');
    } catch (err) {
      showToast(`Error terminating PID ${pid}: ${err}`, 'danger');
    }
    return false;
  };

  window.resolveResourceControl = async function(id, decision, sessionKey, actionName) {
    const verb = decision === 'dismiss' ? 'keep this session running' : decision === 'resume' ? 'resume this entire session' : `apply ${String(actionName || 'this intervention').replaceAll('_', ' ')}`;
    if (!await saConfirm(`Save this resource policy change: ${verb}?`, { title: 'Resource policy', okLabel: 'Save' })) return;
    const revert = stage(['posture', 'resources'], ['attention', 'resources', 'tab-badges'], () => {
      if (!id) return;
      mapAttentionItems(it => (it.kind === 'resource' && it.id === id ? null : it));
      const r = telemetryData.resources;
      if (r && r.control && r.control.pending) {
        telemetryData.resources = { ...r, control: { ...r.control, pending: r.control.pending.filter(x => x.id !== id) } };
      }
    });
    try {
      const res = await apiFetch('/resources/control', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ id, decision, session_key: sessionKey || '' })
      });
      if (!res.ok) throw new Error(await res.text());
      showToast(decision === 'dismiss' ? 'Session kept running for the cooldown window.' : decision === 'resume' ? 'Session resumed.' : 'Intervention applied.', 'success');
      cardNote('', '', activeTab === 'sessions' && activeSub === 'resources' ? 'resource-board' : 'attention-list', decision === 'dismiss' ? 'kept running' : decision === 'resume' ? 'resumed' : 'applied');
      fetchTelemetry({ slow: true });
    } catch (err) {
      revert();
      showToast(`Resource decision failed: ${err}`, 'danger');
    }
  };

  window.resolveGuardPrompt = async function(id, verdict, scope) {
    const action = verdict === 'allow'
      ? (scope === 'always' ? 'allow every future path matched by this rule' : 'allow this request once')
      : 'deny this request and remember the rule';
    if (!await saConfirm(`Apply guard decision: ${action}?`, { title: 'Guard decision', okLabel: 'Apply' })) return;
    const revert = stage(['guardPending', 'posture'], ['attention', 'tab-badges'], () => {
      telemetryData.guardPending = (telemetryData.guardPending || []).filter(x => x.id !== id);
      mapAttentionItems(it => (it.kind === 'guard' && it.id === id ? null : it));
    });
    try {
      const res = await apiFetch('/guard/resolve', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, verdict, scope })
      });
      if (!res.ok) throw new Error(await res.text());
      showToast(`Guard request ${verdict === 'allow' ? 'allowed' : 'denied'}${scope === 'always' ? ' for this rule' : ' once'}.`, 'success');
      cardNote('', '', 'attention-list', verdict === 'allow' ? 'allowed' : 'denied');
      fetchTelemetry({ slow: false });
    } catch (err) {
      revert();
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
    drawerMode = 'policy';
    openDrawer({
      title: 'Resource policy editor',
      icon: 'activity',
      variant: 'resource-policy',
      foot: `<button type="button" class="btn btn-ghost" data-action="policy-cancel">Cancel</button>`
        + `<button type="button" class="btn btn-primary" data-action="policy-save">Save and apply</button>`,
      onClose: () => { resourcePolicyDraft = null; drawerMode = null; },
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

  window.killOrphans = function(family) {
    const agents = (telemetryData.status && telemetryData.status.agents) ? telemetryData.status.agents : [];
    return killLeftovers(agents.filter(a => harnessMeta(a.name).key === family && a.is_orphan), family);
  };
  // One family's leftovers, from the family drawer.
  window.killFamilyOrphans = function(key) {
    const fam = familyByKey(key);
    if (!fam) return;
    return killLeftovers((fam.processes || []).filter(p => p.is_orphan), familyLabel(fam, telemetryData.sessions));
  };
  async function killLeftovers(orphans, family) {
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
  }

  // Bulk allow: one click for a group the operator has already judged (all
  // hosts under one suffix for one agent). Sequential and bounded — the
  // allowlist is a user-owned file, not a bulk-import target.
  window.bulkAllowHosts = async function(agent, hosts) {
    const list = String(hosts || '').split(',').filter(Boolean);
    const revert = stageAllow(agent, list);
    refillUninspected();
    let ok = 0;
    for (const host of list) {
      try {
        const res = await apiFetch('/allowlist', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ agent, host })
        });
        if (res.ok) ok++;
      } catch { /* continue; the toast reports the tally */ }
    }
    // None landed: put everything back. A partial run keeps the optimistic
    // rows until the reconcile below shows which ones the daemon took.
    if (ok === 0 && list.length) { revert(); refillUninspected(); }
    showToast(`Allowlisted ${ok} of ${list.length} hosts for ${agent}`, ok === list.length ? 'success' : ok ? 'warn' : 'danger');
    await fetchTelemetry();
    if (ok) list.forEach(host => cardNote(allowRowSel(agent, host), '.mute-row', 'firewall-container', 'allowlisted'));
    refillUninspected();
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
    const revert = stageAllow(agent, [host]);
    refillUninspected();
    try {
      const res = await apiFetch('/allowlist', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent, host })
      });
      if (res.ok) {
        showToast(`Allowlisted ${host} for ${agent}`, 'success');
        cardNote(allowRowSel(agent, host), '.mute-row', 'firewall-container', 'allowlisted');
        await fetchTelemetry();
        refillUninspected();
      } else {
        revert();
        refillUninspected();
        showToast(`Failed to allowlist ${host}.`, 'danger');
      }
    } catch (err) {
      revert();
      refillUninspected();
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

  window.muteFlag = async function(rule, host, agent) {
    agent = agent || '';
    const revert = stage(['mutes'], ['flags'], () => {
      telemetryData.mutes = [...(telemetryData.mutes || []), agent ? { rule, host, agent } : { rule, host }];
    });
    try {
      const res = await apiFetch('/mute', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(agent ? { rule, host, agent } : { rule, host })
      });
      if (res.ok) {
        const who = agent ? ` from ${agent}` : '';
        showToast(host === '*'
          ? `Dismissed ${rule}${who} — future flags of this class are suppressed`
          : `Muted ${rule} for ${host}${who} — future flags suppressed`, 'success');
        cardNote(`#flags-list [data-action="unmute"][data-rule="${cssq(rule)}"][data-host="${cssq(host)}"][data-agent="${cssq(agent)}"]`, '.mute-row', 'flags-list', 'muted');
        fetchTelemetry();
        return true;
      }
      revert();
      showToast(`Failed to mute: ${await res.text()}`, 'danger');
    } catch (err) {
      revert();
      showToast(`Error muting: ${err}`, 'danger');
    }
    return false;
  };

  // A served explanation action (finding card, attention item). The request
  // comes from flag.explain.actions, found by flag id + action id (+ host:
  // allow-host appears once per destination); each id runs the console's
  // existing optimistic path. allow-host, mute and dismiss resolve the flag,
  // so its card leaves the list; POST /allowlist does not acknowledge the
  // flag on the daemon, so the allow is followed by /flags/acknowledge.
  window.explainAct = async function(flagId, actionId, host) {
    const f = (telemetryData.flags || []).find(x => x.id === flagId)
      || (telemetryData.flagsView || []).find(x => x.id === flagId)
      || planFlagCache.get(flagId);
    const a = f && f.explain && (f.explain.actions || []).find(x => x.id === actionId
      && (!host || (x.body && x.body.host) === host));
    if (!a) {
      showToast('That action is no longer offered for this finding — the list is refreshing.', 'info');
      fetchTelemetry();
      return;
    }
    const body = a.body || {};
    switch (a.id) {
      case 'dismiss':
        return window.dismissFlag(f.id);
      case 'kill':
        if (await window.killProcess(Number(body.pid), body.started_at, f.agent)) {
          window.markLabel('flag:' + f.id, 'not_ok', 'kill', { quiet: true });
        }
        return;
      case 'open-incident':
        return window.openIncidentReport(new URLSearchParams(String(a.path).split('?')[1] || '').get('id') || '');
      case 'mute-rule-host':
      case 'mute-class':
        if (await window.muteFlag(body.rule, body.host, body.agent)) stageDropFlag(f.id);
        return;
      case 'allow-host': {
        const revertAllow = stageAllow(body.agent, [body.host]);
        const revertDrop = stageDropFlag(f.id);
        const send = async (method, path, payload) => {
          const res = await apiFetch(path, {
            method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
          });
          if (!res.ok) throw new Error(await res.text());
        };
        try {
          await send(a.method, a.path, body);
        } catch (err) {
          revertDrop();
          revertAllow();
          showToast(`Failed to allowlist ${body.host}: ${err.message || err}`, 'danger');
          return;
        }
        try {
          await send('POST', '/flags/acknowledge', { flag_id: f.id });
        } catch (err) {
          revertDrop();
          showToast(`Allowlisted ${body.host}, but the flag was not marked reviewed: ${err.message || err}`, 'danger');
          fetchTelemetry();
          return;
        }
        showToast(`Allowlisted ${body.host} for ${body.agent}`, 'success');
        cardNote('', '', 'flags-list', 'allowlisted');
        fetchTelemetry();
        return;
      }
      case 'allow-path': {
        try {
          const res = await apiFetch(a.path, {
            method: a.method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
          });
          if (!res.ok) throw new Error(await res.text());
        } catch (err) {
          showToast(`Failed to allow ${body.path}: ${err.message || err}`, 'danger');
          return;
        }
        showToast(`Allowed ${body.path} for ${body.agent}`, 'success');
        fetchTelemetry();
        return;
      }
    }
  };

  // A pattern card's served action (Attention, Flags), found by pattern key +
  // action id (+ host). Before the request (reverted if it fails) the card's
  // open count drops by the submitted flag ids — all of them for a mute —
  // and reads 0 open with its buttons disabled once none is left; those
  // flags leave the lists; the next snapshot reconciles the pattern.
  function stagePatternDone(key, submitted) {
    return stage(['patterns', 'flags', 'flagsView'], ['flags', 'attention', 'chart-flags', 'status', 'tab-badges'], () => {
      const p = (telemetryData.patterns || []).find(x => x.key === key);
      const ids = new Set(submitted || (p && p.flag_ids) || []);
      telemetryData.patterns = (telemetryData.patterns || []).map(x => x.key !== key ? x
        : patternAfterDismiss(x, submitted ? submitted.length : x.unacked));
      telemetryData.flags = (telemetryData.flags || []).filter(f => !ids.has(f.id));
      telemetryData.flagsView = (telemetryData.flagsView || []).filter(f => !ids.has(f.id));
    });
  }
  window.patternAct = async function(key, actionId, host) {
    const p = (telemetryData.patterns || []).find(x => x.key === key);
    const a = p && !p.dismissed && (p.actions || []).find(x => x.id === actionId
      && (!host || (x.body && x.body.host) === host));
    if (!a) {
      showToast('That action is no longer offered for this pattern — the list is refreshing.', 'info');
      fetchTelemetry();
      return;
    }
    const body = a.body || {};
    const send = async (method, path, payload) => {
      const res = await apiFetch(path, {
        method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error(await res.text());
    };
    const dismiss = (p.actions || []).find(x => x.id === 'dismiss-all');
    const openIds = (dismiss && dismiss.body && dismiss.body.flag_ids) || [];
    switch (a.id) {
      case 'kill':
        return window.killProcess(Number(body.pid), body.started_at, p.agent);
      case 'mute-rule-host':
      case 'mute-class':
        if (await window.muteFlag(body.rule, body.host, body.agent)) stagePatternDone(key);
        return;
      case 'dismiss-all': {
        const revert = stagePatternDone(key, openIds);
        try {
          await send(a.method, a.path, body);
        } catch (err) {
          revert();
          showToast(`Failed to dismiss the pattern: ${err.message || err}`, 'danger');
          return;
        }
        showToast(`Dismissed ${openIds.length} flag${openIds.length === 1 ? '' : 's'} — the rule keeps watching`, 'info');
        cardNote(`[data-pattern-key="${cssq(key)}"] .pattern-open`, '.pattern-card', 'flags-list', 'dismissed');
        fetchTelemetry();
        return;
      }
      case 'allow-host': {
        const revertAllow = stageAllow(body.agent, [body.host]);
        const revert = stagePatternDone(key, openIds);
        try {
          await send(a.method, a.path, body);
        } catch (err) {
          revert();
          revertAllow();
          showToast(`Failed to allowlist ${body.host}: ${err.message || err}`, 'danger');
          return;
        }
        if (openIds.length) {
          try {
            await send('POST', '/flags/acknowledge', { flag_ids: openIds });
          } catch (err) {
            revert();
            showToast(`Allowlisted ${body.host}, but its flags were not marked reviewed: ${err.message || err}`, 'danger');
            fetchTelemetry();
            return;
          }
        }
        showToast(`Allowlisted ${body.host} for ${body.agent}`, 'success');
        fetchTelemetry();
        return;
      }
    }
  };

  window.unmuteFlag = async function(rule, host, agent) {
    agent = agent || '';
    const revert = stage(['mutes'], ['flags'], () => {
      telemetryData.mutes = (telemetryData.mutes || []).filter(m => !(m.rule === rule && m.host === host && (m.agent || '') === agent));
    });
    try {
      const q = `rule=${encodeURIComponent(rule)}&host=${encodeURIComponent(host)}` + (agent ? `&agent=${encodeURIComponent(agent)}` : '');
      const res = await apiFetch(`/mute?${q}`, { method: 'DELETE' });
      if (res.ok) {
        showToast(`Unmuted ${rule} for ${host}${agent ? ` from ${agent}` : ''}`, 'info');
        cardNote('', '', 'flags-list', 'unmuted');
        fetchTelemetry();
      } else {
        revert();
        showToast(`Failed to unmute.`, 'danger');
      }
    } catch (err) {
      revert();
      showToast(`Error unmuting: ${err}`, 'danger');
    }
  };

  window.promoteVendorKeys = async function() {
    const stats = (telemetryData.status && telemetryData.status.firewall_stats) || {};
    const revert = stage(['status'], ['firewall'], () => withMode(monitorVendorKeyIDs(stats), 'block'));
    try {
      const res = await apiFetch('/firewall/mode', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'vendor-key', mode: 'block' })
      });
      if (res.ok) {
        const body = await res.json().catch(() => ({}));
        const n = (body.promoted || []).length;
        showToast(n ? `Promoted ${n} vendor-key rule${n === 1 ? '' : 's'} to block.` : 'Vendor-key rules already blocking.', 'success');
        cardNote('', '', 'firewall-container', 'vendor keys blocking');
        fetchTelemetry();
      } else {
        revert();
        showToast('Failed to promote vendor-key rules.', 'danger');
      }
    } catch (err) {
      revert();
      showToast(`Error promoting vendor-key rules: ${err}`, 'danger');
    }
  };

  window.promoteRule = async function(rule) {
    const revert = stage(['status'], ['firewall'], () => withMode([rule], 'block'));
    try {
      const res = await apiFetch('/firewall/mode', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, mode: 'block' })
      });
      if (res.ok) {
        showToast(`Rule “${rule}” promoted to block.`, 'success');
        cardNote(`#firewall-container [data-rule="${cssq(rule)}"]`, '.fw-rule', 'firewall-container', 'blocking');
        fetchTelemetry();
      } else {
        revert();
        showToast(`Failed to promote “${rule}”.`, 'danger');
      }
    } catch (err) {
      revert();
      showToast(`Error promoting “${rule}”: ${err}`, 'danger');
    }
  };

  // Blocking must be reversible — a rule you can only tighten is a ratchet.
  window.demoteRule = async function(rule) {
    const revert = stage(['status'], ['firewall'], () => withMode([rule], 'monitor'));
    try {
      const res = await apiFetch('/firewall/mode', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, mode: 'monitor' })
      });
      if (res.ok) {
        showToast(`Rule “${rule}” back to monitor.`, 'success');
        cardNote(`#firewall-container [data-rule="${cssq(rule)}"]`, '.fw-rule', 'firewall-container', 'monitoring');
        fetchTelemetry();
      } else {
        revert();
        showToast(`Failed to demote “${rule}”.`, 'danger');
      }
    } catch (err) {
      revert();
      showToast(`Error demoting “${rule}”: ${err}`, 'danger');
    }
  };

  window.removeAllowlistEntry = async function(agent, host) {
    const revert = stage(['allowlist'], ['firewall'], () => {
      telemetryData.allowlist = (telemetryData.allowlist || []).filter(p => !(p.agent === agent && p.host === host));
    });
    try {
      const res = await apiFetch('/allowlist', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent, host })
      });
      if (res.ok) {
        showToast(`Removed ${host} for ${agent}.`, 'info');
        cardNote('', '', 'firewall-container', 'removed');
      } else {
        revert();
        showToast(`Failed to remove ${host}.`, 'danger');
      }
    } catch (err) {
      revert();
      showToast(`Error removing ${host}: ${err}`, 'danger');
    }
  };

  // Session drill-down: jump from a flag to just its harness session's events.
  // "View session in timeline" (finding cards, Attention): open the session
  // in the Sessions tab — its rail card selected, its trace loaded — and keep
  // Events, Flags and Incidents scoped to it for the Events tab. Selects
  // outright: selectSession toggles, which would close an already-open one.
  window.filterTimelineToSession = async function(sid) {
    timelineSession = sid;
    timelinePids = null;
    timelinePidLabel = '';
    suppressFreshOnce = true;
    renderEvents();
    renderFlags();
    renderIncidents();
    paintScopeBar();
    selectedSessionId = sid;
    switchTab('sessions');
    try { await loadSessionTimeline(sid, true); } catch { /* the trace stays empty; the next select retries */ }
    renderNow(['sessions']);
    const card = document.querySelector(`#session-rail [data-action="select-session"][data-id="${cssq(sid)}"]`);
    if (card && card.scrollIntoView) {
      card.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'nearest' });
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
    paintScopeBar();
    switchTab('events');
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
    paintScopeBar();
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
    // A drawer opened from inside the open drawer can go back to it.
    const back = () => (el.closest('#drawer') ? currentDrawerBack() : null);
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
      case 'worktree-remove':
        e.preventDefault();
        window.removeWorktree(d.path, d.branch);
        break;
      case 'worktree-prune':
        e.preventDefault();
        window.pruneWorktrees(d.repo);
        break;
      case 'worktree-hide':
        e.preventDefault();
        window.hideWorktreeRepo(d.repo);
        break;
      case 'worktree-remove-all':
        e.preventDefault();
        window.removeAllWorktrees(d.repo);
        break;
      case 'worktree-reveal':
        e.preventDefault();
        window.revealWorktree(d.path);
        break;
      case 'worktree-reconnect':
        e.preventDefault();
        window.reconnectWorktree(d.path, d.repo);
        break;
      case 'worktree-trash-orphan':
        e.preventDefault();
        window.trashOrphanWorktree(d.path);
        break;
      case 'worktree-advise':
        e.preventDefault();
        window.adviseWorktree(d.path);
        break;
      case 'worktree-ask':
        e.preventDefault();
        window.askWorktreeAgent(d.path);
        break;
      case 'worktree-filter':
        worktreesState.filter.state = d.state || '';
        renderNow(['worktrees']);
        break;
      case 'worktree-stale':
        worktreesState.filter.stale = !worktreesState.filter.stale;
        renderNow(['worktrees']);
        break;
      case 'worktrees-rescan':
        loadWorktrees(true);
        break;
      case 'clutter-rescan':
        loadClutter(true);
        break;
      case 'clutter-filter':
        clutterState.filter.kind = d.kind || '';
        renderNow(['clutter']);
        break;
      case 'clutter-more':
        clutterState.expanded.add(d.project || '');
        renderNow(['clutter']);
        break;
      case 'clutter-advise':
        e.preventDefault();
        window.adviseClutterProject(d.project);
        break;
      case 'clutter-trash':
        e.preventDefault();
        window.trashClutter(d.path);
        break;
      case 'clutter-clean':
        e.preventDefault();
        window.cleanClutter(d.name);
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
        window.openIncidentReport(d.id, { back: back() });
        break;
      case 'incident-status':
        window.setIncidentStatus(d.id, d.status);
        break;
      case 'open-file':
        e.preventDefault();
        window.openFileDetail(d.path, { back: back() });
        break;
      case 'open-plan':
        e.preventDefault();
        window.openPlanDrawer(d.subject, { back: back() });
        break;
      case 'ask-plan':
        e.preventDefault();
        window.askAdvisorPlan(d.subject);
        break;
      case 'mark-label':
        e.preventDefault();
        window.markLabel(d.subject, d.label);
        break;
      case 'file-reveal':
      case 'file-open':
        e.preventDefault();
        window.fileAction(d.action === 'file-reveal' ? 'reveal' : 'open', d.path);
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
      case 'view-family':
        e.preventDefault();
        window.openFamilyDrawer(d.key, { back: back() });
        break;
      case 'family-events': {
        e.preventDefault();
        const fam = familyByKey(d.key);
        if (!fam) break;
        const pids = [Number(fam.root_pid), ...(fam.processes || []).map(p => Number(p.pid))];
        const label = familyLabel(fam, telemetryData.sessions);
        closeDrawer();
        window.filterTimelineToPids([...new Set(pids)], label);
        break;
      }
      case 'kill-family-orphans':
        e.preventDefault();
        e.stopPropagation();
        window.killFamilyOrphans(d.key);
        break;
      case 'show-more':
        e.preventDefault();
        expandedLists.add(d.key || '');
        if (d.key === 'events') renderNow(['events']);
        else if (String(d.key).startsWith('agents:')) renderNow(['agents']);
        else if (String(d.key).startsWith('pattern:')) renderNow(['attention', 'flags']);
        else if (d.key === 'spend') renderNow(['spend']);
        else fillFamilyDrawer();
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
        window.openEndpointDetail(d.host, d.agent, { back: back() });
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
      case 'toggle-session-dup':
        sessionDupOpen[(d.bucket ? d.bucket + '|' : '') + d.key] = el.getAttribute('aria-expanded') !== 'true';
        renderSessionBoard();
        break;
      case 'toggle-family-dup':
        familyDupOpen[d.key] = el.getAttribute('aria-expanded') !== 'true';
        renderResourceMissionControl();
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
      case 'copy-report':
        window.copySessionReport(d.id);
        break;
      case 'copy-path':
        (navigator.clipboard ? navigator.clipboard.writeText(d.path || '') : Promise.reject(new Error('no clipboard'))).then(
          () => showToast('Path copied', 'success'),
          () => showToast('Copy failed — select the path from its tooltip', 'danger'));
        break;
      case 'mute-flag':
        window.muteFlag(d.rule, d.host, d.agent);
        break;
      case 'mute-rule':
        window.muteFlag(d.rule, '*', d.agent);
        break;
      case 'dismiss-flag':
        window.dismissFlag(d.id);
        break;
      case 'explain-act':
        if (d.patternKey) window.patternAct(d.patternKey, d.actionId, d.host);
        else window.explainAct(d.flagId, d.actionId, d.host);
        break;
      case 'retriage':
        window.retriageFlag(d.id);
        break;
      case 'open-uninspected':
        e.preventDefault();
        window.openUninspected({ back: back() });
        break;
      case 'goto-top':
        e.preventDefault();
        window.scrollTo({ top: 0, behavior: reducedMotion ? 'auto' : 'smooth' });
        break;
      case 'clear-scope':
        e.preventDefault();
        window.clearTimelineSession();
        break;
      case 'goto-tab':
        e.preventDefault();
        switchTab(d.tab, { group: d.group });
        break;
      case 'policy-refresh':
        e.preventDefault();
        loadPolicy();
        break;
      case 'agent-refresh':
        e.preventDefault();
        loadAgent();
        break;
      case 'agent-clear':
        e.preventDefault();
        window.clearAgentChat();
        break;
      case 'agent-save-plan':
        e.preventDefault();
        window.saveAgentRequest();
        break;
      case 'agent-save-proposal':
        e.preventDefault();
        window.saveAgentProposal(Number(d.message));
        break;
      case 'agent-dispatch':
        e.preventDefault();
        window.dispatchAgent({ planId: Number(d.plan), mode: d.mode });
        break;
      case 'agent-dispatch-proposal':
        e.preventDefault();
        window.dispatchAgent({ messageId: Number(d.message), mode: d.mode });
        break;
      case 'agent-plan-delete':
        e.preventDefault();
        window.deleteAgentPlan(Number(d.plan));
        break;
      case 'agent-skill':
        e.preventDefault();
        window.showAgentSkill(d.skill);
        break;
      case 'agent-copy':
        e.preventDefault();
        (navigator.clipboard ? navigator.clipboard.writeText(d.text || '') : Promise.reject(new Error('no clipboard'))).then(
          () => showToast('Copied', 'success'),
          () => showToast('Copy failed — select the text instead', 'danger'));
        break;
      case 'unmute':
        window.unmuteFlag(d.rule, d.host, d.agent);
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
    ['proxy-prompt-injection', 'Prompt injection in a response'],
    ['secret-in-transcript', 'Secret appeared in an agent transcript']
  ];

  // patchList-keyed by rule id: a reconcile while nothing changed for a row
  // (or a different row's override changed) leaves that row's <select> node
  // alone — no lost focus mid-pick.
  function renderNotifyRules() {
    const list = document.getElementById('notify-rules-list');
    if (!list) return;
    const overrides = (telemetryData.notifyCfg && telemetryData.notifyCfg.overrides) || {};
    const curOf = (rule) => rule in overrides ? (overrides[rule] ? 'always' : 'never') : 'default';
    patchList(list, NOTIFY_RULES, {
      key: ([rule]) => rule,
      hash: ([rule]) => curOf(rule),
      html: ([rule, label]) => {
        const cur = curOf(rule);
        return `<div class="notify-rule-row">
        <span class="notify-rule-name" title="${escapeHTML(rule)}">${escapeHTML(label)}</span>
        <select class="select select-sm" data-notify-rule="${escapeHTML(rule)}" aria-label="Notifications for ${escapeHTML(label)}">
          <option value="default"${cur === 'default' ? ' selected' : ''}>Default</option>
          <option value="always"${cur === 'always' ? ' selected' : ''}>Always</option>
          <option value="never"${cur === 'never' ? ' selected' : ''}>Never</option>
        </select>
      </div>`;
      }
    });
    renderNotifyScopes();
  }

  // Per-workspace scopes: existing ones with a remove button, patchList-keyed
  // by rule+workspace, plus a compact add form (rule + path prefix +
  // page/silence). The daemon matches by path prefix, longest first. The add
  // form is static DOM outside the patched list — a reconcile while the
  // operator is typing a workspace path must never touch it.
  function renderNotifyScopes() {
    const list = document.getElementById('notify-scopes-list');
    if (!list) return;
    const scopes = (telemetryData.notifyCfg && telemetryData.notifyCfg.scopes) || [];
    patchList(list, scopes, {
      key: s => s.rule + '|' + s.workspace,
      hash: s => s.notify,
      html: s => `<div class="notify-rule-row">
        <span class="notify-rule-name" title="${escapeHTML(s.workspace)}">${escapeHTML(s.rule)} <span class="notify-scope-path">${escapeHTML(s.workspace)}</span></span>
        <span class="notify-scope-mode ${s.notify ? 'on' : 'off'}">${s.notify ? 'page' : 'quiet'}</span>
        <button class="source-remove" title="Remove this scope" data-action="notify-scope-remove" data-rule="${escapeHTML(s.rule)}" data-workspace="${escapeHTML(s.workspace)}"><svg class="icon"><use href="#i-close"/></svg></button>
      </div>`,
      empty: '<div class="notify-scope-empty">No workspace scopes yet</div>'
    });
    ensureNotifyScopeAddForm();
  }

  // Built once and left alone on every later render: the add-form's own
  // inputs (the workspace path in particular) must survive a telemetry
  // reconcile while the operator is mid-edit.
  function ensureNotifyScopeAddForm() {
    if (document.getElementById('notify-scope-add-form')) return;
    const list = document.getElementById('notify-scopes-list');
    if (!list || !list.parentNode) return;
    const form = document.createElement('div');
    form.className = 'notify-scope-add';
    form.id = 'notify-scope-add-form';
    form.innerHTML = `
        <select class="select select-sm" id="notify-scope-rule" aria-label="Rule for the workspace scope">
          ${NOTIFY_RULES.map(([rule, label]) => `<option value="${escapeHTML(rule)}">${escapeHTML(label)}</option>`).join('')}
        </select>
        <input class="input input-sm" id="notify-scope-path" placeholder="repo path, e.g. ~/work/prod" autocomplete="off" spellcheck="false">
        <select class="select select-sm" id="notify-scope-mode" aria-label="Scope action">
          <option value="always">Page</option>
          <option value="never">Quiet</option>
        </select>
        <button class="btn btn-ghost btn-sm" data-action="notify-scope-add" title="Add this workspace scope"><svg class="icon"><use href="#i-arrow"/></svg><span>Add</span></button>`;
    list.parentNode.insertBefore(form, list.nextSibling);
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

  // Notification rules live in the Policy tab (the header bell is a link to
  // it); the panel keeps the popover's element ids.
  const notifyPop = document.getElementById('notify-pop');
  if (notifyPop) {
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
  const slowTimer = setInterval(fetchTelemetry, 30000);

  let pollTimer = null;
  let es = null;
  const startPolling = () => {
    if (sessionEnded) return;
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
    es = new EventSource(streamURL);
    es.onopen = () => { esFailures = 0; stopPolling(); };

    // Typed deltas: patch local state and mark only the panels that read the
    // changed slice; the scheduler renders the visible ones.
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
        if (!isEventsFiltered()) telemetryData.eventsView = telemetryData.events;
        if (e.kind === 9) flashFirewallPanel(); // proxy-hit
        // The open session's waterfall follows its own trace live.
        if (selectedSessionId && e.session_id === selectedSessionId) {
          loadSessionTimeline(selectedSessionId).then(() => markDirty('sessions'));
        }
      } catch { sparkBump(1, 0); /* unparseable frame still counts */ }
      markDirty('events');
    });
    // Patterns and posture come only from /snapshot: a flag frame schedules
    // one reconcile 2 s after the last frame of a burst, so a storm folds
    // into its pattern card instead of standing as rows until the poll.
    let flagReconcile = 0;
    es.addEventListener('flag', (msg) => {
      try { telemetryData.flags = upsertById(telemetryData.flags, JSON.parse(msg.data)); } catch { /* next reconcile repairs */ }
      markDirty('flags', 'attention', 'chart-flags', 'status', 'tab-badges');
      clearTimeout(flagReconcile);
      flagReconcile = setTimeout(() => fetchTelemetry({ slow: false }), 2000);
    });
    es.addEventListener('incident', (msg) => {
      // Delta incidents are the bare report (no workflow join); the 30s
      // reconcile supplies workflow state.
      try { telemetryData.incidents = upsertById(telemetryData.incidents, JSON.parse(msg.data)); } catch { /* next reconcile repairs */ }
      markDirty('incidents', 'attention', 'status');
    });
    es.addEventListener('session', (msg) => {
      try { telemetryData.sessions = upsertById(telemetryData.sessions, JSON.parse(msg.data)); } catch { /* next reconcile repairs */ }
      markDirty('sessions', 'chart-memory', 'tab-badges');
    });
    es.addEventListener('posture', (msg) => {
      // posture.groups is the attention queue.
      try { telemetryData.posture = JSON.parse(msg.data); } catch { /* next reconcile repairs */ }
      markDirty('posture', 'attention', 'tab-badges');
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
