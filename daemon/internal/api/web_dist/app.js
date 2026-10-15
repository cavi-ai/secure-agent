document.addEventListener('DOMContentLoaded', () => {
  // Console auth: the menubar opens /dashboard/#ct=<console-token>. The token
  // gates the telemetry endpoints on this listener (the proxy token agents
  // carry is a different credential and is NOT accepted here). A fragment is
  // used because fragments are never sent to the server — the token stays off
  // the wire and out of server logs.
  //
  // The fragment is lifted, kept for the life of the TAB in sessionStorage,
  // and stripped from the address bar. Without the sessionStorage copy a
  // single reload lost the token and the
  // console sat behind a wall of 403s showing "can't reach the daemon"
  // forever. sessionStorage (not localStorage): the token dies with the tab
  // rather than being retained across browser sessions.
  const SS_TOKEN_KEY = 'sa.console-token';
  const hashParams = new URLSearchParams(location.hash.slice(1));
  const initialContext = consoleContextFromHash(location.hash);
  let pendingConsoleContext = Object.values(initialContext).some(Boolean) ? initialContext : null;
  let consoleToken = hashParams.get('ct') || '';
  if (consoleToken) {
    try { sessionStorage.setItem(SS_TOKEN_KEY, consoleToken); } catch { /* private mode: memory only */ }
    if (window.history.replaceState) {
      // Retain only the route and record identifiers. The credential never
      // survives in a reload link, address-bar history or drawer context.
      history.replaceState(null, '', location.pathname + location.search + (pendingConsoleContext ? consoleContextHash(initialContext) : ''));
    }
  } else {
    try { consoleToken = sessionStorage.getItem(SS_TOKEN_KEY) || ''; } catch { consoleToken = ''; }
  }
  const pausedElements = new Map();
  let recoveryFocus = null;
  // A rejected credential pauses the existing view. A tab without a
  // credential at boot has no cached data to display.
  function showSessionEnded() {
    const cached = booted;
    document.body.classList.add(cached ? 'is-paused' : 'is-ended');
    const ended = document.getElementById('session-ended');
    recoveryFocus = document.activeElement;
    document.querySelectorAll('.app > *, .masthead-right, #drawer, #agent-dock, #confirm-layer').forEach(el => {
      if (el !== ended && !el.classList.contains('masthead')) {
        pausedElements.set(el, { inert: el.inert, hidden: el.hidden });
        el.inert = true;
        if (!cached) el.hidden = true;
      }
    });
    const reason = document.getElementById('console-access-reason');
    if (reason) reason.textContent = cached
      ? 'Console access expired. Your view is preserved; live updates and actions are paused.'
      : 'Open Secure Agent to connect this tab securely.';
    if (ended) ended.hidden = false;
    document.getElementById('console-reconnect')?.focus({ preventScroll: true });
  }
  const consoleAuth = createConsoleAuth({ token: consoleToken, onRejected: endSession });
  const apiFetch = consoleAuth.fetch;

  const btnRefresh = document.getElementById('btn-refresh');

  // Screen-reader announcements for state the eye would catch on its own.
  const liveRegion = document.getElementById('a11y-live');
  window.saAnnounce = function(text) {
    if (!liveRegion || !text) return;
    liveRegion.textContent = '';
    // A tick later so repeated identical strings re-announce.
    setTimeout(() => { liveRegion.textContent = text; }, 30);
  };

  // Agent dock state (openAgentDock): the drawer closes it on open.
  let agentDockOpen = false;
  let agentDockOpener = null;
  let attentionGeneration = 0;
  const attentionWrites = new Set();
  const detailDrawer = createDrawer({
    request: (...args) => apiFetch(...args),
    toast: (...args) => showToast(...args),
    markDirty: (...names) => markDirty(...names),
    closeAgentDock: () => closeAgentDock(),
    auth: { ended: () => sessionEnded, generation: () => handoffGeneration },
    attention: { select: key => selectAttention(key), bumpGeneration: () => { attentionGeneration++; } },
    family: {
      byKey: key => familyByKey(key),
      label: fam => familyLabel(fam, telemetryData.sessions),
      select: key => { selectedResourceKey = key; },
      sections: fam => familyDrawerSections(fam, {
        sessions: telemetryData.sessions, events: telemetryData.events, flags: telemetryData.flags,
        expanded: expandedLists, now: Date.now(),
      })
    },
    plan: { load: subject => loadPlanSlot(subject) },
    flag: {
      cache: f => planFlagCache.set(f.id, f),
      advisorEnabled: () => !!(telemetryData.status && telemetryData.status.advisor_enabled)
    },
    session: { capture: el => captureSessionReturn(el), restore: st => restoreSessionReturn(st) }
  });
  const { root: drawer, body: drawerBody, foot: drawerFoot, title: drawerTitle, closeButton: btnDrawerClose } = detailDrawer;
  window.saCloseDrawer = detailDrawer.close;

  function attentionItems() { return needsItems(telemetryData.posture); }
  function selectAttention(key, { focus = false } = {}) {
    const items = attentionItems();
    const item = items.find(it => `${it.kind}:${it.id}` === key);
    if (!item) return;
    const origin = { key, order: items.map(it => `${it.kind}:${it.id}`), generation: ++attentionGeneration };
    if (item.kind==='hook_delivery') origin.hookForwarderID=item.hook_delivery?.report.forwarder_id;
    if (item.kind==='hook') origin.hookRepair=hookRepairScope(item.hook_finding,item.session_id);
    const view = needView(item, homeContext(window.SA));
    origin.signature = attentionSignature(item);
    detailDrawer.setMode('attention');
    detailDrawer.setCopyVisible(false);
    detailDrawer.open({ title: item.title || view.word, icon: 'shield', attentionOrigin: origin,
      body: `<div class="panel-body attention-inspector"><p class="finding-why">${escapeHTML(view.agent)}</p><h3>${escapeHTML(view.what)}</h3><p>${escapeHTML(view.why)}</p>${view.body ? view.body() : `<p>${escapeHTML(item.detail || '')}</p>`}</div>`,
      foot: actionBarHTML(view.items), onClose: () => { detailDrawer.setMode(null); } });
    drawerBody.querySelectorAll('details.body-evidence').forEach(part => { part.open = true; });
    renderAttention();
    if (focus) btnDrawerClose?.focus({ preventScroll: true });
  }
  function attentionSignature(item) {
    const ctx = homeContext(window.SA);
    return JSON.stringify([item, ctx.flags.get(item.id), ctx.patterns.get(item.id), ctx.routine.get(item.id), ctx.incidents.get(item.id), reviewDrafts.get(item.id)]);
  }
  function refreshAttentionInspector(item) {
    const selection = detailDrawer.selection();
    if (detailDrawer.mode() !== 'attention' || !selection) return;
    const signature = attentionSignature(item);
    if (selection.signature === signature) return;
    selection.signature = signature;
    const view = needView(item, homeContext(window.SA));
    const focused = drawer.contains(document.activeElement) ? document.activeElement : null;
    // Every served data field contributes to the choice: verdict, scope,
    // expiry, intervention and evidence revision must survive unchanged.
    const identity = control => control?.dataset.action
      ? JSON.stringify(Object.entries(control.dataset).sort(([a], [b]) => a.localeCompare(b))) : null;
    const choice = identity(focused);
    drawerTitle.textContent = item.title || view.word;
    drawerBody.innerHTML = `<div class="panel-body attention-inspector"><p class="finding-why">${escapeHTML(view.agent)}</p><h3>${escapeHTML(view.what)}</h3><p>${escapeHTML(view.why)}</p>${view.body ? view.body() : `<p>${escapeHTML(item.detail || '')}</p>`}</div>`;
    drawerBody.querySelectorAll('details.body-evidence').forEach(part => { part.open = true; });
    drawerFoot.innerHTML = actionBarHTML(view.items);
    drawerFoot.hidden = !view.items.length;
    if (focused && !focused.isConnected) {
      const replacement = choice && Array.from(drawer.querySelectorAll('[data-action]')).find(control => {
        if (identity(control) !== choice || control.disabled || control.matches(':disabled')
          || control.closest('[hidden], [inert], [aria-hidden="true"]')) return false;
        for (let part = control; part && part !== drawer; part = part.parentElement) {
          const style = getComputedStyle(part);
          if (style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse') return false;
        }
        // Replaced More disclosures start closed. Reveal the same choice
        // before restoring focus, without invoking or changing the action.
        for (let part = control.closest('details'); part; part = part.parentElement?.closest('details')) part.open = true;
        return control.getClientRects().length > 0;
      });
      (replacement || btnDrawerClose)?.focus({ preventScroll: true });
    }
  }
  function reconcileAttention({ previous, focus = false } = {}) {
    const selection = detailDrawer.selection();
    if (!selection || drawer.hidden || sessionEnded || attentionWrites.size) return;
    const items = attentionItems();
    const next = nextAttentionKey(selection.key, previous || selection.order, items);
    if (selection.hookRepair && next!==selection.key) {
      openHookInspector('repair',selection.hookRepair,{back:{label:'Needs you',reopen:()=>{detailDrawer.close();switchTab('home');}}});
      window.saAnnounce('Hook finding changed. Checking newer evidence.');
      return;
    }
    if (selection.hookForwarderID && next!==selection.key) {
      openHookInspector('delivery',{id:selection.hookForwarderID},{back:{label:'Needs you',reopen:()=>{detailDrawer.close();switchTab('home');}}});
      window.saAnnounce('Delivery finding changed. Loading current evidence.');
      return;
    }
    if (next === selection.key) {
      selection.order = items.map(it => `${it.kind}:${it.id}`);
      refreshAttentionInspector(items.find(it => `${it.kind}:${it.id}` === next));
      return;
    }
    if (next) {
      selectAttention(next, { focus });
      window.saAnnounce('Showing the next item that needs you.');
    } else {
      detailDrawer.clearSelection();
      attentionGeneration++;
      detailDrawer.setMode('attention-empty');
      detailDrawer.open({ title: 'Needs you', icon: 'shield', body: '<div class="empty" role="status"><span>No items need your attention. New requests will appear in the queue.</span></div>', foot: '' });
      if (focus) btnDrawerClose?.focus({ preventScroll: true });
      window.saAnnounce('No items need your attention.');
    }
  }
  function beginAttentionWrite() {
    const selection = detailDrawer.selection();
    const ticket = { selection, seq: detailDrawer.seq(), auth: handoffGeneration, order: attentionItems().map(it => `${it.kind}:${it.id}`) };
    attentionWrites.add(ticket);
    const pausedButtons = new Map();
    if (selection) drawer.querySelectorAll('button[data-action]').forEach(b => { pausedButtons.set(b, b.disabled); b.disabled = true; });
    const finish = (success) => {
      attentionWrites.delete(ticket);
      if (!selection || detailDrawer.selection() !== selection || ticket.seq !== detailDrawer.seq() || ticket.auth !== handoffGeneration || sessionEnded) return false;
      for (const [button, disabled] of pausedButtons) button.disabled = disabled;
      if (success) reconcileAttention({ previous: ticket.order, focus: true });
      return true;
    };
    finish.isCurrent = () => ticket.seq === detailDrawer.seq() && ticket.auth === handoffGeneration && !sessionEnded;
    return finish;
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
  let cancelDialog = null;

  function saDialog({ title, message, okLabel, withInput, placeholder, danger }) {
    if (sessionEnded) return Promise.resolve(withInput ? null : false);
    if (cancelDialog) cancelDialog();
    const opener = document.activeElement;
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
        cancelDialog = null;
        if (opener?.isConnected) opener.focus({ preventScroll: true });
        resolve(value);
      };
      const okHandler = () => finish(withInput ? (confirmInputEl.value || '') : true);
      const cancelHandler = () => finish(withInput ? null : false);
      cancelDialog = cancelHandler;
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

  btnRefresh.addEventListener('click', () => {
    fetchTelemetry({ full: true });
    showToast('Refreshing telemetry data...', 'info');
  });
  document.getElementById('btn-retry-connection')?.addEventListener('click', () => fetchTelemetry({ full: true }));

  const btnAddSource = document.getElementById('btn-add-source');
  const sourceInput = document.getElementById('source-input');
  if (btnAddSource) btnAddSource.addEventListener('click', () => window.addSource());
  if (sourceInput) sourceInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') window.addSource(); });

  let telemetryData = {
    status: null,
    resources: null,
    flags: [],       // unfiltered — feeds KPIs
    reviews: { reviews: [], degraded: false },
    patterns: [],    // /snapshot patterns: repeating findings, one card each
    routine: [],     // /snapshot routine: the same reads across agents, one decision each
    flagsView: [],   // filtered — feeds the flags panel
    incidents: [],
    events: [],       // unfiltered — feeds KPIs
    eventsView: [],   // filtered — feeds the event timeline
    fleet: [],
    audit: [],
    sources: [],
    uninspected: [],  // /egress/uninspected rows — the drill-down list
    egressEpisodes: [], // /egress/episodes observed cadence and advice
    expectedEgress: [], // /expected-egress operator decisions
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
  let spendView = { by: 'day', since: '7d' };
  try {
    const saved = JSON.parse(sessionStorage.getItem(SPEND_VIEW_KEY) || '{}') || {};
    if (SPEND_BY.includes(saved.by)) spendView.by = saved.by;
    if (SPEND_SINCE.includes(saved.since)) spendView.since = saved.since;
  } catch { /* private mode or a corrupt entry: the default view */ }
  const spendCardPath = () =>
    `/costs?since=${spendView.since}&by=${spendView.by}&tz=${-(new Date()).getTimezoneOffset()}&cached=1`;
  // Spend reads the daemon's usage cache (cached=1): each report's last copy
  // answers at once, one saved before a restart too, while the daemon
  // computes a fresh one (refreshing: true). The card says so and re-reads
  // every 2 s, at most 30 times in a row, until it lands. Every slow cycle
  // starts a load (loadSpend) beside its other fetches; a newer load drops an
  // older one's answer.
  const SPEND_POLL_MS = 2000;
  const SPEND_POLLS = 30;
  let spendDayGen = 0;
  let spendGen = 0;
  let spendPollTimer = null;
  let spendPolls = 0;

  // ---------- connectivity ----------
  // Live response states:
  //  - 'ok':           fetches succeed.
  //  - 'unreachable':  network-level failure — the daemon or its proxy
  //                    listener is gone; the last known state stays visible.
  //  - 'invalid-response': the daemon replied with malformed telemetry.
  // A credential challenge pauses access until the app hands off a fresh token.
  let connState = 'ok';
  let sessionEnded = !consoleToken;
  let liveUpdates = null;
  let lastSnapshotAt = 0;
  // Fast refreshes supersede fast state without starving slower reports.
  let telemetryFetchGen = 0;
  let telemetrySlowGen = 0;
  let expectedEgressReadGen = 0;
  let prevUptimeSec = 0;
  // Deduplicate report failure toasts until the next successful read. Snapshot
  // failures have a persistent headline instead of a second transient alert.
  const failedEndpoints = new Set();
  const reportHealth = createConsoleReportHealth();

  let consoleLifecycleController;
  function consoleLifecycleControllerModule() {
    return consoleLifecycleController ||= createConsoleLifecycle({
      state: {
        get SS_TOKEN_KEY() { return SS_TOKEN_KEY; },
        get cancelDialog() { return cancelDialog; },
        set cancelDialog(value) { cancelDialog = value; },
        get consoleAuth() { return consoleAuth; },
        get consoleToken() { return consoleToken; },
        set consoleToken(value) { consoleToken = value; },
        get eventHistoryPage() { return eventHistoryPage; },
        set eventHistoryPage(value) { eventHistoryPage = value; },
        get expectedEgressReadGen() { return expectedEgressReadGen; },
        set expectedEgressReadGen(value) { expectedEgressReadGen = value; },
        get failedEndpoints() { return failedEndpoints; },
        get handoffGeneration() { return handoffGeneration; },
        set handoffGeneration(value) { handoffGeneration = value; },
        get liveUpdates() { return liveUpdates; },
        set liveUpdates(value) { liveUpdates = value; },
        get protectionContext() { return protectionContext; },
        set protectionContext(value) { protectionContext = value; },
        get protectionContextGeneration() { return protectionContextGeneration; },
        set protectionContextGeneration(value) { protectionContextGeneration = value; },
        get reviewResult() { return reviewResult; },
        set reviewResult(value) { reviewResult = value; },
        get reviewResultSeq() { return reviewResultSeq; },
        set reviewResultSeq(value) { reviewResultSeq = value; },
        get drawerReviewResult() { return detailDrawer.reviewResult(); },
        set drawerReviewResult(value) { detailDrawer.setReviewResult(value); },
        get drawerMode() { return detailDrawer.mode(); },
        get reportHealth() { return reportHealth; },
        get sessionEnded() { return sessionEnded; },
        set sessionEnded(value) { sessionEnded = value; },
        get sessionWorkbench() { return sessionWorkbench; },
        get sparkTimer() { return sparkTimer; },
        set sparkTimer(value) { sparkTimer = value; },
        get spendDayGen() { return spendDayGen; },
        set spendDayGen(value) { spendDayGen = value; },
        get spendGen() { return spendGen; },
        set spendGen(value) { spendGen = value; },
        get spendPollTimer() { return spendPollTimer; },
        set spendPollTimer(value) { spendPollTimer = value; },
        get telemetryData() { return telemetryData; },
        set telemetryData(value) { telemetryData = value; }
      },
      actions: {
        get closeDrawer() { return detailDrawer.close; },
        get apiFetch() { return apiFetch; },
        clearInterval: (...args) => window.clearInterval(...args),
        clearTimeout: (...args) => window.clearTimeout(...args),
        get consolePosturePresentation() { return consolePosturePresentation; },
        get consoleReportHealthText() { return consoleReportHealthText; },
        get createEventHistoryPage() { return createEventHistoryPage; },
        get document() { return document; },
        get homeGroupOpen() { return homeGroupOpen; },
        get isConsoleReport() { return isConsoleReport; },
        get isEventsFiltered() { return isEventsFiltered; },
        get isFlagsFiltered() { return isFlagsFiltered; },
        get markDirty() { return markDirty; },
        get resetPolicyState() { return resetPolicyState; },
        get renderNow() { return renderNow; },
        get renderPosture() { return renderPosture; },
        get renderReportHealth() { return renderReportHealth; },
        get renderSnapshotHealth() { return renderSnapshotHealth; },
        get sessionStorage() { return sessionStorage; },
        get showSessionEnded() { return showSessionEnded; },
        get showToast() { return showToast; },
        get switchTab() { return switchTab; },
        get window() { return window; }
      }
    });
  }
  function noteEndpointFailure(...args) { return consoleLifecycleControllerModule().noteEndpointFailure(...args); }
  function hasSnapshotHeadline(...args) { return consoleLifecycleControllerModule().hasSnapshotHeadline(...args); }
  function renderSnapshotHealth(...args) { return consoleLifecycleControllerModule().renderSnapshotHealth(...args); }
  function renderReportHealth(...args) { return consoleLifecycleControllerModule().renderReportHealth(...args); }
  function reportSucceeded(...args) { return consoleLifecycleControllerModule().reportSucceeded(...args); }
  function reportFailed(...args) { return consoleLifecycleControllerModule().reportFailed(...args); }
  function endSession(...args) { return consoleLifecycleControllerModule().endSession(...args); }
  function clearProtectionContext(...args) { return consoleLifecycleControllerModule().clearProtectionContext(...args); }
  function focusProtectionContext(...args) { return consoleLifecycleControllerModule().focusProtectionContext(...args); }
  function viewEgressExpectation(...args) { return consoleLifecycleControllerModule().viewEgressExpectation(...args); }
  function backToEgressContext(...args) { return consoleLifecycleControllerModule().backToEgressContext(...args); }
  function paintTabsPosture(...args) { return consoleLifecycleControllerModule().paintTabsPosture(...args); }
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
    if (text) text.textContent = connState === 'invalid-response'
      ? "The daemon returned invalid telemetry — showing the last known state and retrying…"
      : (lastSnapshotAt ? `Can't reach Secure Agent. Last connected at ${new Date(lastSnapshotAt).toLocaleTimeString()} — retrying automatically.`
        : 'Waiting for Secure Agent. No live data received — retrying automatically.');
  }

  // Credential rejection stops delivery. No mutation is queued or replayed.
  let handoffGeneration = 0;
  window.addEventListener('hashchange', async () => {
    const handoff = new URLSearchParams(location.hash.slice(1));
    const fresh = handoff.get('ct');
    if (!fresh) {
      if (!sessionEnded && isConsoleRoute(location.hash)) switchTab(location.hash, {skipHash:true});
      return;
    }
    const generation = ++handoffGeneration;
    endSession();
    consoleToken = fresh;
    consoleAuth.replaceToken(fresh);
    try { sessionStorage.setItem(SS_TOKEN_KEY, fresh); } catch { /* memory only */ }
    // Strip the credential immediately. A general reopen keeps the current
    // route; an explicit drill-down from the menu bar takes its requested tab.
    let route = routeKey({ tab: activeTab, sub: activeTab === 'protection' ? activeProtection : activeTab === 'system' ? activeSystemSub : activeSub });
    try { route = sessionStorage.getItem('sa.console-tab') || route; } catch { /* memory only */ }
    const context = consoleContextFromHash(location.hash);
    route = context.route || route || 'home';
    if (context.route || context.session || context.flag || context.incident || context.file) {
      pendingConsoleContext = { ...context, route };
    }
    history.replaceState(null, '', location.pathname + location.search + consoleContextHash(pendingConsoleContext || { route }));
    const reason = document.getElementById('console-access-reason');
    reason.textContent = 'Checking the connection. Your view is preserved; actions remain paused.';
    try {
      const response = await apiFetch('/snapshot');
      if (!response.ok || !isConsoleReport('snapshot', await response.json())) throw new Error('Connection unavailable');
    } catch {
      if (generation === handoffGeneration) reason.textContent = 'Could not reconnect. Check that Secure Agent is running, then choose Reconnect again.';
      return;
    }
    if (generation !== handoffGeneration) return;
    sessionEnded = false;
    document.body.classList.remove('is-ended', 'is-paused');
    document.getElementById('session-ended').hidden = true;
    for (const [el, previous] of pausedElements) {
      el.inert = previous.inert;
      el.hidden = previous.hidden;
    }
    pausedElements.clear();
    if (activeTab === 'protection' && activeProtection === 'rules') loadPolicy();
    detailDrawer.syncMode();
    if (handoff.has('tab')) switchTab(route, { skipHash: true });
    if (recoveryFocus?.isConnected) recoveryFocus.focus({ preventScroll: true });
    telemetryFetchGen++;
    telemetrySlowGen++;
    if (liveUpdates) liveUpdates.stop();
    startLiveUpdates();
    clearInterval(sparkTimer);
    sparkTimer = setInterval(() => { sparkAdvance(); drawSpark(); }, 1000);
    if (sessionWorkbench.selectedSessionId && !pendingConsoleContext?.session) sessionWorkbench.refresh();
  });

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
  // One active selection per history view; relative-window cutoffs change
  // on each request, so scope is the selected filters rather than the URL.
  const historyScopes = { flags: null, events: null };
  const reviewDrafts = new Map();
  let reviewCursor = '';
  let reviewPageSeq = 0;
  let reviewResult = null;
  let reviewResultSeq = 0;
  window.reviewAct = async function(id, revision, action, scope) {
    if (!validReviewDecision(revision, action, scope)) {
      showToast('Review decision unavailable. Refresh the evidence before choosing again.', 'danger');
      return;
    }
    const auth = handoffGeneration;
    if (scope && scope.kind !== 'once' && !await window.saConfirm('Count future activity as expected only for the recorded executable path, workspace, file and exact endpoint? ' + (scope.kind === 'session' ? 'This ends with the current session.' : `Expires after ${scope.expiry === '7d' ? '7 days' : '24 hours'}.`) + ' Firewall and payload checks remain active. Revoke under Protection → Rules & permissions.', {title:'Expected activity',okLabel:'Save permission'})) return;
    if (sessionEnded || auth !== handoffGeneration) return;
    const seq = ++reviewResultSeq;
    const current = attentionItems().find(item => item.kind === 'review' && item.id === id)?.review
      || telemetryData.reviews?.reviews?.find(review => review.id === id);
    const review = current?.revision === revision ? JSON.parse(JSON.stringify(current)) : null;
    const finishAttention = beginAttentionWrite();
    reviewDrafts.set(id, { action, scope, conflict: false });
    try {
      const res = await apiFetch('/reviews/decision', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({id,revision,action,...(scope ? {scope} : {})}) });
      if (sessionEnded || auth !== handoffGeneration) { finishAttention(false); return; }
      if (res.status === 409) {
        reviewDrafts.set(id, { action, scope, conflict: true });
        finishAttention(false);
        await fetchTelemetry();
        if (sessionEnded || auth !== handoffGeneration) return;
        markDirty('flags', 'attention');
        showToast('Evidence changed. Review the new facts and choose again.', 'info');
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const receipt = await res.json();
      if (sessionEnded || auth !== handoffGeneration) { finishAttention(false); return; }
      if (!validReviewReceipt(receipt, id, revision, action)) throw new Error('Invalid decision receipt');
      if (seq === reviewResultSeq) {
        reviewResult = { receipt, review };
        markDirty('attention');
        window.saAnnounce(reviewResultLabel(receipt));
      }
      reviewDrafts.delete(id);
    } catch {
      finishAttention(false);
      if (sessionEnded || auth !== handoffGeneration) return;
      showToast('Review not confirmed. Check history before deciding again.', 'danger');
      await fetchTelemetry();
      return;
    }
    await fetchTelemetry();
    finishAttention(true);
    if (!sessionEnded && auth === handoffGeneration) markDirty('flags', 'attention');
  };
  window.dismissReviewResult = function() {
    reviewResult = null;
    markDirty('attention');
  };
  window.openReviewResult = function(result = reviewResult) {
    detailDrawer.openReviewResult(result);
  };
  // Review pagination is explicit; each response is bounded to 100 records.
  window.loadReviewPage = async function(after) {
    const seq = ++reviewPageSeq;
    try {
      const res = await apiFetch('/reviews?limit=100&after=' + encodeURIComponent(after || ''));
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const page = await res.json();
      if (seq !== reviewPageSeq) return;
      if (!Array.isArray(page.reviews)) throw new Error('Invalid review response');
      telemetryData.reviews = page;
      reviewCursor = after || '';
      markDirty('flags');
    } catch (err) { showToast(`Could not load reviews: ${err}`, 'danger'); }
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

  let sparkTimer = consoleToken ? setInterval(() => { sparkAdvance(); drawSpark(); }, 1000) : null;

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
    const html = sessionScopeOn() || window.SA.sessionInvestigationReturn ? scopeBarHTML({
      session: timelineSession, pids: timelinePids, pidLabel: timelinePidLabel,
      events: scopedBySession(t.eventsView || [], timelineSession, timelinePids).length,
      flags: scopedBySession(t.flagsView || [], timelineSession, timelinePids).length,
      returnToSession: window.SA.sessionInvestigationReturn,
    }) : '';
    bar.hidden = !html;
    if (bar._saHTML !== html) {
      const focusedAction = bar.contains(document.activeElement) ? document.activeElement?.dataset.action : '';
      bar.innerHTML = html;
      bar._saHTML = html;
      if (focusedAction) Array.from(bar.querySelectorAll('[data-action]')).find(el => el.dataset.action === focusedAction)?.focus({ preventScroll: true });
    }
  }

  // Posture pill on the stuck tab bar: the hero's count; a click goes back
  // to the top.
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

  let historyControllerController;
  function historyControllerControllerModule() {
    return historyControllerController ||= createHistoryController({
      state: {
        get eventHistoryPage() { return eventHistoryPage; },
        set eventHistoryPage(value) { eventHistoryPage = value; },
        get failedEndpoints() { return failedEndpoints; },
        get filters() { return filters; },
        get historyScopes() { return historyScopes; },
        get reportHealth() { return reportHealth; },
        get sessionEnded() { return sessionEnded; },
        set sessionEnded(value) { sessionEnded = value; },
        get suppressFreshOnce() { return suppressFreshOnce; },
        set suppressFreshOnce(value) { suppressFreshOnce = value; },
        get telemetryData() { return telemetryData; },
        set telemetryData(value) { telemetryData = value; },
        get timelineSession() { return timelineSession; },
        set timelineSession(value) { timelineSession = value; }
      },
      actions: {
        get createEventHistoryPage() { return createEventHistoryPage; },
        get document() { return document; },
        get fetchTelemetry() { return fetchTelemetry; },
        get homeGroupOpen() { return homeGroupOpen; },
        get isConsoleRoute() { return isConsoleRoute; },
        get isEventsFiltered() { return isEventsFiltered; },
        get isFlagsFiltered() { return isFlagsFiltered; },
        get loadViews() { return loadViews; },
        get markDirty() { return markDirty; },
        get renderEvents() { return renderEvents; },
        get renderNow() { return renderNow; },
        get renderReportHealth() { return renderReportHealth; },
        get requestEventHistoryPage() { return requestEventHistoryPage; },
        get showToast() { return showToast; },
        get switchTab() { return switchTab; },
        get syncFilterControls() { return syncFilterControls; }
      }
    });
  }
  function sinceParam(...args) { return historyControllerControllerModule().sinceParam(...args); }
  function isFlagsFiltered(...args) { return historyControllerControllerModule().isFlagsFiltered(...args); }
  function isEventsFiltered(...args) { return historyControllerControllerModule().isEventsFiltered(...args); }
  function eventsHistoryScope(...args) { return historyControllerControllerModule().eventsHistoryScope(...args); }
  function syncHistoryViews(...args) { return historyControllerControllerModule().syncHistoryViews(...args); }
  function flagsQuery(...args) { return historyControllerControllerModule().flagsQuery(...args); }
  function eventsQuery(...args) { return historyControllerControllerModule().eventsQuery(...args); }
  window.pageSessionEvents = (...args) => historyControllerControllerModule().pageSessionEvents(...args);
  function wireFilter(...args) { return historyControllerControllerModule().wireFilter(...args); }
  window.applyView = (...args) => historyControllerControllerModule().applyView(...args);
  function bindFilters(...args) { return historyControllerControllerModule().bindFilters(...args); }
  historyControllerControllerModule().bindFilters();
  let eventHistoryPage = createEventHistoryPage();
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
      tab: routeKey({ tab: activeTab, sub: activeTab === 'protection' ? activeProtection : activeTab === 'system' ? activeSystemSub : activeSub }),
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
  // The console groups Home, Sessions, Protection, System and Agent.
  // State persists per tab-session; the hash carries the tab and sub-view
  // for deep links (#ct is lifted
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
    ['posture', renderPosture], ['status', renderStatus], ['resources', renderResourceMissionControl], ['history', renderResourceHistory], ['sessions', () => sessionWorkbench.render()],
    ['chart-flags', renderChartFlags], ['chart-memory', renderChartMemory], ['spend', renderSpend],
    ['agents', renderAgents],
    ['endpoints', renderEndpoints], ['recurring-egress', renderEgressEpisodes], ['firewall', renderFirewall], ['incidents', renderIncidents], ['fleet', renderFleet],
    ['audit', renderAudit], ['sources', renderSources], ['flags', renderFlags], ['attention', renderAttention], ['session-daily', renderSessionDaily],
    ['events', renderEvents], ['activity', renderActivity], ['worktrees', renderWorktrees], ['clutter', renderClutter], ['tab-badges', renderTabBadges],
    ['notify', renderNotifyRules], ['policy', renderPolicyLists], ['expected-egress', renderExpectedEgressRules], ['agent', renderAgent]
  ];
  // Panel → where it lives: tab, tab/sub-view, or tab:group (a Home
  // <details> group). A panel absent here is global (always on screen).
  const PANEL_VIEW = {
    attention: 'home', spend: 'home', 'session-daily': 'home',
    flags: 'home:findings', incidents: 'home:findings',
    activity: 'home:trends', 'chart-flags': 'home:trends', 'chart-memory': 'system/resources',
    sessions: 'sessions/board', agents: 'sessions/processes', fleet: 'sessions/processes',
    resources: 'system/resources', history: 'system/resources',
    events: 'sessions/events',
    endpoints: 'protection/traffic', 'recurring-egress': 'protection/traffic', firewall: 'protection/rules', sources: 'protection/sources',
    worktrees: 'system/worktrees', clutter: 'system/clutter',
    notify: 'protection/rules', policy: 'protection/rules', 'expected-egress': 'protection/rules', audit: 'protection/audit', agent: 'agent'
  };
  // A panel is on screen when its tab is active, its sub-view is the open
  // one, and its Home group is expanded.
  function panelOnScreen(name) {
    const v = PANEL_VIEW[name];
    if (!v) return true;
    // The docked conversation is on screen over any tab.
    if (name === 'agent' && agentDockOpen) return true;
    const [route, group] = v.split(':');
    const [tab, sub] = route.split('/');
    if (tab !== activeTab || (sub && sub !== (tab === 'protection' ? activeProtection : tab === 'system' ? activeSystemSub : activeSub))) return false;
    return !group || homeGroupOpen(group);
  }
  // Panel → the element whose focused control holds its render.
  const PANEL_EL = {
    resources: 'resource-board', history: 'history-board', sessions: 'session-rail', agents: 'agents-container',
    fleet: 'fleet-container', endpoints: 'endpoints-container', 'recurring-egress': 'recurring-egress-container', firewall: 'firewall-container', sources: 'sources-list', incidents: 'incidents-container',
    audit: 'audit-container', flags: 'flags-list', attention: 'attention-list', 'expected-egress': 'expected-egress-container', events: 'events-container',
    worktrees: 'worktrees-container', clutter: 'clutter-container', notify: 'notify-pop', agent: 'agent-side'
  };
  const SLOW_ONLY = new Set(['resources', 'history', 'fleet', 'audit', 'sources', 'activity', 'spend', 'recurring-egress', 'expected-egress']);
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
    setTabBadge('processes', groupAgentsByHarness(agents).filter(g => !g.infra).length);
    setTabBadge('sessions', t.sessions && t.sessions.length
      ? groupSessionsByHarness(t.sessions, trees, agents).reduce((n, g) => n + (g.infra ? 0 : familySize(g.live)), 0)
      : sessionRows(agents, trees).length);
    paintTabsPosture();
    paintScopeBar();
  }

  let protectionContext = null;
  let protectionContextGeneration = 0;
  let activeProtection = 'traffic';
  let activeTab = 'home';
  let activeSub = 'board';
  let activeSystemSub = 'worktrees';

  const worktreeController = createWorktreeController({
    request: apiFetch,
    toast: showToast,
    confirm: (...args) => window.saConfirm(...args),
    render: renderNow,
    markDirty,
    visible: view => activeTab === 'system' && activeSystemSub === view,
    now: Date.now,
    history: { open: () => !!historyState.seq, paint: () => paintHistory() },
    discuss: discussWorktreeTarget,
    toastHost: { show: showToastHost, hideWhenEmpty: hideToastHostWhenEmpty }
  });
  for (const name of ['removeWorktree', 'removeAllWorktrees', 'removeAllRemovable', 'revealWorktree', 'reconnectWorktree',
    'trashOrphanWorktree', 'trashReviewedWorktree', 'discussWorktree', 'discussWorktreeGroup', 'adviseWorktree', 'adviseWorktreeGroup',
    'trashClutter', 'adviseClutterProject', 'cleanClutter', 'askWorktreeAgent', 'pruneWorktrees', 'hideWorktreeRepo']) {
    window[name] = (...args) => worktreeController[name](...args);
  }

  async function openHookInspector(kind, data, options = {}) {
    if (sessionEnded) return;
    const repair=kind==='repair', evidence=kind==='evidence' || repair;
    const scope = {session:data.session || '',harness:data.harness || '',event:data.event || '',event_scope:repair?'exact':data.event_scope || 'group',handler:data.handler || '',config:data.config || '',script:data.script || '',id:data.id || '',
      ...(repair?{after:data.after || '',problem:data.problem || '',explanation:data.explanation || '',guidance:data.guidance || ''}:{})};
    const attrs = `data-action="${repair ? 'hook-repair-check' : evidence ? 'hook-evidence' : 'hook-delivery-inspect'}" ` + Object.entries(scope).map(([k,v]) => `data-${k}="${escapeHTML(v)}"`).join(' ');
    const retry = `<button type="button" class="btn btn-ghost btn-sm" ${attrs}>${repair?'Check again':'Refresh '+(evidence?'evidence':'delivery')}</button>`;
    detailDrawer.setMode('hook-' + kind);
    detailDrawer.setCopyVisible(false);
    if (!detailDrawer.open({title:repair?'Check hook repair':evidence ? 'Recorded hook runs' : 'Hook delivery',icon:'history',body:repair?hookRepairHTML(scope):'<p role="status">Loading hook evidence…</p>',foot:retry,back:options.back})) return;
    const seq=detailDrawer.seq(), auth=handoffGeneration;
    const current=()=>!sessionEnded && auth===handoffGeneration && seq===detailDrawer.seq() && !drawer.hidden;
    try {
      const query = new URLSearchParams({harness:scope.harness,event:scope.event,event_scope:scope.event_scope,handler_id:scope.handler,config_id:scope.config,script:scope.script});
      if(repair) query.set('verify_after',scope.after);
      const response=await apiFetch(evidence ? '/sessions/'+encodeURIComponent(scope.session)+'/hook-evidence?'+query : '/status');
      if (!response.ok) throw new Error('Hook evidence unavailable');
      const payload=await response.json();
      if (!current()) return;
      if (evidence) {
        if (!(repair?validHookRepair(payload,scope):validHookEvidence(payload,scope))) throw new Error('Invalid hook evidence');
        drawerBody.innerHTML=repair?hookRepairHTML(scope,payload):hookEvidenceHTML(payload);
      } else {
        const row=payload.hook_ingestion?.forwarders?.find(r=>r.report?.forwarder_id===scope.id);
        if (row && !validHookForwarder(row)) throw new Error('Invalid delivery evidence');
        drawerBody.innerHTML=(row ? hookForwardersHTML([row],false) : '<p>No report for this forwarding instance is available. Current delivery state and recovery are unknown.</p>')
          +`<button type="button" class="link-btn" data-action="hook-setup" data-harness="${escapeHTML(row?.report.harness || '')}">Hook setup and verification</button>`;
      }
    } catch {
      if (current()) drawerBody.innerHTML=repair?hookRepairHTML(scope,null,'Verification unavailable. Check again; repair remains unconfirmed.'):'<p role="status">Hook evidence unavailable. Refresh to retry; recovery is unknown.</p>';
    }
  }

  function openHookSetup(harness, options = {}) {
    if (sessionEnded) return;
    detailDrawer.setMode('hook-setup');
    detailDrawer.setCopyVisible(false);
    detailDrawer.open({title:'Hook setup and verification',icon:'history',body:hookSetupHTML(harness,telemetryData.status?.hook_ingestion),back:options.back});
  }

  // History drawer: the ledger grouped by day, filtered by kind or by the
  // day picked in the chart. seq is the drawer it painted, so a reload
  // never writes into another drawer.
  const historyState = { seq: 0, kind: '', day: '' };
  function paintHistory() {
    if (!historyState.seq || historyState.seq !== detailDrawer.seq() || drawer.hidden) return;
    const { ledger } = worktreeController.worktreesState;
    drawerBody.innerHTML = ledger
      ? cleanupHistoryHTML(ledger, historyState, Date.now())
      : '<div class="loading">Reading the cleanup ledger…</div>';
  }
  function openHistory(day) {
    if (day !== undefined) historyState.day = day;
    if (!(historyState.seq && historyState.seq === detailDrawer.seq() && !drawer.hidden)) {
      const opened = detailDrawer.open({ title: 'Cleanup history', icon: 'history',
        onClose: () => Object.assign(historyState, { seq: 0, kind: '', day: '' }) });
      if (!opened) return;
      historyState.seq = detailDrawer.seq();
      const { ledger, ledgerAt } = worktreeController.worktreesState;
      if (!ledger || Date.now() - ledgerAt > WORKTREE_STALE_MS) worktreeController.loadLedger();
    }
    paintHistory();
  }

  // Policy lists are not telemetry either: they load when Protection → Rules &
  // permissions opens and on its Refresh, never on the refresh cycle.
  const policyState = { guardRules: null, pathAllows: null, mutes: null, expected: null, scopes: null,
    loading: false, error: '', scopeMutations: new Map(), expectedMutations: new Map(), expectedRemoval: null };
  const policyRendered = new Map();
  let policyController;
  function consolePolicyControllerModule() {
    return policyController ||= createConsolePolicy({
      state: { policyState, get sessionEnded() { return sessionEnded; }, get handoffGeneration() { return handoffGeneration; } },
      actions: { apiFetch: (...args) => apiFetch(...args), markDirty, decisionPermissionRows, validExpectedPatterns }
    });
  }
  function loadPolicy(kind) { return consolePolicyControllerModule().load(kind); }
  function resetPolicyState() { return consolePolicyControllerModule().reset(); }
  function policyReady(kind) { return consolePolicyControllerModule().ready(kind); }
  function renderPolicyLists() {
    const put = (id, badge, rows, html) => {
      const el = document.getElementById(id);
      if (el && policyRendered.get(id) !== html) {
        const active = document.activeElement;
        const focused = el.contains(active) && active.dataset.action ? { ...active.dataset } : null;
        el.innerHTML = html;
        policyRendered.set(id, html);
        if (focused) {
          const target = Array.from(el.querySelectorAll('[data-action]')).find(button => !button.disabled &&
            ['action', 'id', 'key', 'kind'].every(field => button.dataset[field] === focused[field]));
          if (target) target.focus({ preventScroll: true });
          else { el.tabIndex = -1; el.focus({ preventScroll: true }); }
        }
      }
      const b = document.getElementById(badge);
      if (b) b.textContent = rows ? rows.length : '—';
    };
    const st = policyState;
    consolePolicyControllerModule();
    const view = key => ({ ...st, ...st.reports[key] });
    put('policy-guard-rules', 'badge-guard-rules', st.guardRules, policyListHTML('guard', st.guardRules, view('guardRules')));
    put('policy-path-allows', 'badge-path-allows', st.pathAllows, policyListHTML('path', st.pathAllows, view('pathAllows')));
    put('policy-mutes', 'badge-mutes', st.mutes, policyListHTML('mute', st.mutes, view('mutes')));
    put('policy-expected', 'badge-expected', st.expected, policyListHTML('expected', st.expected, view('expected')));
    put('policy-scopes', 'badge-scopes', st.scopes, policyListHTML('scope', st.scopes, view('scopes')));
  }

  window.revokeScope = async function(id) {
    const record = policyState.scopes?.find(r => r.id === id);
    if (!policyReady('scope') || policyState.scopeMutations.has(id) || !decisionScopeApplicability(record).revoke) return;
    const mutation = { auth: handoffGeneration, status: 'confirming' };
    const current = () => !sessionEnded && mutation.auth === handoffGeneration && policyState.scopeMutations.get(id) === mutation;
    policyState.scopeMutations.set(id, mutation);
    const confirmed = await window.saConfirm(`Revoke this saved permission for ${record.resource_path}${record.destination ? ' → ' + record.destination : ''}? Other permissions and policies may still allow matching activity. This does not undo past access or remediate past exposure.`, { title: 'Revoke permission', okLabel: 'Revoke permission' });
    if (!current()) return;
    if (!confirmed) { policyState.scopeMutations.delete(id); return; }
    if (!policyReady('scope') || !decisionScopeApplicability(policyState.scopes?.find(r => r.id === id)).revoke) {
      policyState.scopeMutations.delete(id); markDirty('policy'); return;
    }
    mutation.status = 'saving';
    markDirty('policy');
    try {
      const res = await apiFetch('/decision-scopes?id=' + encodeURIComponent(id), {method:'DELETE'});
      if (!res.ok || !validScopeRevocation(await res.json(), id)) throw new Error('Revocation not confirmed');
      if (!current()) return;
      consolePolicyControllerModule().invalidate('scope');
      mutation.status = 'saved';
      markDirty('policy');
      showToast('Permission revocation saved. Other permissions may still apply; past access is unchanged.', 'success');
      await loadPolicy('scope');
    } catch {
      if (!current()) return;
      mutation.status = 'unconfirmed';
      markDirty('policy');
      showToast('Revocation not confirmed. Refresh permissions before trying again.', 'danger');
    }
  };

  window.forgetExpected = async function(key) {
    const records = policyState.expected;
    if (!policyReady('expected') || !validExpectedPatterns(records) || policyState.expectedMutations.has(key)) return;
    const record = records.find(r => r.key === key);
    if (!record) return;
    const mutation = { auth: handoffGeneration, status: 'confirming' };
    const current = () => !sessionEnded && mutation.auth === handoffGeneration && policyState.expectedMutations.get(key) === mutation;
    policyState.expectedMutations.set(key, mutation);
    const target = record.scope === 'file'
      ? `Remove the non-secret file exception for ${record.agent}: ${record.path}? This exception covers all readers and destinations for this agent and file.`
      : `Remove the expected read/connect exception for ${record.agent}: ${record.reader} reads ${record.path}, then reaches ${record.dest}?`;
    const confirmed = await window.saConfirm(target + ' Future matching activity is evaluated under remaining exceptions and policies. Past activity and exposure are unchanged.',
      { title: 'Remove exception', okLabel: 'Remove exception' });
    if (!current()) return;
    if (!confirmed) { policyState.expectedMutations.delete(key); return; }
    const latest = policyState.expected?.find(r => r.key === key);
    if (!policyReady('expected') || !latest || ['agent', 'reader', 'path', 'dest', 'scope'].some(field => latest[field] !== record[field])) {
      policyState.expectedMutations.delete(key); markDirty('policy'); return;
    }
    mutation.status = 'saving';
    markDirty('policy');
    try {
      const response = await apiFetch('/expected?key=' + encodeURIComponent(key), { method: 'DELETE' });
      if (!response.ok) throw new Error('Removal unavailable');
      const receipt = await response.json();
      if (receipt?.status !== 'ok' || receipt.key !== key) throw new Error('Removal not confirmed');
      if (!current()) return;
      // A read begun before this receipt cannot restore the removed row.
      consolePolicyControllerModule().invalidate('expected');
      policyState.expected = policyState.expected.filter(r => r.key !== key);
      policyState.expectedRemoval = { ...record };
      policyState.expectedMutations.delete(key);
      markDirty('policy');
      showToast('Exception removal saved. Remaining exceptions and policies still apply; past activity is unchanged.', 'success');
      await loadPolicy('expected');
    } catch {
      if (!current()) return;
      mutation.status = 'unconfirmed';
      markDirty('policy');
      showToast('Removal not confirmed. Refresh exceptions before trying again.', 'danger');
    }
  };

  // Agent tab: the system agent's status, chat, plans and runs load when
  // the tab opens and after each action. While the model answers or a
  // headless run is in flight, the busy part is re-read every
  // AGENT_POLL_MS (tab open only); when it settles, everything once more.
  const AGENT_POLL_MS = 1500;
  const AGENT_POLL_LIMIT = 1200;
  const AGENT_TIMEOUT_MS = 15000;
  const agentState = { status: null, chat: null, plans: null, runs: null, recommendations: null, skills: null, error: '', sendError: '', sending: false, actionRequests: new Set(), readVersion: {}, polls: 0, lastCount: 0, seenMessageKeys: null, unreadMessageKeys: new Set(), reading: null, restoreReading: false };
  // Literal paths: the proxy's console allow-list test reads them from here.
  const AGENT_PATHS = { status: '/agent/status', chat: '/agent/chat', plans: '/agent/plans', runs: '/agent/runs', recommendations: '/agent/recommendations' };
  let agentPollTimer = null;
  const agentReducedMotion = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  agentReducedMotion?.addEventListener('change', event => {
    if (!event.matches) return;
    const thread = document.getElementById('agent-thread');
    thread?.getAnimations?.({ subtree: true }).forEach(animation => {
      if (animation.id === 'agent-message-arrival') animation.cancel();
    });
  });
  // Agent dock: the Agent tab's conversation (#agent-chat) moved beside the
  // current page, so asking about a worktree does not navigate away. It and
  // the inspector drawer share the right edge: one is open at a time.
  const agentDockNarrow = window.matchMedia ? window.matchMedia('(max-width: 900px)') : null;
  // Below 900px the dock covers the page instead of narrowing it.
  function syncAgentDockInert() {
    const app = document.querySelector('.app');
    if (app && !sessionEnded) app.inert = agentDockOpen && !!(agentDockNarrow && agentDockNarrow.matches);
  }
  agentDockNarrow?.addEventListener('change', syncAgentDockInert);
  function captureAgentThreadReading() {
    const thread = document.getElementById('agent-thread');
    if (!thread?.getClientRects().length || !thread.clientHeight) return null;
    const bounds = thread.getBoundingClientRect();
    const anchor = Array.from(thread.children).find(node => node._saKey && node.getBoundingClientRect().bottom > bounds.top);
    return { top: thread.scrollTop, follow: thread.scrollHeight - thread.scrollTop - thread.clientHeight < 80,
      anchor: anchor?._saKey, offset: anchor ? anchor.getBoundingClientRect().top - bounds.top : 0 };
  }
  function restoreAgentThreadReading(reading) {
    const thread = document.getElementById('agent-thread');
    if (!thread?.getClientRects().length || !thread.clientHeight) return;
    if (!reading || reading.follow) thread.scrollTop = thread.scrollHeight;
    else {
      thread.scrollTop = reading.top;
      const anchor = Array.from(thread.children).find(node => node._saKey === reading.anchor);
      if (anchor) thread.scrollTop += anchor.getBoundingClientRect().top - thread.getBoundingClientRect().top - reading.offset;
    }
    agentState.reading = captureAgentThreadReading();
    agentState.restoreReading = false;
  }
  function updateAgentJumpLatest(reading) {
    const button = document.getElementById('agent-jump-latest');
    if (!button) return;
    const messages = (agentState.chat?.messages || []).filter(message => message.origin !== 'analysis');
    const empty = !agentState.status?.enabled || !messages.length;
    if (empty || reading?.follow) agentState.unreadMessageKeys.clear();
    const count = agentState.unreadMessageKeys.size;
    button.textContent = count ? `${count} new message${count === 1 ? '' : 's'} · Jump to latest` : 'Jump to latest';
    button.hidden = empty || !reading || reading.follow;
  }
  function jumpToLatestAgentMessage() {
    const thread = document.getElementById('agent-thread');
    if (!thread?.getClientRects().length || !thread.clientHeight) return;
    thread.scrollTop = thread.scrollHeight;
    const input = document.getElementById('agent-input');
    if (input?.isConnected && !input.disabled && input.getClientRects().length) input.focus({preventScroll: true});
    agentState.unreadMessageKeys.clear();
    agentState.reading = captureAgentThreadReading();
    updateAgentJumpLatest(agentState.reading);
    restoreAgentThreadReading({follow: true});
  }
  document.getElementById('agent-thread')?.addEventListener('scroll', () => {
    if (agentState.restoreReading) return;
    const reading = captureAgentThreadReading();
    if (!reading) return;
    agentState.reading = reading;
    updateAgentJumpLatest(reading);
  }, {passive: true});
  function openAgentDock() {
    const dock = document.getElementById('agent-dock');
    const chat = document.getElementById('agent-chat');
    const body = document.getElementById('agent-dock-body');
    if (activeTab === 'agent' || !dock || !chat || !body) {
      switchTab('agent');
      return;
    }
    detailDrawer.close();
    agentState.reading = captureAgentThreadReading() || agentState.reading;
    agentState.restoreReading = true;
    if (!agentDockOpen) agentDockOpener = document.activeElement;
    if (chat.parentElement !== body) body.appendChild(chat);
    dock.hidden = false;
    agentDockOpen = true;
    document.body.classList.add('agent-docked');
    syncAgentDockInert();
    markDirty('agent');
    restoreAgentThreadReading(agentState.reading);
    loadAgent();
    const input = document.getElementById('agent-input');
    if (input) input.focus({ preventScroll: true });
  }
  // restoreFocus returns focus to what opened the dock (Close, Escape); a
  // move to the Agent tab focuses there instead.
  function closeAgentDock(restoreFocus = false) {
    if (!agentDockOpen) return;
    const dock = document.getElementById('agent-dock');
    const chat = document.getElementById('agent-chat');
    const layout = document.querySelector('#tab-agent .agent-layout');
    agentState.reading = captureAgentThreadReading() || agentState.reading;
    agentState.restoreReading = true;
    if (chat && layout) layout.insertBefore(chat, layout.firstChild);
    if (dock) dock.hidden = true;
    agentDockOpen = false;
    document.body.classList.remove('agent-docked');
    syncAgentDockInert();
    restoreAgentThreadReading(agentState.reading);
    const opener = agentDockOpener;
    agentDockOpener = null;
    if (restoreFocus && opener && opener.isConnected) opener.focus({ preventScroll: true });
  }
  document.addEventListener('keydown', e => {
    const dock = document.getElementById('agent-dock');
    if (e.key !== 'Escape' || e.defaultPrevented || sessionEnded || !agentDockOpen || !dock || !dock.contains(document.activeElement)) return;
    // Escape while writing a message keeps the panel.
    const a = document.activeElement;
    if (a.matches('textarea, input') && a.value) return;
    e.preventDefault();
    closeAgentDock(true);
  });
  const agentComposer = document.getElementById('agent-composer');
  const agentInput = document.getElementById('agent-input');
  const agentHarnessSelect = document.getElementById('agent-harness');
  const agentWorkdirInput = document.getElementById('agent-workdir');
  const agentHandoffInput = document.getElementById('agent-handoff-input');
  const agentHandoffWorkdir = document.getElementById('agent-handoff-workdir');
  let agentActivePane = '';
  function setAgentPanel(pane, toggle = false) {
    if (pane && !['queue', 'history', 'tools'].includes(pane)) return;
    // The queue, history and tools live in the Agent tab: show it.
    if (pane && agentDockOpen) switchTab('agent');
    if (toggle && pane === agentActivePane) pane = '';
    const previous = agentActivePane;
    agentActivePane = pane;
    const side = document.getElementById('agent-side');
    if (!side) return;
    side.hidden = !pane;
    document.getElementById('agent-workspace').classList.toggle('has-inspector', !!pane);
    side.querySelectorAll('[data-agent-pane]').forEach(el => { el.hidden = el.dataset.agentPane !== pane; });
    document.querySelectorAll('[data-action="agent-panel"]').forEach(el => {
      el.setAttribute('aria-expanded', String(el.dataset.panel === pane));
    });
    const title = document.getElementById('agent-panel-title');
    if (pane) {
      title.textContent = ({ queue: 'Review queue', history: 'History', tools: 'Tools' })[pane];
      title.focus({ preventScroll: true });
    } else if (previous) {
      document.querySelector(`[data-action="agent-panel"][data-panel="${previous}"]`)?.focus({ preventScroll: true });
    }
  }
  document.getElementById('agent-side')?.addEventListener('keydown', e => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setAgentPanel(''); }
  });
  try { if (agentWorkdirInput) agentWorkdirInput.value = sessionStorage.getItem('sa.agent-workdir') || ''; } catch { /* private mode */ }
  async function agentFetch(path, opts = {}) {
    const init = { timeoutMs: AGENT_TIMEOUT_MS, method: opts.method || 'GET' };
    if (opts.body !== undefined) {
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(opts.body);
    }
    const r = await apiFetch(path, init);
    const text = await r.text();
    if (!r.ok) throw new Error(text.trim() || String(r.status));
    try { return JSON.parse(text); } catch { return null; }
  }
  let agentControllerController;
  function agentControllerControllerModule() {
    return agentControllerController ||= createAgentController({
      state: {
        get AGENT_PATHS() { return AGENT_PATHS; },
        get agentInput() { return agentInput; },
        get agentState() { return agentState; },
        get agentWorkdirInput() { return agentWorkdirInput; }
      },
      actions: {
        get agentFetch() { return agentFetch; },
        get fillAgentHarnesses() { return fillAgentHarnesses; },
        get followAgent() { return followAgent; },
        get loadAgent() { return loadAgent; },
        get markDirty() { return markDirty; },
        get renderNow() { return renderNow; },
        get showToast() { return showToast; },
        get window() { return window; }
      }
    });
  }
  function agentBusy(...args) { return agentControllerControllerModule().agentBusy(...args); }
  function loadAgent(...args) { return agentControllerControllerModule().loadAgent(...args); }
  window.sendAgentMessage = (...args) => agentControllerControllerModule().sendAgentMessage(...args);
  window.runLocalAgentAction = (...args) => agentControllerControllerModule().runLocalAgentAction(...args);
  function followAgent(wasBusy) {
    if (!agentBusy()) {
      agentState.polls = 0;
      if (wasBusy) loadAgent(['chat', 'plans', 'runs', 'recommendations']);
      return;
    }
    if (agentPollTimer || (activeTab !== 'agent' && !agentDockOpen) || agentState.polls >= AGENT_POLL_LIMIT) return;
    agentState.polls++;
    agentPollTimer = setTimeout(() => {
      agentPollTimer = null;
      loadAgent(agentState.chat && agentState.chat.chatting ? ['chat'] : ['runs']);
    }, AGENT_POLL_MS);
  }
  // The harness picker belongs only to the separate handoff form.
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
    const dockStateEl = document.getElementById('agent-dock-state');
    if (dockStateEl) dockStateEl.textContent = agentState.error || agentStateText(st);
    const advisorStateEl = document.getElementById('advisor-state');
    if (advisorStateEl) advisorStateEl.textContent = advisorStateText(telemetryData.status && telemetryData.status.advisor_health);
    const unavailable = !enabled || !!(st && st.reason) || agentBusy();
    const feedback = document.getElementById('agent-feedback');
    if (feedback) { feedback.hidden = !agentState.sendError; feedback.textContent = agentState.sendError; }
    document.getElementById('agent-workspace').dataset.agentReady = String(enabled && st.reachable && !st.reason);
    if (agentComposer) {
      agentComposer.classList.toggle('off', !enabled);
      agentComposer.querySelectorAll('textarea, select, input, button').forEach(el => { el.disabled = !enabled; });
      const send = document.getElementById('agent-send');
      send.disabled = unavailable;
      const sendHTML = agentState.sending ? agentSpinnerHTML() + ' Sending…' : (agentBusy() ? agentSpinnerHTML() + ' Working…' : 'Send <span class="agent-send-key" aria-hidden="true">↵</span>');
      if (send.innerHTML !== sendHTML) send.innerHTML = sendHTML;
      agentComposer.setAttribute('aria-busy', String(agentBusy()));
    }
    document.querySelectorAll('.agent-quick').forEach(el => { el.disabled = unavailable; });
    const analyzeBtn = document.getElementById('agent-analyze');
    if (analyzeBtn) analyzeBtn.title = !enabled ? 'Enable the local system agent in Settings' : (st && st.reason) || (agentBusy() ? 'The agent is already working' : 'Review recorded flags and actions with local Ollama');
    const thread = document.getElementById('agent-thread');
    if (thread && st && !enabled) {
      agentState.unreadMessageKeys.clear();
      agentState.reading = {top: 0, follow: true};
      updateAgentJumpLatest(agentState.reading);
      if (thread._saEmpty !== 'off') { thread.innerHTML = agentOffHTML(); thread._saEmpty = 'off'; }
    } else if (thread) {
      const items = agentThreadItems(agentState.chat, st, agentState.runs, agentState);
      const reading = (agentState.restoreReading ? agentState.reading : captureAgentThreadReading()) || agentState.reading;
      const follow = agentState.lastCount === 0 || !reading || reading.follow;
      patchList(thread, items, { key: i => i.key, html: i => i.html, empty: agentEmptyThreadHTML(st) });
      const pending = items.find(item => item.key === 'pending');
      const pendingLabel = thread.querySelector('.agent-pending-label');
      if (pendingLabel && pendingLabel.textContent !== pending.label) pendingLabel.textContent = pending.label;
      const arrivals = agentMessageArrivals(agentState.chat, agentState.seenMessageKeys);
      agentState.seenMessageKeys = arrivals.seen;
      agentState.unreadMessageKeys = agentUnreadMessageKeys(items, arrivals.arrived, agentState.unreadMessageKeys, follow);
      updateAgentJumpLatest(reading);
      if (arrivals.arrived.size && !(agentReducedMotion && agentReducedMotion.matches)) {
        const motion = getComputedStyle(thread);
        const duration = parseFloat(motion.getPropertyValue('--agent-message-enter')) || 160;
        const easing = motion.getPropertyValue('--ease').trim() || 'ease-out';
        items.forEach((item, index) => {
          const node = thread.children[index];
          if (arrivals.arrived.has(item.key) && node && node.animate) {
            node.animate([{ opacity: 0.35, transform: 'translateY(4px)' }, { opacity: 1, transform: 'translateY(0)' }],
              { id: 'agent-message-arrival', duration, easing });
          }
        });
      }
      restoreAgentThreadReading(follow ? {follow: true} : reading);
      agentState.lastCount = items.length;
    }
    const plans = agentState.plans;
    const recommendations = agentPendingRecommendations(agentState.recommendations);
    const recommendationsEl = document.getElementById('agent-recommendations');
    if (recommendationsEl && agentState.recommendations) {
      patchList(recommendationsEl, recommendations, { key: m => m.id, html: m => agentRecommendationHTML(m, st),
        empty: '<div class="agent-queue-empty"><svg class="icon"><use href="#i-shield"/></svg><h4>No actions waiting</h4><p>Choose Analyze activity below the conversation to turn recorded flags and actions into recommendations.</p></div>' });
    }
    const recommendationsBadge = document.getElementById('badge-agent-recommendations');
    if (recommendationsBadge) recommendationsBadge.textContent = recommendations.filter(m => (m.review_state || 'pending') === 'pending').length;
    const plansEl = document.getElementById('agent-plans');
    if (plansEl && plans) {
      patchList(plansEl, plans, { key: p => p.id, html: p => agentPlanHTML(p, st),
        empty: '<p class="agent-history-empty">Saved handoff plans will appear here.</p>' });
    }
    const badge = document.getElementById('badge-agent-plans');
    if (badge) badge.textContent = plans ? plans.length : 0;
    const runsEl = document.getElementById('agent-runs');
    if (runsEl && agentState.runs) {
      const now = Date.now();
      patchList(runsEl, agentState.runs, { key: r => r.id, html: r => agentRunHTML(r, st, now),
        empty: '<p class="agent-history-empty">Completed and running commands will appear here.</p>' });
    }
    const hEl = document.getElementById('agent-harnesses');
    if (hEl) hEl.innerHTML = agentHarnessesHTML(st);
    const sEl = document.getElementById('agent-skills');
    if (sEl) sEl.innerHTML = agentSkillsHTML(st);
  }
  window.saveAgentRequest = async function() {
    const text = agentHandoffInput ? agentHandoffInput.value.trim() : '';
    if (!text) { showToast("Write the request first — it becomes the plan's task", 'info'); return; }
    const workdir = agentHandoffWorkdir.value.trim() || (agentState.status && agentState.status.home) || '';
    try {
      const res = await agentFetch('/agent/plans', { method: 'POST',
        body: { harness: agentHarnessSelect.value, mode: 'terminal', workdir, task: text } });
      agentHandoffInput.value = '';
      showToast(`Saved as plan #${res.plan.id} — dispatch it from Plans`, 'success');
      setAgentPanel('history');
      document.getElementById('agent-plans-panel').open = true;
      loadAgent(['plans']);
    } catch (err) {
      showToast('Not saved: ' + (err.message || err), 'danger');
    }
  };
  window.analyzeAgentActivity = async function(flagIds) {
    if (flagIds && flagIds.length) window.location.hash = 'agent';
    setAgentPanel('queue');
    try {
      await agentFetch('/agent/analyze', { method: 'POST', body: flagIds && flagIds.length ? { flag_ids: flagIds } : {} });
      showToast('Local Ollama is reviewing recorded activity; the result will appear in the queue', 'info');
      loadAgent(['chat']);
    } catch (err) { showToast('Analysis not started: ' + (err.message || err), 'danger'); }
  };
  window.saveAgentRecommendation = async function(messageId) {
    const card = document.querySelector(`#agent-recommendations [data-message="${Number(messageId)}"]`);
    const harness = card && card.querySelector('.agent-recommendation-harness')?.value;
    const workdir = card && card.querySelector('.agent-recommendation-workdir')?.value.trim() || (agentState.status && agentState.status.home);
    if (!harness || !workdir) { showToast('Choose a harness and folder for the saved plan', 'info'); return; }
    try {
      const res = await agentFetch('/agent/plans', { method: 'POST', body: { message_id: messageId, harness, workdir, mode: 'terminal' } });
      showToast(`Saved as plan #${res.plan.id}; no harness was started`, 'success');
      setAgentPanel('history');
      document.getElementById('agent-plans-panel').open = true;
      loadAgent(['recommendations', 'plans']);
    } catch (err) { showToast('Plan not saved: ' + (err.message || err), 'danger'); }
  };
  window.dismissAgentRecommendation = async function(messageId) {
    try {
      await agentFetch('/agent/recommendations', { method: 'POST', body: { message_id: messageId, state: 'dismissed' } });
      loadAgent(['recommendations']);
    } catch (err) { showToast('Recommendation not dismissed: ' + (err.message || err), 'danger'); }
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
      setAgentPanel('history');
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
      detailDrawer.open({ title: s.title, icon: 'doc',
        body: `<div class="panel-body"><p>${escapeHTML(s.summary)}</p><pre class="agent-skill-body">${escapeHTML(s.body)}</pre></div>` });
    } catch (err) {
      showToast("Couldn't load the skill: " + (err.message || err), 'danger');
    }
  };
  if (agentComposer) {
    agentComposer.addEventListener('submit', (e) => { e.preventDefault(); window.sendAgentMessage(); });
    agentInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); window.sendAgentMessage(); }
    });
    agentHarnessSelect.addEventListener('change', () => {
      try { sessionStorage.setItem('sa.agent-harness', agentHarnessSelect.value); } catch { /* private mode */ }
    });
    agentWorkdirInput.addEventListener('change', () => {
      try { sessionStorage.setItem('sa.agent-workdir', agentWorkdirInput.value.trim()); } catch { /* private mode */ }
    });
  }

  // Home groups: markup supplies defaults; saved booleans restore the tab. A panel
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
    document.querySelectorAll('details.home-group').forEach(d => {
      if (typeof saved[d.dataset.group] === 'boolean') d.open = saved[d.dataset.group];
    });
  } catch { /* private mode or corrupt value: retain markup defaults */ }
  document.querySelectorAll('details.home-group').forEach(d => d.addEventListener('toggle', () => {
    persistHomeGroups();
    if (!d.open) return;
    if (d.dataset.group === 'findings') fetchTelemetry();
    PANELS.forEach(([name]) => { if (PANEL_VIEW[name] === 'home:' + d.dataset.group) dirtyPanels.add(name); });
    renderDirty();
  }));

  // switchTab takes any route: a tab, "sessions/<sub>", or an old tab id
  // (menu bar deep link, saved view, stored tab, in-page link) through the
  // alias table. opts.group expands that Home group.
  function switchTab(id, opts = {}) {
    if (protectionContext && !opts.keepProtectionContext) clearProtectionContext();
    const r = resolveConsoleRoute(id);
    // The Agent tab shows the conversation itself: take it back from the dock.
    if (r.tab === 'agent') closeAgentDock();
    const from = activeTab;
    activeTab = r.tab;
    document.body.classList.toggle('agent-page', activeTab === 'agent');
    if (r.tab === 'sessions') activeSub = r.sub;
    if (r.tab === 'protection') activeProtection = r.sub;
    if (r.tab === 'system') activeSystemSub = r.sub;
    if (from === 'home' && activeTab !== 'home' && detailDrawer.selection()) detailDrawer.close();
    document.querySelectorAll('.tab-btn').forEach(b => {
      const on = b.dataset.tab === activeTab;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.tabpanel').forEach(p => { p.hidden = activeTab === 'protection' ? !['tab-egress', 'tab-policy'].includes(p.id) : p.id !== 'tab-' + activeTab; });
    const protectionNav = document.getElementById('protection-nav');
    if (protectionNav) protectionNav.hidden = activeTab !== 'protection';
    document.querySelectorAll('[data-protection-section]').forEach(p => { p.hidden = activeTab !== 'protection' || p.dataset.protectionSection !== activeProtection; });
    document.querySelectorAll('[data-protection-view]').forEach(b => {
      const on = activeTab === 'protection' && b.dataset.protectionView === activeProtection;
      b.classList.toggle('active', on); b.setAttribute('aria-selected', String(on));
    });
    document.querySelectorAll('#tab-sessions .subtab-btn[data-subtab]').forEach(b => {
      const on = b.dataset.subtab === activeSub;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('#tab-sessions .subview').forEach(v => { v.hidden = v.id !== 'sub-' + activeSub; });
    document.querySelectorAll('#tab-system [data-system-subtab]').forEach(b => {
      const on = b.dataset.systemSubtab === activeSystemSub;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', String(on));
    });
    document.querySelectorAll('#tab-system .system-subview').forEach(v => {
      v.hidden = v.dataset.systemView !== activeSystemSub;
    });
    const group = opts.group && document.getElementById('home-' + opts.group);
    if (group && activeTab === 'home' && !group.open) group.open = true;
    const key = routeKey({ tab: activeTab, sub: activeTab === 'protection' ? activeProtection : activeTab === 'system' ? activeSystemSub : activeSub });
    try { sessionStorage.setItem('sa.console-tab', key); } catch { /* private mode */ }
    if (!opts.skipHash && window.history.replaceState) {
      history.replaceState(null, '', location.pathname + location.search + consoleRouteHash({ tab: activeTab, sub: activeTab === 'protection' ? activeProtection : activeTab === 'system' ? activeSystemSub : activeSub }));
    }
    PANELS.forEach(([name]) => { if (panelOnScreen(name)) dirtyPanels.add(name); });
    renderDirty();
    if (activeTab === 'system') worktreeController.activate(activeSystemSub);
    if (activeTab === 'protection' && activeProtection === 'rules') loadPolicy();
    if (activeTab === 'agent' && from !== 'agent') loadAgent();
    const focus = r.focus === 'attention' ? document.getElementById('attention-center') : group;
    if (focus && focus.scrollIntoView) focus.scrollIntoView({ behavior: 'auto', block: 'start' });
  }

  // Grouped primary tabs reopen their last sub-view.
  document.querySelectorAll('.tab-btn').forEach(b =>
    b.addEventListener('click', () => switchTab(b.dataset.tab === 'sessions' ? 'sessions/' + activeSub : b.dataset.tab === 'protection' ? 'protection/' + activeProtection : b.dataset.tab === 'system' ? 'system/' + activeSystemSub : b.dataset.tab)));
  document.querySelectorAll('#tab-sessions .subtab-btn[data-subtab]').forEach(b =>
    b.addEventListener('click', () => switchTab('sessions/' + b.dataset.subtab)));
  document.querySelectorAll('#tab-system [data-system-subtab]').forEach(b =>
    b.addEventListener('click', () => switchTab('system/' + b.dataset.systemSubtab)));

  // Tab badges: the "something needs you here" signal for hidden panels.
  // home, sessions, egress are tab badges; the sessions and processes
  // counts also sit on their sub-view buttons.
  const BADGE_ELS = {
    home: ['tab-badge-home'],
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

  let telemetryRefreshController;
  function telemetryRefreshControllerModule() {
    return telemetryRefreshController ||= createTelemetryRefresh({
      state: {
        get PANELS() { return PANELS; },
        get SLOW_ONLY() { return SLOW_ONLY; },
        get booted() { return booted; },
        set booted(value) { booted = value; },
        get eventHistoryPage() { return eventHistoryPage; },
        set eventHistoryPage(value) { eventHistoryPage = value; },
        get expectedEgressReadGen() { return expectedEgressReadGen; },
        set expectedEgressReadGen(value) { expectedEgressReadGen = value; },
        get firstEventRender() { return firstEventRender; },
        set firstEventRender(value) { firstEventRender = value; },
        get handoffGeneration() { return handoffGeneration; },
        set handoffGeneration(value) { handoffGeneration = value; },
        get lastSnapshotAt() { return lastSnapshotAt; },
        set lastSnapshotAt(value) { lastSnapshotAt = value; },
        get notifyCfgHash() { return notifyCfgHash; },
        set notifyCfgHash(value) { notifyCfgHash = value; },
        get pendingConsoleContext() { return pendingConsoleContext; },
        set pendingConsoleContext(value) { pendingConsoleContext = value; },
        get prevEventKeys() { return prevEventKeys; },
        set prevEventKeys(value) { prevEventKeys = value; },
        get prevUptimeSec() { return prevUptimeSec; },
        set prevUptimeSec(value) { prevUptimeSec = value; },
        get reportHealth() { return reportHealth; },
        get reviewCursor() { return reviewCursor; },
        set reviewCursor(value) { reviewCursor = value; },
        get sessionEnded() { return sessionEnded; },
        set sessionEnded(value) { sessionEnded = value; },
        get telemetryData() { return telemetryData; },
        set telemetryData(value) { telemetryData = value; },
        get telemetryFetchGen() { return telemetryFetchGen; },
        set telemetryFetchGen(value) { telemetryFetchGen = value; },
        get telemetrySlowGen() { return telemetrySlowGen; },
        set telemetrySlowGen(value) { telemetrySlowGen = value; },
        get timelineSession() { return timelineSession; },
        set timelineSession(value) { timelineSession = value; }
      },
      actions: {
        get acceptEventHistoryPage() { return acceptEventHistoryPage; },
        get apiFetch() { return apiFetch; },
        get eventsHistoryScope() { return eventsHistoryScope; },
        get eventsQuery() { return eventsQuery; },
        get failEventHistoryPage() { return failEventHistoryPage; },
        get fillFamilyDrawer() { return detailDrawer.fillFamily; },
        get flagsQuery() { return flagsQuery; },
        get homeGroupOpen() { return homeGroupOpen; },
        get isConsoleReport() { return isConsoleReport; },
        get isEventsFiltered() { return isEventsFiltered; },
        get isFlagsFiltered() { return isFlagsFiltered; },
        get loadSpend() { return loadSpend; },
        get markDirty() { return markDirty; },
        get noteEndpointFailure() { return noteEndpointFailure; },
        get openConsoleContext() { return openConsoleContext; },
        get parseUptimeSec() { return parseUptimeSec; },
        get reconcileRetriage() { return reconcileRetriage; },
        get renderAll() { return renderAll; },
        get renderReportHealth() { return renderReportHealth; },
        get reportFailed() { return reportFailed; },
        get reportSucceeded() { return reportSucceeded; },
        get setConnState() { return setConnState; },
        get showToast() { return showToast; },
        get sparkIngestEvents() { return sparkIngestEvents; },
        get syncHistoryViews() { return syncHistoryViews; },
        get validEventHistoryPage() { return validEventHistoryPage; },
        get window() { return window; }
      }
    });
  }
  function fetchTelemetry(...args) { return telemetryRefreshControllerModule().fetchTelemetry(...args); }
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

  // loadSpend reads the three spend reports from the usage cache; now renders
  // at once (a view the user just chose), else when the panel may.
  let spendControllerController;
  function spendControllerControllerModule() {
    return spendControllerController ||= createSpendController({
      state: {
        get SPEND_BY() { return SPEND_BY; },
        get SPEND_POLLS() { return SPEND_POLLS; },
        get SPEND_POLL_MS() { return SPEND_POLL_MS; },
        get SPEND_SINCE() { return SPEND_SINCE; },
        get SPEND_VIEW_KEY() { return SPEND_VIEW_KEY; },
        get expandedLists() { return expandedLists; },
        get handoffGeneration() { return handoffGeneration; },
        set handoffGeneration(value) { handoffGeneration = value; },
        get reportHealth() { return reportHealth; },
        get sessionEnded() { return sessionEnded; },
        set sessionEnded(value) { sessionEnded = value; },
        get spendBySel() { return spendBySel; },
        get spendDayGen() { return spendDayGen; },
        set spendDayGen(value) { spendDayGen = value; },
        get spendGen() { return spendGen; },
        set spendGen(value) { spendGen = value; },
        get spendPollTimer() { return spendPollTimer; },
        set spendPollTimer(value) { spendPollTimer = value; },
        get spendPolls() { return spendPolls; },
        set spendPolls(value) { spendPolls = value; },
        get spendSinceSel() { return spendSinceSel; },
        get spendView() { return spendView; },
        set spendView(value) { spendView = value; },
        get telemetryData() { return telemetryData; },
        set telemetryData(value) { telemetryData = value; }
      },
      actions: {
        get apiFetch() { return apiFetch; },
        clearTimeout: (...args) => window.clearTimeout(...args),
        get document() { return document; },
        get isConsoleReport() { return isConsoleReport; },
        get loadSpend() { return loadSpend; },
        get markDirty() { return markDirty; },
        get renderNow() { return renderNow; },
        get renderReportHealth() { return renderReportHealth; },
        get reportFailed() { return reportFailed; },
        get reportSucceeded() { return reportSucceeded; },
        get resetSpendDay() { return resetSpendDay; },
        get sessionStorage() { return sessionStorage; },
        setTimeout: (...args) => window.setTimeout(...args),
        get spendCardPath() { return spendCardPath; },
        get spendDayWindow() { return spendDayWindow; },
        get syncSpendDayGuidance() { return syncSpendDayGuidance; },
        get topCostRows() { return topCostRows; }
      }
    });
  }
  function loadSpend(...args) { return spendControllerControllerModule().loadSpend(...args); }
  function resetSpendDay(...args) { return spendControllerControllerModule().resetSpendDay(...args); }
  function loadSpendDay(...args) { return spendControllerControllerModule().loadSpendDay(...args); }
  function selectSpendDay(...args) { return spendControllerControllerModule().selectSpendDay(...args); }
  function expandSpendDayRepositories(...args) { return spendControllerControllerModule().expandSpendDayRepositories(...args); }
  const onSpendView = (...args) => spendControllerControllerModule().onSpendView(...args);
  // Spend card controls: a change saves the view, clears the card and loads
  // the new report.
  const spendBySel = document.getElementById('spend-by');
  const spendSinceSel = document.getElementById('spend-since');
  if (spendBySel) spendBySel.value = spendView.by;
  if (spendSinceSel) spendSinceSel.value = spendView.since;
  syncSpendDayGuidance();
  spendBySel?.addEventListener('change', onSpendView);
  spendSinceSel?.addEventListener('change', onSpendView);

  function handleSpendDayKeydown(event) {
    if (sessionEnded || event.defaultPrevented || event.isComposing
      || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    const current = event.target?.closest?.('button[data-action="select-spend-day"]');
    const bars = current?.closest('.spend-bars');
    if (!bars) return;
    const buttons = Array.from(bars.querySelectorAll('button[data-action="select-spend-day"]'))
      .filter(button => !button.disabled && !button.matches(':disabled') && button.closest('.spend-bars') === bars);
    const index = buttons.indexOf(current);
    if (index < 0) return;
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1
      : Math.max(0, Math.min(buttons.length - 1, index + (event.key === 'ArrowLeft' ? -1 : 1)));
    event.preventDefault();
    // Move focus within the current chart; activation keeps its native meaning.
    if (buttons[next] !== current) buttons[next].focus();
  }
  document.getElementById('spend-card')?.addEventListener('keydown', handleSpendDayKeydown);

  function renderStatus() {
    const chip = document.getElementById('system-status');
    if (!telemetryData.connected) {
      if (chip) chip.className = 'status-chip down';
      document.getElementById('status-text').textContent = connState === 'invalid-response' ? 'Telemetry unavailable' : 'Disconnected';
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
    const flags24h = s.unacted_flags_24h != null
      ? s.unacted_flags_24h
      : unactedLast24h(telemetryData.flags, Date.now()).length;
    setKpi('count-flags', flags24h);
    const fact = document.getElementById('home-findings-fact');
    if (fact) fact.textContent = `${flags24h} in 24 h`;
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
  const endedSessionsOpen = {}; // harness key → ended tail expanded
  const sessionDupOpen = {}; // '<live|ended>|<folded rail row key>' → expanded
  const familyDupOpen = {}; // folded Resources family row key → expanded
  const agentGroupOpen = {};
  const agentTreeOpen = {}; // instance root pid → helper disclosure open
  // cappedList keys the operator expanded ("events", "agents:<harness>",
  // "family-procs:<family key>"); re-renders keep those lists whole.
  const expandedLists = new Set();
  // Findings-history rows ticked for a bulk review, by row key.
  const historySelected = new Set();
  function syncHistoryChecks() {
    document.querySelectorAll('#flags-list .log-check').forEach(c => { c.checked = historySelected.has(c.dataset.rowKey); });
  }

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
    sessionWorkbench.filterChanged();
    sessionWorkbench.render();
    renderAgents();
  }
  function showEndedSessions(origin) {
    const fromDetail = !!origin?.closest('#session-detail');
    harnessFilter.liveOnly = false;
    harnessFilterChanged();
    if (fromDetail) sessionWorkbench.showList();
    const selected = Array.from(document.querySelectorAll('#session-rail [data-action="select-session"]'))
      .find(el => el.dataset.id === sessionWorkbench.selectedSessionId && el.getClientRects().length);
    const target = selected || (liveOnlySwitch?.getClientRects().length ? liveOnlySwitch : null);
    target?.focus({preventScroll: true});
  }
  function clearHarnessFilter(origin) {
    const fromSessions = !!origin?.closest('#session-board-panel');
    const searchId = fromSessions ? 'session-cwd-filter' : origin?.closest('#agents-container') ? 'agent-filter-text' : null;
    harnessFilter.harnesses = {};
    harnessFilter.text = '';
    harnessFilterChanged();
    const panel = fromSessions && document.getElementById('session-board-panel');
    if (panel && panel.dataset.pane !== 'list') sessionWorkbench.showList();
    const search = searchId && document.getElementById(searchId);
    if (search?.isConnected && search.getClientRects().length) search.focus({preventScroll: true});
  }
  syncHarnessFilterControls();
  for (const el of harnessTextInputs) {
    el.addEventListener('input', () => { harnessFilter.text = el.value; harnessFilterChanged(); });
  }
  liveOnlySwitch?.addEventListener('change', () => { harnessFilter.liveOnly = liveOnlySwitch.checked; harnessFilterChanged(); });


  // ---------- act in place ----------
  const stagedWrite = createStagedWrite({
    telemetry: () => telemetryData,
    render: renderNow,
    beginAttentionWrite,
    request: apiFetch
  });
  // posture.groups is the attention queue: map its items, drop empty groups;
  // a dropped item leaves posture.items and needs_you with it.
  function mapAttentionItems(fn) {
    const p = telemetryData.posture;
    if (!p || !p.groups) return;
    telemetryData.posture = mapPostureAttention(p, fn);
  }
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
  // Posture headline: the one-glance answer, plus clickable jump-off points
  // into the panels below (drill-down without leaving the page).

  // Dismissal removes an incident from Needs you while retaining its report.
  // Resolution records the operator's note. Both refresh the saved workflow.
  window.setIncidentStatus = async function(id, status) {
    const body = { id, status };
    if (status === 'resolved') {
      const note = await saPrompt('Resolve this incident. What did you do?', {
        title: 'Resolve incident', okLabel: 'Resolve', danger: false, placeholder: 'rotated the key, removed the file…'
      });
      if (note === null) return; // cancelled
      body.note = note;
    }
    const revert = stagedWrite.stage(['incidents', 'posture'], ['incidents', 'attention', 'posture', 'status'], () => {
      telemetryData.incidents = (telemetryData.incidents || []).map(inc => inc.id !== id ? inc
        : { ...inc, workflow: { ...(inc.workflow || {}), status, ...(body.note ? { resolution_note: body.note } : {}) } });
      mapAttentionItems(it => (it.kind !== 'incident' || it.id !== id ? it : status === 'open' ? { ...it, status } : null));
    });
    await stagedWrite.write(revert, () => stagedWrite.send('POST', '/incidents/status', body), {
      ok: async r => {
        const result = await r.json();
        revert.commit?.();
        if (revert.isCurrent?.() !== false && detailDrawer.isIncidentOpen(id)) {
          const actions = drawerBody.querySelector('.incident-workflow-actions');
          if (actions) actions.innerHTML = incidentWorkflowHTML(id, result.workflow);
        }
        showToast(status === 'resolved' ? 'Incident closure recorded as reported' : 'Incident dismissed from Needs you', 'success');
        cardNote(`#incidents-container [data-action="open-incident"][data-id="${cssq(id)}"]`, '.log-row', 'incidents-container', status);
        fetchTelemetry();
      },
      error: err => showToast('Failed to update incident: ' + err.message, 'danger')
    });
  };

  const incidentRemediationInFlight = new Set();
  window.reportIncidentStep = async function(id, stepId, revision, evidence, status) {
    if (incidentRemediationInFlight.has(id)) return;
    incidentRemediationInFlight.add(id);
    const buttons = Array.from(document.querySelectorAll('[data-action="incident-remediation"]')).filter(button => button.dataset.id === id);
    buttons.forEach(button => { button.disabled = true; });
    try {
      const r = await stagedWrite.send('POST', '/incidents/remediation',
        { id, step_id: stepId, expected_revision: revision, expected_evidence: evidence, status });
      const result = await r.json();
      if (!result.incident || !result.incident.remediation) throw new Error('Saved remediation result unavailable');
      if (detailDrawer.isIncidentOpen(id)) {
        const section = drawerBody.querySelector('.incident-remediation');
        if (section) section.outerHTML = incidentRemediationHTML(id, result.incident.remediation);
      }
      showToast(status === 'reported' ? 'Step recorded as reported; credential verification remains unavailable' : 'Step marked pending', 'success');
      fetchTelemetry();
    } catch (err) {
      showToast('Failed to record remediation: ' + err.message, 'danger');
      fetchTelemetry();
      if (detailDrawer.isIncidentOpen(id)) window.openIncidentReport(id);
    } finally {
      incidentRemediationInFlight.delete(id);
      buttons.forEach(button => { button.disabled = false; });
    }
  };

  // Discuss: the daemon writes the question from the worktree's fresh facts
  // (a repository's, from its cached report) and the local model answers in
  // the conversation, docked beside the page. target is {path} or {repo}.
  async function discussWorktreeTarget(target) {
    try {
      const res = await agentFetch('/agent/worktree', { method: 'POST', body: target });
      if (res && res.message && res.message.id) {
        const chat = agentState.chat || (agentState.chat = { messages: [] });
        agentState.readVersion.chat = (agentState.readVersion.chat || 0) + 1;
        if (!(chat.messages || []).some(m => m.id === res.message.id)) chat.messages = [...(chat.messages || []), res.message];
        chat.chatting = true;
      }
    } catch (err) {
      showToast(err.message || String(err), 'danger');
      return;
    }
    openAgentDock();
  }
  const worktreeSearch = document.getElementById('worktree-search');
  if (worktreeSearch) worktreeSearch.addEventListener('input', () => {
    worktreeController.setWorktreeSearch(worktreeSearch.value);
    renderNow(['worktrees']);
  });

  // Reclaimed chart tooltip: a day's numbers above its column on hover and
  // keyboard focus, value first. The column's label carries the same.
  const reclaimEl = document.getElementById('worktrees-reclaim');
  const reclaimTip = document.getElementById('reclaim-tip');
  function showReclaimTip(col) {
    if (!reclaimTip || !col || !col.dataset.day) return;
    const line = (cls, text) => {
      const el = document.createElement(cls === 'rc-tip-value' ? 'strong' : 'span');
      el.className = cls;
      el.textContent = text;
      return el;
    };
    const [freed, trash] = reclaimDayText(col.dataset.freed, col.dataset.count, col.dataset.trash, col.dataset.trashCount);
    reclaimTip.replaceChildren(
      line('rc-tip-value', freed),
      ...(trash ? [line('rc-tip-line', trash)] : []),
      line('rc-tip-meta', fmtDayKey(col.dataset.day, localDayKey(new Date()), true)));
    reclaimTip.hidden = false;
    const box = reclaimTip.offsetParent ? reclaimTip.offsetParent.getBoundingClientRect() : { left: 0, top: 0, width: window.innerWidth };
    const r = col.getBoundingClientRect();
    const w = reclaimTip.offsetWidth;
    const left = Math.max(8, Math.min(box.width - w - 8, r.left - box.left + r.width / 2 - w / 2));
    reclaimTip.style.setProperty('left', left + 'px');
    reclaimTip.style.setProperty('top', (r.top - box.top - reclaimTip.offsetHeight - 6) + 'px');
  }
  function hideReclaimTip() { if (reclaimTip) reclaimTip.hidden = true; }
  if (reclaimEl) {
    reclaimEl.addEventListener('pointerover', e => showReclaimTip(e.target.closest('.rc-col[data-day]')));
    reclaimEl.addEventListener('pointerleave', hideReclaimTip);
    reclaimEl.addEventListener('focusin', e => showReclaimTip(e.target.closest('.rc-col[data-day]')));
    reclaimEl.addEventListener('focusout', hideReclaimTip);
  }

  const worktreeAddForm = document.getElementById('worktree-add-form');
  if (worktreeAddForm) worktreeAddForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('worktree-add-input');
    const path = (input.value || '').trim();
    if (!path) return;
    if (await worktreeController.addRepo(path)) input.value = '';
  });

  window.addSource = async function() {
    const input = document.getElementById('source-input');
    const value = (input.value || '').trim();
    if (!value) return;
    const revert = stagedWrite.stage(['sources'], ['sources'], () => {
      telemetryData.sources = [...(telemetryData.sources || []), { source: value, origin: 'user' }];
    });
    await stagedWrite.write(revert, () => apiFetch('/firewall/sources', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: value, op: 'add' })
    }), {
      ok: async res => {
        const data = await res.json();
        input.value = '';
        showToast(`Watching ${value} — ${data.registered} secret(s) registered`, 'success');
        cardNote(`#sources-list [data-action="remove-source"][data-source="${cssq(value)}"]`, '.source-item', 'sources-list', 'watching');
        fetchTelemetry();
      },
      failed: async res => showToast('Failed to add source: ' + (await res.text()), 'danger'),
      error: err => showToast('Failed to add source: ' + err, 'danger')
    });
  };

  window.removeSource = async function(source) {
    const revert = stagedWrite.stage(['sources'], ['sources'], () => {
      telemetryData.sources = (telemetryData.sources || []).filter(x => x.source !== source);
    });
    await stagedWrite.write(revert, () => apiFetch('/firewall/sources', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source, op: 'remove' })
    }), {
      ok: () => {
        showToast(`Stopped watching ${source}`, 'info');
        cardNote('', '', 'sources-list', 'stopped watching');
        fetchTelemetry();
      },
      failed: async res => showToast('Failed to remove source: ' + (await res.text()), 'danger'),
      error: err => showToast('Failed to remove source: ' + err, 'danger')
    });
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
  const advisorSig = advisorVerdictSignature;

  function reconcileRetriage() {
    if (!pendingRetriage.size) return;
    const health = telemetryData.connected && telemetryData.status && telemetryData.status.advisor_health;
    for (const [id, p] of pendingRetriage) {
      const f = (telemetryData.flags || []).find(x => x.id === id);
      if (f && advisorSig(f.advisor) !== p.baseline) {
        pendingRetriage.delete(id);
        showToast(`Advisor verdict updated for ${f.rule}`, 'success');
        if (detailDrawer.isFlagOpen(id)) {
          window.openFlagDetail(id, { back: detailDrawer.returnTarget() });
        }
      } else if (Date.now() - p.at > RETRIAGE_TIMEOUT_MS && !advisorRetriageIsActive(health, id)) {
        pendingRetriage.delete(id);
        showToast(health && health.circuit_open
          ? 'Advisor is offline (verdicts paused) — check the local model server'
          : "Advisor hasn't returned a new verdict — check its current status", health && health.circuit_open ? 'danger' : 'info');
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

  // Acknowledge one finding: remove its pending decision while retaining its
  // reviewed facts in history. The rule keeps watching; revert restores both.
  function stageDropFlag(id) {
    return stagedWrite.stage(['flags', 'flagsView', 'posture'], ['flags', 'attention', 'posture', 'chart-flags', 'status', 'tab-badges'], () => {
      telemetryData.flags = (telemetryData.flags || []).filter(x => x.id !== id);
      if (telemetryData.flagsView !== null) telemetryData.flagsView = (telemetryData.flagsView || []).map(x => x.id === id ? reviewedFlag(x) : x);
      mapAttentionItems(it => (it.kind === 'flag' && it.id === id ? null : it));
    });
  }
  window.dismissFlag = async function(id) {
    const revert = stageDropFlag(id);
    await stagedWrite.write(revert, () => stagedWrite.send('POST', '/flags/acknowledge', { flag_id: id }), {
      ok: () => {
        revert.commit?.();
        showToast('Flag dismissed — the rule keeps watching', 'info');
        if (revert.isCurrent?.() !== false && !detailDrawer.selection() && detailDrawer.isFlagOpen(id)) detailDrawer.close();
        cardNote('', '', 'flags-list', 'dismissed');
        fetchTelemetry();
      },
      error: err => showToast(`Failed to dismiss flag: ${err.message || err}`, 'danger')
    });
  };

  // Revision-bound records use their captured revisions; source-only rows
  // keep the legacy acknowledgment batches. Refresh after a partial failure
  // so successful earlier decisions remain visible without retrying a choice.
  window.historyBulkReview = async function() {
    const rows = Array.from(historySelected).map(k => (window.SA.historyRows || new Map()).get(k)).filter(Boolean);
    const ids = [...new Set(rows.flatMap(r => r.flagIds))];
    const reviews = rows.filter(r => r.review).map(r => r.review);
    if (!ids.length && !reviews.length) return;
    const n = rows.length;
    if (!await window.saConfirm(`Mark ${n} finding${n === 1 ? '' : 's'} reviewed? They stay in history; rules keep watching.`,
      { title: 'Mark reviewed', okLabel: 'Mark reviewed', danger: false })) return;
    const revert = stagedWrite.stage(['routine', 'patterns', 'flags', 'flagsView', 'posture'], ['flags', 'attention', 'posture', 'chart-flags', 'status', 'tab-badges'], () => {
      Object.assign(telemetryData, reviewedAfterOptimistic(telemetryData, ids));
    });
    const saved = await stagedWrite.write(revert, async () => {
      for (const review of reviews) {
        const res = await apiFetch('/reviews/decision', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: review.id, revision: review.revision, action: 'acknowledge' })
        });
        if (res.status === 409) {
          reviewDrafts.set(review.id, { action: 'acknowledge', conflict: true });
          throw new Error('Evidence changed. Review the new facts and choose again.');
        }
        if (!res.ok) throw new Error(await res.text());
      }
      for (let i = 0; i < ids.length; i += 500) await stagedWrite.send('POST', '/flags/acknowledge', { flag_ids: ids.slice(i, i + 500) });
      return { ok: true };
    }, {
      ok: () => {
        revert.commit?.();
        historySelected.clear();
        syncHistoryChecks();
        showToast(`Marked ${n} reviewed — the rules keep watching`, 'success');
      },
      error: err => showToast(`Mark reviewed failed: ${err.message || err}`, 'danger')
    });
    if (!saved) {
      await fetchTelemetry();
      markDirty(['flags', 'attention']);
      return;
    }
    fetchTelemetry();
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
    get protectionContext() { return protectionContext; },
    sessionHelpOpen,
    endedSessionsOpen,
    sessionDupOpen,
    familyDupOpen,
    agentGroupOpen,
    agentTreeOpen,
    expanded: expandedLists,
    reviewDrafts,
    get reviewResult() { return reviewResult; },
    get reviewCursor() { return reviewCursor; },
    historySelected,
    historyRows: new Map(),
    harnessFilter,
    reconcileAttention,
    get attentionKey() { return detailDrawer.selection()?.key || ''; },
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
    get worktrees() { return worktreeController.worktreesState; },
    get clutter() { return worktreeController.clutterState; },
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
  const sessionWorkbench = createSessionWorkbench({
    apiFetch, renderNow,
    onSelect(id) {
      if (activeTab === 'sessions' && activeSub === 'board') {
        history.replaceState(null, '', location.pathname + location.search + consoleContextHash({ route: 'sessions', session: id }));
      }
    },
  });
  window.selectSession = sessionWorkbench.selectSession;
  window.setSessionView = sessionWorkbench.setView;
  window.showSessionList = sessionWorkbench.showList;
  window.jumpToLatestSession = sessionWorkbench.jumpToLatest;
  window.showCurrentSessionStatus = sessionWorkbench.showCurrentStatus;
  window.loadEarlierSessionMemory = sessionWorkbench.loadEarlier;
  window.retrySessionTrace = sessionWorkbench.retryTrace;
  window.SA.refreshSessionOverview = sessionWorkbench.refreshCurrent;
  window.SA.renderSessionBoard = sessionWorkbench.render;

  Object.defineProperties(window.SA, {
    postureHealth: { get() { return { lastSnapshotAt, error: reportHealth.failures(['snapshot'])[0]?.error || '' }; } },
    activeTab: { get() { return activeTab; } },
    timelineSession: { get() { return timelineSession; }, set(v) { timelineSession = v; } },
    timelinePids: { get() { return timelinePids; }, set(v) { timelinePids = v; } },
    timelinePidLabel: { get() { return timelinePidLabel; }, set(v) { timelinePidLabel = v; } },
    eventHistoryPage: { get() { return eventHistoryPage; } },
    prevFwStats: { get() { return prevFwStats; }, set(v) { prevFwStats = v; } },
    prevEventKeys: { get() { return prevEventKeys; }, set(v) { prevEventKeys = v; } },
    firstEventRender: { get() { return firstEventRender; }, set(v) { firstEventRender = v; } },
    suppressFreshOnce: { get() { return suppressFreshOnce; }, set(v) { suppressFreshOnce = v; } },
    selectedResourceKey: { get() { return selectedResourceKey; }, set(v) { selectedResourceKey = v; } },
    selectedSessionId: { get() { return sessionWorkbench.selectedSessionId; } },
    sessionTimeline: { get() { return sessionWorkbench.sessionTimeline; } },
    sessionTimelineState: { get() { return sessionWorkbench.sessionTimelineState; } },
    sessionView: { get() { return sessionWorkbench.sessionView; } },
    sessionMemoryPage: { get() { return sessionWorkbench.sessionMemoryPage; } },
    sessionMemoryState: { get() { return sessionWorkbench.sessionMemoryState; } },
    sessionOverview: { get() { return sessionWorkbench.sessionOverview; } },
    sessionOverviewState: { get() { return sessionWorkbench.sessionOverviewState; } },
    sessionOutcomes: { get() { return sessionWorkbench.sessionOutcomes; } },
    sessionOutcomesState: { get() { return sessionWorkbench.sessionOutcomesState; } },
    sessionHooks: { get() { return sessionWorkbench.sessionHooks; } },
    sessionHooksState: { get() { return sessionWorkbench.sessionHooksState; } },
  });

  // Export: copy the session's markdown report. Safari only honours a
  // clipboard write started inside the click, so where ClipboardItem exists
  // the write starts now with the report body still loading.
  window.copySessionReport = function(id) {
    let partial = false;
    const text = apiFetch('/sessions/' + encodeURIComponent(id) + '/report?format=md').then(async r => {
      const body = await r.text();
      if (!r.ok) throw new Error((body || '').trim() || 'HTTP ' + r.status);
      partial = r.headers && r.headers.get('X-Secure-Agent-Report-State') === 'partial';
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
      () => showToast(partial ? 'Partial session report copied — review its evidence and limits' : 'Session report copied (markdown)', partial ? 'warning' : 'success'),
      err => showToast('Export failed: ' + ((err && err.message) || err), 'danger'));
  };
  for (const name of ['openIncidentReport', 'openEndpointDetail', 'openFileDetail', 'openPlanDrawer', 'openFlagDetail', 'openUninspected', 'openFamilyDrawer']) {
    window[name] = (...args) => detailDrawer[name](...args);
  }

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
  const planResponseCache = new Map();
  const instructionRequests = new Map();
  const planPolls = new Map();
  const planSlots = subject => Array.from(document.querySelectorAll('.plan-slot'))
    .filter(el => el.dataset.planSubject === subject);
  function paintPlanSlots(subject, resp) {
    if (resp && resp.flag) planFlagCache.set(resp.flag.id, resp.flag);
    planResponseCache.set(subject, resp);
    planSlots(subject).forEach(el => { el.innerHTML = planHTML(resp, undefined, instructionRequests.get(subject)); });
  }
  window.applyAgentInstruction = async function(subject, revision) {
    const resp = planResponseCache.get(subject);
    const preview = resp?.instruction;
    if (!preview?.ready || preview.applied || preview.revision !== revision || instructionRequests.get(subject)?.busy) return;
    const state = { busy: true, error: '' };
    instructionRequests.set(subject, state);
    paintPlanSlots(subject, resp);
    try {
      const res = await apiFetch('/agent/instructions', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject, revision })
      });
      if (!res.ok) throw new Error((await res.text()).trim() || 'Instruction update failed');
      const result = await res.json();
      if (!result?.applied || result.path !== preview.path || result.instruction !== preview.instruction) throw new Error('The update could not be confirmed; inspect the instruction file before retrying.');
      const current = planResponseCache.get(subject);
      if (current?.instruction?.path === preview.path && current.instruction.instruction === preview.instruction) {
        current.instruction = { ...result, ready: true };
      }
      showToast('Safety rule applied to ' + result.path, 'success');
    } catch (err) {
      state.error = 'Could not confirm the update: ' + (err.message || err);
      const current = planResponseCache.get(subject);
      if (current?.instruction) current.instruction = { ...current.instruction, ready: false, reason: state.error };
      // Refresh the file revision without automatically repeating a write.
      await loadPlanSlot(subject);
    } finally {
      state.busy = false;
      const current = planResponseCache.get(subject);
      if (current) paintPlanSlots(subject, current);
    }
  };
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

  async function openConsoleContext(context, generation) {
    const current = () => !sessionEnded && generation === handoffGeneration;
    if (!current()) return;
    if (context.session) {
      // A saved filter must not hide the record explicitly requested by the
      // operator. Reset only when it would exclude this session.
      const session = (telemetryData.sessions || []).find(s => s.id === context.session);
      const groups = groupSessionsByHarness(telemetryData.sessions || [], [], telemetryData.agents || []);
      if (session && !visibleSessionMembers(applySessionFilters(groups, harnessFilter)).some(s => s.id === session.id)) {
        const group = groups.find(g => visibleSessionMembers([g]).some(s => s.id === session.id));
        if (!sessionMatchesText(session, harnessFilter.text)) harnessFilter.text = '';
        if (group) delete harnessFilter.harnesses[group.key];
        if (session.status === 'ended') harnessFilter.liveOnly = false;
        harnessFilterChanged();
      }
      switchTab('sessions');
      await window.selectSession(context.session);
    } else if (context.route) switchTab(context.route, { skipHash: true });
    if (!current()) return;
    if (context.session && (sessionWorkbench.selectedSessionId !== context.session || activeTab !== 'sessions' || activeSub !== 'board')) return;
    const hash = consoleContextHash(context);
    const returnToSession = () => {
      detailDrawer.close();
      window.filterTimelineToSession(context.session);
      history.replaceState(null, '', location.pathname + location.search + consoleContextHash({ route: 'sessions', session: context.session }));
    };
    const back = context.session ? { label: 'session', reopen: returnToSession } : undefined;
    if (context.flag) window.openFlagDetail(context.flag, { back });
    else if (context.incident) window.openIncidentReport(context.incident, { back });
    else if (context.file) window.openFileDetail(context.file);
    if (context.flag || context.incident || context.file) {
      detailDrawer.afterClose(() => {
        if (location.hash === hash) history.replaceState(null, '', location.pathname + location.search
          + consoleContextHash({ route: context.route, session: context.session }));
      });
    }
    history.replaceState(null, '', location.pathname + location.search + hash);
  }

  // Permissions from one saved decision stay with their result. Reads and
  // confirmations are scoped to this drawer and authentication generation.
  let sessionPermissions = null;
  function currentDecisionPermissions(st) {
    return !!st && st === sessionPermissions && !sessionEnded && !drawer.hidden &&
      detailDrawer.mode() === 'permissions' && st.seq === detailDrawer.seq() && st.auth === handoffGeneration &&
      (st.origin !== 'session' || st.receipt.sessionID === sessionWorkbench.selectedSessionId);
  }
  function renderSessionPermissions(st) {
    const top = drawerBody.scrollTop;
    const focused = drawerBody.contains(document.activeElement) ? document.activeElement : null;
    const partKey = focused?.closest('[data-session-part]')?.dataset.sessionPart;
    const disclosures = new Map(Array.from(drawerBody.querySelectorAll('[data-session-part]'), part =>
      [part.dataset.sessionPart, Array.from(part.querySelectorAll('details'), d => d.open)]));
    patchSessionDetail(drawerBody, 'permissions:' + st.receipt.reviewID, sessionPermissionsHTML(st.receipt, st));
    for (const part of drawerBody.querySelectorAll('[data-session-part]')) {
      const saved = disclosures.get(part.dataset.sessionPart);
      if (saved) Array.from(part.querySelectorAll('details')).forEach((d, i) => { d.open = !!saved[i]; });
      if (partKey === part.dataset.sessionPart && focused && !focused.isConnected) {
        const target = Array.from(part.querySelectorAll('button, summary')).find(el =>
          focused.tagName === 'SUMMARY' ? el.tagName === 'SUMMARY' : el.dataset.action === focused.dataset.action);
        (target || btnDrawerClose)?.focus({ preventScroll: true });
      }
    }
    drawerBody.scrollTop = top;
  }
  window.SA.closeSessionPermissions = () => {
    if (detailDrawer.mode() === 'permissions' && sessionPermissions?.origin === 'session') detailDrawer.close();
  };
  window.SA.invalidateSessionPermissions = () => {
    if (detailDrawer.mode() !== 'permissions' || sessionPermissions?.origin !== 'session') return;
    Object.assign(sessionPermissions, { loading: false, busy: '', error: 'unavailable' });
    renderSessionPermissions(sessionPermissions);
  };
  window.openSessionPermissions = async function(reviewID, sessionID) {
    const receipt = sessionPermissionReceipt(sessionWorkbench.sessionOutcomes, reviewID, sessionID);
    if (sessionID !== sessionWorkbench.selectedSessionId) return;
    await openDecisionPermissions(receipt, 'session', { label: 'session result', reopen: detailDrawer.close });
  };
  window.openReviewResultPermissions = async function() {
    if (!drawer || drawer.hidden || detailDrawer.mode() !== 'review-result') return;
    await openDecisionPermissions(reviewResultPermissionReceipt(detailDrawer.reviewResult()), 'review-result', detailDrawer.back());
  };
  async function openDecisionPermissions(receipt, origin, back) {
    if (!drawer || !receipt || sessionEnded) return;
    detailDrawer.setMode('permissions');
    detailDrawer.setCopyVisible(false);
    detailDrawer.open({ title: 'Decision permissions', icon: 'doc',
      back,
      onClose: () => { if (detailDrawer.mode() === 'permissions') detailDrawer.setMode(null); sessionPermissions = null; } });
    sessionPermissions = { receipt, origin, seq: detailDrawer.seq(), auth: handoffGeneration, rows: null,
      loading: false, error: '', busy: '', mutationError: false, revoked: new Set() };
    btnDrawerClose?.focus({ preventScroll: true });
    await window.refreshSessionPermissions();
  }
  window.refreshSessionPermissions = async function() {
    const st = sessionPermissions;
    if (!currentDecisionPermissions(st) || st.loading || st.busy) return;
    st.loading = true;
    renderSessionPermissions(st);
    try {
      const response = await apiFetch('/decision-scopes');
      if (!response.ok) throw new Error('Permissions unavailable');
      const rows = await response.json();
      const viewRows = decisionPermissionRows(st.receipt, rows);
      if (!currentDecisionPermissions(st)) return;
      Object.assign(st, { rows: viewRows, error: '',
        mutationError: false, readAt: new Date().toISOString() });
    } catch {
      if (!currentDecisionPermissions(st)) return;
      st.error = 'unavailable';
    }
    if (!currentDecisionPermissions(st)) return;
    st.loading = false;
    renderSessionPermissions(st);
    window.saAnnounce(st.error ? 'Permission status unavailable. Last known records retained.' : 'Permission records loaded.');
  };
  window.revokeSessionPermission = async function(id) {
    const st = sessionPermissions;
    if (!currentDecisionPermissions(st) || st.loading || st.busy || st.error || st.mutationError || st.revoked.has(id)) return;
    const row = st.rows?.find(r => r.id === id);
    if (!row?.revoke || !row.record) return;
    const record = row.record;
    st.busy = id;
    const consequence = row.consequence;
    const confirmed = await window.saConfirm(`Revoke this saved scope for ${record.resource_path}${record.destination ? ' → ' + record.destination : ''}? ${consequence} This does not undo previous access or remediate past exposure.`, { title: 'Revoke permission', okLabel: 'Revoke permission' });
    if (!currentDecisionPermissions(st)) return;
    if (!confirmed) { st.busy = ''; renderSessionPermissions(st); return; }
    renderSessionPermissions(st);
    btnDrawerClose?.focus({ preventScroll: true });
    try {
      const response = await apiFetch('/decision-scopes?id=' + encodeURIComponent(id), { method: 'DELETE' });
      if (!response.ok) throw new Error('Revocation unavailable');
      const result = await response.json();
      if (!validScopeRevocation(result, id)) throw new Error('Revocation confirmation unavailable');
      if (!currentDecisionPermissions(st)) return;
      st.revoked.add(id);
      st.busy = '';
      window.saAnnounce('Permission revocation saved. The original decision and remaining risk are retained.');
      await window.refreshSessionPermissions();
    } catch {
      if (!currentDecisionPermissions(st)) return;
      Object.assign(st, { busy: '', mutationError: true });
      renderSessionPermissions(st);
      window.saAnnounce('Revocation confirmation unavailable. Refresh permissions before retrying.');
    }
  };

  const familyByKey = key => ((telemetryData.resources && telemetryData.resources.sessions) || []).find(f => f.key === key);

  // Session investigation return context. Navigation restores reading state;
  // it never replays a decision or process-control action.
  let sessionInvestigation = null;
  let sessionReturnSequence = 0;
  const validSessionReturn = st => !!st && !sessionEnded && st.auth === handoffGeneration && st.session === sessionWorkbench.selectedSessionId;
  function applySessionEventFilters(saved) {
    if (!saved) return;
    Object.assign(filters.events, saved);
    for (const [id, key] of [['event-filter', 'kind'], ['event-window', 'since']]) {
      const control = document.querySelector('#' + id);
      if (control) control.value = filters.events[key];
    }
  }
  function captureSessionReturn(el) {
    if (sessionEnded || activeTab !== 'sessions' || activeSub !== 'board' || !sessionWorkbench.selectedSessionId || !el?.closest('#session-detail')) return null;
    return { id: ++sessionReturnSequence, session: sessionWorkbench.selectedSessionId, view: sessionWorkbench.sessionView, auth: handoffGeneration,
      detailTop: document.querySelector('#session-detail .session-detail-body')?.scrollTop || 0,
      railTop: document.querySelector('#session-rail')?.scrollTop || 0, pageY: window.scrollY || 0,
      opener: el, target: { ...el.dataset },
      scope: { session: timelineSession, pids: timelinePids && [...timelinePids], label: timelinePidLabel,
        events: { ...filters.events }, page: copyEventHistoryPage(eventHistoryPage) } };
  }
  function restoreSessionReturn(st) {
    if (!validSessionReturn(st)) return;
    if (sessionInvestigation?.id === st.id && st.active) {
      st.destination.events = { ...filters.events };
      st.destination.page = copyEventHistoryPage(eventHistoryPage);
    }
    detailDrawer.close();
    if (sessionInvestigation?.id === st.id) sessionInvestigation.active = false;
    sessionWorkbench.restoreView(st.view);
    timelineSession = st.scope.session; timelinePids = st.scope.pids; timelinePidLabel = st.scope.label;
    applySessionEventFilters(st.scope.events);
    syncHistoryViews();
    eventHistoryPage = copyEventHistoryPage(st.scope.page);
    suppressFreshOnce = true;
    renderEvents(); renderFlags(); renderIncidents(); paintScopeBar();
    switchTab('sessions', { skipHash: true });
    renderNow(['sessions']);
    const body = document.querySelector('#session-detail .session-detail-body');
    const rail = document.querySelector('#session-rail');
    if (body) body.scrollTop = st.detailTop;
    if (rail) rail.scrollTop = st.railTop;
    window.scrollTo(0, st.pageY);
    const target = st.opener.isConnected ? st.opener : Array.from(document.querySelectorAll('#session-detail [data-action]'))
      .find(el => Object.entries(st.target).every(([key, value]) => el.dataset[key] === value));
    target?.focus({ preventScroll: true });
    fetchTelemetry({ slow: false });
  }
  function showSessionInvestigation(st) {
    if (!validSessionReturn(st)) return;
    st.active = true;
    timelineSession = st.destination.session;
    timelinePids = st.destination.pids; timelinePidLabel = st.destination.label;
    applySessionEventFilters(st.destination.events);
    syncHistoryViews();
    if (st.destination.page) eventHistoryPage = copyEventHistoryPage(st.destination.page);
    suppressFreshOnce = true;
    renderEvents(); renderFlags(); renderIncidents(); paintScopeBar();
    switchTab(st.destination.route, { group: st.destination.group, skipHash: true });
    document.querySelector('#scope-bar [data-action="session-investigation-return"]')?.focus({ preventScroll: true });
    fetchTelemetry();
  }
  function beginSessionInvestigation(st, destination) {
    if (!validSessionReturn(st)) return false;
    sessionInvestigation = Object.assign(st, { destination: { ...destination, events: { ...filters.events } } });
    const mark = part => ({ ...history.state, saSessionInvestigation: { id: st.id, part } });
    history.replaceState(mark('session'), '', location.pathname + location.search + consoleContextHash({ route: 'sessions', session: st.session }));
    history.pushState(mark('evidence'), '', location.pathname + location.search + consoleRouteHash(resolveConsoleRoute(destination.route)));
    showSessionInvestigation(st);
    return true;
  }
  Object.defineProperty(window.SA, 'sessionInvestigationReturn', { get: () => !!sessionInvestigation?.active && validSessionReturn(sessionInvestigation) });
  window.SA.clearSessionInvestigation = () => {
    sessionInvestigation = null;
    if (detailDrawer.returnTarget()?.sessionReturn) detailDrawer.close();
  };
  window.openSessionFindings = function(id, el) {
    const st = id === sessionWorkbench.selectedSessionId ? captureSessionReturn(el) : null;
    if (beginSessionInvestigation(st, { route: 'home', group: 'findings', session: id, pids: null, label: '' })) return;
    timelineSession = id; timelinePids = null; timelinePidLabel = ''; suppressFreshOnce = true;
    syncHistoryViews();
    paintScopeBar(); switchTab('home', { group: 'findings' }); fetchTelemetry();
  };
  window.openSessionEvents = function(id, el) {
    const st = id === sessionWorkbench.selectedSessionId ? captureSessionReturn(el) : null;
    if (beginSessionInvestigation(st, { route: 'events', session: id, pids: null, label: '' })) return;
    timelineSession = id; timelinePids = null; timelinePidLabel = ''; suppressFreshOnce = true;
    syncHistoryViews();
    paintScopeBar(); switchTab('events'); fetchTelemetry({ slow: false });
  };
  window.openSessionFamilyEvents = (st, pids, label) => beginSessionInvestigation(st,
    { route: 'events', session: null, pids: [...new Set(pids)], label });
  window.returnToSessionInvestigation = function() {
    const st = sessionInvestigation;
    if (!validSessionReturn(st) || !st.active) return;
    const marker = history.state?.saSessionInvestigation;
    if (marker?.id === st.id && marker.part === 'evidence') history.back();
    else {
      restoreSessionReturn(st);
      history.replaceState(null, '', location.pathname + location.search + consoleContextHash({ route: 'sessions', session: st.session }));
    }
  };
  window.addEventListener('popstate', e => {
    const st = sessionInvestigation;
    const marker = e.state?.saSessionInvestigation;
    if (!validSessionReturn(st) || marker?.id !== st.id) {
      window.SA.clearSessionInvestigation(); paintScopeBar();
      if (!sessionEnded) {
        const context = consoleContextFromHash(location.hash);
        if (context.route || context.session) openConsoleContext(context, handoffGeneration);
      }
      return;
    }
    if (marker.part === 'session') restoreSessionReturn(st);
    else if (marker.part === 'evidence') showSessionInvestigation(st);
  });

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
    const revert = stagedWrite.stage(['posture', 'resources'], ['attention', 'posture', 'resources', 'tab-badges'], () => {
      if (!id) return;
      mapAttentionItems(it => (it.kind === 'resource' && it.id === id ? null : it));
      const r = telemetryData.resources;
      if (r && r.control && r.control.pending) {
        telemetryData.resources = { ...r, control: { ...r.control, pending: r.control.pending.filter(x => x.id !== id) } };
      }
    });
    await stagedWrite.write(revert, () => stagedWrite.send('POST', '/resources/control', { id, decision, session_key: sessionKey || '' }), {
      ok: () => {
        revert.commit?.();
        showToast(decision === 'dismiss' ? 'Session kept running for the cooldown window.' : decision === 'resume' ? 'Session resumed.' : 'Intervention applied.', 'success');
        cardNote('', '', activeTab === 'system' && activeSystemSub === 'resources' ? 'resource-board' : 'attention-list', decision === 'dismiss' ? 'kept running' : decision === 'resume' ? 'resumed' : 'applied');
        fetchTelemetry({ slow: true });
      },
      error: err => {
        showToast(`Resource decision failed: ${err}`, 'danger');
        fetchTelemetry({ slow: true });
      }
    });
  };

  window.resolveGuardPrompt = async function(id, verdict, scope, expiry) {
    const action = verdict === 'allow'
      ? (scope === 'always' ? 'allow every future path matched by this rule' : scope === 'session' ? 'allow this file and tool in this session until it ends' : scope === 'exact' ? `allow this file and tool in this workspace for ${expiry === '7d' ? '7 days' : '24 hours'}` : 'allow this request once')
      : (scope === 'always' ? 'deny every future path matched by this rule' : 'deny this request once');
    if (scope !== 'once' && !await saConfirm(`Apply guard decision: ${action}? Executable identity uses its observed path. File approvals do not authorize network access. Revoke under Protection → Rules & permissions.`, { title: 'Guard decision', okLabel: 'Apply' })) return;
    const revert = stagedWrite.stage(['guardPending', 'posture'], ['attention', 'posture', 'tab-badges'], () => {
      telemetryData.guardPending = (telemetryData.guardPending || []).filter(x => x.id !== id);
      mapAttentionItems(it => (it.kind === 'guard' && it.id === id ? null : it));
    });
    await stagedWrite.write(revert, () => stagedWrite.send('POST', '/guard/resolve', { id, verdict, scope, ...(expiry ? {expiry} : {}) }), {
      ok: async res => {
        const receipt = await res.json();
        if (!receipt.resolved) throw new Error('This request is unavailable for that decision. Refresh requests and permissions.');
        revert.commit?.();
        showToast(`Guard decision saved: ${action}.`, 'success');
        cardNote('', '', 'attention-list', verdict === 'allow' ? 'allowed' : 'denied');
        if (sessionWorkbench.selectedSessionId) sessionWorkbench.refresh('overview');
        fetchTelemetry({ slow: false });
      },
      error: err => showToast(`Guard decision failed: ${err}`, 'danger')
    });
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
    detailDrawer.setMode('policy');
    detailDrawer.open({
      title: 'Resource policy editor',
      icon: 'activity',
      variant: 'resource-policy',
      foot: `<button type="button" class="btn btn-ghost" data-action="policy-cancel">Cancel</button>`
        + `<button type="button" class="btn btn-primary" data-action="policy-save">Save and apply</button>`,
      onClose: () => { resourcePolicyDraft = null; detailDrawer.setMode(null); },
    });
    renderResourcePolicyEditor();
    drawerFoot.querySelector('[data-action="policy-cancel"]')?.addEventListener('click', detailDrawer.close);
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
      detailDrawer.close();
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

  async function saveExpectedEgress(episodeId, kind) {
    if (!['destination', 'scope'].includes(kind)) return;
    let row = (telemetryData.egressEpisodes || []).find(e => e.id === episodeId);
    if (!row) {
      try {
        const res = await apiFetch('/egress/episodes');
        if (res.ok) {
          telemetryData.egressEpisodes = (await res.json()).episodes || [];
          row = telemetryData.egressEpisodes.find(e => e.id === episodeId);
        }
      } catch { /* the message below handles a stale or unavailable episode */ }
    }
    if (!row) { showToast('This activity is no longer available for review.', 'warn'); return; }
    const o = row.observed || {};
    const s = o.scope || {};
    if (kind === 'scope' && !o.scope_complete) return;
    const description = kind === 'scope'
      ? `Future destinations for ${s.agent || 'this agent'} running ${s.exe_path || 'unknown executable'} under ${s.harness || 'unknown harness'} in ${s.workspace || 'unknown workspace'} will be quieted as expected egress.`
      : `Connections to ${o.host || 'this destination'}:${o.port || '?'} (${o.protocol || 'unknown protocol'}) from ${s.agent || 'this agent'} will be quieted as expected egress.`;
    if (!await window.saConfirm(`${description} Security flags, guard decisions, and proxy inspection continue.`, {
      title: kind === 'scope' ? 'Expect this activity scope' : 'Expect this destination', okLabel: 'Save expectation', danger: false
    })) return;
    const revert = stagedWrite.stage(['egressEpisodes', 'posture'], ['recurring-egress', 'attention', 'posture', 'status', 'tab-badges'], () => {
      Object.assign(telemetryData, egressAfterExpect(telemetryData, episodeId, kind));
    });
    const saved = await stagedWrite.write(revert, () => apiFetch('/expected-egress', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ episode_id: episodeId, kind })
    }), {
      ok: () => {
        revert.commit?.();
        showToast('Expected connection saved. Security detection remains active.', 'success');
      },
      failed: res => showToast(`Could not save expectation: Error: HTTP ${res.status}`, 'danger'),
      error: err => showToast(`Could not save expectation: ${err}`, 'danger')
    });
    if (saved) await fetchTelemetry({ slow: true });
  }

  async function revokeExpectedEgress(id) {
    if (!await window.saConfirm('Revoke this expected connection? Its future informational egress candidates will appear again.', {
      title: 'Revoke expectation', okLabel: 'Revoke', danger: false
    })) return;
    try {
      const res = await apiFetch(`/expected-egress?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showToast('Expected connection revoked.', 'success');
      await fetchTelemetry({ slow: true });
    } catch (err) { showToast(`Could not revoke expectation: ${err}`, 'danger'); }
  }

  async function assessEgressEpisode(id) {
    try {
      const res = await apiFetch(`/egress/episodes/${encodeURIComponent(id)}/assess`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showToast('Advisor assessment requested.', 'info');
      setTimeout(() => fetchTelemetry({ slow: true }), 5000);
    } catch (err) { showToast(`Could not assess activity: ${err}`, 'danger'); }
  }

  const findingActions = createFindingActions({
    request: apiFetch,
    toast: showToast,
    refetch: fetchTelemetry,
    writes: stagedWrite,
    telemetry: () => telemetryData,
    cardNote,
    cssq,
    loadPolicy,
    flags: {
      find: id => (telemetryData.flags || []).find(x => x.id === id)
        || (telemetryData.flagsView || []).find(x => x.id === id)
        || planFlagCache.get(id),
      drop: stageDropFlag
    },
    drawer: {
      back: detailDrawer.back,
      refill: detailDrawer.refillUninspected,
      refillOpen: detailDrawer.refillUninspectedDrawer,
      closeFlag: id => { if (!detailDrawer.selection() && detailDrawer.isFlagOpen(id)) detailDrawer.close(); }
    }
  });
  for (const name of ['bulkAllowHosts', 'assessHost', 'allowHost', 'openFDASettings', 'muteFlag', 'explainAct', 'routineAct',
    'explainAllowOrg', 'patternAct', 'unmuteFlag', 'promoteVendorKeys', 'promoteRule', 'demoteRule', 'removeAllowlistEntry']) {
    window[name] = (...args) => findingActions[name](...args);
  }

  // Session drill-down: jump from a finding to its durable session.
  // "View session in timeline" (finding cards, Attention): open the session
  // in the Sessions tab — its rail card selected, its memory loaded — and keep
  // Events, Flags and Incidents scoped to it for the Events tab. Selects
  // outright and preserves the chosen Memory/Trace mode.
  window.filterTimelineToSession = async function(sid) {
    timelineSession = sid;
    timelinePids = null;
    timelinePidLabel = '';
    suppressFreshOnce = true;
    syncHistoryViews();
    renderEvents();
    renderFlags();
    renderIncidents();
    paintScopeBar();
    switchTab('sessions');
    fetchTelemetry({ slow: false });
    await window.selectSession(sid);
    if (sessionWorkbench.selectedSessionId !== sid) return;
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
    syncHistoryViews();
    renderEvents();
    renderFlags();
    renderIncidents();
    paintScopeBar();
    switchTab('events');
    fetchTelemetry({ slow: false });
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
    syncHistoryViews();
    renderEvents();
    renderFlags();
    renderIncidents();
    paintScopeBar();
    fetchTelemetry({ slow: false });
  };

  const btnSessionClear = document.getElementById('session-clear');
  if (btnSessionClear) btnSessionClear.addEventListener('click', () => window.clearTimelineSession());
  const btnFlagsSessionClear = document.getElementById('flags-session-clear');
  if (btnFlagsSessionClear) btnFlagsSessionClear.addEventListener('click', () => window.clearTimelineSession());

  // A More menu closes on a choice, a click outside it, or Escape.
  const closeMenus = keep => {
    for (const m of document.querySelectorAll('details.act-more[open]')) if (m !== keep) m.open = false;
  };
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenus(null); });

  // Event delegation: every actionable element carries data-action + data-*
  // attributes and is dispatched here. Values pass through the HTML attribute
  // context ONLY (escapeHTML suffices) — no JS-string context exists at all,
  // which removes the inline-handler injection class structurally rather than
  // by escaping discipline.
  document.addEventListener('click', (e) => {
    const menu = e.target.closest('details.act-more');
    closeMenus(menu && !e.target.closest('.act-menu') ? menu : null);
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const d = el.dataset;
    // Queue drill-downs keep their queue origin; historical openers do not.
    const back = () => {
      if (el.closest('#drawer')) return detailDrawer.back();
      const row = el.closest('#attention-list [data-need-key]');
      if (row && activeTab === 'home') {
        const key = row.dataset.needKey;
        const origin = { key, order: attentionItems().map(it => `${it.kind}:${it.id}`), generation: ++attentionGeneration };
        return { label: 'Needs you', attentionOrigin: origin, reopen: () => selectAttention(key) };
      }
      return detailDrawer.sessionBack(el);
    };
    switch (d.action) {
      case 'toggle-row': {
        e.preventDefault();
        if (!expandedLists.delete(d.key)) expandedLists.add(d.key);
        renderNow(d.key.startsWith('need:') ? ['attention'] : ['flags', 'incidents']);
        break;
      }
      case 'history-select':
        if (el.checked) historySelected.add(d.rowKey); else historySelected.delete(d.rowKey);
        paintHistoryBulk(window.SA);
        break;
      case 'history-select-all':
        historySelected.clear();
        if (el.checked) for (const k of (window.SA.historyRows || new Map()).keys()) historySelected.add(k);
        syncHistoryChecks();
        paintHistoryBulk(window.SA);
        break;
      case 'history-bulk-clear':
        e.preventDefault();
        historySelected.clear();
        syncHistoryChecks();
        paintHistoryBulk(window.SA);
        break;
      case 'history-bulk-review':
        e.preventDefault();
        window.historyBulkReview();
        break;
      case 'expect-egress':
        e.preventDefault();
        saveExpectedEgress(d.episodeId, d.kind);
        break;
      case 'view-egress-expectation':
        e.preventDefault();
        viewEgressExpectation(d.id, d.episodeId);
        break;
      case 'back-egress-context':
        e.preventDefault();
        backToEgressContext();
        break;
      case 'revoke-expected-egress':
        e.preventDefault();
        revokeExpectedEgress(d.id);
        break;
      case 'assess-egress-episode':
        e.preventDefault();
        assessEgressEpisode(d.id);
        break;
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
      case 'worktree-discuss':
        e.preventDefault();
        window.discussWorktree(d.path);
        break;
      case 'agent-dock-close':
        e.preventDefault();
        closeAgentDock(true);
        break;
      case 'agent-dock-expand':
        e.preventDefault();
        switchTab('agent');
        document.getElementById('agent-input')?.focus({ preventScroll: true });
        break;
      case 'worktree-review-trash':
        e.preventDefault();
        window.trashReviewedWorktree(d.path);
        break;
      case 'worktree-advise':
        e.preventDefault();
        window.adviseWorktree(d.path);
        break;
      case 'worktree-advise-all':
        e.preventDefault();
        window.adviseWorktreeGroup(d.repo);
        break;
      case 'worktree-discuss-all':
        e.preventDefault();
        window.discussWorktreeGroup(d.repo);
        break;
      case 'worktree-ask':
        e.preventDefault();
        window.askWorktreeAgent(d.path);
        break;
      case 'worktree-filter':
        worktreeController.setWorktreeFilter(d.state);
        renderNow(['worktrees']);
        break;
      case 'worktree-stale':
        worktreeController.toggleStaleFilter();
        renderNow(['worktrees']);
        break;
      case 'worktrees-rescan':
        worktreeController.loadWorktrees(true);
        worktreeController.loadLedger();
        break;
      case 'worktrees-remove-removable':
        e.preventDefault();
        window.removeAllRemovable();
        break;
      case 'worktrees-history':
        e.preventDefault();
        openHistory();
        break;
      case 'reclaim-day':
        e.preventDefault();
        openHistory(historyState.seq && historyState.day === d.day ? '' : d.day);
        break;
      case 'history-kind':
        historyState.kind = d.kind || '';
        paintHistory();
        break;
      case 'history-day':
        historyState.day = d.day || '';
        paintHistory();
        break;
      case 'removal-toast-close':
        worktreeController.closeRemovalToast();
        break;
      case 'clutter-rescan':
        worktreeController.loadClutter(true);
        break;
      case 'clutter-filter':
        worktreeController.setClutterKind(d.kind);
        renderNow(['clutter']);
        break;
      case 'clutter-more':
        worktreeController.expandClutterProject(d.project);
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
      case 'incident-remediation':
        window.reportIncidentStep(d.id, d.stepId, Number(d.revision), d.evidence, d.status);
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
      case 'apply-agent-instruction':
        e.preventDefault();
        window.applyAgentInstruction(d.subject, d.revision);
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
      case 'session-current':
        window.filterTimelineToSession(d.session).then(() => {
          if (sessionWorkbench.selectedSessionId === d.session) window.showCurrentSessionStatus();
        });
        break;
      case 'hook-repair-check':
        e.preventDefault();
        openHookInspector('repair',d,{back:back() || detailDrawer.returnTarget()});
        break;
      case 'hook-evidence':
        e.preventDefault();
        openHookInspector('evidence',d,{back:back() || detailDrawer.returnTarget()});
        break;
      case 'hook-delivery-inspect':
        e.preventDefault();
        openHookInspector('delivery',d,{back:back() || detailDrawer.returnTarget()});
        break;
      case 'hook-setup':
        e.preventDefault();
        openHookSetup(d.harness,{back:back() || detailDrawer.returnTarget()});
        break;
      case 'session-status':
        window.showCurrentSessionStatus();
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
        const origin = detailDrawer.returnTarget()?.sessionReturn;
        detailDrawer.close();
        if (!window.openSessionFamilyEvents(origin, pids, label)) window.filterTimelineToPids([...new Set(pids)], label);
        break;
      }
      case 'kill-family-orphans':
        e.preventDefault();
        e.stopPropagation();
        window.killFamilyOrphans(d.key);
        break;
      case 'show-more':
        e.preventDefault();
        if (d.key === 'spend' && expandSpendDayRepositories(el)) break;
        expandedLists.add(d.key || '');
        if (d.key === 'events') renderNow(['events']);
        else if (String(d.key).startsWith('agents:')) renderNow(['agents']);
        else if (String(d.key).startsWith('pattern:')) renderNow(['attention', 'flags']);
        else if (d.key === 'history') renderNow(['flags']);
        else if (d.key === 'history-incidents') renderNow(['incidents']);
        else if (d.key === 'spend') renderNow(['spend']);
        else detailDrawer.fillFamily();
        break;
      case 'resource-control':
        e.preventDefault();
        e.stopPropagation();
		window.resolveResourceControl(d.id, d.decision, d.session, d.intervention);
        break;
      case 'guard-resolve':
        e.preventDefault();
        window.resolveGuardPrompt(d.id, d.verdict, d.scope, d.expiry);
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
      case 'session-list':
        window.showSessionList();
        break;
      case 'show-ended-sessions':
        showEndedSessions(el);
        break;
      case 'session-latest':
        window.jumpToLatestSession();
        break;
      case 'session-view':
        window.setSessionView(d.view);
        break;
      case 'memory-earlier':
        window.loadEarlierSessionMemory();
        break;
      case 'memory-retry':
        if (sessionWorkbench.selectedSessionId) sessionWorkbench.refresh('memory');
        break;
      case 'trace-retry':
        window.retrySessionTrace();
        break;
      case 'session-overview-retry':
        if (sessionWorkbench.selectedSessionId) sessionWorkbench.refresh('overview');
        break;
      case 'session-outcomes-retry':
        if (sessionWorkbench.selectedSessionId) sessionWorkbench.refresh('results');
        break;
      case 'session-hooks-retry':
        if (sessionWorkbench.selectedSessionId) sessionWorkbench.refresh('hooks');
        break;
      case 'session-permissions':
        window.openSessionPermissions(d.review, d.session);
        break;
      case 'session-permissions-refresh':
        window.refreshSessionPermissions();
        break;
      case 'session-permission-revoke':
        window.revokeSessionPermission(d.id);
        break;
      case 'session-findings':
        window.openSessionFindings(d.id, el);
        break;
      case 'session-events':
        window.openSessionEvents(d.id, el);
        break;
      case 'event-history-earlier':
      case 'event-history-newer':
      case 'event-history-latest':
        e.preventDefault();
        window.pageSessionEvents(d.action.slice('event-history-'.length));
        break;
      case 'session-investigation-return':
        window.returnToSessionInvestigation();
        break;
      case 'toggle-ended-sessions':
        endedSessionsOpen[d.harness] = !endedSessionsOpen[d.harness];
        sessionWorkbench.render();
        break;
      case 'toggle-session-dup':
        sessionDupOpen[(d.bucket ? d.bucket + '|' : '') + d.key] = el.getAttribute('aria-expanded') !== 'true';
        sessionWorkbench.render();
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
      case 'all-harnesses':
        harnessFilter.harnesses = {};
        harnessFilterChanged();
        break;
      case 'clear-harness-filter':
        clearHarnessFilter(el);
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
      case 'review-decision':
        window.reviewAct(d.id, Number(d.revision), d.decision, d.scope ? {kind:d.scope,...(d.expiry ? {expiry:d.expiry} : {})} : undefined);
        break;
      case 'open-review-result':
        e.preventDefault();
        window.openReviewResult();
        break;
      case 'open-review-result-permissions':
        e.preventDefault();
        window.openReviewResultPermissions();
        break;
      case 'dismiss-review-result':
        e.preventDefault();
        window.dismissReviewResult();
        document.querySelector('.tab-btn[data-tab="home"]')?.focus({ preventScroll: true });
        break;
      case 'revoke-scope':
        window.revokeScope(d.id);
        break;
      case 'review-page':
        window.loadReviewPage(d.after);
        break;
      case 'explain-act':
        if (d.patternKey) window.patternAct(d.patternKey, d.actionId, d.host);
        else window.explainAct(d.flagId, d.actionId, d.host);
        break;
      case 'explain-allow-org':
        window.explainAllowOrg(d.flagId, d.org);
        break;
      case 'routine-act':
        window.routineAct(d.routineKey, d.actionId);
        break;
      case 'retriage':
        window.retriageFlag(d.id);
        break;
      case 'open-flag':
        e.preventDefault();
        window.openFlagDetail(d.id, { back: back() });
        break;
      case 'open-uninspected':
        e.preventDefault();
        window.openUninspected({ back: back() });
        break;
      case 'goto-top':
        e.preventDefault();
        window.scrollTo({ top: 0, behavior: reducedMotion ? 'auto' : 'smooth' });
        break;
      case 'retry-posture':
        fetchTelemetry({ full: true });
        break;
      case 'clear-scope':
        e.preventDefault();
        window.clearTimelineSession();
        break;
      case 'select-spend-day':
        e.preventDefault();
        selectSpendDay(d.day);
        break;
      case 'reset-spend-day':
        e.preventDefault();
        resetSpendDay(true);
        break;
      case 'goto-protection':
        e.preventDefault();
        switchTab('protection/' + d.protectionView);
        break;
      case 'select-attention':
        e.preventDefault();
        selectAttention(d.needKind + ':' + d.needId);
        break;
      case 'goto-tab':
        e.preventDefault();
        switchTab(d.tab, { group: d.group });
        break;
      case 'policy-refresh':
        e.preventDefault();
        loadPolicy();
        break;
      case 'policy-refresh-report':
        e.preventDefault();
        loadPolicy(d.kind);
        break;
      case 'open-config':
        e.preventDefault();
        (async () => {
          try {
            const res = await apiFetch('/ui/open-config', { method: 'POST' });
            if (!res.ok) throw new Error((await res.text()).trim() || String(res.status));
            showToast('Opening the active config file', 'info');
          } catch (err) {
            showToast(`Could not open config: ${err.message || err}`, 'danger');
          }
        })();
        break;
      case 'forget-expected':
        e.preventDefault();
        window.forgetExpected(d.key);
        break;
      case 'agent-refresh':
        e.preventDefault();
        loadAgent();
        break;
      case 'agent-jump-latest':
        e.preventDefault();
        jumpToLatestAgentMessage();
        break;
      case 'agent-panel':
        e.preventDefault();
        setAgentPanel(d.panel, true);
        break;
      case 'agent-close-panel':
        e.preventDefault();
        setAgentPanel('');
        break;
      case 'agent-quick': {
        e.preventDefault();
        const prompt = agentQuickPrompt(d.command);
        if (!prompt || !agentInput || !agentState.status?.enabled || agentState.status.reason || agentBusy()) break;
        agentInput.value = [agentInput.value.trim(), prompt].filter(Boolean).join('\n\n').slice(0, 8000);
        agentInput.focus();
        break;
      }
      case 'agent-analyze':
        e.preventDefault();
        window.analyzeAgentActivity();
        break;
      case 'agent-save-recommendation':
        e.preventDefault();
        window.saveAgentRecommendation(Number(d.message));
        break;
      case 'agent-dismiss-recommendation':
        e.preventDefault();
        window.dismissAgentRecommendation(Number(d.message));
        break;
      case 'agent-clear':
        e.preventDefault();
        window.clearAgentChat();
        break;
      case 'agent-save-plan':
        e.preventDefault();
        window.saveAgentRequest();
        break;
      case 'agent-run-local':
        e.preventDefault();
        window.runLocalAgentAction(Number(d.message));
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
    }
  });

  // The toast host is a top-layer popover shown while it holds a toast.
  function showToastHost(host) {
    if (typeof host.showPopover !== 'function') return;
    try {
      if (host.matches(':popover-open')) host.hidePopover();
      host.showPopover();
    } catch { /* unsupported */ }
  }
  function hideToastHostWhenEmpty(host) {
    if (host.childElementCount) return;
    if (host.classList.contains('toast-host')) {
      host.remove();
    } else if (host.id === 'toast-container' && typeof host.hidePopover === 'function' && host.matches(':popover-open')) {
      try { host.hidePopover(); } catch { /* ok */ }
    }
  }

  function showToast(msg, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = msg;

    // The drawer is ordinary DOM (z-index 200), and the toast container is a
    // top-layer popover — so toasts already paint above an open drawer without
    // the old "append inside the <dialog>" dance that native modals required.
    const host = document.getElementById('toast-container');
    if (!host) return;
    showToastHost(host);

    // A sticky toast (removal progress) stays last in the stack.
    const sticky = host.querySelector('.toast-sticky');
    host.insertBefore(toast, sticky);
    // Keep the stack short: an endpoint-failure burst must not build a toast
    // column taller than the viewport (which pushes the oldest ones off-screen).
    // The sticky toast is never dropped.
    let brief = host.querySelectorAll('.toast:not(.toast-sticky)');
    while (brief.length > (sticky ? 3 : 4)) {
      brief[0].remove();
      brief = host.querySelectorAll('.toast:not(.toast-sticky)');
    }

    setTimeout(() => {
      toast.remove();
      hideToastHostWhenEmpty(host);
    }, 4000);
  }

  // ---------- notification preferences ----------
  // Per-rule overrides over the daemon's default policy (severity >= 3
  // notifies). Each rule gets Default / Always / Never; the menubar reads the
  // same store, so one choice silences both surfaces.
  const NOTIFY_RULES = [
    ['proxy-secret-leak', 'Secret leaving in agent traffic'],
    ['sensitive-read-then-connect', 'Sensitive read near a connection'],
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

  // Notification rules live in Protection → Rules & permissions (the header
  // bell is a link to it); the panel keeps the popover's element ids.
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
  // Testability hook: ?nosse skips the push stream (headless E2E can then
  // use virtual time — a pending SSE response stalls the virtual clock).
  const noSSE = new URLSearchParams(location.search).has('nosse');

  const upsertById = (list, item) => {
    list = list || [];
    const i = list.findIndex(x => x && x.id === item.id);
    if (i >= 0) list[i] = item; else list.unshift(item);
    return list;
  };
  function startLiveUpdates() {
  liveUpdates = createConsoleLiveUpdates({
    refresh: fetchTelemetry,
    streamURL: '/events/stream' + (consoleToken ? '?ct=' + encodeURIComponent(consoleToken) : ''),
    EventSourceImpl: noSSE ? null : window.EventSource,
    // Typed deltas: patch local state and mark only the panels that read the
    // changed slice; the scheduler renders the visible ones.
    handlers: {
      event: (msg) => {
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
          // Trace continues to follow event deltas while visible.
          sessionWorkbench.activity(e);
        } catch { sparkBump(1, 0); /* unparseable frame still counts */ }
        markDirty('events');
      },
      // Patterns and posture come only from /snapshot: a flag frame schedules
      // one reconcile 2 s after the last frame of a burst, so a storm folds
      // into its pattern card instead of standing as rows until the poll.
      flag: (msg) => {
        try {
          const flag = JSON.parse(msg.data);
          telemetryData.flags = upsertById(telemetryData.flags, flag);
          // Unfiltered history receives the delta immediately without losing
          // reviewed rows. Filtered history waits for its scoped response.
          if (!isFlagsFiltered() && telemetryData.flagsView !== null) {
            telemetryData.flagsView = upsertById(telemetryData.flagsView, flag);
          }
        } catch { /* next reconcile repairs */ }
        markDirty('flags', 'attention', 'chart-flags', 'status', 'tab-badges');
      },
      incident: (msg) => {
        // Delta incidents are the bare report (no workflow join); the 30s
        // reconcile supplies workflow state.
        try { telemetryData.incidents = upsertById(telemetryData.incidents, JSON.parse(msg.data)); } catch { /* next reconcile repairs */ }
        markDirty('incidents', 'attention', 'status');
      },
      session: (msg) => {
        try { telemetryData.sessions = upsertById(telemetryData.sessions, JSON.parse(msg.data)); } catch { /* next reconcile repairs */ }
        markDirty('sessions', 'chart-memory', 'tab-badges');
      },
      posture: (msg) => {
        // posture.groups is the attention queue.
        try { telemetryData.posture = JSON.parse(msg.data); } catch { /* next reconcile repairs */ }
        markDirty('posture', 'attention', 'tab-badges');
      },
      review: () => { fetchTelemetry(); }
    }
  });
  liveUpdates.start();
  }
  if (sessionEnded) showSessionEnded();
  else startLiveUpdates();
});
