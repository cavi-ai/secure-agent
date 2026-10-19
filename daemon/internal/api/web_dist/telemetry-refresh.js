// Own the telemetry refresh workflow: it publishes into the telemetry store
// and reaches the rest of the console through explicit state and callbacks.
function createTelemetryRefresh({ store, state, actions }) {
  const data = store.data;
  async function fetchTelemetry(opts) {
    // The shared request gate handles credential rejection. Other failures mark that report stale
    // or unavailable; snapshot failure also changes the connection status.
    // A failed endpoint NEVER overwrites the panel's last good data.
    if (state.sessionEnded) return;
    const slow = !opts || opts.slow !== false;
    const ticket = store.beginRefresh(slow);
    actions.syncHistoryViews();
    const current = () => !state.sessionEnded && ticket.current();
    const currentSlow = () => !state.sessionEnded && ticket.currentSlow();
    let changedSlow = false;
    let changedResources = false;
    const obsolete = () => {
      if (current()) return false;
      if (!state.sessionEnded && changedSlow) {
        actions.markDirty(...state.PANELS.map(p => p[0]).filter(n => state.SLOW_ONLY.has(n)));
        if (changedResources) actions.fillFamilyDrawer();
      }
      return true;
    };
    const grab = async (key, path, ownsResult = current) => {
      if (state.sessionEnded) return null;
      try {
        const r = await actions.apiFetch(path);
        if (state.sessionEnded) return null;
        if (!ownsResult()) return null;
        if (!r.ok) { actions.noteEndpointFailure(key); actions.reportFailed(key, `HTTP ${r.status}`); return null; }
        const value = await r.json();
        if (!ownsResult()) return null;
        if (!actions.isConsoleReport(key, value)) { actions.reportFailed(key, 'Invalid response'); return null; }
        if (key !== 'snapshot') actions.reportSucceeded(key);
        return value;
      } catch {
        if (ownsResult()) actions.reportFailed(key, 'Request failed or response unreadable');
        return null;
      }
    };

    if (slow) actions.loadSpend(); // beside this cycle: its reports never hold the first render
    const requests = [grab('snapshot', '/snapshot'), grab('guard decisions', '/guard/pending')];
    if (slow) requests.push(grab('resources', '/resources', currentSlow));
    const reviewQueryCursor = state.reviewCursor;
    if (reviewQueryCursor) requests.push(grab('reviews', '/reviews?limit=100&after=' + encodeURIComponent(reviewQueryCursor), () => current() && state.reviewCursor === reviewQueryCursor).then(page => { if (page) data.reviews = page; }));
    const [snap, guardPending, resources] = await Promise.all(requests);
    if (state.sessionEnded) return;
    if (resources && currentSlow()) {
      data.resources = resources;
      changedResources = changedSlow = true;
    }
    if (current()) {
      if (guardPending) data.guardPending = guardPending;
      if (snap) {
        const uptime = snap.status ? actions.parseUptimeSec(snap.status.uptime) : 0;
        if (store.applySnapshot(snap, { uptime, keepReviews: !!state.reviewCursor })) {
          actions.showToast('Daemon restarted — reconnected to the new instance', 'info');
          actions.resetEventFreshness();
        }
        // Clear the snapshot failure only after its data has been published.
        actions.reportSucceeded('snapshot');
      }
    }

    if (currentSlow()) {
      const grabSlow = (key, path) => grab(key, path, currentSlow);
      const [fleet, audit, sources, rollup, uninspected, notifyCfg, allowlist, episodes, egressEpisodes, expectedEgress] = await Promise.all([
        grabSlow('fleet', '/fleet'),
        grabSlow('audit', '/audit?limit=50'),
        grabSlow('firewall sources', '/firewall/sources'),
        grabSlow('activity rollup', '/stats/rollup?hours=168'),
        grabSlow('uninspected egress', '/egress/uninspected?hours=24&limit=200'),
        grabSlow('notification rules', '/notify/rules'),
        grabSlow('allowlist', '/allowlist'),
        grabSlow('resource episodes', '/resources/episodes'),
        grabSlow('recurring egress', '/egress/episodes'),
        grabSlow('expected egress', '/expected-egress')
      ]);
      if (state.sessionEnded) return;
      if (currentSlow()) {
        changedSlow = true;
        // A reconcile while the operator is typing a workspace path must not
        // dirty (and re-render) the notify panel unless the served config
        // actually changed — a stable hash, not the poll cadence, decides.
        const notifyChanged = store.applySlowReports({ fleet, audit, sources, rollup, uninspected, notifyCfg, allowlist,
          episodes, egressEpisodes, expectedEgress }, ticket.ownsExpectedEgress());
        if (notifyChanged) actions.markDirty('notify');
      }
    }

    if (obsolete()) return;
    actions.syncHistoryViews();
    actions.sparkIngestEvents(data.events);
    if (actions.isFlagsFiltered() || actions.homeGroupOpen('findings')) {
      const v = await grab('flags', actions.flagsQuery());
      if (obsolete()) return;
      if (v) data.flagsView = v;
    }
    if (actions.isEventsFiltered()) {
      const scope = actions.eventsHistoryScope();
      const page = state.eventHistoryPage;
      const cursor = page.pending?.cursor ?? page.cursor;
      const session = state.timelineSession;
      page.loading = true;
      const ownsPage = () => current() && scope === actions.eventsHistoryScope() && page === state.eventHistoryPage
        && cursor === (page.pending?.cursor ?? page.cursor);
      const v = await grab('events', actions.eventsQuery(), ownsPage);
      if (obsolete()) return;
      if (ownsPage()) {
        if (v && (Array.isArray(v) || actions.validEventHistoryPage(v, session))) {
          data.eventsView = session ? actions.acceptEventHistoryPage(page, v) : v;
          page.loading = false;
        } else {
          if (v) actions.reportFailed('events', 'Event page does not match this session');
          actions.failEventHistoryPage(page);
        }
      }
    }

    actions.renderReportHealth(); // Filter changes can hide a failed filtered report.
    data.connected = !!(snap && snap.status);
    actions.reconcileRetriage();

    const invalidSnapshot = state.reportHealth.failures(['snapshot']).some(report => report.error === 'Invalid response');
    actions.setConnState(data.connected ? 'ok' : invalidSnapshot ? 'invalid-response' : 'unreachable');

    if (!state.booted || (opts && opts.full)) actions.renderAll();
    // 'notify' is excluded here: it dirties itself above, only when its
    // fetched config actually changed, so an unrelated poll tick never
    // erases an in-progress workspace-scope edit.
    else actions.markDirty(...state.PANELS.map(p => p[0]).filter(n => (slow || !state.SLOW_ONLY.has(n)) && n !== 'notify'));
    if (resources) actions.fillFamilyDrawer();
    if (actions.window.SA && actions.window.SA.refreshSessionOverview) actions.window.SA.refreshSessionOverview(!!(opts && opts.full));
    // Apply once, only after authenticated telemetry succeeds. A newer
    // credential handoff invalidates an opener awaiting session data.
    if (snap && state.pendingConsoleContext && current()) {
      const context = state.pendingConsoleContext;
      state.pendingConsoleContext = null;
      await actions.openConsoleContext(context, state.handoffGeneration);
    }
  }


  return { fetchTelemetry };
}
