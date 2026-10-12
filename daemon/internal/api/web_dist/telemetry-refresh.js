// Own the telemetry refresh workflow through explicit state and callbacks.
function createTelemetryRefresh({ state, actions }) {
  async function fetchTelemetry(opts) {
    // The shared request gate handles credential rejection. Other failures mark that report stale
    // or unavailable; snapshot failure also changes the connection status.
    // A failed endpoint NEVER overwrites the panel's last good data.
    if (state.sessionEnded) return;
    const slow = !opts || opts.slow !== false;
    const gen = ++state.telemetryFetchGen;
    const slowGen = slow ? ++state.telemetrySlowGen : 0;
    const expectedReadGen = slow ? ++state.expectedEgressReadGen : 0;
    actions.syncHistoryViews();
    const current = () => !state.sessionEnded && gen === state.telemetryFetchGen;
    const currentSlow = () => !state.sessionEnded && slow && slowGen === state.telemetrySlowGen;
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
    if (reviewQueryCursor) requests.push(grab('reviews', '/reviews?limit=100&after=' + encodeURIComponent(reviewQueryCursor), () => current() && state.reviewCursor === reviewQueryCursor).then(page => { if (page) state.telemetryData.reviews = page; }));
    const [snap, guardPending, resources] = await Promise.all(requests);
    if (state.sessionEnded) return;
    if (resources && currentSlow()) {
      state.telemetryData.resources = resources;
      changedResources = changedSlow = true;
    }
    if (current()) {
      if (guardPending) state.telemetryData.guardPending = guardPending || [];
      if (snap) {
        state.lastSnapshotAt = Date.now();
        const status = snap.status;
        if (status) {
          const up = actions.parseUptimeSec(status.uptime);
          if (state.prevUptimeSec > 0 && up < state.prevUptimeSec - 5) {
            actions.showToast('Daemon restarted — reconnected to the new instance', 'info');
            state.prevEventKeys = new Set();
            state.firstEventRender = true;
          }
          state.prevUptimeSec = up;
          state.telemetryData.status = status;
        }
        if (snap.flags) state.telemetryData.flags = (snap.flags || []).filter(f => !f.acknowledged);
        if (snap.reviews && !state.reviewCursor) state.telemetryData.reviews = snap.reviews;
        if (snap.patterns) state.telemetryData.patterns = snap.patterns || [];
        if (snap.routine) state.telemetryData.routine = snap.routine || [];
        if (snap.incidents) state.telemetryData.incidents = snap.incidents || [];
        if (snap.events) state.telemetryData.events = snap.events || [];
        if (snap.posture) state.telemetryData.posture = snap.posture;
        if (snap.suggestions) state.telemetryData.suggestions = snap.suggestions || [];
        if (snap.mutes) state.telemetryData.mutes = snap.mutes || [];
        if (snap.sessions) state.telemetryData.sessions = snap.sessions || [];
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
        if (fleet) state.telemetryData.fleet = fleet || [];
        if (audit) state.telemetryData.audit = audit || [];
        if (sources) state.telemetryData.sources = sources || [];
        if (rollup) state.telemetryData.rollup = rollup || [];
        if (uninspected) state.telemetryData.uninspected = uninspected || [];
        if (episodes) state.telemetryData.episodes = episodes || [];
        if (egressEpisodes) state.telemetryData.egressEpisodes = egressEpisodes.episodes || [];
        if (expectedEgress && expectedReadGen === state.expectedEgressReadGen) state.telemetryData.expectedEgress = expectedEgress.rules || [];
        if (notifyCfg) {
          // A reconcile while the operator is typing a workspace path must not
          // dirty (and re-render) the notify panel unless the served config
          // actually changed — a stable hash, not the poll cadence, decides.
          const h = JSON.stringify(notifyCfg);
          if (h !== state.notifyCfgHash) { state.notifyCfgHash = h; state.telemetryData.notifyCfg = notifyCfg; actions.markDirty('notify'); }
        }
        if (allowlist) state.telemetryData.allowlist = allowlist || [];
      }
    }

    if (obsolete()) return;
    actions.syncHistoryViews();
    actions.sparkIngestEvents(state.telemetryData.events);
    if (actions.isFlagsFiltered() || actions.homeGroupOpen('findings')) {
      const v = await grab('flags', actions.flagsQuery());
      if (obsolete()) return;
      if (v) state.telemetryData.flagsView = v || [];
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
          state.telemetryData.eventsView = session ? actions.acceptEventHistoryPage(page, v) : v;
          page.loading = false;
        } else {
          if (v) actions.reportFailed('events', 'Event page does not match this session');
          actions.failEventHistoryPage(page);
        }
      }
    }

    actions.renderReportHealth(); // Filter changes can hide a failed filtered report.
    state.telemetryData.connected = !!(snap && snap.status);
    actions.reconcileRetriage();

    const invalidSnapshot = state.reportHealth.failures(['snapshot']).some(report => report.error === 'Invalid response');
    actions.setConnState(state.telemetryData.connected ? 'ok' : invalidSnapshot ? 'invalid-response' : 'unreachable');

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
