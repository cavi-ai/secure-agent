// Own the history controller workflow through explicit state and callbacks.
function createHistoryController({ state, actions }) {
  function sinceParam(v) {
    const ms = { '1h': 3600e3, '24h': 86400e3, '7d': 604800e3 }[v];
    return ms ? new Date(Date.now() - ms).toISOString() : '';
  }
  function isFlagsFiltered() {
    const f = state.filters.flags;
    return f.agent !== 'all' || f.rule !== 'all' || f.minsev !== 'all' || f.since !== 'all';
  }
  function isEventsFiltered() {
    const f = state.filters.events;
    return !!state.timelineSession || f.kind !== 'all' || f.since !== 'all';
  }

  function eventsHistoryScope() {
    return JSON.stringify({ ...state.filters.events, session: state.timelineSession || '' });
  }
  function syncHistoryViews() {
    const changed = [];
    for (const [name, filtered] of [['flags', actions.isFlagsFiltered()], ['events', actions.isEventsFiltered()]]) {
      const requested = filtered || (name === 'flags' && actions.homeGroupOpen('findings'));
      const scope = requested ? (name === 'events' ? eventsHistoryScope() : JSON.stringify(state.filters[name])) : null;
      const view = name + 'View';
      if (scope !== state.historyScopes[name]) {
        state.historyScopes[name] = scope;
        if (name === 'events') state.eventHistoryPage = actions.createEventHistoryPage(sinceParam(state.filters.events.since));
        state.telemetryData[view] = requested ? null : state.telemetryData[name];
        state.reportHealth.reset(name);
        state.failedEndpoints.delete(name);
        changed.push(name);
      } else if (!requested) state.telemetryData[view] = state.telemetryData[name];
    }
    if (changed.length) {
      actions.renderReportHealth();
      actions.markDirty(...changed, 'tab-badges');
    }
  }

  function flagsQuery() {
    const f = state.filters.flags, p = new URLSearchParams();
    if (f.agent !== 'all') p.set('agent', f.agent);
    if (f.rule !== 'all') p.set('rule', f.rule);
    if (f.minsev !== 'all') p.set('min_severity', f.minsev);
    const since = sinceParam(f.since);
    if (since) p.set('since', since);
    p.set('limit', '200');
    return '/flags?' + p.toString();
  }
  function eventsQuery() {
    const f = state.filters.events, p = new URLSearchParams();
    if (state.timelineSession) p.set('session_id', state.timelineSession);
    if (f.kind !== 'all') p.set('kind', f.kind);
    const since = state.timelineSession ? state.eventHistoryPage.since || sinceParam(f.since) : sinceParam(f.since);
    if (since) p.set('since', since);
    p.set('limit', '200');
    if (state.timelineSession) {
      p.set('page', '1');
      const cursor = state.eventHistoryPage.pending?.cursor ?? state.eventHistoryPage.cursor;
      if (cursor) p.set('before', cursor);
    }
    return '/events?' + p.toString();
  }

  async function pageSessionEvents(direction) {
    const page = state.eventHistoryPage;
    if (state.sessionEnded || !state.timelineSession || !actions.requestEventHistoryPage(state.eventHistoryPage, direction)) return;
    actions.suppressFresh();
    actions.renderEvents();
    await actions.fetchTelemetry({ slow: false });
    if (!state.sessionEnded && page === state.eventHistoryPage) {
      actions.suppressFresh();
      actions.renderNow(['events']);
    }
  };

  function wireFilter(id, obj, key) {
    const el = actions.document.getElementById(id);
    if (el) el.addEventListener('change', () => { obj[key] = el.value; actions.suppressFresh(); actions.fetchTelemetry(); });
  }
  function bindFilters() {
  wireFilter('event-filter', state.filters.events, 'kind');
  wireFilter('event-window', state.filters.events, 'since');
  wireFilter('flags-agent', state.filters.flags, 'agent');
  wireFilter('flags-rule', state.filters.flags, 'rule');
  wireFilter('flags-severity', state.filters.flags, 'minsev');
  wireFilter('flags-window', state.filters.flags, 'since');
  }


  function applyView(name) {
    const view = actions.loadViews().find(v => v.name === name);
    if (!view) return;
    Object.assign(state.filters.flags, view.flags || {});
    Object.assign(state.filters.events, view.events || {});
    const search = actions.document.getElementById('global-search');
    if (search) search.value = view.search || '';
    actions.syncFilterControls();
    const pop = actions.document.getElementById('views-pop');
    if (pop) pop.hidden = true;
    if (view.tab && actions.isConsoleRoute(view.tab)) actions.switchTab(view.tab);
    actions.suppressFresh();
    actions.fetchTelemetry();
    actions.showToast(`View applied: ${name}`, 'info');
  };

  return { sinceParam, isFlagsFiltered, isEventsFiltered, eventsHistoryScope, syncHistoryViews, flagsQuery, eventsQuery, pageSessionEvents, wireFilter, applyView, bindFilters };
}
