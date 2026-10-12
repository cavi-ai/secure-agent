// Own the spend controller workflow through explicit state and callbacks.
function createSpendController({ state, actions }) {
  async function loadSpend(now) {
    if (state.sessionEnded) return;
    const gen = ++state.spendGen;
    actions.clearTimeout(state.spendPollTimer);
    state.spendPollTimer = null;
    const cardPath = actions.spendCardPath();
    const cardTZ = Number(new URLSearchParams(cardPath.split('?')[1]).get('tz'));
    state.telemetryData.spendRefresh = { loading: true, delayed: false };
    if (now) actions.renderNow(['spend']); else actions.markDirty('spend');
    const ownsResult = key => !state.sessionEnded && gen === state.spendGen && (key !== 'spend card' || cardPath === actions.spendCardPath());
    const grab = async (key, path) => {
      if (state.sessionEnded) return null;
      try {
        const r = await actions.apiFetch(path);
        if (state.sessionEnded) return null;
        if (!ownsResult(key)) return null;
        if (!r.ok) { actions.reportFailed(key, `HTTP ${r.status}`); return null; }
        const value = await r.json();
        if (!ownsResult(key)) return null;
        if (!actions.isConsoleReport(key, value)) { actions.reportFailed(key, 'Invalid response'); return null; }
        actions.reportSucceeded(key);
        return value;
      } catch {
        if (ownsResult(key)) actions.reportFailed(key, 'Request failed or response unreadable');
        return null;
      }
    };
    const [costs, costsCard, costPlans] = await Promise.all([
      grab('spend', '/costs?since=24h&by=repo&cached=1'),
      grab('spend card', cardPath),
      grab('spend plans', '/costs/plans')
    ]);
    if (state.sessionEnded || gen !== state.spendGen) return;
    if (costs) state.telemetryData.costs = costs;
    if (costPlans) state.telemetryData.costPlans = costPlans;
    if (costsCard && cardPath === actions.spendCardPath()) {
      state.telemetryData.costsCard = costsCard;
      state.telemetryData.costsCardTZ = cardTZ;
      if (state.telemetryData.spendDay) {
        if (!actions.spendDayWindow(state.telemetryData.spendDay, costsCard, cardTZ)) resetSpendDay();
        else loadSpendDay();
      }
    }
    state.telemetryData.spendRefresh = { loading: false,
      delayed: state.reportHealth.failures(['spend', 'spend card', 'spend plans']).length > 0 };
    if (now) actions.renderNow(['spend']); else actions.markDirty('spend');
    if (!state.telemetryData.spendRefresh.delayed && ![state.telemetryData.costs, state.telemetryData.costsCard].some(r => r && r.refreshing)) { state.spendPolls = 0; return; }
    if (state.spendPolls >= state.SPEND_POLLS) return; // the slow cycle keeps asking
    state.spendPolls++;
    state.spendPollTimer = actions.setTimeout(() => loadSpend(false), state.SPEND_POLL_MS);
  }

  function resetSpendDay(focus = false) {
    const day = state.telemetryData.spendDay;
    state.spendDayGen++;
    state.telemetryData.spendDay = '';
    state.telemetryData.spendDayReport = null;
    state.telemetryData.spendDayRefresh = {};
    actions.renderNow(['spend']);
    if (focus) Array.from(actions.document.querySelectorAll('[data-action="select-spend-day"]')).find(button => button.dataset.day === day)?.focus({ preventScroll: true });
  }
  async function loadSpendDay() {
    const day = state.telemetryData.spendDay;
    const range = actions.spendDayWindow(day, state.telemetryData.costsCard, state.telemetryData.costsCardTZ);
    if (!range || state.sessionEnded) return;
    const gen = ++state.spendDayGen, auth = state.handoffGeneration;
    const owns = () => !state.sessionEnded && auth === state.handoffGeneration && gen === state.spendDayGen && day === state.telemetryData.spendDay;
    const params = new URLSearchParams({ since: range.since, until: range.until, by: 'repo', tz: String(range.tz), cached: '1' });
    state.telemetryData.spendDayRefresh = { loading: true };
    actions.renderNow(['spend']);
    try {
      const res = await actions.apiFetch('/costs?' + params);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const report = await res.json();
      if (!owns()) return;
      if (!actions.isConsoleReport('spend card', report)) throw new Error('Invalid usage response');
      if (report.by !== 'repo' || Date.parse(report.since) !== Date.parse(range.since) || Date.parse(report.until) !== Date.parse(range.until)) throw new Error('Usage response does not match the selected day');
      state.telemetryData.spendDayReport = report;
      state.telemetryData.spendDayRefresh = { loading: false, delayed: !!report.refreshing };
    } catch (err) {
      if (!owns()) return;
      state.telemetryData.spendDayRefresh = { loading: false, delayed: true, error: 'Could not load this day: ' + (err.message || err) };
    }
    if (owns()) actions.renderNow(['spend']);
  }
  function selectSpendDay(day) {
    if (!actions.spendDayWindow(day, state.telemetryData.costsCard, state.telemetryData.costsCardTZ)) return;
    state.telemetryData.spendDay = day;
    state.telemetryData.spendDayReport = null;
    loadSpendDay();
  }

  function expandSpendDayRepositories(control) {
    const inspector = control.closest('.spend-day-inspector');
    if (!inspector) return false;
    const shown = new Set(Array.from(inspector.querySelectorAll('[data-spend-repo]'), node => node.dataset.spendRepo));
    const rows = state.telemetryData.spendDayReport?.rows || [];
    const next = actions.topCostRows({ rows }, rows.length).find(row => !shown.has(String(row.key)));
    state.expandedLists.add('spend');
    actions.renderNow(['spend']);
    const target = next && Array.from(inspector.querySelectorAll('[data-spend-repo]')).find(node => node.dataset.spendRepo === String(next.key));
    // Explicit expansion moves to the first newly revealed repository. Native
    // focus supplies ordinary visibility; background rendering never scrolls.
    (target || inspector.querySelector('[data-action="reset-spend-day"]'))?.focus();
    return true;
  }


  const onSpendView = () => {
    const by = state.spendBySel && state.spendBySel.value, since = state.spendSinceSel && state.spendSinceSel.value;
    state.spendView = { by: state.SPEND_BY.includes(by) ? by : 'repo', since: state.SPEND_SINCE.includes(since) ? since : '24h' };
    try { actions.sessionStorage.setItem(state.SPEND_VIEW_KEY, JSON.stringify(state.spendView)); } catch { /* private mode */ }
    actions.syncSpendDayGuidance();
    actions.resetSpendDay();
    state.telemetryData.costsCard = null;
    state.reportHealth.reset('spend card'); // The new query has no retained card yet.
    actions.renderReportHealth();
    state.spendPolls = 0;
    actions.renderNow(['spend']);
    actions.loadSpend(true);
  };

  return { loadSpend, resetSpendDay, loadSpendDay, selectSpendDay, expandSpendDayRepositories, onSpendView };
}
