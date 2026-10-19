// Own the console lifecycle workflow through explicit state and callbacks.
function createConsoleLifecycle({ store, state, actions }) {
  function noteEndpointFailure(key) {
    if (state.failedEndpoints.has(key)) return;
    state.failedEndpoints.add(key);
    if (key === 'snapshot' && hasSnapshotHeadline()) return;
    actions.showToast(`Couldn't load ${key} — will keep retrying`, 'danger');
  }

  function hasSnapshotHeadline() {
    const banner = actions.document.getElementById('posture-banner');
    return !!(banner && !banner.hidden && actions.document.getElementById('posture-health'));
  }
  function renderSnapshotHealth() {
    if (state.sessionEnded || !actions.window.SA || !hasSnapshotHeadline()) return;
    actions.renderPosture();
    paintTabsPosture();
  }
  function renderReportHealth() {
    if (state.sessionEnded) return;
    const snapshotInHeadline = hasSnapshotHeadline() && !actions.document.getElementById('posture-health').hidden;
    actions.document.querySelectorAll('[data-reports]').forEach(el => {
      const keys = el.dataset.reports.split('|').filter(key =>
        !['spend', 'spend card', 'spend plans'].includes(key)
        && (key !== 'snapshot' || !snapshotInHeadline)
        && (key !== 'flags' || actions.isFlagsFiltered() || actions.homeGroupOpen('findings')) && (key !== 'events' || actions.isEventsFiltered()));
      const failures = state.reportHealth.failures(keys);
      const text = actions.consoleReportHealthText(failures);
      if (el.textContent !== text) el.textContent = text;
      el.hidden = failures.length === 0;
    });
  }
  function reportSucceeded(key) {
    state.reportHealth.success(key);
    state.failedEndpoints.delete(key);
    if (key === 'snapshot') actions.renderSnapshotHealth();
    actions.renderReportHealth();
  }
  function reportFailed(key, reason) {
    state.reportHealth.failure(key, reason);
    if (key === 'snapshot') actions.renderSnapshotHealth();
    actions.renderReportHealth();
  }


  function endSession() {
    state.consoleToken = '';
    state.consoleAuth.replaceToken('');
    try { actions.sessionStorage.removeItem(state.SS_TOKEN_KEY); } catch { /* private mode */ }
    if (state.sessionEnded) return;
    state.sessionEnded = true;
    clearProtectionContext();
    actions.resetPolicyState();
    state.reviewResult = null;
    actions.clearGuardResult?.();
    state.reviewResultSeq++;
    if (state.drawerMode === 'review-result' || state.drawerMode === 'permissions') actions.closeDrawer();
    state.drawerReviewResult = null;
    if (state.cancelDialog) state.cancelDialog();
    actions.clearInterval(state.sparkTimer);
    actions.clearTimeout(state.spendPollTimer);
    state.spendPollTimer = null;
    state.spendDayGen++;
    state.spendGen++; // invalidate spend responses already in flight
    state.sessionWorkbench.invalidate();
    state.eventHistoryPage = actions.createEventHistoryPage();
    actions.window.SA.invalidateSessionPermissions?.();
    actions.window.SA.clearSessionInvestigation?.();
    if (state.liveUpdates) state.liveUpdates.stop();
    actions.showSessionEnded();
  }


  function clearProtectionContext() {
    if (!state.protectionContext) return;
    state.protectionContext = null;
    state.protectionContextGeneration++;
    actions.markDirty('expected-egress', 'recurring-egress');
  }

  function focusProtectionContext(context) {
    const rules = context.phase === 'rules';
    const container = actions.document.getElementById(rules ? 'expected-egress-container' : 'recurring-egress-container');
    const attr = rules ? 'expectedEgressRule' : 'egressEpisodeId';
    const id = rules ? context.ruleId : context.episodeId;
    const target = [...(container?.querySelectorAll(rules ? '[data-expected-egress-rule]' : '[data-egress-episode-id]') || [])].find(node => node.dataset[attr] === id);
    const node = target || container?.querySelector('.protection-context');
    if (node) {
      node.focus({preventScroll:true});
      node.scrollIntoView({behavior:'auto',block:'center'});
    }
    return node;
  }

  async function viewEgressExpectation(ruleId, episodeId) {
    if (state.sessionEnded || typeof ruleId !== 'string' || !ruleId || typeof episodeId !== 'string' || !episodeId) return;
    const generation = ++state.protectionContextGeneration;
    const context = {ruleId,episodeId,phase:'rules',status:'loading',generation};
    state.protectionContext = context;
    const auth = state.handoffGeneration;
    const ownsContext = () => !state.sessionEnded && state.protectionContext === context && generation === state.protectionContextGeneration && auth === state.handoffGeneration;
    const found = (store.data.expectedEgress || []).some(rule => rule.id === ruleId && !rule.revoked_at);
    if (found) context.status = 'ready';
    actions.switchTab('protection/rules', {keepProtectionContext:true});
    actions.renderNow(['expected-egress']);
    const initialFocus = focusProtectionContext(context);
    if (found) return;
    const ownsRead = store.beginExpectedEgressRead();
    try {
      const res = await actions.apiFetch('/expected-egress');
      if (!ownsContext()) return;
      if (!res.ok) throw new Error('Expectation read failed');
      const report = await res.json();
      if (!ownsContext()) return;
      if (!actions.isConsoleReport('expected egress', report)) throw new Error('Invalid expectation response');
      if (ownsRead()) store.data.expectedEgress = report.rules || [];
      context.status = 'ready';
    } catch {
      if (!ownsContext()) return;
      context.status = ownsRead() ? 'error' : 'ready';
    }
    if (!ownsContext()) return;
    const retainFocus = actions.document.activeElement === initialFocus;
    actions.renderNow(['expected-egress']);
    if (retainFocus) focusProtectionContext(context);
  }

  function backToEgressContext() {
    if (!state.protectionContext || state.sessionEnded) return;
    state.protectionContext.phase = 'traffic';
    state.protectionContext.status = 'ready';
    state.protectionContext.generation = ++state.protectionContextGeneration;
    actions.switchTab('protection/traffic', {keepProtectionContext:true});
    actions.renderNow(['recurring-egress']);
    focusProtectionContext(state.protectionContext);
  }


  function paintTabsPosture() {
    const pill = actions.document.getElementById('tabs-posture');
    const text = actions.document.getElementById('tabs-posture-text');
    if (!pill || !text) return;
    const view = actions.consolePosturePresentation(store.data.posture, actions.window.SA?.postureHealth);
    pill.dataset.state = view.state;
    text.textContent = view.pill;
  }

  return { noteEndpointFailure, hasSnapshotHeadline, renderSnapshotHealth, renderReportHealth, reportSucceeded, reportFailed, endSession, clearProtectionContext, focusProtectionContext, viewEgressExpectation, backToEgressContext, paintTabsPosture };
}
