// Exercise the Monitoring destination through production rendering and actions.
(() => {
  const { data, ready, wait, idle, openTab, iso } = window.DomTest;
  const path = (state, supported = true) => ({ state, supported, detail: 'This session only.', last_seen: state === 'observed' ? iso(1000) : '' });
  const row = (id, pid, harness, workspace) => ({ session_id: id, root_pid: pid, harness, workspace, identity_basis: id ? 'transcript' : 'unresolved', guard: path(harness === 'claude' ? 'observed' : 'unsupported', harness === 'claude'), trace: path(id ? 'observed' : 'unattributed'), payload: path('not-observed') });
  data['/status'].coverage = { sessions: [row('sess-claude-1', 101, 'claude', '/workspace/api-service'), row('sess-codex-3', 301, 'codex', '/workspace/data-pipeline'), row('', 401, 'openclaw', '/')] };
  data['/posture'].coverage_items = [{ kind: 'event_loss', id: 'bus', title: 'Telemetry was dropped', detail: 'Earlier deliveries cannot be recovered.' }];
  ready().then(async () => {
    const probe = {};
    try {
      openTab('monitoring');
      const detail = () => document.getElementById('monitoring-detail');
      await wait(() => !!detail().querySelector('h2'));
      probe.primary = location.hash === '#monitoring' && document.querySelector('.tab-btn[data-tab="monitoring"]').getAttribute('aria-selected') === 'true';
      probe.list = document.getElementById('monitoring-count').textContent.includes('2') && document.querySelectorAll('#monitoring-sessions [data-monitoring-key]').length === 2 && !document.getElementById('monitoring-other').open;
      probe.paths = detail().querySelectorAll('[data-monitoring-path]').length === 3 && detail().textContent.includes('Last observed');
      const select = key => document.querySelector(`[data-monitoring-key="${key}"]`).click();
      select('session:sess-codex-3');
      await idle();
      probe.reading = !matchMedia('(max-width: 800px)').matches || (detail().getBoundingClientRect().top >= document.querySelector('.sidebar').getBoundingClientRect().bottom && detail().getBoundingClientRect().top < innerHeight);
      probe.unsupported = detail().textContent.includes('Not supported') && !detail().querySelector('[data-monitoring-path="guard"] .observed');
      const input = document.getElementById('monitoring-search');
      input.value = 'no-matching-work'; input.dispatchEvent(new Event('input', { bubbles: true })); await idle();
      probe.search = !document.querySelector('#monitoring-sessions button') && detail().querySelector('h2').textContent === 'data-pipeline';
      input.value = ''; input.dispatchEvent(new Event('input', { bubbles: true })); await idle();
      document.getElementById('monitoring-other').open = true; select('process:401');
      probe.unlinked = detail().querySelector('h2').textContent === 'Workspace not identified' && !detail().querySelector('[data-monitoring-action="open"]') && detail().textContent.includes('not an identified session');
      document.querySelector('[data-monitoring-action="issues"]').click();
      probe.issues = !document.getElementById('monitoring-issues').hidden && document.getElementById('monitoring-issues').textContent.includes('Earlier deliveries cannot be recovered');
      document.querySelector('[data-monitoring-action="issues"]').click();
      document.activeElement.blur(); select('session:sess-claude-1');
      document.getElementById('monitoring-identity').open = true;
      data['/status'].coverage.sessions_stale = true; document.getElementById('btn-refresh').click();
      await wait(() => detail().querySelector('[data-monitoring-action="open"]')?.disabled);
      probe.stale = document.getElementById('monitoring-notice').textContent.includes('stale') && !detail().querySelector('.monitoring-state.observed') && document.getElementById('monitoring-identity').open;
      data['/status'].coverage.sessions_stale = false; document.getElementById('btn-refresh').click();
      await wait(() => !detail().querySelector('[data-monitoring-action="open"]').disabled);
      detail().querySelector('[data-monitoring-action="open"]').click();
      await wait(() => window.SA.activeTab === 'sessions' && window.SA.selectedSessionId === 'sess-claude-1');
      probe.handoff = true;
      openTab('monitoring');
      data['/status'].coverage.sessions = data['/status'].coverage.sessions.slice(1);
      document.getElementById('btn-refresh').click();
      await wait(() => detail().textContent.includes('Choose a session or process'));
      probe.removed = !document.querySelector('#monitoring-sessions [aria-pressed="true"]') && !detail().querySelector('[data-monitoring-action="open"]');
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
    } catch (error) { probe.error = error.message; }
    document.body.dataset.monitoringProbe = JSON.stringify(probe);
  });
})();
