(() => {
  const {ready, wait, idle, openTab} = window.DomTest;
  localStorage.removeItem('sa.session-list-view');
  ready().then(async () => {
    const probe = {};
    try {
      openTab('sessions'); window.showSessionList(); await idle();
      const rail = document.getElementById('session-rail');
      const switchTo = view => document.querySelector(`[data-action="session-list-view"][data-view="${view}"]`);
      probe.default = rail.dataset.view === 'harness' && switchTo('harness').getAttribute('aria-pressed') === 'true';
      const selected = window.SA.selectedSessionId;
      switchTo('sessions').focus(); switchTo('sessions').click(); await idle();
      probe.switch = rail.dataset.view === 'sessions' && switchTo('sessions').getAttribute('aria-pressed') === 'true';
      probe.selection = window.SA.selectedSessionId === selected && !!rail.querySelector(`[data-id="${selected}"][aria-pressed="true"]`);
      probe.icons = [...rail.querySelectorAll('.session-group:not(.infra) > summary')].every(head => head.querySelector('use[href="#i-folder"]') && !head.querySelector('.harness-tile'));
      probe.preference = localStorage.getItem('sa.session-list-view') === 'sessions';
      probe.focus = document.activeElement === switchTo('sessions');
      const search = document.getElementById('session-cwd-filter');
      search.value = 'no-such-repository'; search.dispatchEvent(new Event('input', {bubbles: true})); await idle();
      probe.empty = rail.textContent.includes('No live sessions match') && !window.SA.selectedSessionId;
      search.value = ''; search.dispatchEvent(new Event('input', {bubbles: true})); await idle();
      document.getElementById('btn-refresh').click(); await idle();
      probe.refresh = rail.dataset.view === 'sessions' && window.SA.selectedSessionId === selected;
      switchTo('harness').click(); await idle();
      probe.return = rail.dataset.view === 'harness' && window.SA.selectedSessionId === selected && !!rail.querySelector('.harness-tile');
      probe.actions = [...rail.querySelectorAll('[data-action="kill"]')].every(button => button.closest('.session-card.selected .sc-actions'));
      probe.fits = document.documentElement.scrollWidth <= innerWidth && rail.scrollWidth <= rail.clientWidth;
      if (location.search.includes('sessionviewshot')) { switchTo('sessions').click(); await idle(); }
    } catch(error) { probe.error = error.message; }
    document.body.dataset.sessionViews = JSON.stringify(probe);
  });
})();
