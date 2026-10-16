// Search and reading continuity through the real render and refresh lifecycle.
(() => {
  const {data, ready, wait, idle, openTab} = window.DomTest;
  const sample = {session_id:'sess-claude-1', harness:'claude', workspace:'/workspace/api-service', guard:{state:'observed', detail:'Session observation', last_seen:'2026-10-15T12:00:00Z'}, trace:{state:'observed'}, payload:{state:'not-observed'}};
  data['/status'].coverage = {sessions:[sample]};
  ready().then(async () => {
    const probe = {};
    try {
      openTab('home');
      await wait(() => !!document.querySelector('.coverage-session'));
      const root = document.querySelector('.coverage-session').parentElement;
      root.open = true;
      const row = root.querySelector('.coverage-session');
      row.open = true;
      row.querySelector('summary').focus();
      sample.guard.last_seen = '2026-10-15T12:01:00Z';
      document.querySelector('#btn-refresh').click();
      await wait(() => document.querySelector('#coverage-list').textContent.includes('12:01:00'));
      await idle();
      const updated = document.querySelector('.coverage-session');
      probe.reading = updated.open && updated.parentElement.open;
      probe.focus = document.activeElement === updated.querySelector('summary');
      const input = document.querySelector('#global-search');
      const search = async value => {input.value = value; input.dispatchEvent(new Event('input', {bubbles:true})); await idle();};
      await search('no-such-session');
      probe.empty = !document.querySelector('#session-daily .session-daily-card') && document.querySelector('#session-daily').textContent.includes('No sessions match');
      document.querySelector('#session-daily [data-action="clear-global-search"]')?.click();
      await idle();
      probe.clear = input.value === '' && document.activeElement === input && !!document.querySelector('#session-daily .session-daily-card');
      await search('api-service');
      probe.match = [...document.querySelectorAll('#session-daily .session-daily-card')].map(el => el.dataset.session).sort().join(',') === 'sess-claude-1,sess-claude-sub';
      openTab('sessions');
      await search('no-such-session');
      probe.rail = !document.querySelector('#session-rail [data-action="select-session"]') && document.querySelector('#session-rail').textContent.includes('No live sessions match');
      document.querySelector('#session-rail [data-action="clear-harness-filter"]')?.click();
      await idle();
      probe.railClear = input.value === '' && !!document.querySelector('#session-rail [data-action="select-session"]');
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
    } catch(error) {probe.error = error.message;}
    document.body.dataset.homeUxProbe = JSON.stringify(probe);
  });
})();
