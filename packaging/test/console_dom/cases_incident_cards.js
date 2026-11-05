(() => {
  const {ready, idle, realFetch, openTab, data, iso} = window.DomTest;
  const frame = () => realFetch('/__console_frame_checkpoint', {cache:'no-store'});
  ready().then(async () => {
    const probe = {};
    try {
      const summary = "Security rule 'secret-in-transcript' triggered by agent 'codex' (PID 0). Evidence: "
        + '/workspace/transcripts/2026/11/session-with-a-long-identifier.jsonl matched pattern rule db-conn-string. '.repeat(12);
      const incidents = Array.from({length:4}, (_, n) => ({id:'card-' + n, rule:'secret-in-transcript',
        agent:'codex', risk:n ? 'HIGH' : 'CRITICAL', timestamp:iso(n * 60000), summary, workflow:{status:'open'}}));
      const items = incidents.map(inc => ({kind:'incident', priority:3, id:inc.id, rule:inc.rule,
        title:inc.risk === 'CRITICAL' ? 'Critical incident' : 'Open incident', detail:summary, status:'open'}));
      data['/incidents'] = incidents;
      window.SA.t.incidents = incidents;
      window.SA.t.posture = {...window.SA.t.posture, needs_you:4, groups:[{key:'agent:codex',agent:'codex',items}]};
      openTab('home'); renderAttention(); await idle(); await frame();
      const rows = [...document.querySelectorAll('#attention-list .need')];
      const first = rows[0];
      first.querySelector('.need-head').focus({preventScroll:true});
      probe.count = rows.length === 4;
      probe.compact = rows.every(row => row.getBoundingClientRect().height <= 180);
      probe.title = rows.every(row => row.querySelector('.need-what').textContent === 'Secret appeared in an agent transcript');
      probe.evidence = !first.textContent.includes('session-with-a-long-identifier') && incidents[0].summary === summary;
      probe.risk = first.querySelector('.need-meta').textContent.includes('Critical risk') && rows[1].classList.contains('sev-warn');
      probe.actions = rows.every(row => ['open-incident','incident-status'].every(action =>
        row.querySelector(`[data-action="${action}"]`)?.getBoundingClientRect().width > 0));
      probe.focus = document.activeElement === first.querySelector('.need-head')
        && getComputedStyle(document.activeElement).outlineStyle !== 'none';
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
      const preview = window.CONSOLE_TEST.captureCard ? document.querySelector('.home-review').cloneNode(true) : null;
      first.querySelector('.need-head').click(); await frame();
      probe.inspector = document.querySelector('.attention-inspector')?.textContent.includes(summary);
      window.saCloseDrawer(); await frame();
      document.activeElement?.blur();
      if (preview) {
        const sprites = [...document.querySelectorAll('svg')].filter(svg => svg.querySelector('symbol'));
        document.body.replaceChildren(...sprites, preview);
      }
    } catch(error) {probe.error = error.message;}
    document.body.dataset.incidentCards = JSON.stringify(probe);
  });
})();
