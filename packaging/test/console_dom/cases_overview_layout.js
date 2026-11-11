(() => {
  const {ready, idle, realFetch, openTab, data, route, iso} = window.DomTest;
  const frame = () => realFetch('/__console_frame_checkpoint', {cache:'no-store'});
  ready().then(async () => {
    const probe = {viewport:{width:innerWidth,height:innerHeight,document:document.documentElement.clientWidth,dpr:devicePixelRatio}};
    try {
      openTab('home'); await idle();
      const sessions = Array.from({length:9}, (_, n) => ({id:'overview-' + n, harness:'codex', repo:'workspace-' + n,
        branch:'feature/retained-position', status:'active', last_seen_at:iso(10000 + n * 1000)}));
      data['/sessions'] = sessions; window.SA.t.sessions = sessions; renderSessionDaily();
      let items = Array.from({length:3}, (_, n) => ({kind:'flag', id:'overview-flag-' + n, priority:2,
        title:'Review recorded access ' + n, detail:'Retained evidence', rule:'credential-access'}));
      const paint = () => {
        const posture = {...window.SA.t.posture, state:items.length ? 'attention' : 'all-clear', needs_you:items.length,
          summary:items.length ? `${items.length} items need review — first: recorded credential access in the current workspace requires a decision before this operation can continue.` : 'No pending decisions. See finding history and incidents for remaining risk.',
          items, groups:items.length ? [{key:'session:overview',agent:'codex',workspace:'/workspace',items}] : [], coverage_count:0, coverage_items:[]};
        if (!items.length) posture.attention_summary = {version:1,buckets:['decisions','security','monitoring'].map(kind => ({kind,count:0,coverage_count:0}))};
        data['/posture'] = posture; window.SA.t.posture = posture; renderPosture(); renderAttention();
      };
      const settle = async () => {await frame(); document.getElementById('tab-home').getAnimations({subtree:true}).forEach(a=>a.finish()); await frame();};
      paint(); await settle(); scrollTo(0,0);
      const panel = document.querySelector('.session-daily-panel');
      const rows = () => [...panel.querySelectorAll('.session-daily-card')].map(el=>el.dataset.session);
      const initial = rows();
      const opener = panel.querySelector('[data-action="recent-session-results"]');
      opener.focus({preventScroll:true});
      const before = panel.getBoundingClientRect().top;
      // The advisor line keeps one line, so a narrower review label cannot reflow the banner.
      const advisor = document.getElementById('posture-advisor');
      probe.advisorOneLine = !advisor.hidden && !!advisor.getClientRects().length
        && advisor.getBoundingClientRect().height <= parseFloat(getComputedStyle(advisor).lineHeight) + 1
        && advisor.title === advisor.textContent;
      route('/flags/acknowledge', ({body}) => {
        items = items.filter(item=>item.id !== JSON.parse(body).flag_id); paint();
        return {ok:true,status:200,json:async()=>({acknowledged:true})};
      });
      probe.dismiss = true;
      probe.dismissPositions = [];
      for (let n=0; n<3; n++) {
        await window.dismissFlag('overview-flag-' + n); await idle(); await settle();
        probe.dismiss &&= Math.abs(panel.getBoundingClientRect().top-before)<2;
        probe.dismissPositions.push({top:panel.getBoundingClientRect().top,scroll:scrollY});
      }
      probe.empty = document.getElementById('attention-center').hidden
        && !!document.getElementById('attention-empty')?.getClientRects().length;
      probe.quietDismissal = !document.getElementById('toast-container').textContent.includes('Flag dismissed');
      sessions[0].last_seen_at = iso(100);
      sessions[8].last_seen_at = iso(0); renderSessionDaily(); await frame();
      probe.order = JSON.stringify(rows()) === JSON.stringify(initial);
      probe.focus = document.activeElement === opener && opener.isConnected;
      probe.liveTime = panel.querySelector('[data-session="overview-0"] time')?.dateTime === sessions[0].last_seen_at;
      const refresh = document.querySelector('[data-action="recent-work-refresh"]');
      probe.updates = refresh?.classList.contains('has-updates');
      refresh?.click(); await frame();
      probe.refresh = rows()[0] === 'overview-8';
      probe.workspace = panel.querySelector('.session-daily-card strong')?.textContent === 'workspace-8';
      items = Array.from({length:12}, (_, n) => ({kind:'flag',id:'overflow-' + n,priority:2,title:'Review recorded access ' + n,detail:'Retained evidence',rule:'credential-access'}));
      paint(); await settle();
      const queue = document.querySelector('.home-review-body');
      probe.bounded = !!queue && queue.scrollHeight > queue.clientHeight && queue.clientHeight <= 520;
      const breakdown = document.querySelector('.attention-overview');
      breakdown.querySelector('summary').click(); await frame();
      probe.breakdown = breakdown.open && Math.abs(panel.getBoundingClientRect().top-before)<2;
      probe.still = Math.abs(panel.getBoundingClientRect().top-before)<2;
      probe.motion = !document.getElementById('tab-home').getAnimations({subtree:true}).some(a=>a.id==='attention-continuity');
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
      probe.geometry = {before,after:panel.getBoundingClientRect().top,height:queue?.clientHeight,scrollHeight:queue?.scrollHeight,rows:document.getElementById('attention-list').children.length};
    } catch(error) {probe.error = error.message;}
    document.body.dataset.overviewLayout = JSON.stringify(probe);
  });
})();
