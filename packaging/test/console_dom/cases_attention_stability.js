(() => {
  const {data, route, ready, idle, realFetch, openTab} = window.DomTest;
  const probe = {geometry:{}};
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const frame = () => realFetch('/__console_frame_checkpoint', {cache:'no-store'});
  ready().then(async () => {
    try {
      openTab('home'); await idle(); await frame();
      const root = document.getElementById('tab-home');
      const list = document.getElementById('attention-list');
      const support = root.querySelector('.home-support');
      const make = id => ({kind:'flag', id, priority:2, title:'Review credential access ' + id, detail:'Recorded access requires review', rule:'credential-access', session_id:'sess-claude-1'});
      const initial = Array.from({length:9}, (_, n) => make('stable-' + n));
      let items = initial.slice();
      const set = next => {
        items = next;
        const posture = {...window.SA.t.posture, state:next.length ? 'attention' : 'all-clear', needs_you:next.length, items:next,
          groups:next.length ? [{key:'session:claude',agent:'claude',workspace:'/work',items:next}] : [], coverage_count:0, coverage_items:[]};
        if (!next.length) posture.attention_summary = {version:1,buckets:['decisions','security','monitoring'].map(kind => ({kind,count:0,coverage_count:0}))};
        else delete posture.attention_summary;
        data['/posture'] = posture; window.SA.t.posture = posture; renderAttention();
      };
      const settle = async () => {await frame(); root.getAnimations({subtree:true}).forEach(a => a.finish()); await frame();};
      const row = id => list.querySelector('[data-need-key="flag:' + id + '"]');
      const own = () => root.getAnimations({subtree:true}).filter(a => a.id === 'attention-continuity');
      set(items); await settle(); scrollTo(0,0);
      const kept = row('stable-5');
      kept.querySelector('.need-head').focus({preventScroll:true});
      const before = kept.getBoundingClientRect().top;
      set(items.filter(i => i.id !== 'stable-3'));
      const during = kept.getBoundingClientRect().top;
      probe.geometry.middle = {before,during,animations:own().length};
      probe.middle = !row('stable-3') && row('stable-5') === kept && (reduced ? !own().length : Math.abs(before-during)<2 && own().length>0);
      await settle();
      probe.focus = document.activeElement === kept.querySelector('.need-head');
      const supportBefore = support.getBoundingClientRect().top;
      set([make('inserted'), ...items]);
      probe.insertion = !!row('inserted') && (reduced ? !own().length : Math.abs(supportBefore-support.getBoundingClientRect().top)<2);
      const running = own();
      set(items);
      probe.unchanged = row('stable-5') === kept && running.length === own().length && running.every(a => own().includes(a));
      // A changed selected row retains its corresponding keyboard choice.
      kept.querySelector('.need-head').focus({preventScroll:true});
      kept.querySelector('.need-head').click();
      probe.focus = probe.focus && row('stable-5') === kept && row('stable-5').classList.contains('is-selected')
        && document.activeElement === (innerWidth>=1180 ? kept.querySelector('.need-head') : document.getElementById('btn-drawer-close'));
      document.getElementById('btn-drawer-close').click(); await idle();
      set([make('final')]); await settle();
      const finalTop = support.getBoundingClientRect().top;
      row('final').querySelector('.need-head').focus({preventScroll:true});
      set([]);
      probe.last = document.getElementById('attention-center').hidden && !list.children.length && document.activeElement.id === 'session-daily-title'
        && (reduced ? !own().length : Math.abs(finalTop-support.getBoundingClientRect().top)<2);
      set([make('restored')]);
      set([make('restored'),make('newest')]); await settle();
      probe.interrupted = !!row('restored') && !!row('newest') && !document.getElementById('attention-center').hidden && !own().length;
      let reject = true, received = [];
      route('/flags/acknowledge', ({body}) => {
        const payload = JSON.parse(body); received.push(payload);
        if (!reject) set(items.filter(item => item.id !== payload.flag_id));
        return {ok:!reject,status:reject?503:200,json:async()=>({acknowledged:true}),text:async()=> 'Fixture rejection'};
      });
      await window.dismissFlag('restored'); await idle(); await settle();
      probe.rollback = !!row('restored') && !!row('newest') && !document.getElementById('attention-center').hidden;
      reject = false;
      await window.dismissFlag('restored'); await idle(); await settle();
      probe.write = !row('restored') && !!row('newest') && received.length === 2 && received.every(p => p.flag_id === 'restored' && Object.keys(p).length===1);
      set(initial); await settle();
      row('stable-5').scrollIntoView({block:'start'}); await frame();
      const anchorTop = row('stable-5').getBoundingClientRect().top;
      set(items.filter(item => item.id !== 'stable-0'));
      probe.scrolled = Math.abs(row('stable-5').getBoundingClientRect().top-anchorTop)<2;
      probe.geometry.scrolled = {before:anchorTop,after:row('stable-5').getBoundingClientRect().top};
      await settle(); set(initial); await settle(); scrollTo(0,0);
      const app = document.querySelector('.app');
      const closedPadding = parseFloat(getComputedStyle(app).paddingRight);
      const opener = row('stable-4').querySelector('.need-head');
      opener.focus({preventScroll:true}); opener.click(); await idle(); await frame();
      app.getAnimations().forEach(a => a.finish()); await frame();
      const docked = innerWidth>=1180;
      const basePadding = parseFloat(getComputedStyle(app).paddingRight);
      const targetPadding = closedPadding;
      const isModal = document.getElementById('drawer').getAttribute('aria-modal') === 'true';
      scrollTo(0, Math.min(350, document.documentElement.scrollHeight-innerHeight));
      await frame(); const readingTop = scrollY;
      document.getElementById('btn-drawer-close').click();
      const immediatePadding = parseFloat(getComputedStyle(app).paddingRight);
      probe.geometry.drawer = {viewport:innerWidth,docked,basePadding,targetPadding,immediatePadding,readingTop,after:scrollY};
      probe.drawer = docked ? (reduced ? Math.abs(immediatePadding-targetPadding)<2 : immediatePadding>targetPadding+100) : isModal && !document.querySelector('.app > main').inert;
      probe.reading = Math.abs(readingTop-scrollY)<2 && document.activeElement===opener;
      probe.gutter = getComputedStyle(document.documentElement).scrollbarGutter.includes('stable');
      await idle(); await frame();
      probe.fits = document.documentElement.scrollWidth<=innerWidth;
    } catch(error) {probe.error = error.message;}
    document.body.dataset.attentionStabilityProbe = JSON.stringify(probe);
  });
})();
