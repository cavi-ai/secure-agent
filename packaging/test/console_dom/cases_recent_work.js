(() => {
  const {ready,wait,idle,route,openTab,data,iso,realFetch}=window.DomTest;
  const frame=()=>realFetch('/__console_frame_checkpoint',{cache:'no-store'});
  const sid='ended-archive';
  data['/sessions']=[
    {id:sid,harness:'claude',repo:'archive',workspace:'/workspace/archive',branch:'release',status:'ended',started_at:iso(60000),last_seen_at:iso(10000),ended_at:iso(5000)},
    {id:'live-other',harness:'codex',repo:'other',workspace:'/workspace/other',status:'active',last_seen_at:iso(20000)},
  ];
  route('/sessions/'+sid+'/outcomes',()=>({ok:true,json:async()=>({session_id:sid,observed_at:iso(0),history:{reviews:[],incidents:[],interventions:[],guards:[],evidence:Object.fromEntries(['reviews','incidents','interventions','guards'].map(k=>[k,{available:true,at_limit:false,limit:100}]))}})}));
  const search=async value=>{const input=document.querySelector('#global-search');input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));await idle();};
  const opener=()=>document.querySelector(`#session-daily [data-action="recent-session-results"][data-session="${sid}"]`);
  const inResults=()=>window.SA.activeTab==='sessions' && window.SA.selectedSessionId===sid && window.SA.sessionView==='results' && !!document.querySelector('#session-detail .sd-follow-up');
  ready().then(async()=>{
    const probe={};
    try {
      openTab('sessions');await idle();
      const filter=document.querySelector('#session-cwd-filter');filter.value='different';filter.dispatchEvent(new Event('input',{bubbles:true}));await idle();
      openTab('home');await search('ARCHIVE');
      await wait(()=>!!opener());
      probe.ended=opener().closest('.session-daily-row').textContent.includes('ended') && !document.querySelector('#session-daily').textContent.includes('No live');
      await frame();opener().scrollIntoView({block:'center'});opener().focus();const pageY=scrollY,maxBefore=document.documentElement.scrollHeight-innerHeight;
      opener().click();await wait(inResults);await idle();
      probe.direct=inResults() && !!document.querySelector('[data-action="recent-work-home"]') && !document.querySelector('#session-live-only').checked;
      document.querySelector('[data-action="recent-work-home"]').click();
      await wait(()=>window.SA.activeTab==='home');await idle();await frame();
      probe.back=document.querySelector('#global-search').value==='ARCHIVE' && document.activeElement===opener() && Math.abs(scrollY-pageY)<3 && document.querySelector('#session-cwd-filter').value==='different' && document.querySelector('#session-live-only').checked;
      if (!probe.back) probe.backState={search:document.querySelector('#global-search').value,focus:document.activeElement?.dataset,top:scrollY,before:pageY,maxBefore,maxAfter:document.documentElement.scrollHeight-innerHeight,filter:document.querySelector('#session-cwd-filter').value,live:document.querySelector('#session-live-only').checked};
      history.forward();await wait(inResults);await idle();
      probe.forward=!!document.querySelector('[data-action="recent-work-home"]');
      history.back();await wait(()=>window.SA.activeTab==='home');await idle();await frame();
      probe.browserBack=document.activeElement===opener() && document.querySelector('#global-search').value==='ARCHIVE';
      data['/sessions']=data['/sessions'].filter(s=>s.status==='ended');document.querySelector('#btn-refresh').click();await idle();
      probe.quiet=!!opener() && !document.querySelector('#session-daily').textContent.includes('No live');
      opener().focus();data['/sessions'][0].ended_at=iso(0);document.querySelector('#btn-refresh').click();await idle();
      probe.refreshFocus=document.activeElement===opener();
      await search('unmatched');probe.empty=document.querySelector('#session-daily').textContent.includes('No sessions match');
      document.querySelector('#session-daily [data-action="clear-global-search"]').click();await idle();
      probe.clear=document.querySelector('#global-search').value==='' && !!opener();
      probe.fits=document.documentElement.scrollWidth<=innerWidth && document.querySelector('#session-daily').scrollWidth<=document.querySelector('#session-daily').clientWidth;
      document.querySelector('[data-action="recent-work-all"]').click();await idle();
      probe.all=window.SA.activeTab==='sessions' && !document.querySelector('#session-live-only').checked && !!document.querySelector(`#session-rail [data-id="${sid}"]`) && !document.documentElement.classList.contains('recent-work-navigation');
    } catch(error) {probe.error=error.message;}
    document.body.dataset.recentWorkProbe=JSON.stringify(probe);
  });
})();
