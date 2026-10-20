(() => {
  const {data,route,ready,wait,idle,openTab,scenarios}=window.DomTest;
  const guards={kind:'guard',id:'decision-1',priority:5,title:'Access request',detail:'Inspect the access request',path:'/work/.env',rule:'env',available_scopes:[{kind:'once'}],session_id:'sess-claude-1'};
  const hook={kind:'hook',id:'repair-1',priority:1,title:'Hook needs repair',session_id:'sess-claude-1'};
  const group={key:'session:claude',label:'Session',agent:'claude',workspace:'/work',items:[guards,hook]};
  const initial={...data['/posture'],state:'critical',summary:'Retained security evidence needs review.',needs_you:2,items:[{kind:'guard_pending',id:guards.id,title:guards.title,severity:1},{kind:'hook',id:hook.id,title:hook.title,severity:1}],groups:[group],coverage_count:1,coverage_items:[{kind:'collector_down',id:'transcript',title:'Transcript collection unavailable',detail:'Check the collector.'}],attention_summary:{version:1,buckets:[{kind:'decisions',count:1,coverage_count:0,first:{kind:'guard',id:guards.id,title:guards.title,session_id:'sess-claude-1'}},{kind:'security',count:0,coverage_count:0},{kind:'monitoring',count:1,coverage_count:1,first:{kind:'hook',id:hook.id,title:hook.title,session_id:'sess-claude-1'}}]}};
  data['/posture']=structuredClone(initial);
  let failed=false;
  route('/snapshot',()=>failed?{ok:false,status:503,json:async()=>({})}:undefined);
  ready().then(async()=>{
    const probe={};
    try {
      openTab('home');await idle();
      const box=()=>document.querySelector('#attention-summary');
      const refresh=async()=>{document.querySelector('#btn-refresh').click();await idle();};
      probe.categories=['Waiting for your decision','Security review','Monitoring problems'].every(t=>box().textContent.includes(t));
      probe.counts=box().textContent.includes('1 queued item') && box().textContent.includes('2 current problems') && document.querySelector('#badge-attention-count').textContent==='2';
      box().querySelector('[data-need-id="decision-1"]').click();await idle();
      probe.identity=document.querySelector('#drawer-title-text').textContent==='Access request' && !!document.querySelector('#drawer-foot [data-id="decision-1"][data-action="guard-resolve"]');
      document.querySelector('#btn-drawer-close').click();
      box().querySelector('[data-action="view-monitoring"]').click();await idle();
      probe.monitoring=document.activeElement===document.querySelector('#coverage-title') && !document.querySelector('#coverage-center').hidden;
      if(scenarios.has('attentionshot')) {document.querySelector('#attention-summary-title').scrollIntoView();document.body.dataset.attentionSummaryProbe=JSON.stringify(probe);return;}
      failed=true;await refresh();await wait(()=>!!window.SA.postureHealth.error);await idle();
      probe.stale=box().textContent.includes('Last known') && !box().querySelector('[data-action="select-attention"]') && document.querySelector('#posture-state').textContent==='Urgent review' && !document.querySelector('#posture-health').hidden;
      failed=false;await refresh();await wait(()=>!window.SA.postureHealth.error);await idle();
      probe.recovery=!!box().querySelector('[data-need-id="decision-1"]') && !box().textContent.includes('Last known');
      data['/posture'].attention_summary.buckets[0].first.id='foreign';await refresh();
      probe.invalid=box().textContent.includes('unavailable') && !box().querySelector('[data-need-id="foreign"]') && document.querySelectorAll('#attention-list .need-row').length===2;
      delete data['/posture'].attention_summary;await refresh();
      probe.legacy=box().textContent.includes('unavailable') && document.querySelector('#badge-attention-count').textContent==='2';
      data['/posture']=structuredClone(initial);await refresh();
      const focus=box().querySelector('[data-need-id="decision-1"]');focus.focus();
      await refresh();probe.focus=document.activeElement===focus;
      probe.fits=box().scrollWidth<=box().clientWidth && document.documentElement.scrollWidth<=innerWidth;
    } catch(error) {probe.error=error.message;}
    document.body.dataset.attentionSummaryProbe=JSON.stringify(probe);
  });
})();
