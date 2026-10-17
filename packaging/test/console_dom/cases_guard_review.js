(() => {
  const {ready,wait,idle,route,openTab,data,iso,realFetch}=window.DomTest;
  const p={id:'guard-1',session_id:'sess-claude-1',agent:'claude',tool:'Read',path:'/workspace/api-service/.env',rule_id:'env-files',workspace:'/workspace/api-service',reader_exe:'/usr/local/bin/claude',available_scopes:[{kind:'once'},{kind:'session'},{kind:'exact',expiry:'24h'}]};
  data['/guard/pending']=[p];
  const item={...p,kind:'guard',priority:5,title:'Access request',detail:'Claude requests Read access',rule:p.rule_id};
  data['/posture'].groups=[{agent:'claude',label:'api-service',workspace:'/workspace/wrong-group',items:[item]}];
  data['/posture'].items=[item];data['/posture'].needs_you=1;
  route('/sessions/'+p.session_id+'/outcomes',()=>({ok:true,json:async()=>({session_id:p.session_id,observed_at:iso(0),history:{reviews:[],incidents:[],interventions:[],guards:[],evidence:Object.fromEntries(['reviews','incidents','interventions','guards'].map(k=>[k,{available:true,at_limit:false,limit:100}]))}})}));
  let writes=0;
  route('/guard/resolve',()=>{writes++;return {ok:true,json:async()=>({resolved:false})};});
  ready().then(async()=>{
    const probe={};
    try {
      openTab('home');await wait(()=>!!document.querySelector('[data-action="guard-inspect"]'));
      if(location.search.includes('guardreviewdemo')) {document.querySelector('#attention-center').scrollIntoView({block:'start'});return;}
      const inspect=()=>document.querySelector('#attention-list [data-action="guard-inspect"]');
      const row=inspect().closest('.need');
      probe.facts=[p.path,p.tool,p.workspace,p.reader_exe,p.rule_id].every(s=>row.textContent.includes(s)) && !row.textContent.includes('wrong-group');
      await realFetch('/__console_frame_checkpoint');inspect().scrollIntoView({block:'center'});inspect().focus();const top=scrollY;
      inspect().click();await wait(()=>window.SA.selectedSessionId===p.session_id && window.SA.sessionView==='memory');await idle();
      probe.inspect=writes===0 && data['/guard/pending'].length===1 && window.SA.activeTab==='sessions' && window.SA.sessionView==='memory';
      document.querySelector('[data-action="recent-work-home"]').click();await wait(()=>window.SA.activeTab==='home');await idle();await realFetch('/__console_frame_checkpoint');
      probe.return=document.activeElement===inspect() && Math.abs(scrollY-top)<3 && writes===0;
      const choice=()=>document.querySelector('#attention-list [data-action="guard-resolve"][data-scope="exact"]');
      choice().closest('details').querySelector('summary').click();choice().click();await wait(()=>!document.querySelector('#confirm-layer').hidden);
      const confirm=document.querySelector('#confirm-layer');
      probe.confirm=[p.path,p.tool,p.workspace,p.reader_exe,'24 hours'].every(s=>confirm.textContent.includes(s));
      probe.cancelFocused=document.activeElement===document.querySelector('#confirm-cancel');
      document.querySelector('#confirm-cancel').click();await idle();probe.cancel=writes===0;
      choice().click();await wait(()=>!confirm.hidden);document.querySelector('#confirm-ok').click();
      await wait(()=>document.querySelector('#guard-result').textContent.includes('Request no longer pending'));await idle();
      probe.expired=writes===1 && !document.querySelector('#guard-result [data-action="guard-result-permissions"]');
      probe.fits=document.documentElement.scrollWidth<=innerWidth && row.scrollWidth<=row.clientWidth;
    } catch(error) {probe.error=error.message;}
    document.body.dataset.guardReviewProbe=JSON.stringify(probe);
  });
})();
