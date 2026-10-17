(() => {
  const {ready,wait,idle,route,openTab,data,iso,realFetch}=window.DomTest;
  const session='sess-claude-1', workspace='/workspace/api-service';
  data['/sessions'].find(s=>s.id===session).workspace=workspace;
  const scope=(id,path,label='Timed permission',extra={})=>({id,kind:'exact',agent:'claude',session_id:session,workspace:path,rule_id:'env-files',operation:'guard:Read',resource_path:path+'/.env',reader_exe:'/usr/local/bin/claude',created_at:iso(60000),expires_at:iso(-86400000),applicability:{label,revoke:label==='Timed permission'},...extra});
  let rows=[scope('permission-app',workspace),scope('permission-other','/workspace/other'),scope('permission-child',workspace+'/sub'),scope('permission-unassigned',''),scope('permission-expired',workspace,'Expired',{expires_at:iso(10000)}),scope('permission-revoked',workspace,'Revoked',{revoked_at:iso(1000)}),scope('permission-unknown',workspace,'Applicability unknown')];
  let fail=false,writes=[];
  route('/decision-scopes',({method,query})=>{
    if(method==='DELETE') {const id=query.get('id');writes.push(id);rows=rows.map(r=>r.id===id ? {...r,revoked_at:iso(0),applicability:{label:'Revoked',revoke:false}} : r);return {ok:true,json:async()=>({revoked:true,id})};}
    return {ok:!fail,json:async()=>rows};
  });
  const value=(id,v)=>{const el=document.getElementById(id);el.value=v;el.dispatchEvent(new Event('change',{bubbles:true}));};
  ready().then(async()=>{
    const probe={};
    try {
      openTab('sessions');await window.selectSession(session);await window.setSessionView('memory');await idle();
      const opener=()=>document.querySelector('#session-detail [data-action="workspace-permissions"]');
      await wait(()=>!!opener());
      const body=document.querySelector('#session-detail .session-detail-body');body.scrollTop=Math.min(70,body.scrollHeight-body.clientHeight);const top=body.scrollTop;
      opener().focus();opener().click();await wait(()=>!!document.querySelector('#policy-scopes [data-id="permission-app"]'));await idle();
      const panel=()=>document.getElementById('policy-scopes');
      const revoke=id=>panel().querySelector(`[data-action="revoke-scope"][data-id="${id}"]`);
      const ws=()=>document.getElementById('permission-workspace');
      probe.entry=ws().value==='workspace:'+workspace && !panel().textContent.includes('/workspace/other') && !panel().textContent.includes('/sub/.env') && writes.length===0;
      if (!probe.entry) probe.entryState={workspace:ws().value,tab:window.SA.activeTab,session:window.SA.selectedSessionId,text:panel().textContent};
      probe.groups=['saved','unknown','expired','revoked'].every(k=>panel().querySelector(`[data-permission-status="${k}"]`));
      probe.limits=panel().textContent.includes('Last successful read') && document.getElementById('workspace-permissions-panel').textContent.includes('do not establish current access') && document.getElementById('broader-policies-title').parentElement.textContent.includes('not filtered by workspace');
      if(location.search.includes('workspacedemo')) {document.getElementById('workspace-permissions-panel').scrollIntoView({block:'start'});return;}
      value('permission-status','saved');await idle();await realFetch('/__console_frame_checkpoint');const reviewTop=scrollY;revoke('permission-app').click();await wait(()=>!document.getElementById('confirm-layer').hidden);
      probe.confirm=document.getElementById('confirm-message').textContent.includes('permission-app') && document.getElementById('confirm-message').textContent.includes(workspace) && document.activeElement===document.getElementById('confirm-cancel');
      document.getElementById('confirm-cancel').click();await idle();probe.cancel=writes.length===0;
      revoke('permission-app').click();await wait(()=>!document.getElementById('confirm-layer').hidden);document.getElementById('confirm-ok').click();
      await wait(()=>panel().textContent.includes('Revocation saved'));await idle();
      probe.revoked=writes.join(',')==='permission-app' && ws().value==='workspace:'+workspace && document.getElementById('permission-status').value==='saved' && !revoke('permission-app');
      await realFetch('/__console_frame_checkpoint');probe.reading=Math.abs(scrollY-reviewTop)<3;
      value('permission-status','all');value('permission-workspace','unassigned');await idle();
      probe.unassigned=!!revoke('permission-unassigned') && !panel().querySelector('[data-id="permission-other"]');
      value('permission-workspace','workspace:/workspace/other');await idle();fail=true;
      document.querySelector('#workspace-permissions-panel [data-action="policy-refresh-report"]').click();
      await wait(()=>panel().textContent.includes('current status is unavailable'));await idle();
      probe.stale=panel().textContent.includes('/workspace/other') && !revoke('permission-other');
      fail=false;panel().querySelector('[data-action="policy-refresh-report"]').click();await wait(()=>!!revoke('permission-other'));await idle();
      probe.retry=ws().value==='workspace:/workspace/other';
      value('permission-status','saved');await idle();
      document.querySelector('#scope-bar [data-action="session-investigation-return"]').click();await wait(()=>window.SA.activeTab==='sessions');await idle();await realFetch('/__console_frame_checkpoint');
      probe.back=window.SA.selectedSessionId===session && window.SA.sessionView==='memory' && document.activeElement===opener() && Math.abs(document.querySelector('#session-detail .session-detail-body').scrollTop-top)<3;
      history.forward();await wait(()=>window.SA.activeTab==='protection');await idle();
      probe.forward=ws().value==='workspace:/workspace/other' && document.getElementById('permission-status').value==='saved' && !!revoke('permission-other');
      value('permission-status','expired');await idle();probe.empty=!!panel().querySelector('[data-action="permission-filter-clear"]');
      panel().querySelector('[data-action="permission-filter-clear"]').click();await idle();probe.clear=ws().value==='all' && document.getElementById('permission-status').value==='all';
      probe.fits=document.documentElement.scrollWidth<=innerWidth && panel().scrollWidth<=panel().clientWidth;
      panel().querySelector('[data-action="permission-session"][data-id="permission-other"]').click();await wait(()=>window.SA.activeTab==='sessions' && window.SA.selectedSessionId===session);await idle();
      probe.inspect=writes.length===1 && !window.SA.sessionInvestigationReturn;
    } catch(error) {probe.error=error.message;}
    document.body.dataset.workspacePermissionsProbe=JSON.stringify(probe);
  });
})();
