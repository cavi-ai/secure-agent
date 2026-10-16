(() => {
  const {ready,wait,idle,route,openTab,iso}=window.DomTest;
  const sid='sess-claude-1';
  let failed=false,permissionsFailed=false,scopeRevoked=false;
  const response=body=>({ok:true,json:async()=>structuredClone(body)});
  const data={session_id:sid,observed_at:iso(0),history:{
    evidence:Object.fromEntries(['reviews','incidents','interventions','guards'].map(k=>[k,{available:true,at_limit:false,limit:100}])),
    reviews:[{id:'review-follow-up',revision:2,context:{rule:'Sensitive file read'},decision:{action:'acknowledge',revision:1,at:iso(30000)},evidence_available:true,evidence_flag_available:true,evidence_flag_id:'follow-up-flag'}],
    guards:[{id:'guard-follow-up',session_id:sid,rule_id:'credentials',verdict:'allow',scope:'exact',at:iso(20000),scope_ids:['scope-follow-up','scope-missing']}],
    interventions:[{id:'process-follow-up',kind:'pause',requested_at:iso(10000),status:'applied',verification:'pending'}],
    incidents:[{id:'incident-follow-up',remediation:{steps:[{id:'step-follow-up',item:{name:'Example API key',action:'Revoke key'},status:'reported',verification:'unverified',reported_at:iso(5000),newer_evidence:true}]}}],
  }};
  route('/sessions/'+sid+'/outcomes',()=>failed?{ok:false,status:503}:response(data));
  route('/decision-scopes',()=>permissionsFailed?{ok:false,status:503}:response([
    {id:'scope-follow-up',kind:'exact',agent:'claude',rule_id:'credentials',operation:'guard:Read',resource_path:'/workspace/api-service/.env',created_at:iso(20000),expires_at:new Date(Date.now()+86400000).toISOString(),...(scopeRevoked?{revoked_at:iso(0)}:{}),applicability:{label:scopeRevoked?'Revoked':'Timed permission',revoke:!scopeRevoked}},
    {id:'unrelated',kind:'exact',agent:'claude',rule_id:'other',operation:'guard:Read',resource_path:'/unrelated-resource',created_at:iso(0)},
  ]));
  route('/flags/follow-up-flag/explain',()=>response({id:'follow-up-flag',rule:'Sensitive file read',severity:'high',title:'New sensitive read',detail:'New evidence for the selected session.',ts:iso(0)}));
  const box=()=>document.querySelector('#session-detail .sd-follow-up');
  const group=key=>box().querySelector(`[data-follow-up-group="${key}"]`);
  const body=()=>document.querySelector('#session-detail .session-detail-body');
  const refresh=async()=>{box().querySelector('[data-action="session-outcomes-retry"]').click();await idle();};
  ready().then(async()=>{
    const probe={};
    try {
      openTab('sessions');await wait(()=>!!document.querySelector(`#session-rail [data-id="${sid}"]`));
      document.querySelector(`#session-rail [data-id="${sid}"]`).click();await idle();
      document.querySelector('[data-action="session-view"][data-view="results"]').click();
      await wait(()=>box()?.textContent.includes('Permissions read at'));await idle();
      probe.initial=body().scrollTop<2 && box().getBoundingClientRect().top>=body().getBoundingClientRect().top-2;
      probe.groups=!!group('evidence') && !!group('actions') && !!group('permissions') && box().textContent.includes('not technically verified');
      group('evidence').querySelector('summary').click();await idle();
      const opener=box().querySelector('[data-action="open-flag"]');opener.focus();const top=body().scrollTop;
      await refresh();
      probe.reading=group('evidence').open && document.activeElement.dataset.id==='follow-up-flag' && Math.abs(body().scrollTop-top)<3;
      box().querySelector('[data-action="open-flag"]').click();await wait(()=>document.querySelector('#drawer-body').textContent.includes('New sensitive read'));await idle();
      document.querySelector('#btn-drawer-back').click();await idle();
      probe.back=window.SA.sessionView==='results' && document.activeElement.dataset.id==='follow-up-flag';
      group('permissions').querySelector('summary').click();await idle();
      probe.scoped=box().textContent.includes('Timed permission') && box().textContent.includes('Current status unknown') && !box().textContent.includes('unrelated-resource');
      box().querySelector('[data-action="session-guard-permissions"]').click();await wait(()=>document.querySelector('#drawer-body').textContent.includes('scope-missing'));await idle();
      probe.permissions=document.querySelector('#drawer-body').textContent.includes('Expires') && !document.querySelector('#drawer-body').textContent.includes('unrelated-resource');
      document.querySelector('#btn-drawer-back').click();await idle();
      scopeRevoked=true;await refresh();probe.revoked=box().textContent.includes('Revoked');
      permissionsFailed=true;await refresh();
      probe.independent=box().textContent.includes('Permission status unavailable') && !box().textContent.includes('Timed permission') && !document.querySelector('#session-detail').textContent.includes('Last known results');
      failed=true;await refresh();
      probe.stale=box().textContent.includes('Last known follow-up') && !box().querySelector('[data-action="open-flag"], [data-action="session-guard-permissions"]');
      failed=false;permissionsFailed=false;await refresh();
      probe.retry=!box().textContent.includes('Last known follow-up') && !!box().querySelector('[data-action="open-flag"]');
      probe.fits=document.documentElement.scrollWidth<=innerWidth && box().scrollWidth<=box().clientWidth;
      document.querySelector('#session-rail [data-id="sess-codex-3"]').click();await idle();
      probe.selection=window.SA.selectedSessionId==='sess-codex-3' && !document.querySelector('#session-detail').textContent.includes('Sensitive file read');
    } catch(error) {probe.error=error.message;}
    document.body.dataset.followUpProbe=JSON.stringify(probe);
  });
})();
