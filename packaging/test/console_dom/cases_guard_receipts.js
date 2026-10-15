(() => {
  const {data,route,ready,wait,idle,iso,openTab}=window.DomTest;
  const session='sess-claude-1', id='guard-1';
  data['/guard/pending'][0].session_id=session;
  const receipt={id,session_id:session,rule_id:'cloud-creds',verdict:'allow',scope:'session',at:iso(0),scope_ids:['guard-permission']};
  let submitted=false,revoked=false,fail=false,writes=0;
  const answer=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
  route('/guard/resolve',()=>{
    writes++; submitted=true;
    data['/guard/pending']=[];
    for(const g of data['/posture'].groups) g.items=g.items.filter(r=>r.id!==id);
    data['/posture'].groups=data['/posture'].groups.filter(g=>g.items.length);
    data['/posture'].items=data['/posture'].items.filter(r=>r.id!==id);
    data['/posture'].needs_you=data['/posture'].items.length;
    return answer({resolved:true,receipt});
  });
  route('/decision-scopes',({method})=>{
    if(method==='DELETE'){revoked=true;return answer({revoked:true,id:'guard-permission'});}
    if(fail)return answer({},503);
    return answer([{id:'guard-permission',kind:'session',agent:'claude',session_id:session,rule_id:'cloud-creds',operation:'guard:Read',resource_path:'/fixture/.env',workspace:'/fixture',reader_exe:'/fixture/agent',created_at:iso(1000),applicability:{label:revoked?'Revoked':'Session permission',revoke:!revoked},...(revoked?{revoked_at:iso(0)}:{})}]);
  });
  route('/sessions/'+session+'/outcomes',()=>answer({session_id:session,observed_at:iso(0),history:{reviews:[],incidents:[],interventions:[],guards:submitted?[{...receipt,resolution_id:id}]:[],evidence:Object.fromEntries(['reviews','incidents','interventions','guards'].map(k=>[k,{available:true,at_limit:false,limit:200}]))}}));
  ready().then(async()=>{
    const probe={};
    const fits=()=>document.documentElement.scrollWidth<=innerWidth;
    try{
      openTab('home');
      const choice=document.querySelector('[data-action="guard-resolve"][data-scope="session"]');
      choice.closest('details').querySelector('summary').click();choice.click();
      await wait(()=>!document.querySelector('#confirm-layer').hidden);
      document.querySelector('#confirm-ok').click();
      await wait(()=>!document.querySelector('#guard-result').hidden);await idle();
      const result=document.querySelector('#guard-result');
      probe.submitted=result.textContent.includes('Answer submitted') && result.textContent.includes('does not prove') && writes===1;
      probe.fits=fits();
      result.querySelector('[data-action="guard-result-permissions"]').click();
      await wait(()=>document.querySelector('#drawer-body [data-action="session-permission-revoke"]'));await idle();
      probe.permission=document.querySelector('#drawer-body').textContent.includes('/fixture/.env') && document.querySelector('#drawer-body').textContent.includes('Guard decision');
      fail=true;document.querySelector('[data-action="session-permissions-refresh"]').click();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('Last known permission records'));
      probe.stale=!document.querySelector('#drawer-body [data-action="session-permission-revoke"]');
      fail=false;document.querySelector('[data-action="session-permissions-refresh"]').click();
      await wait(()=>document.querySelector('#drawer-body [data-action="session-permission-revoke"]'));
      document.querySelector('[data-action="session-permission-revoke"]').click();
      await wait(()=>!document.querySelector('#confirm-layer').hidden);document.querySelector('#confirm-ok').click();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('Revocation saved'));
      probe.revoked=revoked && writes===1;
      document.querySelector('#btn-drawer-close').click();
      result.querySelector('[data-action="guard-result-history"]').click();
      await wait(()=>document.querySelector('#session-detail').textContent.includes('Guard allowed'));
      probe.history=!!document.querySelector('[data-action="session-guard-permissions"][data-id="guard-1"]');
      document.querySelector('[data-action="session-guard-permissions"]').click();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('Revoked'));await idle();
      probe.historyPermission=fits() && document.querySelector('#drawer-body').textContent.includes('guard-permission');
    }catch(error){probe.error=error.message;}
    document.body.dataset.guardReceiptProbe=JSON.stringify(probe);
  });
})();
