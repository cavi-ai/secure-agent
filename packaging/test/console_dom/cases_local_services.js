// Synthetic endpoint evidence through the production Monitoring drawer.
(() => {
  const {route,ready,wait,openTab,iso} = window.DomTest;
  let calls=0,fail=false;
  const report={generated_at:iso(1000),enforcement:'not_assessed',scope:'Metadata only',omitted_endpoints:2,
    managed:{state:'unloaded',transport:'inherited-unix-v1',enforcement:'private_transport'},
    inventory:{state:'partial',scope:'Visible listeners only; permission limits apply',truncated:true,
      listeners:[{pid:42,command:'unidentified-server',address:'0.0.0.0:23456',binding:'wildcard',runtime_hint:'unknown'}]},
    services:[{endpoint:'http://127.0.0.1:23456',metadata:{state:'model_metadata',http_status:200},cross_origin:{state:'model_metadata',sharing:'advertised'},foreign_host:{state:'model_metadata'},findings:['Unrelated Host accepted'],enforcement:'not_assessed'}],
    hardening:[{runtime:'ollama',title:'Ollama',support:'browser_hardening_only',settings:'OLLAMA_HOST=127.0.0.1:11434\nOLLAMA_ORIGINS=',steps:['Review the existing service before restart'],verification:['Recheck every direct backend listener'],limitations:['Built-in origins remain allowed; no native local API-key enforcement'],documentation:'https://docs.ollama.com/faq'}]};
  route('/local-services',()=>{calls++;return new Response(fail?'unavailable':JSON.stringify(report),{status:fail?503:200,headers:{'Content-Type':'application/json'}});});
  const preview={id:'reviewed-service',preview_hash:'bound-service',source:'/private/model.plist',label:'com.example.model',endpoint:'http://127.0.0.1:19001',change:{runtime:'mlx',scope:'authenticated_inference',port:19001},settings:['Use the protected gateway and Unix worker'],client_fields:['advisor.api_key_file'],warnings:['Restart interrupts active requests']};
  let applied=false,rolledBack=false;
  route('/local-services/remediation',async(options)=>{
    const input=JSON.parse(options.body);
    if(input.action==='apply')applied=input.id===preview.id&&input.preview_hash===preview.preview_hash&&Object.keys(input).length===3;
    if(input.action==='rollback')rolledBack=input.label===preview.label;
    const value=input.action==='preview'?preview:{...preview,state:input.action==='rollback'?'restored_stopped':'verified',verified_at:'2026-11-09T18:00:00Z',checks:['owned_loopback_listener','authorized_one_token_inference']};
    return new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}});
  });
  ready().then(async()=>{
    const probe={};
    try {
      probe.onDemand=calls===0;
      openTab('monitoring');
      document.querySelector('[data-action="local-services-open"]').click();
      const body=()=>document.getElementById('drawer-body');
      await wait(()=>body().textContent.includes('Unrelated Host accepted'));
      probe.open=document.getElementById('drawer-title-text').textContent==='Local model servers' && calls===1;
      probe.scope=body().textContent.includes('Managed private connection') && body().textContent.includes('unloaded') && body().textContent.includes('External service protection is not established');
      probe.gaps=body().textContent.includes('2 additional') && body().textContent.includes('partial') && body().textContent.includes('wildcard');
      body().querySelector('.local-service-profile').open=true;
      body().querySelector('.local-service-inventory').open=true;
      probe.profile=body().textContent.includes('not applied') && body().textContent.includes('no native local API-key enforcement') && !!body().querySelector('[data-action="local-services-copy"]');
      probe.fits=document.documentElement.scrollWidth<=innerWidth && body().scrollWidth<=body().clientWidth;
      fail=true;
      document.querySelector('[data-action="local-services-refresh"]').click();
      await wait(()=>!!body().querySelector('[role="alert"]'));
      probe.failed=!body().textContent.includes('Managed private connection') && !document.querySelector('[data-action="local-services-refresh"]').disabled;
      fail=false;
      document.querySelector('[data-action="local-services-refresh"]').click();
      await wait(()=>body().textContent.includes('Unrelated Host accepted'));
      probe.retry=calls===3 && !body().querySelector('[role="alert"]');
      document.querySelector('[data-action="service-remediation-open"]').click();
      document.getElementById('service-remediation-source').value=preview.source;
      document.querySelector('[data-action="service-remediation-preview"]').click();
      await wait(()=>!!document.querySelector('[data-action="service-remediation-apply"]'));
      probe.review=body().textContent.includes('advisor.api_key_file')&&body().textContent.includes('Unix worker')&&!applied;
      probe.reviewFits=document.documentElement.scrollWidth<=innerWidth&&body().scrollWidth<=body().clientWidth;
      document.querySelector('[data-action="service-remediation-apply"]').click();
      await wait(()=>!document.getElementById('confirm-layer').hidden);
      probe.confirm=!applied;
      document.getElementById('confirm-ok').click();
      await wait(()=>body().textContent.includes('Last verified'));
      probe.applied=applied&&body().textContent.includes('authorized_one_token_inference');
      document.querySelector('[data-action="service-remediation-rollback"]').click();
      await wait(()=>!document.getElementById('confirm-layer').hidden);
      document.getElementById('confirm-ok').click();
      await wait(()=>body().textContent.includes('restored_stopped'));
      probe.rollback=rolledBack&&body().textContent.includes('service is stopped');
    } catch(error) {probe.error=error.message;}
    document.body.dataset.localServicesProbe=JSON.stringify(probe);
  });
})();
