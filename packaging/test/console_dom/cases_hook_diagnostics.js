// Clipboard outcomes are controlled; rendering, request ownership and actions
// run through the production console.
(() => {
  const {data,route,ready,wait,idle,openTab,iso,scenarios}=window.DomTest;
  const host={report:{type:'hook_forwarder',version:2,harness:'hermes',forwarder_id:'host-1',sequence:1,ts:iso(1000),state:'error',pending:2,delivery_failures:3,dropped:1,health:{source_state:'connected',delivery_error:'recorder-failed',report_error:false}},received_at:iso(1000),freshness:'recent',assessment:{state:'needs-action',title:'Hook delivery needs attention',issues:[{stage:'delivery',code:'recorder-failed',next_action:'Restore recorder storage.'}],evidence_gap:true,limits:['Host observations only.']}};
  const ingestion={available:true,since:iso(30000),rejected:0,harnesses:[],forwarders:[host]};
  data['/status'].hook_ingestion=ingestion;
  const finding={id:'failure-1',kind:'execution-errors',harness:'claude',event:'PreToolUse',script:'/private/guard.py',handler_id:'handler-1',config_id:'revision-1',count:3,first_at:iso(7000),last_at:iso(5000),needs_action:true,title:'Hook repeatedly failed',detail:'Three execution errors observed.',next_action:'Restore the handler dependency.',limits:['Only recorded completions were assessed.']};
  route('/sessions/sess-claude-1/overview',()=>({ok:true,json:async()=>({session_id:'sess-claude-1',requests:[],findings:[],hook_ingestion:ingestion,hook_health:{available:true,since:iso(1800000),until:iso(0),observed_runs:3,unattributed_runs:0,truncated:false,findings:[finding]}})}));
  route('/sessions/sess-claude-1/hooks',()=>({ok:true,json:async()=>[{...finding,runs:3,errors:3,blocks:0,cancelled:0,chars:0,total_ms:0,duration_samples:3,char_samples:0}]}));
  let failed=false,holdRead=false,releaseRead,clipboardFail=false,holdClipboard=false,releaseClipboard;
  const writes=[];
  Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:text=>{
    if(clipboardFail) return Promise.reject(new Error('Clipboard denied'));
    writes.push(text);
    return holdClipboard?new Promise(resolve=>{releaseClipboard=resolve;}):Promise.resolve();
  }}});
  route('/sessions/sess-claude-1/hook-evidence',({query})=>{
    const result=()=>({ok:!failed,status:failed?503:200,json:async()=>({session_id:'sess-claude-1',filter:{harness:query.get('harness'),event:query.get('event'),event_scope:query.get('event_scope'),handler_id:query.get('handler_id'),config_id:query.get('config_id'),script:query.get('script'),...(query.has('verify_after')?{verify_after:query.get('verify_after')}:{})},since:iso(1800000),until:iso(0),truncated:false,rows:[{id:'run-1',ts:iso(5000),status:'error',duration_ms:0,evidence:{handler_id:'handler-1',config_id:'revision-1',duration_known:true,chars_known:false,reason_code:'timeout'},output:'PRIVATE_OUTPUT'}],...(query.has('verify_after')?{verification:{state:'successful-completion',title:'Successful completion observed',detail:'A newer completion succeeded.',config_id:'revision-1',observed_at:iso(1000),run_ids:['new-run'],truncated:false,limits:['This does not establish lasting repair or protection coverage.']}}:{})})});
    return holdRead?new Promise(resolve=>{releaseRead=()=>resolve(result());}):result();
  });
  ready().then(async()=>{
    const probe={};
    try {
      const button=()=>document.querySelector('#drawer-foot [data-action="hook-diagnostic-copy"]');
      const preview=()=>document.querySelector('.hook-diagnostic-preview textarea');
      const copied=()=>document.querySelector('#hook-diagnostic-status')?.textContent.includes('copied');
      openTab('sessions');await window.selectSession('sess-claude-1');await window.setSessionView('hooks');await idle();
      const detail=document.querySelector('#session-detail');
      const evidence=()=>detail.querySelector('[data-action="hook-evidence"]');
      evidence().click();await wait(()=>button()&&!button().disabled);
      const expected=preview().value;
      button().click();await wait(copied);
      probe.copy=writes[0]===expected && expected.includes('handler-1') && expected.includes('Returned characters: unknown') && expected.includes('0ms');
      probe.metadata=!expected.includes('/private/guard.py') && !expected.includes('PRIVATE_OUTPUT');
      clipboardFail=true;button().click();await wait(()=>document.querySelector('#hook-diagnostic-status')?.textContent.includes('Copy failed'));
      probe.failure=document.querySelector('.hook-diagnostic-preview').open && document.activeElement===preview() && preview().selectionStart===0 && preview().selectionEnd===expected.length && !button().disabled;
      clipboardFail=false;button().click();await wait(copied);probe.retry=writes.at(-1)===expected;
      failed=true;document.querySelector('#drawer-foot [data-action="hook-evidence"]').click();
      probe.cleared=button().disabled && !preview();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('Hook evidence unavailable'));
      probe.readFailure=button().disabled && !preview();
      failed=false;document.querySelector('#drawer-foot [data-action="hook-evidence"]').click();await wait(()=>button()&&!button().disabled);
      probe.readRetry=!!preview();
      document.querySelector('#btn-drawer-close').click();
      detail.querySelector('[data-action="hook-repair-check"]').click();await wait(()=>button()&&!button().disabled);
      const repair=preview().value;button().click();await wait(copied);
      probe.repair=writes.at(-1)===repair && repair.includes('Original failure: Hook repeatedly failed') && repair.includes('Original guidance: Restore the handler dependency.') && repair.includes('Successful completion observed') && repair.includes('lasting repair');
      document.querySelector('#btn-drawer-close').click();openTab('home');
      document.querySelector('.hook-monitoring [data-action="hook-delivery-inspect"][data-id="host-1"]').click();await wait(()=>button()&&!button().disabled);
      const delivery=preview().value;button().click();await wait(copied);
      probe.delivery=writes.at(-1)===delivery && delivery.includes('Session: not supplied') && delivery.includes('Restore recorder storage.') && delivery.includes('cumulative') && delivery.includes('dropped');
      document.querySelector('.hook-diagnostic-preview').open=true;
      probe.fits=document.documentElement.scrollWidth<=innerWidth && document.querySelector('#drawer-body').scrollWidth<=document.querySelector('#drawer-body').clientWidth;
      if(scenarios.has('diagnosticshot')) {preview().scrollIntoView();document.body.dataset.diagnosticProbe=JSON.stringify(probe);return;}
      document.querySelector('#btn-drawer-close').click();openTab('sessions');
      evidence().click();await wait(()=>button()&&!button().disabled);
      holdClipboard=true;button().click();await wait(()=>!!releaseClipboard);
      probe.busy=button().disabled;
      document.querySelector('#btn-drawer-close').click();detail.querySelector('[data-action="hook-setup"]').click();releaseClipboard();await idle();holdClipboard=false;
      probe.copyOwnership=document.querySelector('#drawer-title-text').textContent.includes('setup') && !button() && !document.querySelector('#hook-diagnostic-status');
      document.querySelector('#btn-drawer-close').click();
      holdRead=true;evidence().click();await wait(()=>!!releaseRead);
      probe.loading=button().disabled && !preview();
      document.querySelector('#btn-drawer-close').click();detail.querySelector('[data-action="hook-setup"]').click();releaseRead();await idle();
      probe.readOwnership=document.querySelector('#drawer-title-text').textContent.includes('setup') && !button() && !preview();
    } catch(error) {probe.error=error.message;}
    document.body.dataset.diagnosticProbe=JSON.stringify(probe);
  });
})();
