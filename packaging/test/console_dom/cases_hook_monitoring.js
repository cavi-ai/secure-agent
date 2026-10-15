// The real Home overview, navigation and refresh lifecycle against controlled
// status snapshots. Forwarding host scope must never select a guessed session.
(() => {
  const {data,iso,ready,wait,idle,route,openTab,scenarios}=window.DomTest;
  const initial={available:true,since:iso(60000),rejected:0,harnesses:[{harness:'claude',accepted:3,last_received_at:iso(1000)}],forwarders:[]};
  data['/status'].hook_ingestion=structuredClone(initial);
  data['/posture']={state:'all-clear',needs_you:0,coverage_count:0,items:[],groups:[],coverage_items:[]};
  let failed=false;
  route('/snapshot',()=>{if(failed) throw new Error('offline');});
  const report=(id,harness,state='connected',freshness='recent',dropped=0)=>({report:{type:'hook_forwarder',version:1,forwarder_id:id,harness,state,sequence:1,ts:iso(1000),pending:0,delivery_failures:2,dropped},received_at:iso(1000),freshness});
  const overview=()=>document.querySelector('.hook-monitoring');
  const refresh=async()=>{document.querySelector('#btn-refresh').click();await idle();await wait(()=>!window.SA.postureHealth.error);await idle();};
  ready().then(async()=>{
    const probe={};
    try {
      openTab('home');
      await wait(()=>!!overview());
      document.querySelector('[data-hook-disclosure="monitoring"]').open=true;
      probe.usedOnly=[...overview().querySelectorAll('[data-hook-runtime]')].map(r=>r.dataset.hookRuntime).sort().join(',')==='claude,codex';
      probe.neutral=document.querySelector('#coverage-center').dataset.gap==='false' && document.querySelector('#coverage-title').textContent==='Monitoring';
      probe.receipt=overview().textContent.includes('3 accepted deliveries') && overview().textContent.includes('across all sessions');
      probe.unknown=overview().querySelector('[data-hook-runtime="codex"]').textContent.includes('No completion received in this daemon run') && overview().textContent.includes('Forwarding state unknown');
      probe.limits=overview().textContent.includes('not confirm durable storage or protection coverage');
      const disclosure=overview().querySelector('[data-hook-disclosure="sessions:claude"]');
      disclosure.open=true;
      const sessionLink=disclosure.querySelector('[data-session="sess-claude-1"]');
      sessionLink.focus();
      data['/status'].hook_ingestion.harnesses[0].accepted=4;
      await refresh();
      probe.reading=overview().querySelector('[data-hook-disclosure="sessions:claude"]').open && document.activeElement.dataset.session==='sess-claude-1';
      overview().querySelector('[data-session="sess-claude-1"]').click();
      await wait(()=>window.SA.selectedSessionId==='sess-claude-1' && window.SA.sessionView==='hooks');
      probe.sessionLink=window.SA.selectedSessionId==='sess-claude-1' && window.SA.sessionView==='hooks';
      openTab('home');
      const h=data['/status'].hook_ingestion;
      h.forwarders=[report('codex-good','codex'),report('codex-bad','codex','error'),report('codex-old','codex','error','stale',1),report('hermes-host','hermes'),report('opencode-host','opencode'),report('openclaw-host','openclaw')];
      h.rejected=2;h.last_rejected_at=iso(1000);h.forwarders_truncated=true;
      await refresh();
      const codex=overview().querySelector('[data-hook-runtime="codex"]');
      probe.mixed=codex.textContent.includes('1 host with active errors') && codex.textContent.includes('1 host with unknown current state') && codex.textContent.includes('Evidence gap');
      probe.allSupported=overview().querySelectorAll('[data-hook-runtime]').length===5;
      probe.gapStyle=document.querySelector('#coverage-center').dataset.gap==='true';
      probe.unattributed=overview().textContent.includes('2 rejected shared records') && overview().textContent.includes('cannot be attributed to a runtime');
      probe.truncated=overview().textContent.includes('Other forwarding instances may be omitted');
      codex.querySelector('[data-hook-disclosure^="hosts:"]').open=true;
      codex.querySelector('[data-id="codex-bad"]').click();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('codex-bad'));
      probe.hostLink=document.querySelector('#drawer-body').textContent.includes('Session ID not supplied') && window.SA.selectedSessionId==='sess-claude-1';
      document.querySelector('#btn-drawer-close').click();
      overview().querySelector('[data-action="hook-setup"][data-harness="hermes"]').click();
      await wait(()=>document.querySelector('#drawer-body').textContent.includes('Hermes'));
      probe.setup=document.querySelector('#drawer-body').textContent.includes('Hermes') && !document.querySelector('#drawer-body').textContent.includes('OpenCode v1');
      document.querySelector('#btn-drawer-close').click();
      failed=true;document.querySelector('#btn-refresh').click();
      await wait(()=>!!window.SA.postureHealth.error);await idle();
      probe.stale=overview().textContent.includes('Last loaded observations') && !overview().textContent.includes('host with active errors') && overview().textContent.includes('Last known completion receipt');
      failed=false;
      overview().querySelector('[data-action="retry-posture"]').click();
      await wait(()=>!window.SA.postureHealth.error);await idle();
      probe.retry=overview().textContent.includes('host with active errors') && !overview().textContent.includes('Last loaded observations');
      if(scenarios.has('monitoringshot')) {for(const el of overview().querySelectorAll('details')) el.open=false; document.querySelector('#coverage-center').scrollIntoView();window.scrollBy(0,-160);document.body.dataset.monitoringProbe=JSON.stringify(probe);return;}
      data['/status'].hook_ingestion={...initial,since:iso(0),harnesses:[],forwarders:[]};
      await refresh();
      probe.restart=!overview().textContent.includes('4 accepted') && !overview().querySelector('[data-id="codex-bad"]') && overview().textContent.includes('No completion received in this daemon run');
      data['/status'].hook_ingestion={available:true,harnesses:'malformed'};
      await refresh();
      probe.malformed=overview().textContent.includes('Ingestion diagnostics unavailable') && !overview().querySelector('[data-action="hook-delivery-inspect"]');
      probe.fits=overview().scrollWidth<=overview().clientWidth && document.documentElement.scrollWidth<=innerWidth;
    } catch(error) {probe.error=error.message;}
    document.body.dataset.monitoringProbe=JSON.stringify(probe);
  });
})();
