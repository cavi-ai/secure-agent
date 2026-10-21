(() => {
 const {route,ready,idle,openTab,realFetch,wait}=window.DomTest;
 const response=v=>new Response(JSON.stringify(v),{headers:{'Content-Type':'application/json'}});
 const state={enabled:true,reachable:true,model:'fixture-model',resources:{active:false,queued:0,context_tokens:32768,idle_seconds:120,background_remaining_ms:120000,background_paused:false},residency:{available:true,loaded:true,bytes:2147483648},session:{id:4,messages:2},classifier:{configured:true,state:'unavailable'}};
 let controls=[],forgotten=false;
 route('/agent/status',()=>response(state));
 route('/agent/control',(init)=>{controls.push(JSON.parse(init.body).action);state.resources.background_paused=controls.at(-1)==='pause';return response(state.resources);});
 route('/agent/memory',(init)=>{if(init?.method==='DELETE')forgotten=true;return response({facts:forgotten?[]:[{id:1,summary:'Recorded worktree check',references:['worktree:fixture'],at:'2026-10-21T12:00:00Z'}],sessions:[]});});
 (async()=>{
  const receipt={};
  try{
   await ready();openTab('agent');await idle();await realFetch('/__console_frame_checkpoint',{cache:'no-store'});
   await wait(()=>document.getElementById('agent-resource-state').textContent.includes('GB'),100);
   receipt.loaded=document.getElementById('agent-resource-state').textContent.includes('2.0 GB');
   receipt.session=document.getElementById('agent-session-state').textContent.includes('2 of 8 turns');
   document.getElementById('agent-pause').click();await idle();await realFetch('/__console_frame_checkpoint',{cache:'no-store'});
   receipt.paused=controls.includes('pause') && document.getElementById('agent-pause').textContent.includes('Resume');
   document.getElementById('agent-pause').click();await idle();await realFetch('/__console_frame_checkpoint',{cache:'no-store'});receipt.resumed=controls.includes('resume');
   document.querySelector('[data-action="agent-panel"][data-panel="tools"]').click();await idle();await realFetch('/__console_frame_checkpoint',{cache:'no-store'});
   receipt.classifier=document.getElementById('agent-classifier-state').textContent.includes('unavailable');
   document.querySelector('[data-action="agent-panel"][data-panel="history"]').click();await idle();await realFetch('/__console_frame_checkpoint',{cache:'no-store'});
   document.querySelector('#agent-memory').closest('details').open=true;
   receipt.memory=document.getElementById('agent-memory').textContent.includes('Recorded worktree check');
   const search=document.getElementById('agent-memory-query');search.value='no match';search.dispatchEvent(new Event('input'));
   receipt.search=!document.getElementById('agent-memory').textContent.includes('Recorded worktree check');
   receipt.observed=document.getElementById('agent-resource-state').textContent;receipt.errorText=document.getElementById('agent-state').textContent;
   receipt.bounds=document.documentElement.scrollWidth<=document.documentElement.clientWidth;
   await realFetch('/__console_frame_checkpoint',{cache:'no-store'});
  }catch(e){receipt.error=String(e.stack||e)}
  document.body.dataset.agentResources=JSON.stringify(receipt);
 })();
})();