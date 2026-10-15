// Exercise native controls against retained metadata in the real console.
(() => {
  const { route, ready, wait, idle, openTab, iso, scenarios } = window.DomTest;
  const group = (script, extra={}) => ({harness:'claude',event:'PreToolUse',script,handler_id:script+'-id',config_id:'revision-1',runs:3,errors:0,blocks:0,cancelled:0,chars:0,total_ms:0,duration_samples:0,char_samples:0,last_at:iso(0),...extra});
  let rows=[group('unknown.py'),group('guard.py',{errors:2,runs:5,total_ms:400,duration_samples:3}),group('zero.py',{duration_samples:3,char_samples:3,blocks:1}),group('cancel.py',{cancelled:1,chars:90,char_samples:1})];
  let failed=false, hold=false, release;
  route('/sessions/sess-claude-1/hooks',()=> {
    const result=()=>({ok:!failed,status:failed?503:200,json:async()=>structuredClone(rows)});
    return hold ? new Promise(resolve=>{release=()=>resolve(result());}) : result();
  });
  route('/sessions/sess-cursor-2/hooks',()=>({ok:true,json:async()=>[]}));
  ready().then(async()=>{
    const probe={};
    try {
      openTab('sessions'); await window.selectSession('sess-claude-1');
      await window.setSessionView('hooks'); await idle();
      const detail=document.querySelector('#session-detail');
      const input=key=>detail.querySelector(`[data-hook-history="${key}"]`);
      const set=async(key,value)=>{const el=input(key);el.value=value;el.dispatchEvent(new Event(key==='query'?'input':'change',{bubbles:true}));await idle();};
      const scripts=()=>[...detail.querySelectorAll('.sd-hooks tbody tr')].map(el=>el.querySelector('[data-label="Handler"]').firstChild.textContent);
      const refresh=async()=>{window.setSessionView('hooks');await wait(()=>!window.SA.sessionHooksState.loading);await idle();};
      probe.initial=scripts().join(',')==='guard.py,cancel.py,unknown.py,zero.py';
      await set('outcome','errors');
      probe.errors=scripts().join(',')==='guard.py' && detail.textContent.includes('1 of 4');
      await set('outcome','blocks');probe.blocks=scripts().join(',')==='zero.py';
      await set('outcome','cancelled');probe.cancelled=scripts().join(',')==='cancel.py';
      await set('outcome','all');
      await set('sort','total_ms');probe.runtime=scripts().join(',')==='guard.py,zero.py,cancel.py,unknown.py';
      await set('sort','chars');probe.chars=scripts().join(',')==='cancel.py,zero.py,guard.py,unknown.py';
      const search=input('query');search.focus();
      await set('query','GUARD.PY-ID');
      probe.search=scripts().join(',')==='guard.py' && document.activeElement===search && input('query')===search;
      await set('query','<img src=x onerror=alert(1)>');
      probe.empty=detail.textContent.includes('No hook groups match') && detail.textContent.includes('0 of 4') && !detail.querySelector('.sd-hooks img');
      await set('query','guard');
      const disclosure=detail.querySelector('.sd-hooks details');disclosure.open=true;
      rows=rows.map(r=>r.script==='guard.py'?{...r,runs:6}:r);
      await refresh();
      probe.refresh=input('query')===search && input('query').value==='guard' && document.activeElement===search && detail.querySelector('.sd-hooks details').open;
      failed=true;await refresh();
      probe.stale=detail.textContent.includes('last loaded totals') && scripts().join(',')==='guard.py' && input('query').value==='guard';
      failed=false;detail.querySelector('[data-action="session-hooks-retry"]').click();
      await wait(()=>!window.SA.sessionHooksState.error);await idle();
      probe.retry=!detail.textContent.includes('last loaded totals') && input('query').value==='guard';
      detail.querySelector('[data-action="hook-history-clear"]').click();await idle();
      probe.clear=input('query').value==='' && input('sort').value==='runs' && input('outcome').value==='all' && scripts().length===4;
      probe.mobile=innerWidth>700 || (getComputedStyle(detail.querySelector('.sd-hooks tbody tr')).display==='grid' && detail.querySelector('.sd-hooks-scroll').scrollWidth<=detail.querySelector('.sd-hooks-scroll').clientWidth);
      probe.fits=document.documentElement.scrollWidth<=innerWidth;
      if(scenarios.has('historyshot')) {detail.querySelector('[data-session-part="hooks-controls"]').scrollIntoView();document.body.dataset.historyProbe=JSON.stringify(probe);return;}
      await set('query','guard');hold=true;window.setSessionView('hooks');await wait(()=>!!release);
      await window.selectSession('sess-cursor-2');release();await idle();
      probe.selection=input('query').value==='' && input('outcome').value==='all' && detail.textContent.includes('No hook runs recorded') && !detail.querySelector('.sd-hooks');
    } catch(error) {probe.error=error.message;}
    document.body.dataset.historyProbe=JSON.stringify(probe);
  });
})();
