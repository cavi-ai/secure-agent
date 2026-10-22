(() => {
  const {data, route, ready, idle, realFetch, openTab} = window.DomTest;
  ready().then(async () => {
    const probe = {};
    try {
      openTab('home'); await idle();
      const id = 'more-opener';
      const flag = {id,agent:'claude',rule:'credential-access',ts:new Date().toISOString(),
        explain:{actions:[{id:'dismiss',label:'Dismiss',recommended:true}]}};
      data['/flags'] = [flag]; window.SA.t.flags = [flag];
      const item = {kind:'flag',id,priority:2,title:'Credential access',detail:'Review recorded credential access'};
      let currentItems = [];
      const set = items => {
        currentItems = items;
        const posture = {...window.SA.t.posture,state:items.length?'attention':'all-clear',needs_you:items.length,
          items,groups:items.length?[{key:'session:claude',agent:'claude',items}]:[],coverage_count:0,coverage_items:[]};
        if (!items.length) posture.attention_summary = {version:1,buckets:['decisions','security','monitoring'].map(kind=>({kind,count:0,coverage_count:0}))};
        else delete posture.attention_summary;
        data['/posture']=posture; window.SA.t.posture=posture; renderAttention();
      };
      const row = () => document.querySelector('[data-need-key="flag:'+id+'"]');
      const close = () => document.getElementById('btn-drawer-close');
      const drawer = document.getElementById('drawer');
      const refreshOpener = async (suffix, block) => {
        set([{...item,detail:item.detail+suffix}]);
        row().querySelector('details.act-more').open = true;
        const opener = row().querySelector('[data-action="open-plan"]');
        opener.focus({preventScroll:true}); opener.click(); await idle();
        // The actual close button owns focus during the source refresh. A
        // list-render focus repair must not make this regression pass.
        close().focus({preventScroll:true});
        set([{...item,detail:item.detail+suffix+' updated'}]);
        const equivalent = row().querySelector('[data-action="open-plan"]');
        const disclosure = equivalent.closest('details');
        const wasClosed = !disclosure.open && !equivalent.checkVisibility();
        const before = {open:disclosure.open,rects:equivalent.getClientRects().length,visible:equivalent.checkVisibility(),same:opener===equivalent,drawer:!drawer.hidden};
        if (block) block(equivalent);
        close().click();
        return {equivalent,disclosure,wasClosed,before};
      };
      const restored = await refreshOpener(' first');
      probe.more = restored.wasClosed && document.activeElement===row().querySelector('.need-head')
        && document.activeElement.checkVisibility() && drawer.hidden;
      probe.moreState = {...restored.before,afterOpen:restored.disclosure.open,afterVisible:restored.equivalent.checkVisibility(),focus:document.activeElement.outerHTML.slice(0,180)};
      probe.unavailable = true;
      for (const [name,block] of [['disabled',el=>{el.disabled=true;}],['hidden',el=>{el.hidden=true;}],['inert',el=>{el.closest('.need-actions').inert=true;}]]) {
        const result = await refreshOpener(' '+name,block);
        probe.unavailable = probe.unavailable && result.wasClosed && document.activeElement===row().querySelector('.need-head')
          && document.activeElement.checkVisibility();
        (probe.unavailableState ||= {})[name]={...result.before,focus:document.activeElement.outerHTML.slice(0,100)};
      }
      route('/flags/acknowledge',({body})=>{
        set(currentItems.filter(it => it.id !== JSON.parse(body).flag_id));
        return {ok:true,status:200,json:async()=>({acknowledged:true})};
      });
      set([{...item,id:'first'},item,{...item,id:'successor'}]);
      row().querySelector('.need-head').focus({preventScroll:true});
      row().querySelector('.need-head').click(); await idle();
      await window.dismissFlag(id); await idle();
      probe.successor = window.SA.attentionKey==='flag:successor';
      close().focus({preventScroll:true}); close().click();
      probe.successor = probe.successor && document.activeElement.closest('[data-need-key]')?.dataset.needKey==='flag:successor';
      set([item]);
      row().querySelector('.need-head').focus({preventScroll:true});
      row().querySelector('.need-head').click(); await idle();
      await window.dismissFlag(id); await idle();
      await realFetch('/__console_frame_checkpoint',{cache:'no-store'});
      const before = scrollY;
      close().focus({preventScroll:true}); close().click();
      probe.empty = drawer.hidden && !row() && document.activeElement.id==='session-daily-title'
        && document.activeElement.getClientRects().length>0 && Math.abs(scrollY-before)<2;
    } catch(error) {probe.error=error.message;}
    document.body.dataset.attentionDrawerFocusProbe=JSON.stringify(probe);
  });
})();
