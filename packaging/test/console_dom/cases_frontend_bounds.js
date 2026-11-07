(() => {
  const {data, ready, idle, openTab, route, realFetch} = window.DomTest;
  const params = new URLSearchParams(location.search);
  const width = Number(params.get('boundswidth'));
  // The browser window has a 500px minimum; a same-origin iframe exercises
  // the console's actual CSS viewport below that minimum in file mode.
  if (window.parent === window && !params.has('boundschild')) {
    const frame = document.createElement('iframe');
    frame.width = String(width); frame.height = '1000'; frame.frameBorder = '0';
    frame.src = `harness.html?frontendbounds&boundschild&boundswidth=${width}`;
    window.addEventListener('message', event => {
      if (event.source === frame.contentWindow && event.data?.frontendBounds) {
        document.body.dataset.frontendBounds = JSON.stringify(event.data.frontendBounds);
      }
    });
    document.addEventListener('DOMContentLoaded', () => document.body.prepend(frame), {once:true});
    return;
  }
  const token = 'WorkspaceWithVeryLongUnbrokenIdentity'.repeat(8);
  const path = '/workspace/' + token;
  for (const session of data['/sessions']) Object.assign(session, {repo:token, branch:'feat/' + token, workspace:path});
  for (const agent of data['/status'].agents) if (agent.cwd) Object.assign(agent, {repo:token, branch:token, workspace:path, cwd:path});
  data['/status'].version = token;
  // Render actual error text from a rejected scope write without changing real data.
  route('/notify/rules', ({method}) => method === 'POST'
    ? {ok:false,status:400,text:async()=>path} : {ok:true,status:200,json:async()=>({rules:{},scopes:[]})});
  data['/agent/skills'][0] = {...data['/agent/skills'][0], title:token, summary:token, body:token};
  const visible = element => {
    if (!element || !element.getClientRects().length || element.closest('[hidden]') || getComputedStyle(element).visibility === 'hidden') return false;
    for (let p=element; p; p=p.parentElement) {
      if (p.tagName === 'DETAILS' && !p.open && !p.querySelector(':scope > summary')?.contains(element)) return false;
    }
    return true;
  };
  const name = element => element.id || element.className || element.tagName;
  const textSpill = container => {
    const bounds = container.getBoundingClientRect(), spill = [];
    for (const element of [container, ...container.querySelectorAll('*')]) {
      if (!visible(element)) continue;
      for (const node of element.childNodes) if (node.nodeType === Node.TEXT_NODE && node.textContent.trim()) {
        const range = document.createRange(); range.selectNodeContents(node);
        for (const rect of range.getClientRects()) {
          if (rect.right <= bounds.right + 1 && rect.left >= bounds.left - 1) continue;
          // Intentional local ellipsis/scroll regions constrain painted text.
          let clipped = false;
          for (let parent=element; parent && parent!==container; parent=parent.parentElement) {
            const style=getComputedStyle(parent), box=parent.getBoundingClientRect();
            if (['auto','scroll','hidden','clip'].includes(style.overflowX)
                && (rect.right > box.right + 1 || rect.left < box.left - 1)) {clipped=true; break;}
          }
          if (!clipped) spill.push({element:name(element),left:rect.left,right:rect.right});
        }
      }
    }
    return spill.slice(0,8);
  };
  const settle = async () => {
    await idle();
    if (location.protocol === 'file:') await new Promise(resolve => setTimeout(resolve, 50));
    else await realFetch('/__console_frame_checkpoint');
    document.getAnimations().forEach(a=>{if(a.effect?.getComputedTiming().endTime!==Infinity)a.finish();});
  };
  ready().then(async () => {
    const probe = {viewport:innerWidth,expected:width,surfaces:[],unnamed:[]};
    const measure = (state, selectors) => {
      for (const selector of selectors) for (const element of document.querySelectorAll(selector)) if (visible(element)) {
        const box = element.getBoundingClientRect();
        probe.surfaces.push({state,selector,left:box.left,right:box.right,client:element.clientWidth,scroll:element.scrollWidth,textSpill:textSpill(element)});
      }
    };
    const checkNames = () => {
      for (const element of document.querySelectorAll('button,input:not([type="hidden"]),select,textarea')) if (visible(element)) {
        const label = element.getAttribute('aria-label') || element.getAttribute('title')
          || element.getAttribute('aria-labelledby')?.split(/\s+/).map(id=>document.getElementById(id)?.textContent).join(' ')
          || element.labels?.[0]?.textContent || (element.tagName === 'BUTTON' ? element.textContent : '');
        if (!label?.trim()) probe.unnamed.push(name(element));
      }
    };
    try {
      document.querySelector('.sidebar-summary').open = true;
      for (const tab of ['home','sessions/board','monitoring','protection/rules','protection/sources','sessions/events','findings']) {
        openTab(tab); await settle(); checkNames();
        measure(tab,['#console-sidebar','#session-rail','.monitoring-rail','.monitoring-detail']);
      }
      probe.notificationName = document.getElementById('notify-scope-path')?.getAttribute('aria-label');
      probe.controlNames = ['flags-agent','flags-rule','flags-severity','flags-window','activity-window','event-filter','event-window','source-input'].every(id=>!!document.getElementById(id)?.getAttribute('aria-label')?.trim());
      openTab('agent'); await settle();
      await window.showAgentSkill(data['/agent/skills'][0].id); await settle();
      measure('skill',['.drawer-head','.drawer-body']);
      probe.skillTitle = document.getElementById('drawer-title-text')?.textContent === token;
      probe.drawerClose = visible(document.getElementById('btn-drawer-close'));
      window.saCloseDrawer(); await settle();
      const confirmation = window.saConfirm(path, {title:token,okLabel:'Confirm'});
      await settle(); measure('confirmation',['.confirm-card','#confirm-message']);
      probe.confirmTitle = document.getElementById('confirm-title')?.textContent === token;
      probe.confirmCancel = visible(document.getElementById('confirm-cancel'));
      document.getElementById('confirm-cancel').click();
      probe.cancelled = await confirmation === false;
      await window.removeNotifyScope('proxy-secret-leak',path); await settle();
      measure('error-toast',['.toast']);
      probe.errorToast = document.querySelector('.toast.danger')?.textContent.includes(path) === true;
      openTab('system/worktrees'); await settle();
      const removable = data['/worktrees'].repos[0].worktrees.find(w=>w.state==='remove');
      const removal = window.removeWorktree(removable.path,removable.branch);
      await settle(); document.getElementById('confirm-ok').click(); await removal; await settle();
      measure('removal-toast',['#removal-toast']);
      probe.removalToast = !!document.getElementById('removal-toast');
      probe.pageFits = document.documentElement.scrollWidth <= document.documentElement.clientWidth;
    } catch(error) {probe.error=error.message;}
    probe.bounded = probe.surfaces.length > 0 && probe.surfaces.every(s=>s.left>=-1 && s.right<=innerWidth+1 && s.scroll<=s.client+1 && !s.textSpill.length);
    probe.named = probe.unnamed.length === 0 && !!probe.notificationName && probe.controlNames;
    document.body.dataset.frontendBounds = JSON.stringify(probe);
    window.parent.postMessage({frontendBounds:probe}, '*');
  });
})();
