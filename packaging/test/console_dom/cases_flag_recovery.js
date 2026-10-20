(() => {
  const {data, route, ready, idle, wait, openTab} = window.DomTest;
  const probe = {};
  ready().then(async () => {
    try {
      const sample = data['/flags'][0];
      const preview = await fetch(`/flags/${sample.id}/explain`);
      probe.previewEvidence = preview.ok && (await preview.json()).id === sample.id;
      probe.previewLabel = document.getElementById('fixture-notice')?.textContent.includes('Synthetic preview');
      const item = {kind:'flag', id:'retained-flag', priority:2, title:'Credential access requires review', detail:'Recorded credential access', rule:'credential-access', session_id:'sess-claude-1'};
      const group = {key:'session:claude', agent:'claude', workspace:'/workspace/app', items:[item]};
      data['/posture'] = {...data['/posture'], needs_you:1, items:[item], groups:[group]};
      data['/flags'] = [];
      let status = 200, acknowledge = false;
      const response = (status, value) => ({ok:status===200, status, json:async()=>value, text:async()=>status===200 ? JSON.stringify(value) : 'Saved flag data unavailable'});
      route('/flags/retained-flag/explain', () => response(status, {...item, agent:'claude', ts:new Date().toISOString(), severity:3, evidence:['Recorded file read']}));
      route('/flags/acknowledge', ({body}) => {
        const exact = JSON.parse(body).flag_id === item.id;
        if (acknowledge && exact) Object.assign(data['/posture'], {needs_you:0, items:[], groups:[]});
        return response(200, {status:'ok', acknowledged:acknowledge && exact});
      });
      openTab('home');
      const refresh = async () => {document.getElementById('btn-refresh').click(); await idle();};
      await refresh();
      const row = () => document.querySelector('[data-need-key="flag:retained-flag"]');
      probe.queueActions = !!row()?.querySelector('[data-action="dismiss-flag"]') && !row().querySelector('.need-meta').textContent.includes('critical');
      row().querySelector('[data-action="open-flag"]').click(); await idle();
      probe.retainedEvidence = document.getElementById('drawer-body').textContent.includes('Recorded file read');
      status = 404;
      await window.openFlagDetail(item.id); await idle();
      const body = () => document.getElementById('drawer-body');
      probe.missing = body().textContent.includes('Evidence unavailable') && body().textContent.includes(item.id) && document.getElementById('drawer-title-text').textContent.includes(item.title)
        && !!body().querySelector('[data-action="open-flag"]') && !!body().querySelector('[data-action="refresh-finding-queue"]')
        && !body().querySelector('[data-action="dismiss-flag"]');
      status = 503;
      body().querySelector('[data-action="open-flag"]').click(); await idle();
      probe.unavailable = body().textContent.includes('Evidence could not be loaded') && body().textContent.includes(item.id)
        && !!body().querySelector('[data-action="dismiss-flag"]');
      status = 200;
      body().querySelector('[data-action="open-flag"]').click(); await idle();
      probe.retry = body().textContent.includes('Recorded file read');
      await window.dismissFlag(item.id); await idle();
      probe.rejected = !!row() && document.getElementById('toast-container').textContent.includes('not marked reviewed');
      acknowledge = true;
      await window.dismissFlag(item.id); await idle();
      probe.dismissed = await wait(() => !row() && window.SA.t.posture.needs_you === 0);
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
    } catch (error) {probe.error = error.message;}
    document.body.dataset.flagRecoveryProbe = JSON.stringify(probe);
  });
})();
