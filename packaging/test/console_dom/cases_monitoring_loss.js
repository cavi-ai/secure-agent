// Exercise diagnostics through the console's real drawer and delegated actions.
(() => {
  const {data,route,ready,wait,iso,openTab} = window.DomTest;
  const displayed = iso(1000);
  Object.assign(data['/status'], {coverage:{sessions:[]},bus_drops:22,bus_drop_at:displayed,bus_dropping:true,
    es_service:{state:'running',bytes_lost:30937721,lost_at:displayed,loss_cause:'rotation',losing:true,lag_seconds:12}});
  data['/posture'].coverage_items = [{kind:'event_loss',id:'event-bus',title:'Telemetry was dropped',detail:'22 missed deliveries'}];
  const response = value => new Response(JSON.stringify(value), {headers:{'Content-Type':'application/json'}});
  route('/doctor', () => response({generated_at:displayed,checks:[{id:'bus',title:'Event bus',state:'fail',detail:'Ingestion queue was full'}]}));
  let cutoff = '';
  route('/doctor/seen', ({body}) => {
    cutoff = JSON.parse(body).seen_at;
    data['/status'].bus_dropping = false;
    data['/status'].es_service.losing = false;
    data['/posture'].coverage_items = [];
    return response({seen_at:cutoff});
  });
  ready().then(async () => {
    const probe = {};
    try {
      document.querySelector('#coverage-list [data-action="monitoring-diagnostics"]').click();
      await wait(() => !!document.querySelector('#drawer-foot [data-action="monitoring-loss-seen"]'));
      probe.open = document.getElementById('drawer-title-text').textContent === 'Monitoring diagnostics';
      probe.loss = document.getElementById('drawer-body').textContent.includes('30.9 MB') && document.getElementById('drawer-body').textContent.includes('Unread spool overwritten during rotation');
      probe.fits = document.documentElement.scrollWidth <= innerWidth;
      if (!new URLSearchParams(location.search).has('shot')) {
        document.querySelector('#drawer-foot [data-action="monitoring-loss-seen"]').click();
        await wait(() => cutoff !== '' && !document.querySelector('#drawer-foot [data-action="monitoring-loss-seen"]'));
        probe.cutoff = cutoff === displayed;
        probe.retained = document.getElementById('drawer-body').textContent.includes('history remains incomplete') && document.getElementById('drawer-body').textContent.includes('30.9 MB');
        document.getElementById('btn-drawer-close').click();
        openTab('monitoring');
        await wait(() => document.getElementById('monitoring-notice').textContent.includes('Monitoring history is incomplete'));
        probe.neutral = !document.querySelector('#monitoring-notice .warning') && !!document.querySelector('#monitoring-notice [data-monitoring-action="diagnostics"]');
        if (!probe.neutral) probe.notice = {html:document.getElementById('monitoring-notice').innerHTML, issues:window.SA.t.posture.coverage_items};
      }
    } catch (error) { probe.error = error.message; }
    document.body.dataset.monitoringLossProbe = JSON.stringify(probe);
  });
})();
