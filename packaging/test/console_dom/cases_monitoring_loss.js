// Exercise diagnostics through the console's real drawer and delegated actions.
(() => {
  const {data,route,ready,wait,iso,openTab} = window.DomTest;
  const displayed = iso(1000);
  Object.assign(data['/status'], {coverage:{sessions:[]},bus_drops:22,bus_drop_at:displayed,bus_dropping:true,
    es_service:{state:'running',bytes_lost:30937721,lost_at:displayed,loss_cause:'rotation',losing:true,lag_seconds:12}});
  data['/posture'].coverage_items = [{kind:'event_loss',id:'event-bus',title:'Telemetry was dropped',detail:'22 missed deliveries'}];
  const response = value => new Response(JSON.stringify(value), {headers:{'Content-Type':'application/json'}});
  let lossReview = {pending:true};
  route('/doctor', () => response({generated_at:displayed,loss_review:lossReview,checks:[{id:'bus',title:'Event bus',state:'fail',detail:'Ingestion queue was full'}]}));
  let cutoff = '';
  route('/doctor/seen', ({body}) => {
    cutoff = JSON.parse(body).seen_at;
    lossReview = {pending:false,seen_at:cutoff};
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
        probe.reviewed = document.getElementById('drawer-body').textContent.includes('Reviewed through');
        document.getElementById('btn-drawer-close').click();
        openTab('monitoring');
        await wait(() => !!document.querySelector('#monitoring-notice .warning'));
        probe.active = data['/status'].bus_dropping && data['/status'].es_service.losing;
        data['/status'].bus_dropping = false;
        data['/status'].es_service.losing = false;
        data['/posture'].coverage_items = [{kind:'event_loss',id:'event-bus',title:'Telemetry was dropped',detail:'22 missed deliveries',monitoring_state:'historical'}];
        document.getElementById('btn-refresh').click();
        await wait(() => !document.querySelector('#monitoring-notice .warning'));
        probe.neutral = !document.querySelector('#monitoring-notice .warning') && !!document.querySelector('#monitoring-notice [data-monitoring-action="diagnostics"]');
        if (!probe.neutral) probe.notice = {html:document.getElementById('monitoring-notice').innerHTML, issues:window.SA.t.posture.coverage_items};
        lossReview.pending = true;
        data['/status'].bus_drops++;
        data['/status'].bus_drop_at = iso(2000);
        document.querySelector('#monitoring-notice [data-monitoring-action="diagnostics"]').click();
        await wait(() => !!document.querySelector('#drawer-foot [data-action="monitoring-loss-seen"]'));
        probe.newLoss = true;
      }
    } catch (error) { probe.error = error.message; }
    document.body.dataset.monitoringLossProbe = JSON.stringify(probe);
  });
})();
