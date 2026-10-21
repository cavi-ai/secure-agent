// Diagnostics retain historical loss separately from current collector health.
function createMonitoringDiagnostics({ request, drawer, generation, ended, refresh }) {
  let active = null;
  const current = state => active === state && !ended() && state.generation === generation() && state.seq === drawer.seq();
  const date = value => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString() : 'Not recorded';
  const bytes = value => value >= 1000000 ? `${(value / 1000000).toFixed(1)} MB` : `${Number(value || 0).toLocaleString()} bytes`;
  async function json(url, options) {
    const response = await request(url, options);
    if (!response.ok) throw new Error('Monitoring diagnostics could not be loaded. Retry to obtain current evidence.');
    return response.json();
  }
  function paint(state) {
    const status = state.status || {}, es = status.es_service || {};
    const lost = status.bus_drops > 0 || es.bytes_lost > 0;
    const review = state.report?.loss_review;
    const canAcknowledge = state.report && lost && (review ? review.pending === true : status.bus_dropping || es.losing);
    const fact = (name, value) => `<div><dt>${escapeHTML(name)}</dt><dd>${escapeHTML(String(value))}</dd></div>`;
    const checks = state.report?.checks || [];
    const body = state.report ? `<p>${lost ? 'Monitoring history remains incomplete. Acknowledgement records that you reviewed the gap; it does not recover missing evidence.' : 'No delivery or file-event loss has been recorded in this daemon run.'}</p>
      ${review?.seen_at ? `<p role="status">Reviewed through ${escapeHTML(date(review.seen_at))}. Current delivery health is reported separately below.</p>` : ''}
      <section><h3>Event delivery</h3><dl class="monitoring-diagnostic-facts">
      ${fact('Missed deliveries', Number(status.bus_drops || 0).toLocaleString())}${fact('Last loss', date(status.bus_drop_at))}
      ${fact('Delivery pressure', status.bus_dropping ? 'Active' : 'No current pressure reported')}
      ${status.bus_drops ? fact('Loss source', 'Ingestion queue was full') : ''}</dl></section>
      <section><h3>File monitoring</h3><dl class="monitoring-diagnostic-facts">
      ${fact('Unread data lost', bytes(es.bytes_lost))}${fact('Last loss', date(es.lost_at))}
      ${es.loss_cause ? fact('Last loss cause', ({rotation:'Unread spool overwritten during rotation',truncation:'Unread spool truncated',invalid_record:'Unreadable spool record skipped',malformed_flood:'Malformed spool flood skipped'})[es.loss_cause] || 'Not recognized') : ''}
      ${fact('Collector', es.collector?.state || es.state || 'Not reported')}
      ${fact('Delivery lag', `${Number(es.lag_seconds || 0)} s`)}</dl></section>
      <section><h3>Diagnostic checks</h3>${checks.filter(check => check.state !== 'pass' || ['bus','file-telemetry','storage'].includes(check.id)).map(check => `<article class="monitoring-diagnostic-check"><strong>${escapeHTML(check.title)} · ${escapeHTML(check.state)}</strong><p>${escapeHTML(check.detail || '')}</p>${check.fix ? `<p>${escapeHTML(check.fix)}</p>` : ''}</article>`).join('')}</section>`
      : state.error ? '' : '<p role="status">Loading monitoring diagnostics…</p>';
    drawer.setMode('monitoring-diagnostics');
    drawer.open({ title: 'Monitoring diagnostics', icon: 'activity', back: state.back,
      body: body + (state.error ? `<p class="monitoring-diagnostic-error" role="alert">${escapeHTML(state.error)}</p>` : ''),
      foot: `<button type="button" class="btn btn-ghost" data-action="monitoring-diagnostics-refresh"${state.busy ? ' disabled' : ''}>Refresh diagnostics</button>`
        + (canAcknowledge ? `<button type="button" class="btn btn-primary" data-action="monitoring-loss-seen"${state.busy ? ' disabled' : ''}>${state.busy ? 'Acknowledging…' : 'Acknowledge earlier losses'}</button>` : ''),
    });
    state.seq = drawer.seq();
  }
  async function open({ back } = {}) {
    const state = active = { generation: generation(), back, report: null, busy: false, error: '' };
    paint(state);
    try {
      const [report, status] = await Promise.all([json('/doctor'), json('/status')]);
      if (!current(state)) return;
      if (!Array.isArray(report?.checks) || !Number.isFinite(Date.parse(report.generated_at)) || !status || typeof status !== 'object') throw new Error('Monitoring diagnostics are incomplete. Refresh before acknowledging losses.');
      state.report = report; state.status = status;
    } catch (error) {
      if (!current(state)) return;
      state.error = error.message || 'Monitoring diagnostics could not be loaded.';
    }
    if (current(state)) paint(state);
  }
  async function acknowledge() {
    const state = active;
    if (!state || !current(state) || state.busy || !state.report) return;
    state.busy = true; state.error = ''; paint(state);
    try {
      const receipt = await json('/doctor/seen', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({seen_at:state.report.generated_at}) });
      if (!current(state)) return;
      if (!receipt?.seen_at || Date.parse(receipt.seen_at) !== Date.parse(state.report.generated_at)) throw new Error('Acknowledgement could not be confirmed. Refresh diagnostics before retrying.');
      await refresh({ full:true });
      if (current(state)) await open({ back:state.back });
    } catch (error) {
      if (current(state)) { state.error = error.message || 'Acknowledgement could not be confirmed.'; }
    } finally {
      if (current(state)) { state.busy = false; paint(state); }
    }
  }
  return { open, acknowledge, refresh: () => open({back:active?.back}) };
}
