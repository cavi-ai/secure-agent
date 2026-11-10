// Live local-model activity distinguishes residency, sockets and routed requests.
function createLocalInference({request,drawer,generation,ended}) {
  let active=null, timer=null;
  const text=value=>escapeHTML(String(value??'Not reported'));
  const current=state=>active===state && !ended() && state.generation===generation() && state.seq===drawer.seq();
  const stateName=value=>text(String(value||'unknown').replaceAll('_',' '));
  function valid(report) {
    const string=value=>typeof value==='string';
    return report && Number.isFinite(Date.parse(report.generated_at)) && report.coverage?.requests==='routed_only'
      && ['discovery','connections'].every(key=>string(report.coverage[key]))
      && typeof report.coverage.truncated==='boolean' && Number.isInteger(report.coverage.pending_endpoints)
      && Array.isArray(report.servers) && report.servers.length<=128 && report.servers.every(s=>string(s.endpoint)&&string(s.runtime)&&string(s.metadata)&&Array.isArray(s.loaded_models)&&s.loaded_models.length<=128&&s.loaded_models.every(m=>string(m.name)))
      && Array.isArray(report.connections) && report.connections.length<=2048 && report.connections.every(c=>Number.isInteger(c.pid)&&string(c.endpoint))
      && Array.isArray(report.requests) && report.requests.length<=192 && report.requests.every(r=>string(r.id)&&string(r.state)&&string(r.endpoint))
      && Array.isArray(report.gateways) && report.gateways.length<=4 && report.gateways.every(g=>string(g.listen)&&string(g.upstream)&&string(g.state));
  }
  function paint(state) {
    let body='<p>Loaded models, connected apps and observed requests are separate signals. Request tracking covers configured gateways; direct traffic can contain inference that this view cannot identify.</p>';
    if(state.error) body+=`<p role="alert">${text(state.error)}</p>`;
    if(state.report && !state.error) {
      const report=state.report, coverage=report.coverage;
      body+=`<p>Discovery: ${stateName(coverage.discovery)} · Connections: ${stateName(coverage.connections)}</p>`;
      if(coverage.truncated)body+='<p role="status">Observation limits were reached. Coverage is partial.</p>';
      if(coverage.pending_endpoints)body+=`<p role="status">${text(coverage.pending_endpoints)} endpoint candidates await another metadata batch.</p>`;
      if(coverage.unclassified_listeners)body+=`<p role="status">${text(coverage.unclassified_listeners)} other listeners remain unclassified. Add a model endpoint to the monitoring configuration to select it explicitly.</p>`;
      body+='<section><h3>Loaded models</h3>';
      if(!report.servers.length)body+='<p>No model servers identified in the current observations.</p>';
      for(const server of report.servers) {
        body+=`<article class="monitoring-diagnostic-check"><strong>${text(server.endpoint)}</strong><p>${text(server.runtime)} · Metadata: ${stateName(server.metadata)}</p>`;
        body+=server.loaded_models.length?`<ul>${server.loaded_models.map(m=>`<li>${text(m.name)}</li>`).join('')}</ul>`:'<p>No loaded models reported.</p>';
        if(Date.parse(server.observed_at)>0)body+=`<p>Metadata observed: ${text(new Date(server.observed_at).toLocaleString())}</p>`;
        body+='</article>';
      }
      body+='</section><section><h3>Connected clients</h3><p>A connection can be idle and does not prove inference.</p>';
      body+=report.connections.length?report.connections.map(c=>`<p>PID ${text(c.pid)} ${text(c.process||'App not identified')} → ${text(c.endpoint)}</p>`).join(''):'<p>No client connections observed in the latest sample. Short requests can occur between samples.</p>';
      const running=report.requests.filter(r=>!r.ended_at), recent=report.requests.filter(r=>r.ended_at).slice(-20).reverse();
      const requestRow=r=>`<article class="monitoring-diagnostic-check"><strong>${text(r.model||'Model not identified')} · ${stateName(r.state)}</strong><p>${text(r.endpoint)} · ${r.pid?`PID ${text(r.pid)}`:'Client not attributed'}${r.session_id?` · Session ${text(r.session_id)}`:''}</p><p>Execution: ${stateName(r.execution)}${Number.isInteger(r.input_tokens)?` · Input tokens: ${text(r.input_tokens)}`:''}${Number.isInteger(r.output_tokens)?` · Output tokens: ${text(r.output_tokens)}`:''}${r.usage_parsing==='partial'?' · Usage parsing incomplete':''}</p></article>`;
      body+='</section><section><h3>Requests in progress</h3>';
      body+=running.length?running.map(requestRow).join(''):'<p>No requests observed in progress through configured gateways.</p>';
      body+='</section><section><h3>Gateways</h3>';
      body+=report.gateways.length?report.gateways.map(g=>`<article class="monitoring-diagnostic-check"><strong>${text(g.listen)} → ${text(g.upstream)}</strong><p>${stateName(g.state)} · Gateway authentication does not isolate the direct backend.</p></article>`).join(''):'<p>No gateway configured. Use the local inference configuration to enable request tracking.</p>';
      body+='</section>';
      if(recent.length)body+=`<details><summary>Recent requests in this daemon run</summary>${recent.map(requestRow).join('')}</details>`;
    } else if(!state.error)body+='<p role="status">Loading local inference activity…</p>';
    if(drawer.body && current(state)) {
      const scroll=drawer.body.scrollTop;drawer.body.innerHTML=body;drawer.body.scrollTop=scroll;
    } else {
      drawer.setMode('local-inference');
      drawer.open({title:'Local inference',icon:'activity',back:state.back,body,foot:'<button type="button" class="btn btn-ghost" data-action="local-inference-refresh">Refresh activity</button>'});
      state.seq=drawer.seq();
    }
  }
  async function load(state) {
    if(!current(state) || state.busy)return;
    state.busy=true;
    try {
      const response=await request('/local-inference');
      if(!response.ok)throw new Error('Local inference monitoring is unavailable. Check that it is enabled and the daemon is running.');
      const report=await response.json();if(!current(state))return;
      if(!valid(report))throw new Error('Local inference observations are incomplete. Refresh before relying on this view.');
      state.report=report;state.error='';
    } catch(error) {if(current(state))state.error=error.message?.startsWith('Local inference')?error.message:'Local inference monitoring is unavailable.';}
    finally {
      state.busy=false;
      if(current(state)) {paint(state);timer=setTimeout(()=>load(state),5000);}
    }
  }
  async function open({back}={}) {
    clearTimeout(timer);
    const state=active={back,generation:generation(),report:null,error:'',busy:false};
    paint(state);drawer.afterClose?.(()=>clearTimeout(timer));await load(state);
  }
  return {open,refresh:()=>{clearTimeout(timer);return active&&current(active)?load(active):undefined;}};
}
