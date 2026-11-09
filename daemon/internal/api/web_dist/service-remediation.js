// A reviewed service operation is bound to the displayed owner/source identity.
function createServiceRemediation({request,drawer,generation,ended,confirm}) {
  let active=null;
  const current=state=>active===state&&!ended()&&state.generation===generation()&&state.seq===drawer.seq();
  const text=value=>escapeHTML(String(value??''));
  const validPreview=value=>value&&['id','preview_hash','label','source','endpoint'].every(key=>typeof value[key]==='string'&&value[key].length>0)
    && ['authenticated_inference','browser_hardening'].includes(value.change?.scope)
    && Array.isArray(value.client_fields)&&value.client_fields.every(item=>typeof item==='string')
    && Array.isArray(value.warnings)&&value.warnings.every(item=>typeof item==='string');
  const validReceipt=value=>validPreview(value)&&['prepared','applying','verified','restored_stopped','failed_restored_stopped','failed_no_change','rollback_required'].includes(value.state)
    && Array.isArray(value.checks)&&value.checks.every(item=>typeof item==='string')
    && (value.state!=='verified'||Number.isFinite(Date.parse(value.verified_at)));
  function paint(state) {
    const preview=state.preview,receipt=state.receipt;
    const list=items=>`<ul>${items.map(item=>`<li>${text(item)}</li>`).join('')}</ul>`;
    let body='<p>Review hardening for a running model service owned by your macOS user. Direct MLX-LM, llama.cpp and Ollama launchd jobs are supported. Other launchers are left unchanged.</p>';
    if(receipt) {
      body+=`<section class="monitoring-diagnostic-check"><h3>${text(receipt.label)}</h3><p>${text(receipt.state)}</p>`;
      if(receipt.state==='verified')body+=`<p>Last verified ${text(new Date(receipt.verified_at).toLocaleString())}. ${receipt.change.scope==='browser_hardening'?'Browser hardening only; the local API remains unauthenticated.':'Authentication and direct-backend checks passed for this service at that time.'}</p>${list(receipt.checks)}`;
      if(receipt.state==='restored_stopped'||receipt.state==='failed_restored_stopped')body+='<p>Original settings were restored. The service is stopped; starting the original service is a separate owner action.</p>';
      if(receipt.failure)body+=`<p role="alert">${text(receipt.failure)}</p>`;
      body+='</section>';
    } else if(preview) {
      body+=`<section><h3>Review before restart</h3><dl class="monitoring-diagnostic-facts"><div><dt>Service</dt><dd>${text(preview.label)}</dd></div><div><dt>Definition</dt><dd>${text(preview.source)}</dd></div><div><dt>Endpoint</dt><dd>${text(preview.endpoint)}</dd></div><div><dt>Protection scope</dt><dd>${text(preview.change.scope.replaceAll('_',' '))}</dd></div></dl>
        <h4>Settings to apply</h4>${list(preview.settings||[])}<h4>Secure Agent client fields to update</h4>${preview.client_fields.length?list(preview.client_fields):'<p>No matching client fields require changes.</p>'}${list(preview.warnings)}</section>`;
    } else {
      body+=`<label for="service-remediation-source">Launchd service definition file</label><input class="service-remediation-input" id="service-remediation-source" type="text" autocomplete="off" spellcheck="false" placeholder="Absolute path to model.plist" value="${text(state.source)}">
        <p>Only the selected running job is changed. A preview reads its definition and capabilities without restarting it.</p>
        <label for="service-remediation-label">Previously remediated service label</label><input class="service-remediation-input" id="service-remediation-label" type="text" autocomplete="off" spellcheck="false" placeholder="com.example.model" value="${text(state.label)}">`;
    }
    if(state.busy)body+='<p role="status">Working on the selected service. Verification may load its existing local model.</p>';
    if(state.error)body+=`<p role="alert">${text(state.error)}</p>`;
    const disabled=state.busy?' disabled':'';
    const foot=preview&&!receipt?`<button type="button" class="btn btn-primary" data-action="service-remediation-apply"${disabled}>Apply and verify</button>`
      :receipt?(['verified','prepared','applying','failed_no_change','rollback_required'].includes(receipt.state)?`<button type="button" class="btn btn-danger" data-action="service-remediation-rollback"${disabled}>Restore original settings</button>`:'')
      :`<button type="button" class="btn btn-primary" data-action="service-remediation-preview"${disabled}>Preview hardening</button><button type="button" class="btn btn-ghost" data-action="service-remediation-lookup"${disabled}>Read last result</button>`;
    drawer.setMode('service-remediation');drawer.open({title:'Review service hardening',icon:'server',back:state.back,body,foot});state.seq=drawer.seq();
  }
  function open({back}={}) {active={back,generation:generation(),source:'',label:'',preview:null,receipt:null,error:'',busy:false};paint(active);}
  async function send(input,label) {
    const state=active;if(!state||!current(state)||state.busy)return;
    state.busy=true;state.error='';paint(state);
    try {
      const response=label?await request('/local-services/receipt?'+new URLSearchParams({label})):await request('/local-services/remediation',{timeoutMs:130000,method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)});
      const raw=await response.text();let value;try{value=JSON.parse(raw);}catch{}
      if(!current(state))return;
      if(!response.ok){if(validReceipt(value?.receipt)){state.receipt=value.receipt;state.preview=null;}throw new Error(value?.error||raw.slice(0,512)||'Service operation failed. Read the last result before retrying.');}
      if(input?.action==='preview') {if(!validPreview(value))throw new Error('Service preview is incomplete. Request a new preview.');state.preview=value;}
      else {if(!validReceipt(value))throw new Error('Service result is incomplete. Read the last result before relying on it.');state.receipt=value;state.preview=null;}
    } catch(error) {if(current(state)){state.error=error.message||'Service operation failed.';if(input?.action==='apply')state.preview=null;}}
    finally {if(current(state)){state.busy=false;paint(state);}}
  }
  async function preview(source) {if(!active||!current(active))return;active.source=source;return send({action:'preview',source});}
  async function lookup(label) {if(!active||!current(active))return;active.label=label;return send(null,label);}
  async function apply() {
    const state=active;if(!state||!current(state)||state.busy||!state.preview)return;
    const preview=state.preview;
    const ok=await confirm(`Restart ${preview.label}, update the displayed client settings, and verify ${preview.change.scope.replaceAll('_',' ')}? On failure the original settings are restored and the service stays stopped.`,{title:'Apply service hardening',okLabel:'Apply and verify',focusCancel:true});
    if(ok&&current(state)&&state.preview===preview)return send({action:'apply',id:preview.id,preview_hash:preview.preview_hash});
  }
  async function rollback() {
    const state=active;if(!state||!current(state)||state.busy||!state.receipt)return;
    const label=state.receipt.label;
    const ok=await confirm(`Stop ${label} and restore its original settings? The service will remain stopped.`,{title:'Restore original service settings',okLabel:'Restore and stop',focusCancel:true});
    if(ok&&current(state))return send({action:'rollback',label});
  }
  return {open,preview,lookup,apply,rollback};
}
