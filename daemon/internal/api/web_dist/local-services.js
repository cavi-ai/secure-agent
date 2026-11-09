// On-demand local service evidence. Profiles are never applied by this view.
function createLocalServices({ request, drawer, generation, ended, copy, toast }) {
  let active = null;
  const current = state => active === state && !ended() && state.generation === generation() && state.seq === drawer.seq();
  const text = value => escapeHTML(String(value ?? 'Not reported'));
  const strings = value => Array.isArray(value) && value.every(item => typeof item === 'string');
  function valid(report) {
    const probe = value => value && typeof value.state === 'string';
    return report?.enforcement === 'not_assessed' && Number.isFinite(Date.parse(report.generated_at))
      && typeof report.scope === 'string' && Number.isInteger(report.omitted_endpoints) && report.omitted_endpoints >= 0
      && (!report.managed || ['state','transport','enforcement'].every(key => typeof report.managed[key] === 'string'))
      && Array.isArray(report.services) && report.services.length <= 16
      && report.services.every(service => typeof service.endpoint === 'string' && service.enforcement === 'not_assessed'
        && probe(service.metadata) && probe(service.cross_origin) && probe(service.foreign_host) && strings(service.findings))
      && (!report.inventory || ['available','partial','unavailable'].includes(report.inventory.state)
        && typeof report.inventory.scope === 'string' && typeof report.inventory.truncated === 'boolean'
        && Array.isArray(report.inventory.listeners) && report.inventory.listeners.length <= 128
        && report.inventory.listeners.every(listener => Number.isInteger(listener.pid) && listener.pid > 0
          && ['command','address','binding','runtime_hint'].every(key => typeof listener[key] === 'string')))
      && Array.isArray(report.hardening) && report.hardening.length <= 4
      && report.hardening.every(profile => ['ollama','llama.cpp','mlx','openai-compatible'].includes(profile.runtime)
        && ['title','support','settings','documentation'].every(key => typeof profile[key] === 'string')
        && ['steps','verification','limitations'].every(key => strings(profile[key])));
  }
  function paint(state) {
    const report = state.report;
    const list = values => `<ul>${values.map(value => `<li>${text(value)}</li>`).join('')}</ul>`;
    let body = '<p>Check local model servers without sending prompts, credentials or model-loading requests. Running servers are not changed.</p>';
    if (report) {
      const managed = report.managed;
      if (managed) {
        const privateTransport = managed.transport === 'inherited-unix-v1' && managed.enforcement === 'private_transport';
        body += `<section class="monitoring-diagnostic-check"><h3>Secure Agent advisor</h3><p>${privateTransport ? 'Managed private connection' : 'Private connection not confirmed'} · ${text(managed.state)}</p><p>This status covers the managed advisor only.</p></section>`;
      }
      body += `<p>Checked ${text(new Date(report.generated_at).toLocaleString())}. ${text(report.scope)}. External service protection is not established by this check.</p>`;
      if (report.omitted_endpoints) body += `<p role="status">${text(report.omitted_endpoints)} additional endpoint candidates were not probed. Use the CLI with an explicit endpoint to check them.</p>`;
      if (report.inventory) {
        const inventory = report.inventory;
        body += `<details class="local-service-inventory"><summary>Visible listeners: ${text(inventory.listeners.length)} · ${text(inventory.state)}${inventory.truncated ? ' · truncated' : ''}</summary><p>${text(inventory.scope)}</p>
          ${inventory.listeners.map(listener => `<p><code>${text(listener.address)}</code> · ${text(listener.binding)} · PID ${text(listener.pid)} ${text(listener.command)} · runtime hint: ${text(listener.runtime_hint)}</p>`).join('')}</details>`;
      } else body += '<p role="status">Listener inventory was not reported. Endpoint observations do not establish listener coverage.</p>';
      body += '<section><h3>Endpoint observations</h3>';
      for (const service of report.services) {
        const observation = (name, probe) => `<div><dt>${text(name)}</dt><dd>${text(probe.state)}${probe.http_status ? ` · HTTP ${text(probe.http_status)}` : ''}${probe.sharing ? ` · sharing ${text(probe.sharing)}` : ''}</dd></div>`;
        body += `<article class="monitoring-diagnostic-check"><h4>${text(service.endpoint)}</h4><dl class="monitoring-diagnostic-facts">${observation('Metadata',service.metadata)}${observation('Foreign Origin',service.cross_origin)}${observation('Foreign Host',service.foreign_host)}</dl>${list(service.findings)}</article>`;
      }
      body += '</section><section><h3>Server hardening</h3><p>Choose the runtime confirmed by the server owner. These profiles are not applied. Restarting a server can interrupt its clients.</p>';
      for (const profile of report.hardening) {
        body += `<details class="local-service-profile"><summary>${text(profile.title)} · ${text(profile.support.replaceAll('_',' '))}</summary>
          ${profile.settings ? `<pre><code>${text(profile.settings)}</code></pre><button type="button" class="btn btn-ghost btn-sm" data-action="local-services-copy" data-runtime="${text(profile.runtime)}">Copy settings</button>` : ''}
          <h4>Apply through the server owner</h4>${list(profile.steps)}<h4>Verify after restart</h4>${list(profile.verification)}<h4>Limits</h4>${list(profile.limitations)}
          ${profile.documentation.startsWith('https://') ? `<p><a href="${text(profile.documentation)}" target="_blank" rel="noopener noreferrer">Runtime documentation</a></p>` : ''}</details>`;
      }
      body += '</section>';
    } else if (state.busy) body += '<p role="status">Checking visible listeners and local metadata…</p>';
    if (state.error) body += `<p role="alert">${text(state.error)}</p>`;
    drawer.setMode('local-services');
    drawer.open({title:'Local model servers',icon:'server',back:state.back,body,
      foot:`<button type="button" class="btn btn-primary" data-action="local-services-refresh"${state.busy ? ' disabled' : ''}>${state.busy ? 'Checking…' : 'Recheck servers'}</button>`});
    state.seq = drawer.seq();
  }
  async function open({back} = {}) {
    const state = active = {back,generation:generation(),report:null,busy:true,error:''};
    paint(state);
    try {
      const response = await request('/local-services');
      if (!response.ok) throw new Error('Local service evidence could not be loaded. Recheck to try again.');
      const report = await response.json();
      if (!current(state)) return;
      if (!valid(report)) throw new Error('Local service evidence is incomplete. Recheck before relying on this report.');
      state.report = report;
    } catch (error) {
      if (current(state)) state.error = error.message?.startsWith('Local service evidence') ? error.message : 'Local service evidence could not be loaded. Recheck to try again.';
    } finally {
      if (current(state)) { state.busy = false; paint(state); }
    }
  }
  async function copySettings(runtime) {
    const state = active;
    if (!state || !current(state) || !state.report || state.busy) return;
    const settings = state.report.hardening.find(profile => profile.runtime === runtime)?.settings;
    if (!settings) return;
    try {
      await copy(settings);
      if (current(state)) toast('Settings copied for review. No server was changed.');
    } catch { if (current(state)) toast('Copy unavailable. Select the displayed settings to copy them.'); }
  }
  return {open,copySettings,refresh:() => active && current(active) && !active.busy ? open({back:active.back}) : undefined};
}
