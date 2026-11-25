import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Exact drawer markup of the monitoring diagnostics, service remediation,
// local services and local inference controllers for a hostile served value
// in every text and attribute position.
const H = `<img src=x onerror=1>"'&amp;`;

const web = new URL('../../../daemon/internal/api/web_dist/', import.meta.url);
function load(file) {
  const ctx = vm.createContext({ Date, URL, URLSearchParams, setTimeout: () => 1, clearTimeout() {}, window: {} });
  for (const name of ['lib.js', file]) vm.runInContext(readFileSync(new URL(name, web), 'utf8'), ctx);
  return ctx;
}
function drawerState() {
  const state = { seq: 0, view: null };
  state.drawer = { seq: () => state.seq, setMode() {}, open(view) { state.seq++; state.view = view; } };
  return state;
}
const shown = state => ({ body: state.view.body, foot: state.view.foot });
const json = value => async () => ({ ok: true, json: async () => structuredClone(value), text: async () => JSON.stringify(value) });
const stamp = value => new Date(value).toLocaleString();

// Monitoring diagnostics
const generated = '2026-10-20T20:15:00Z';
const doctor = { generated_at: generated, loss_review: { pending: true, seen_at: H },
  checks: [{ id: 'bus', title: H, state: H, detail: H, fix: H }, { id: 'x', title: 'hidden', state: 'pass' }, { id: 'storage', title: 'Storage', state: 'pass' }] };
const status = (es = {}) => ({ bus_drops: 5, bus_dropping: true, es_service: { bytes_lost: 1500000, loss_cause: 'rotation', collector: { state: H }, lag_seconds: 3, ...es } });
async function diagnostics(respond, run) {
  const s = drawerState();
  const api = load('monitoring-diagnostics.js').createMonitoringDiagnostics({ request: respond, drawer: s.drawer, generation: () => 1, ended: () => false, refresh: async () => {} });
  const pending = api.open();
  const loading = shown(s);
  await pending;
  if (run) await run(api);
  return { loading, loaded: shown(s) };
}
const diagnosticsServes = es => async url => ({ ok: true, json: async () => structuredClone(url === '/doctor' ? doctor : status(es)) });

// Service remediation
const preview = { id: 'review', preview_hash: 'hash', label: H, source: H, endpoint: H, change: { scope: 'authenticated_inference' },
  client_fields: [H], warnings: [H], settings: [H] };
const receipt = (state, extra = {}) => ({ ...preview, state, verified_at: '2026-11-09T18:00:00Z', checks: [H], failure: H, ...extra });
async function remediation(respond, run) {
  const s = drawerState();
  const api = load('service-remediation.js').createServiceRemediation({ request: respond, drawer: s.drawer, generation: () => 1, ended: () => false, confirm: async () => true });
  api.open();
  const form = shown(s);
  await run(api);
  return { form, result: shown(s) };
}
const remediationServes = value => async () => ({ ok: true, text: async () => JSON.stringify(value) });

// Local services
const services = () => ({ generated_at: '2026-11-09T18:00:00Z', enforcement: 'not_assessed', scope: H, omitted_endpoints: 3,
  managed: { state: H, transport: 'inherited-unix-v1', enforcement: 'private_transport' },
  inventory: { state: 'partial', scope: H, truncated: true, listeners: [{ pid: 42, command: H, address: H, binding: H, runtime_hint: H }] },
  services: [{ endpoint: H, metadata: { state: H, http_status: 200 }, cross_origin: { state: H, sharing: H }, foreign_host: { state: H }, findings: [H], enforcement: 'not_assessed' }],
  hardening: [{ runtime: 'ollama', title: H, support: 'browser_hardening_only', settings: H, steps: [H], verification: [H], limitations: [H], documentation: 'https://e.test/' + H }] });
async function localServices(respond) {
  const s = drawerState();
  const api = load('local-services.js').createLocalServices({ request: respond, drawer: s.drawer, generation: () => 1, ended: () => false, copy: async () => {}, toast() {} });
  const pending = api.open();
  const loading = shown(s);
  await pending;
  return { loading, loaded: shown(s) };
}

// Local inference
const inference = () => ({ generated_at: '2026-11-09T20:00:00Z',
  coverage: { discovery: H, connections: H, requests: 'routed_only', truncated: true, pending_endpoints: 2, unclassified_listeners: 5 },
  servers: [{ endpoint: H, runtime: H, metadata: H, loaded_models: [{ name: H }], observed_at: '2026-11-09T19:00:00Z' }, { endpoint: 'e', runtime: 'r', metadata: 'x_y', loaded_models: [] }],
  connections: [{ pid: 42, process: H, endpoint: H }, { pid: 7, endpoint: 'e' }],
  requests: [{ id: '1', state: 'in_progress', endpoint: H, model: H, pid: 42, session_id: H, execution: 'local_gpu', input_tokens: 3, output_tokens: 4, usage_parsing: 'partial' },
    { id: '2', state: H, endpoint: H, ended_at: 'x' }],
  gateways: [{ listen: H, upstream: H, state: H }] });
async function localInference(respond) {
  const s = drawerState();
  const api = load('local-inference.js').createLocalInference({ request: respond, drawer: s.drawer, generation: () => 1, ended: () => false });
  const pending = api.open();
  const loading = shown(s);
  await pending;
  return { loading, loaded: shown(s) };
}
const emptyInference = { generated_at: '2026-11-09T20:00:00Z', coverage: { discovery: 'a', connections: 'b', requests: 'routed_only', truncated: false, pending_endpoints: 0 },
  servers: [], connections: [], requests: [], gateways: [] };

const cases = {
  'diagnostics with losses and checks': () => diagnostics(diagnosticsServes()),
  'diagnostics with unrecognized loss cause': () => diagnostics(diagnosticsServes({ loss_cause: 'other', bytes_lost: 12, collector: undefined, state: H })),
  'diagnostics acknowledgement failure': () => diagnostics(async (url, options) => {
    if (options?.method === 'POST') throw new Error(H);
    return diagnosticsServes()(url);
  }, api => api.acknowledge()),
  'remediation failed preview': () => remediation(async () => ({ ok: false, text: async () => JSON.stringify({ error: H }) }), api => api.preview(H)),
  'remediation preview': () => remediation(remediationServes(preview), api => api.preview(H)),
  'remediation browser hardening preview': () => remediation(remediationServes({ ...preview, change: { scope: 'browser_hardening' }, client_fields: [] }), api => api.preview(H)),
  'remediation verified result': () => remediation(remediationServes(receipt('verified')), api => api.lookup(H)),
  'remediation browser hardening result': () => remediation(remediationServes(receipt('verified', { change: { scope: 'browser_hardening' } })), api => api.lookup(H)),
  'remediation restored result': () => remediation(remediationServes(receipt('failed_restored_stopped')), api => api.lookup(H)),
  'remediation rejected result': () => remediation(async () => ({ ok: false, text: async () => JSON.stringify({ receipt: receipt('rollback_required'), error: H }) }), api => api.lookup(H)),
  'services report': () => localServices(json(services())),
  'services report without optional sections': () => localServices(json({ ...services(), omitted_endpoints: 0, managed: { state: 'x', transport: 'other', enforcement: 'none' },
    inventory: undefined, hardening: [{ ...services().hardening[0], settings: '', documentation: 'http://e.test' }] })),
  'services unavailable': () => localServices(async () => ({ ok: false })),
  'inference report': () => localInference(json(inference())),
  'inference empty report': () => localInference(json(emptyInference)),
  'inference unavailable': () => localInference(async () => ({ ok: false })),
};

const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const button = (cls, action, label, extra = '') => `<button type="button" class="btn ${cls}" data-action="${action}"${extra}>${label}</button>`;

const diagnosticsLoading = { body: '<p role="status">Loading monitoring diagnostics…</p>', foot: button('btn-ghost', 'monitoring-diagnostics-refresh', 'Refresh diagnostics') };
const diagnosticsFoot = diagnosticsLoading.foot + button('btn-primary', 'monitoring-loss-seen', 'Acknowledge earlier losses');
const diagnosticsBody = (bytes, cause, error = '') => `<p>Monitoring history remains incomplete. Acknowledgement records that you reviewed the gap; it does not recover missing evidence.</p>\n      <p role="status">Reviewed through Not recorded. Current delivery health is reported separately below.</p>\n      <section><h3>Event delivery</h3><dl class="monitoring-diagnostic-facts">\n      <div><dt>Missed deliveries</dt><dd>5</dd></div><div><dt>Last loss</dt><dd>Not recorded</dd></div>\n      <div><dt>Delivery pressure</dt><dd>Active</dd></div>\n      <div><dt>Loss source</dt><dd>Ingestion queue was full</dd></div></dl></section>\n      <section><h3>File monitoring</h3><dl class="monitoring-diagnostic-facts">\n      <div><dt>Unread data lost</dt><dd>${bytes}</dd></div><div><dt>Last loss</dt><dd>Not recorded</dd></div>\n      <div><dt>Last loss cause</dt><dd>${cause}</dd></div>\n      <div><dt>Collector</dt><dd>${E}</dd></div>\n      <div><dt>Delivery lag</dt><dd>3 s</dd></div></dl></section>\n      <section><h3>Diagnostic checks</h3><article class="monitoring-diagnostic-check"><strong>${E} · ${E}</strong><p>${E}</p><p>${E}</p></article><article class="monitoring-diagnostic-check"><strong>Storage · pass</strong><p></p></article></section>${error}`;

const remediationIntro = '<p>Review hardening for a running model service owned by your macOS user. Direct MLX-LM, llama.cpp and Ollama launchd jobs are supported. Other launchers are left unchanged.</p>';
const remediationForm = (source, error = '') => remediationIntro + `<label for="service-remediation-source">Launchd service definition file</label><input class="service-remediation-input" id="service-remediation-source" type="text" autocomplete="off" spellcheck="false" placeholder="Absolute path to model.plist" value="${source}">\n        <p>Only the selected running job is changed. A preview reads its definition and capabilities without restarting it.</p>\n        <label for="service-remediation-label">Previously remediated service label</label><input class="service-remediation-input" id="service-remediation-label" type="text" autocomplete="off" spellcheck="false" placeholder="com.example.model" value="">${error}`;
const remediationFormFoot = button('btn-primary', 'service-remediation-preview', 'Preview hardening') + button('btn-ghost', 'service-remediation-lookup', 'Read last result');
const remediationOpened = { body: remediationForm(''), foot: remediationFormFoot };
const previewBody = (scope, fields) => remediationIntro + `<section><h3>Review before restart</h3><dl class="monitoring-diagnostic-facts"><div><dt>Service</dt><dd>${E}</dd></div><div><dt>Definition</dt><dd>${E}</dd></div><div><dt>Endpoint</dt><dd>${E}</dd></div><div><dt>Protection scope</dt><dd>${scope}</dd></div></dl>\n        <h4>Settings to apply</h4><ul><li>${E}</li></ul><h4>Secure Agent client fields to update</h4>${fields}<ul><li>${E}</li></ul></section>`;
const applyFoot = button('btn-primary', 'service-remediation-apply', 'Apply and verify');
const rollbackFoot = button('btn-danger', 'service-remediation-rollback', 'Restore original settings');
const receiptBody = (state, text, list, after = '') => remediationIntro + `<section class="monitoring-diagnostic-check"><h3>${E}</h3><p>${state}</p>${text}${list}<p role="alert">${E}</p></section>${after}`;
const checks = `<ul><li>${E}</li></ul>`;
const verified = '2026-11-09T18:00:00Z';

const servicesIntro = '<p>Check local model servers without sending prompts, credentials or model-loading requests. Running servers are not changed.</p>';
const servicesLoading = { body: servicesIntro + '<p role="status">Checking visible listeners and local metadata…</p>', foot: button('btn-primary', 'local-services-refresh', 'Checking…', ' disabled') };
const servicesFoot = button('btn-primary', 'local-services-refresh', 'Recheck servers');
const advisor = line => `<section class="monitoring-diagnostic-check"><h3>Secure Agent advisor</h3><p>${line}</p><p>This status covers the managed advisor only.</p></section>`;
const checked = `<p>Checked ${stamp(verified)}. ${E}. External service protection is not established by this check.</p>`;
const listener = `<details class="local-service-inventory"><summary>Visible listeners: 1 · partial · truncated</summary><p>${E}</p>\n          <p><code>${E}</code> · ${E} · PID 42 ${E} · runtime hint: ${E}</p></details>`;
const observations = `<section><h3>Endpoint observations</h3><article class="monitoring-diagnostic-check"><h4>${E}</h4><dl class="monitoring-diagnostic-facts"><div><dt>Metadata</dt><dd>${E} · HTTP 200</dd></div><div><dt>Foreign Origin</dt><dd>${E} · sharing ${E}</dd></div><div><dt>Foreign Host</dt><dd>${E}</dd></div></dl><ul><li>${E}</li></ul></article></section>`;
const copySettings = `<pre><code>${E}</code></pre>` + button('btn-ghost btn-sm', 'local-services-copy', 'Copy settings', ' data-runtime="ollama"');
const documentation = `<p><a href="https://e.test/${E}" target="_blank" rel="noopener noreferrer">Runtime documentation</a></p>`;
const hardening = (settings, link) => `<section><h3>Server hardening</h3><p>Choose the runtime confirmed by the server owner. These profiles are not applied. Restarting a server can interrupt its clients.</p><details class="local-service-profile"><summary>${E} · browser hardening only</summary>\n          ${settings}\n          <h4>Apply through the server owner</h4><ul><li>${E}</li></ul><h4>Verify after restart</h4><ul><li>${E}</li></ul><h4>Limits</h4><ul><li>${E}</li></ul>\n          ${link}</details></section><p><button type="button" class="btn btn-primary" data-action="service-remediation-open">Review a running service</button></p>`;

const inferenceIntro = '<p>Loaded models, connected apps and observed requests are separate signals. Request tracking covers configured gateways; direct traffic can contain inference that this view cannot identify.</p>';
const inferenceFoot = button('btn-ghost', 'local-inference-refresh', 'Refresh activity');
const inferenceLoading = { body: inferenceIntro + '<p role="status">Loading local inference activity…</p>', foot: inferenceFoot };

const expected = {
  'diagnostics with losses and checks': { loading: diagnosticsLoading, loaded: { body: diagnosticsBody('1.5 MB', 'Unread spool overwritten during rotation'), foot: diagnosticsFoot } },
  'diagnostics with unrecognized loss cause': { loading: diagnosticsLoading, loaded: { body: diagnosticsBody('12 bytes', 'Not recognized'), foot: diagnosticsFoot } },
  'diagnostics acknowledgement failure': { loading: diagnosticsLoading, loaded: {
    body: diagnosticsBody('1.5 MB', 'Unread spool overwritten during rotation', `<p class="monitoring-diagnostic-error" role="alert">${E}</p>`), foot: diagnosticsFoot } },
  'remediation failed preview': { form: remediationOpened, result: { body: remediationForm(E, `<p role="alert">${E}</p>`), foot: remediationFormFoot } },
  'remediation preview': { form: remediationOpened, result: { body: previewBody('authenticated inference', `<ul><li>${E}</li></ul>`), foot: applyFoot } },
  'remediation browser hardening preview': { form: remediationOpened,
    result: { body: previewBody('browser hardening', '<p>No matching client fields require changes.</p>'), foot: applyFoot } },
  'remediation verified result': { form: remediationOpened, result: { foot: rollbackFoot,
    body: receiptBody('verified', `<p>Last verified ${stamp(verified)}. Authentication and direct-backend checks passed for this service at that time.</p>`, checks) } },
  'remediation browser hardening result': { form: remediationOpened, result: { foot: rollbackFoot,
    body: receiptBody('verified', `<p>Last verified ${stamp(verified)}. Browser hardening only; the local API remains unauthenticated.</p>`, checks) } },
  'remediation restored result': { form: remediationOpened, result: { foot: '',
    body: receiptBody('failed_restored_stopped', '<p>Original settings were restored. The service is stopped; starting the original service is a separate owner action.</p>', '') } },
  'remediation rejected result': { form: remediationOpened, result: { foot: rollbackFoot,
    body: receiptBody('rollback_required', '', '', `<p role="alert">${E}</p>`) } },
  'services report': { loading: servicesLoading, loaded: { foot: servicesFoot, body: servicesIntro + advisor(`Managed private connection · ${E}`) + checked
    + '<p role="status">3 additional endpoint candidates were not probed. Use the CLI with an explicit endpoint to check them.</p>' + listener + observations + hardening(copySettings, documentation) } },
  'services report without optional sections': { loading: servicesLoading, loaded: { foot: servicesFoot, body: servicesIntro + advisor('Private connection not confirmed · x') + checked
    + '<p role="status">Listener inventory was not reported. Endpoint observations do not establish listener coverage.</p>' + observations + hardening('', '') } },
  'services unavailable': { loading: servicesLoading, loaded: { foot: servicesFoot,
    body: servicesIntro + '<p role="alert">Local service evidence could not be loaded. Recheck to try again.</p>' } },
  'inference report': { loading: inferenceLoading, loaded: { foot: inferenceFoot, body: inferenceIntro
    + `<p>Discovery: ${E} · Connections: ${E}</p><p role="status">Observation limits were reached. Coverage is partial.</p><p role="status">2 endpoint candidates await another metadata batch.</p><p role="status">5 other listeners remain unclassified. Add a model endpoint to the monitoring configuration to select it explicitly.</p>`
    + `<section><h3>Loaded models</h3><article class="monitoring-diagnostic-check"><strong>${E}</strong><p>${E} · Metadata: ${E}</p><ul><li>${E}</li></ul><p>Metadata observed: ${stamp('2026-11-09T19:00:00Z')}</p></article><article class="monitoring-diagnostic-check"><strong>e</strong><p>r · Metadata: x y</p><p>No loaded models reported.</p></article></section>`
    + `<section><h3>Connected clients</h3><p>A connection can be idle and does not prove inference.</p><p>PID 42 ${E} → ${E}</p><p>PID 7 App not identified → e</p></section>`
    + `<section><h3>Requests in progress</h3><article class="monitoring-diagnostic-check"><strong>${E} · in progress</strong><p>${E} · PID 42 · Session ${E}</p><p>Execution: local gpu · Input tokens: 3 · Output tokens: 4 · Usage parsing incomplete</p></article></section>`
    + `<section><h3>Gateways</h3><article class="monitoring-diagnostic-check"><strong>${E} → ${E}</strong><p>${E} · Gateway authentication does not isolate the direct backend.</p></article></section>`
    + `<details><summary>Recent requests in this daemon run</summary><article class="monitoring-diagnostic-check"><strong>Model not identified · ${E}</strong><p>${E} · Client not attributed</p><p>Execution: unknown</p></article></details>` } },
  'inference empty report': { loading: inferenceLoading, loaded: { foot: inferenceFoot, body: inferenceIntro
    + '<p>Discovery: a · Connections: b</p><section><h3>Loaded models</h3><p>No model servers identified in the current observations.</p></section>'
    + '<section><h3>Connected clients</h3><p>A connection can be idle and does not prove inference.</p><p>No client connections observed in the latest sample. Short requests can occur between samples.</p></section>'
    + '<section><h3>Requests in progress</h3><p>No requests observed in progress through configured gateways.</p></section>'
    + '<section><h3>Gateways</h3><p>No gateway configured. Use the local inference configuration to enable request tracking.</p></section>' } },
  'inference unavailable': { loading: inferenceLoading, loaded: { foot: inferenceFoot,
    body: inferenceIntro + '<p role="alert">Local inference monitoring is unavailable. Check that it is enabled and the daemon is running.</p>' } },
};

for (const [name, run] of Object.entries(cases)) {
  test(name, async () => {
    assert.deepEqual(await run(), expected[name]);
  });
}
