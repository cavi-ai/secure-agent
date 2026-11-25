import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadDrawer } from './drawer-harness.mjs';

// Exact drawer markup for hostile served values: each value renders escaped
// once in text and attribute positions, and nested fragments render as markup.
const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';

const status = (code, text = H) => async () => ({ ok: code === 200, status: code, text: async () => text, json: async () => ({}) });
const serves = flag => async () => ({ ok: true, status: 200, json: async () => structuredClone(flag) });
const fails = error => async () => { throw error; };
const flags = (extra = {}) => ({ flag: { cache() {}, advisorEnabled: () => false, ...extra } });

// The body while the request is pending, then after it settles.
async function bodies(start, deps) {
  const h = loadDrawer({ deps });
  const pending = start(h.api);
  const loading = h.dom.body.innerHTML;
  await pending;
  return [loading, h.dom.body.innerHTML];
}

const flagFields = { id: H, title: H, rule: 'sensitive-read', agent: H, ts: H, severity: 7, pid: 4242, session_id: H, workspace: H };
const summary = () => ({ title: H, detail: H, rule: H, session_id: H, group: { workspace: H } });

const cases = {
  'plan slot': () => bodies(api => api.openPlanDrawer(H)),
  'endpoint lookup error': () => bodies(api => api.openEndpointDetail(H, H), { respond: status(500) }),
  'endpoint empty error': () => bodies(api => api.openEndpointDetail(H, H), { respond: status(500, '') }),
  'endpoint thrown value': () => bodies(api => api.openEndpointDetail(H, H), { respond: fails(H) }),
  'file lookup error': () => bodies(api => api.openFileDetail(H), { respond: status(500) }),
  'file thrown value': () => bodies(api => api.openFileDetail(H), { respond: fails(H) }),
  'incident missing': () => bodies(api => api.openIncidentReport(H), { respond: status(404) }),
  'incident failed': () => bodies(api => api.openIncidentReport(H), { respond: status(500) }),
  'incident thrown': () => bodies(api => api.openIncidentReport(H), { respond: fails(new Error(H)) }),
  'flag with advisor': () => bodies(api => api.openFlagDetail(H), { respond: serves({ ...flagFields,
    evidence: [H, { text: H }, { label: H, sub: H }, { label: H }, {}], advisor: { assessment: H, rationale: H } }) }),
  'flag defaults': () => bodies(api => api.openFlagDetail(H), { respond: serves({ id: H, rule: 'sensitive-read' }) }),
  'flag assessed': () => bodies(api => api.openFlagDetail(H), { collaborators: flags({ advisorEnabled: () => true }),
    respond: serves({ ...flagFields, evidence: [{ label: H }], explain: { actions: [], subject: { display: H },
      assessment: { risk: 'high', reason: H, review_state: 'unreviewed', residual_risk: 'possible-exposure', control: 'allowed', evidence_basis: ['os-read'] } } }) }),
  'flag legacy explain': () => bodies(api => api.openFlagDetail(H), { respond: serves({ ...flagFields,
    advisor: { assessment: H, rationale: H }, explain: { actions: [], what: H, disposition: { state: 'warning', text: H, why: H } } }) }),
  'flag missing with summary': () => bodies(api => api.openFlagDetail(H), { collaborators: flags({ summary }), respond: status(404) }),
  'flag missing': () => bodies(api => api.openFlagDetail(H), { respond: status(404) }),
  'flag failed with summary': () => bodies(api => api.openFlagDetail(H), { collaborators: flags({ summary: () => ({ title: H, rule: H }) }), respond: status(500) }),
  'flag failed': () => bodies(api => api.openFlagDetail(H), { respond: status(500, '') }),
  'family gone': async () => {
    let present = true;
    const h = loadDrawer({ deps: { collaborators: { family: { byKey: key => (present ? { key } : undefined), label: fam => H + fam.key, select() {}, sections: () => [] } } } });
    h.api.openFamilyDrawer('fam');
    present = false;
    h.api.fillFamily();
    return h.dom.body.innerHTML;
  },
};

const planSlot = `<div class="plan-slot" data-plan-subject="${E}"><div class="loading-spinner">Loading the playbook…</div></div>`;
const endpointSpinner = `<div class="loading-spinner">Identifying ${E}…</div>`;
const endpointError = text => `<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>Could not identify this endpoint: ${text}</span></div>`;
const fileSpinner = `<div class="loading-spinner">Reading ${E}…</div>`;
const fileError = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Could not read this file: ${E}</span></div>`;
const incidentSpinner = '<div class="loading-spinner">Fetching incident report…</div>';
const flagSpinner = '<div class="loading-spinner">Loading flag evidence…</div>';
const flagHead = `<div class="panel-body flag-inspector">\n      <p>${E} · severity 7 · ${E}</p>\n      <dl class="finding-facts"><dt>Raised</dt><dd>Invalid Date</dd><dt>Process</dt><dd>PID 4242</dd>\n        <dt>Session</dt><dd>${E}</dd><dt>Workspace</dt><dd>${E}</dd><dt>Flag ID</dt><dd>${E}</dd></dl>\n      `;
const flagTail = `\n      <h4>What to do</h4><div class="plan-slot" data-plan-subject="flag:${E}"><div class="loading-spinner">Loading the playbook…</div></div>\n    </div>`;
const dismiss = `<button type="button" class="btn btn-ghost btn-sm" data-action="dismiss-flag" data-id="${E}">Dismiss flag</button>`;
const retry = `<button type="button" class="btn btn-ghost btn-sm" data-action="open-flag" data-id="${E}">Retry evidence</button>`;
const refresh = '<button type="button" class="btn btn-ghost btn-sm" data-action="refresh-finding-queue">Refresh queue</button>';
const queued = `<p>${E}</p><p>This is the queued summary, not the source evidence.</p>`;
const missingText = 'Finding evidence is no longer available. Its source may have expired; the retained session summary does not replace the evidence.';

const expected = {
  'plan slot': [planSlot, planSlot],
  'endpoint lookup error': [endpointSpinner, endpointError(E)],
  'endpoint empty error': [endpointSpinner, endpointError('lookup failed')],
  'endpoint thrown value': [endpointSpinner, endpointError(E)],
  'file lookup error': [fileSpinner, fileError],
  'file thrown value': [fileSpinner, fileError],
  'incident missing': [incidentSpinner, '<div class="empty" role="status"><svg class="icon"><use href="#i-doc"/></svg><span>This incident report is no longer available. Its source may have expired; the retained session summary does not replace the report.</span></div>'],
  'incident failed': [incidentSpinner, '<div class="empty" role="status"><svg class="icon"><use href="#i-doc"/></svg><span>Failed to load the incident report.</span></div>'],
  'incident thrown': [incidentSpinner, `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Error: ${E}</span></div>`],
  'flag with advisor': [flagSpinner, flagHead + `\n      <p><b>Advisor:</b> ${E} · ${E}</p><h4>Recorded evidence</h4><ul class="plan-list"><li>${E}</li><li>${E}</li><li>${E} (${E})</li><li>${E}</li><li></li></ul>\n      <div class="flag-actions-row">${dismiss}</div>` + flagTail],
  'flag defaults': [flagSpinner, `<div class="panel-body flag-inspector">\n      <p>sensitive-read · severity 0 · unknown agent</p>\n      <dl class="finding-facts"><dt>Raised</dt><dd>Invalid Date</dd><dt>Process</dt><dd>PID 0</dd>\n        <dt>Session</dt><dd>unknown</dd><dt>Workspace</dt><dd>unknown</dd><dt>Flag ID</dt><dd>${E}</dd></dl>\n      \n      <h4>Recorded evidence</h4><p>No evidence rows were recorded for this flag.</p>\n      <div class="flag-actions-row">${dismiss}</div>` + flagTail],
  'flag assessed': [flagSpinner, flagHead + `<p class="finding-what">${E}</p><div class="facts"><span class="fact fact-file"><svg class="icon"><use href="#i-doc"/></svg>${E}</span></div><p class="finding-verdict">High risk</p>\n      <div class="finding-assessment"><p class="assessment-state">Unreviewed · Possible exposure · Allowed</p><details class="assessment-limits"><summary>Evidence and limits</summary><ul><li>OS file read</li></ul></details></div><h4>Recorded evidence</h4><ul class="plan-list"><li>${E}</li></ul>\n      <div class="flag-actions-row"><details class="act-more"><summary class="btn btn-ghost btn-sm">More</summary><div class="act-menu"><button class="act-menu-item" data-action="retriage" data-id="${E}">Re-run advisor</button></div></details></div>` + flagTail],
  'flag legacy explain': [flagSpinner, flagHead + `<p class="finding-what">${E}</p><p class="finding-verdict">${E}: ${E}</p>\n      <p><b>Advisor:</b> ${E} · ${E}</p><h4>Recorded evidence</h4><p>No evidence rows were recorded for this flag.</p>\n      <div class="flag-actions-row"></div>` + flagTail],
  'flag missing with summary': [flagSpinner, `<div class="panel-body flag-inspector">\n        <h3>Evidence unavailable</h3>\n        ${queued}\n        <p role="status">${missingText}</p>\n        <dl class="finding-facts"><dt>Flag ID</dt><dd>${E}</dd><dt>Rule</dt><dd>${E}</dd><dt>Session</dt><dd>${E}</dd><dt>Workspace</dt><dd>${E}</dd></dl>\n        <div class="flag-actions-row">\n          ${retry}\n          ${refresh}\n          \n        </div>\n        <p>Refresh the queue to reconcile this missing record.</p>\n      </div>`],
  'flag missing': [flagSpinner, `<div class="panel-body flag-inspector">\n        <h3>Evidence unavailable</h3>\n        \n        <p role="status">${missingText}</p>\n        <dl class="finding-facts"><dt>Flag ID</dt><dd>${E}</dd></dl>\n        \n        <p>The retained history does not replace the missing source evidence.</p>\n      </div>`],
  'flag failed with summary': [flagSpinner, `<div class="panel-body flag-inspector">\n        <h3>Evidence could not be loaded</h3>\n        ${queued}\n        <p role="status">${E}</p>\n        <dl class="finding-facts"><dt>Flag ID</dt><dd>${E}</dd><dt>Rule</dt><dd>${E}</dd></dl>\n        <div class="flag-actions-row">\n          ${retry}\n          ${refresh}\n          ${dismiss}\n        </div>\n        <p>Dismissing marks the flag reviewed. The rule keeps watching.</p>\n      </div>`],
  'flag failed': [flagSpinner, `<div class="panel-body flag-inspector">\n        <h3>Evidence could not be loaded</h3>\n        \n        <p role="status">flag unavailable</p>\n        <dl class="finding-facts"><dt>Flag ID</dt><dd>${E}</dd></dl>\n        <div class="flag-actions-row">\n          ${retry}\n          ${refresh}\n          \n        </div>\n        <p>Dismissing marks the flag reviewed. The rule keeps watching.</p>\n      </div>`],
  'family gone': '<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>This family is no longer running.</span></div>',
};

for (const [name, render] of Object.entries(cases)) {
  test(`drawer markup: ${name}`, async () => {
    assert.deepEqual(await render(), expected[name]);
  });
}
