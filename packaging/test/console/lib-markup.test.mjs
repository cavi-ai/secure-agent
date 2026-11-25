import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

// Exact markup the lib.js render helpers return for hostile served values:
// each value renders escaped once, and nested fragments render as markup.
const libPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../daemon/internal/api/web_dist/lib.js');
const ctx = { window: {} };
vm.runInNewContext(readFileSync(libPath, 'utf8'), ctx, { filename: 'lib.js' });

const H = `<img src=x onerror=1>"'&amp;`;
const E = '&lt;img src=x onerror=1&gt;&quot;&#39;&amp;amp;';
const E8 = '&lt;img src';
const lines = (...rows) => rows.join('\n');

function inUTC(render) {
  const original = process.env.TZ;
  try {
    process.env.TZ = 'UTC';
    return render();
  } finally {
    if (original === undefined) delete process.env.TZ;
    else process.env.TZ = original;
  }
}

const endpointSession = (harness, where, id) => lines('', '    <div class="endpoint-session">', `      <strong>${harness}</strong>`,
  `      <span>${where}</span>`, `      <span class="endpoint-session-id">${id}</span>`, '    </div>');
const endpointEvent = (time, port, who) => lines('', '    <div class="endpoint-event">', `      <span class="endpoint-event-time">${time}</span>`,
  `      <span class="endpoint-event-port">:${port}</span>`, `      <span class="endpoint-event-agent">${who}</span>`, '    </div>');
const noSessions = '<div class="resource-detail-empty">No session attribution on these connections.</div>';
const noEvents = '<div class="resource-detail-empty">No recorded connections.</div>';
const endpointBody = (host, identity, facts, allowed, agents, sessions, events) => lines('', '    <div class="endpoint-head">',
  `      <div class="endpoint-host">${host}</div>`, '      <span class="endpoint-kind">hostname</span>', '    </div>',
  `    <p class="endpoint-identity">${identity}</p>`, `    ${facts}`, `    ${allowed}`, `    <div class="endpoint-actions">${agents}</div>`,
  `    <section class="endpoint-section"><h4>Reached by</h4>${sessions}</section>`,
  `    <section class="endpoint-section"><h4>Recent connections</h4>${events}</section>`);

const endpointDetail = {
  host: H, identity: { kind: H, org: H, name: H }, count: 3, last_seen: H, first_seen: H, agents: [H, 'other'],
  sessions: [{ harness: H, repo: H, branch: H, id: H }, { workspace: H }, {}],
  events: [{ ts: H, remote_port: H, session_id: H }, { exe_path: '/usr/bin/' + H }, {}],
  allowed: [{ agent: H }, { agent: 'b' }],
};

const fileEvent = (middle, last) => lines('', '    <div class="endpoint-event">', '      <span class="endpoint-event-time"> ago</span>',
  `      <span>${middle}</span>`, `      ${last}`, '    </div>');
const fileDetail = {
  path: H, display: H, exists: true, size: 2048, mod_time: H, owned_by_user: false,
  subject: { category_label: H, owner_label: H }, session: { harness: H, repo: H, branch: H, id: H },
  excerpt: H, env_variables: [H, 'TOKEN'], env_withheld: H,
  findings: [{ kind: 'incident', ts: H, risk: H, id: H }, { ts: H, rule: H, agent: H }, { ts: H, rule: H, acknowledged: true }],
  accesses: [{ ts: H, kind: 'file-' + H, exe_path: '/bin/' + H, session_id: H }],
};
const fileActions = lines('', `    <button type="button" class="btn btn-ghost btn-sm" data-action="file-reveal" data-path="${E}">Reveal in Finder</button>`,
  `    <button type="button" class="btn btn-ghost btn-sm" data-action="file-open" data-path="${E}">Open in editor</button>`);
const fileFindings = fileEvent(`Incident · ${E}`, `<button type="button" class="btn btn-ghost btn-sm endpoint-event-agent" data-action="open-incident" data-id="${E}">Open</button>`)
  + fileEvent(E, `<span class="endpoint-event-agent">${E}</span>`) + fileEvent(E, '<span class="endpoint-event-agent">reviewed</span>');

const marks = (subject, routine) => `<button class="btn btn-ghost btn-sm" data-action="mark-label" data-subject="${subject}" data-label="ok">${routine}</button>`
  + `<button class="btn btn-ghost btn-sm" data-action="mark-label" data-subject="${subject}" data-label="not_ok">Mark as not ok</button>`;
const planSlot = subject => `<section class="endpoint-section"><h4>What to do</h4><div class="plan-slot" data-plan-subject="${subject}"><div class="loading-spinner">Loading the playbook…</div></div></section>`;

const remediation = { revision: H, evidence_revision: H, steps: [
  { id: H, status: 'reported', reported_at: H, newer_evidence: true, item: { name: H, path: H, action: H } },
  { id: 's2', item: {} },
] };
const stepAttrs = id => `data-action="incident-remediation" data-id="${E}" data-step-id="${id}" data-revision="${E}" data-evidence="${E}"`;
const remediationSection = buttons => '<section class="incident-remediation"><h4>Remediation steps</h4><p class="body-note">Reports record work you completed. External credential changes remain unverified; reporting a step does not resolve the incident.</p>'
  + `<div class="endpoint-section"><strong>${E}</strong><p class="body-note">${E}</p><p>${E}</p><p>Reported completed · Unverified · ${E}</p><p class="body-note">New evidence since this report; review the incident again.</p>`
  + (buttons ? `<button class="btn btn-ghost btn-sm" ${stepAttrs(E)} data-status="pending">Mark pending</button>` : '') + '</div>'
  + '<div class="endpoint-section"><strong></strong><p></p><p>Pending · Unverified</p>'
  + (buttons ? `<button class="btn btn-ghost btn-sm" ${stepAttrs('s2')} data-status="reported">Report step completed</button>` : '') + '</div></section>';

const labelsResp = {
  subject: H,
  flag: { id: H, agent: H, explain: { actions: [{ id: 'allow-host', body: { host: H }, consequence: H, label: H }] } },
  labels: { summary: { ok: 1 }, similar: [{ label: 'ok', source: H, created_at: H, pattern: H, reason: H }, { label: H, source: H }],
    suggestion: { text: H, action_id: 'allow-host' } },
};
const noHistory = last => lines('', '    <div class="plan-labels">', '      <h5>Your history</h5>',
  '      <p class="plan-status">No earlier judgments on cases like this.</p>', '      ', '      ', `      ${last}`, '    </div>');

const rev = 'a'.repeat(64);
const instruction = (file, extra = {}) => ({ ready: true, path: `/repo/${H}/${file}`, instruction: H, revision: rev, ...extra });
const instructionBlock = (busy, file, action, error = '') => `<div class="plan-instruction" aria-busy="${busy}"><p>Append this safety rule to <code>/repo/${E}/${file}</code>:</p>`
  + `<blockquote>${E}</blockquote><div class="endpoint-actions">${action}</div>${error}</div>`;
const applyButton = suffix => `<button type="button" class="btn btn-primary btn-sm" data-action="apply-agent-instruction" data-subject="${E}" data-revision="${rev}"${suffix}</button>`;

const planResp = {
  subject: H, status: 'stale', advisor_ready: true,
  playbook: { title: H, why: H, now: [H], prevent: [{ kind: 'agent-instruction', step: H, detail: H }, { kind: H, step: H, detail: H }] },
  plan: { risk: H, summary: H, why: [H], remediate: [H], prevent: [{ kind: 'config', step: H, detail: H }], behavior: [H],
    actions: ['kill', 'allow-host', 'nope'], model: H, created_at: H },
  flag: { id: H, agent: H, explain: { actions: [{ id: 'kill', consequence: H }, { id: 'allow-host', body: { host: H }, consequence: H, label: H }] } },
  instruction: { ready: false, reason: H },
};
const step = (kind, rest = '') => `<li><span class="plan-kind">${kind}</span> <strong>${E}</strong>. ${E}${rest}</li>`;
const planAdvisor = lines('', '      <div class="plan-advisor">',
  `        <p class="plan-summary"><span class="plan-risk plan-risk-${E}">${E} risk</span> ${E}</p>`,
  `        <h5>Why it happened</h5><ul class="plan-list"><li>${E}</li></ul>`,
  `        <h5>Do now</h5><ol class="plan-list"><li>${E}</li></ol>`,
  `        <h5>Prevent it</h5><ul class="plan-list">${step('Setting')}</ul>`,
  `        <h5>Change how you work</h5><ul class="plan-list"><li>${E}</li></ul>`,
  `        <div class="endpoint-actions"><button class="btn btn-danger btn-sm" data-action="explain-act" data-flag-id="${E}" data-action-id="kill" title="${E}">Kill ${E}</button>`
    + `<button class="btn btn-ghost btn-sm" data-action="explain-act" data-flag-id="${E}" data-action-id="allow-host" data-host="${E}" title="${E}">${E}</button></div>`,
  `        <p class="plan-meta">Local advisor · ${E} ·  ago</p>`, '      </div>');
const planPlaybook = lines('', `    <p class="plan-why">${E}</p>`, `    <h5>Do now</h5><ol class="plan-list"><li>${E}</li></ol>`,
  `    <h5>Prevent it</h5><ul class="plan-list">${step('Agent instructions', `<p class="plan-status">${E}</p>`)}${step(E)}</ul>`);

const cursorChip = '<span class="harness-chip" title="Cursor"><span class="harness-tile hk-cursor light" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-cursor"/></svg></span><span class="harness-label">Cursor</span></span>';
const unknownChip = `<span class="harness-chip" title="${E}"><span class="harness-glyph" data-harness-color="hsl(264 62% 62%)" aria-hidden="true">&lt;</span><span class="harness-label">${E}</span></span>`;
const clearScope = '<button type="button" class="btn btn-ghost btn-sm" data-action="clear-scope">Clear</button>';
const returnBack = '<button type="button" class="btn btn-ghost btn-sm" data-action="session-investigation-return">Back to session</button>';
const sessionBack = `<button type="button" class="btn btn-ghost btn-sm" data-action="filter-session" data-session="${E}">Back to session</button>`;

const timestampLabel = new Date('2026-07-12T12:00:00Z').toLocaleString(undefined, {
  year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
  timeZone: 'UTC', timeZoneName: 'short',
});

const cases = {
  'localTimestampHTML': [() => inUTC(() => ctx.localTimestampHTML(`Sun Jul 12 2026 12:00:00 GMT+0000 (${H})`)),
    `<time datetime="Sun Jul 12 2026 12:00:00 GMT+0000 (${E})" title="Sun Jul 12 2026 12:00:00 GMT+0000 (${E})">${timestampLabel}</time>`],
  'advisorAdviceHTML allow': [() => ctx.advisorAdviceHTML({ assessment: 'benign', confidence: 0.42, rationale: H }),
    `<span class="advisor-advice allow"><b>Advisor suggests allow</b> (42% conf) — ${E}</span>`],
  'advisorAdviceHTML look': [() => ctx.advisorAdviceHTML({ assessment: H, rationale: H }),
    `<span class="advisor-advice look"><b>Advisor suggests you look first</b> — ${E}</span>`],
  'advisorAdviceHTML deny': [() => ctx.advisorAdviceHTML({ assessment: 'malicious', confidence: 1, rationale: H }),
    `<span class="advisor-advice deny"><b>Advisor suggests deny</b> (100% conf) — ${E}</span>`],
  'endpointDetailHTML empty': [() => ctx.endpointDetailHTML(null), '<div class="empty"><span>No endpoint data</span></div>'],
  'endpointDetailHTML host only': [() => ctx.endpointDetailHTML({ host: H }), endpointBody(E, 'Unknown endpoint', '', '', '', noSessions, noEvents)],
  'endpointDetailHTML full': [() => ctx.endpointDetailHTML(endpointDetail, H), endpointBody(E, `${E} (${E})`,
    '<p class="endpoint-facts"><b>3×</b> in 7d · last  ago · first seen  ago</p>',
    `<div class="endpoint-allowed">Already trusted for ${E}, b — this endpoint stops being flagged for them.</div>`,
    `<button type="button" class="btn btn-ghost btn-sm active" data-action="allow-host" data-agent="${E}" data-host="${E}">Allow for ${E}</button>`
      + `<button type="button" class="btn btn-ghost btn-sm" data-action="allow-host" data-agent="other" data-host="${E}">Allow for other</button>`,
    endpointSession(E, `${E}@${E}`, E8) + endpointSession('agent', E, '') + endpointSession('agent', 'unknown workspace', ''),
    endpointEvent('', E, `session ${E8}`) + endpointEvent('', '', E) + endpointEvent('', '', 'agent'))],
  'fileDetailHTML empty': [() => ctx.fileDetailHTML(null), '<div class="empty"><span>No file data</span></div>'],
  'fileDetailHTML full': [() => ctx.fileDetailHTML(fileDetail, 1), lines('', '    <div class="endpoint-head">',
    `      <div class="endpoint-host">${E}</div>`, `      <span class="endpoint-kind">${E}</span>`, '    </div>',
    `    <p class="endpoint-identity">${E}</p>`, '    <p class="endpoint-facts">2 KB · modified  ago · owned by another user</p>',
    `    <div class="endpoint-actions">${fileActions}</div>`,
    `    <section class="endpoint-section"><h4>Environment variable names</h4><p>Values are never shown.</p><ul><li><code>${E}</code></li><li><code>TOKEN</code></li></ul></section><p>${E}</p>`,
    `    <section class="endpoint-section"><h4>Session</h4>${endpointSession(E, `${E}@${E}`, E8)}</section>`,
    `    <section class="endpoint-section"><h4>Around the secret</h4><pre class="file-excerpt">${E}</pre></section>`,
    `    <section class="endpoint-section"><h4>Findings</h4>${fileFindings}</section>`,
    `    <section class="endpoint-section"><h4>Agent access</h4>${fileEvent(E, `<span class="endpoint-event-agent">${E} · session ${E8}</span>`)}</section>`)],
  'fileDetailHTML deleted': [() => ctx.fileDetailHTML({ path: H, exists: false, excerpt_withheld: H }, 1), lines('', '    <div class="endpoint-head">',
    `      <div class="endpoint-host">${E}</div>`, '      ', '    </div>', '    ', '    <p class="endpoint-facts">deleted since it was flagged</p>',
    '    <div class="endpoint-actions"></div>', '    ', '    ',
    `    <section class="endpoint-section"><h4>Around the secret</h4><p class="file-withheld">${E}</p></section>`, '    ', '    ')],
  'planSlotHTML': [() => ctx.planSlotHTML(H), planSlot(E)],
  'labelsLineHTML counts': [() => ctx.labelsLineHTML({ ok: 2, not_ok: 1 }), '<p class="finding-labels">You marked similar cases 2 as routine and 1 as not ok.</p>'],
  'labelsLineHTML served count': [() => ctx.labelsLineHTML({ ok: H }), `<p class="finding-labels">You marked similar cases ${E} as routine.</p>`],
  'labelsLineHTML none': [() => ctx.labelsLineHTML({}), ''],
  'markButtonsHTML': [() => ctx.markButtonsHTML(H), marks(E, 'Mark as routine')],
  'markButtonsHTML incident': [() => ctx.markButtonsHTML('incident:' + H), marks(`incident:${E}`, 'Send routine feedback')],
  'incidentWorkflowHTML open': [() => ctx.incidentWorkflowHTML(H, { resolution_note: H }),
    `<p class="plan-status">Open incident</p><div class="endpoint-actions"><button class="btn btn-ghost btn-sm" data-action="incident-status" data-id="${E}" data-status="acknowledged" title="Remove from Needs you; keep the report and monitoring">Dismiss</button>`
      + `<button class="btn btn-ghost btn-sm" data-action="incident-status" data-id="${E}" data-status="resolved">Report resolved</button></div><p>${E}</p>`],
  'incidentWorkflowHTML resolved': [() => ctx.incidentWorkflowHTML(H, { status: 'resolved' }), '<p class="plan-status">Reported resolved</p><div class="endpoint-actions"></div>'],
  'incidentRemediationHTML': [() => ctx.incidentRemediationHTML(H, remediation), remediationSection(true)],
  'incidentRemediationHTML without actions': [() => ctx.incidentRemediationHTML(H, remediation, false), remediationSection(false)],
  'incidentRemediationHTML none': [() => ctx.incidentRemediationHTML(H, { steps: [] }), ''],
  'incidentReportHTML': [() => ctx.incidentReportHTML(H, { status: 'acknowledged' }, `# ${H}\nSee \`/etc/${H}\`\n## Evidence\n- ${H}`, remediation),
    `<div class="markdown-view"><h1>${E}</h1><p>See <button type="button" class="file-link" data-action="open-file" data-path="/etc/${E}">/etc/${E}</button></p></div>`
      + `<section class="endpoint-section incident-workflow-actions"><p class="plan-status">Dismissed from Needs you</p><div class="endpoint-actions"><button class="btn btn-ghost btn-sm" data-action="incident-status" data-id="${E}" data-status="resolved">Report resolved</button></div></section>`
      + remediationSection(true) + `<div class="endpoint-actions">${marks(`incident:${E}`, 'Send routine feedback')}</div>`
      + '<p class="body-note">Routine feedback helps the advisor. It does not add an exception or change this incident’s status.</p>'
      + planSlot(`incident:${E}`) + `<div class="markdown-view"><h2>Evidence</h2><ul><li>${E}</li></ul></div>`],
  'labelsHTML full': [() => ctx.labelsHTML(labelsResp, 1), lines('', '    <div class="plan-labels">', '      <h5>Your history</h5>',
    '      <p class="finding-labels">You marked similar cases 1 as routine.</p>',
    `      <ul class="plan-list"><li>Routine · ${E} ·  ago · ${E} · ${E}</li><li>Not ok · ${E} ·  ago</li></ul>`,
    `      <div class="plan-suggestion"><p>${E}</p><button class="btn btn-primary btn-sm" data-action="explain-act" data-flag-id="${E}" data-action-id="allow-host" data-host="${E}" title="${E}">${E}</button></div>`,
    `      <div class="endpoint-actions">${marks(E, 'Mark as routine')}</div>`, '    </div>')],
  'labelsHTML incident': [() => ctx.labelsHTML({ subject: 'incident:' + H, labels: {} }), noHistory('')],
  'labelsHTML none': [() => ctx.labelsHTML({}), ''],
  'agentInstructionHTML not ready': [() => ctx.agentInstructionHTML(H, { ready: false, reason: H }), `<p class="plan-status">${E}</p>`],
  'agentInstructionHTML ready': [() => ctx.agentInstructionHTML(H, instruction('AGENTS.md'), { error: H }),
    instructionBlock(false, 'AGENTS.md', applyButton('>Apply to AGENTS.md'), `<p class="plan-status" role="alert">${E}</p>`)],
  'agentInstructionHTML busy': [() => ctx.agentInstructionHTML(H, instruction('CLAUDE.md'), { busy: true }),
    instructionBlock(true, 'CLAUDE.md', applyButton(' disabled>Applying…'))],
  'agentInstructionHTML applied': [() => ctx.agentInstructionHTML(H, instruction('AGENTS.md', { applied: true })),
    instructionBlock(false, 'AGENTS.md', '<p role="status">Already applied</p>')],
  'agentInstructionHTML other file': [() => ctx.agentInstructionHTML(H, instruction('README.md')), ''],
  'planHTML advisor plan': [() => ctx.planHTML(planResp, 1), lines('', '    <div class="plan">',
    '      <p class="plan-status plan-status-stale">Written before newer evidence arrived. Ask again for an updated plan.</p>',
    `      ${planAdvisor}`, `      <details class="plan-playbook"><summary>Playbook: ${E}</summary>${planPlaybook}</details>`,
    `      <div class="plan-ask"><button class="btn btn-primary btn-sm" data-action="ask-plan" data-subject="${E}">Ask the advisor again</button></div>`,
    '      ', '    </div>')],
  'planHTML playbook only': [() => ctx.planHTML({ subject: H, status: 'disabled', reason: H, playbook: { title: H, why: H }, labels: {} }, 1),
    lines('', '    <div class="plan">', `      <p class="plan-status plan-status-disabled">${E}</p>`, '      ',
      `      <div class="plan-playbook">${lines('', `    <p class="plan-why">${E}</p>`, '    ', '    ')}</div>`,
      `      <div class="plan-ask"><button class="btn btn-primary btn-sm" data-action="ask-plan" data-subject="${E}" disabled>Ask the advisor for a plan</button></div>`,
      `      ${noHistory(`<div class="endpoint-actions">${marks(E, 'Mark as routine')}</div>`)}`, '    </div>')],
  'planHTML none': [() => ctx.planHTML(null), ''],
  'harnessChipHTML logo': [() => ctx.harnessChipHTML('cursor', { label: true }),
    '<span class="harness-chip" title="Cursor"><span class="harness-tile hk-cursor light" aria-hidden="true"><svg class="harness-logo" aria-hidden="true"><use href="#logo-cursor"/></svg></span><span class="harness-label">Cursor</span></span>'],
  'harnessChipHTML glyph': [() => ctx.harnessChipHTML('openclaw'),
    '<span class="harness-chip" title="OpenClaw"><span class="harness-glyph hk-openclaw" aria-hidden="true">O</span></span>'],
  'harnessChipHTML unknown': [() => ctx.harnessChipHTML(H, { label: true }),
    `<span class="harness-chip" title="${E}"><span class="harness-glyph" data-harness-color="hsl(264 62% 62%)" aria-hidden="true">&lt;</span><span class="harness-label">${E}</span></span>`],
  'harnessChipHTML unnamed': [() => ctx.harnessChipHTML(''),
    '<span class="harness-chip" title="agent"><span class="harness-glyph" data-harness-color="hsl(61 62% 62%)" aria-hidden="true">?</span></span>'],
  'scopeBarHTML session': [() => ctx.scopeBarHTML({ session: H, events: 1, flags: 2 }),
    `<span>Scoped to session <b>${E8}</b> · 1 event · 2 flags</span><span class="scope-actions">${sessionBack}${clearScope}</span>`],
  'scopeBarHTML session return': [() => ctx.scopeBarHTML({ session: H, returnToSession: true }),
    `<span>Scoped to session <b>${E8}</b> · 0 events · 0 flags</span><span class="scope-actions">${returnBack}${clearScope}</span>`],
  'scopeBarHTML labelled pids': [() => ctx.scopeBarHTML({ pids: [7, 8], pidLabel: H, events: H, flags: 1 }),
    `<span>Scoped to <b>${E}</b> (2 processes) · 0 events · 1 flag</span><span class="scope-actions">${clearScope}</span>`],
  'scopeBarHTML pid': [() => ctx.scopeBarHTML({ pids: [7] }),
    `<span>Scoped to <b>PID 7</b> (1 process) · 0 events · 0 flags</span><span class="scope-actions">${clearScope}</span>`],
  'scopeBarHTML workspace permissions': [() => ctx.scopeBarHTML({ returnToSession: true, workspacePermissions: true }),
    `<span>Saved permissions · includes other sessions</span><span class="scope-actions">${returnBack}</span>`],
  'scopeBarHTML machine traffic': [() => ctx.scopeBarHTML({ returnToSession: true, machineTraffic: true }),
    `<span>Machine-wide traffic · not attributed to this session</span><span class="scope-actions">${returnBack}</span>`],
  'scopeBarHTML cleared': [() => ctx.scopeBarHTML({ returnToSession: true }), `<span>Evidence filters cleared</span><span class="scope-actions">${returnBack}</span>`],
  'scopeBarHTML unscoped': [() => ctx.scopeBarHTML({}), ''],
  'harnessPillsHTML': [() => ctx.harnessPillsHTML(['cursor', H], { [H]: false }),
    '<button type="button" class="harness-pill off" data-action="all-harnesses" aria-pressed="false">All</button>'
      + `<button type="button" class="harness-pill" data-action="toggle-harness" data-harness="cursor" aria-pressed="true" title="Hide Cursor">${cursorChip}</button>`
      + `<button type="button" class="harness-pill off" data-action="toggle-harness" data-harness="${E}" aria-pressed="false" title="Show ${E}">${unknownChip}</button>`],
  'harnessPillsHTML all on': [() => ctx.harnessPillsHTML(['openclaw']),
    '<button type="button" class="harness-pill" data-action="all-harnesses" aria-pressed="true">All</button>'
      + '<button type="button" class="harness-pill" data-action="toggle-harness" data-harness="openclaw" aria-pressed="true" title="Hide OpenClaw"><span class="harness-chip" title="OpenClaw"><span class="harness-glyph hk-openclaw" aria-hidden="true">O</span><span class="harness-label">OpenClaw</span></span></button>'],
  'harnessPillsHTML none': [() => ctx.harnessPillsHTML([], {}), ''],
  'parseMarkdownToHTML': [() => ctx.parseMarkdownToHTML(`# ${H}\n\n**${H}** and *${H}* with \`${H}\`\nnext ${H}\n\n- ${H}\n  more\n- two\n1. one\n\n\`\`\`\n${H}\n<b>\n\`\`\`\n\n\`\`\`\nopen ${H}`),
    `<div class="markdown-view"><h1>${E}</h1><p><strong>${E}</strong> and <em>${E}</em> with <code class="md-inline-code">${E}</code><br>next ${E}</p>`
      + `<ul><li>${E} more</li><li>two</li></ul><ol><li>one</li></ol><pre class="md-codeblock"><code>${E}\n&lt;b&gt;</code></pre><pre class="md-codeblock"><code>open ${E}</code></pre></div>`],
  'parseMarkdownToHTML empty': [() => ctx.parseMarkdownToHTML(''), ''],
  'assessmentHTML full': [() => ctx.assessmentHTML({ review_state: H, residual_risk: 'possible-exposure', control: 'blocked',
    evidence_basis: ['fingerprint-payload', H], limits: [H], advice: { assessment: H, confidence: 0.5, rationale: H } }),
    '<div class="finding-assessment"><p class="assessment-state">Review state unknown · Possible exposure · Blocked before forwarding</p>'
      + `<details class="assessment-limits"><summary>Evidence and limits</summary><ul><li>Registered secret fingerprint</li><li>${E}</li><li>${E}</li></ul></details>`
      + `<p class="assessment-advice">Advisor opinion: ${E} (50%) · ${E}</p></div>`],
  'assessmentHTML state only': [() => ctx.assessmentHTML({ review_state: 'reviewed', control: 'observed-only' }),
    '<div class="finding-assessment"><p class="assessment-state">Reviewed · Exposure unknown · Observed only</p></div>'],
  'assessmentHTML empty advice': [() => ctx.assessmentHTML({ advice: {} }),
    '<div class="finding-assessment"><p class="assessment-state">Review state unknown · Exposure unknown · Control outcome unknown</p><p class="assessment-advice">Advisor opinion: unrated · </p></div>'],
  'assessmentHTML none': [() => ctx.assessmentHTML(null), ''],
  'payloadOutcomeHTML': [() => ctx.payloadOutcomeHTML({ blocked: 2, observed_only: H, unknown: -1 }),
    '<p class="body-note">Recorded payload findings: 2 blocked before forwarding; 0 observed only; 0 outcome unknown.</p>'
      + '<details class="assessment-limits"><summary>Control result limits</summary><p>These counts cover recorded findings, not every request. Observation does not establish delivery. Earlier exposure and external credential revocation are not verified.</p></details>'],
  'payloadOutcomeHTML none': [() => ctx.payloadOutcomeHTML(null), ''],
  'factChipsHTML full': [() => ctx.factChipsHTML({ agent: 'a', explain: { subject: { display: H, path: '/x/' + H, category: 'keychain' },
    egress: [{ org: H, host: H }, { org: 'Org', host: '1.1.1.1' }, { org: 'Org', host: '2.2.2.2' }, { host: 'fe80::1' }, { org: 'V6', host: 'fe80::2' }, { name: 'n', host: 'h.example' }] } }, H),
    `<div class="facts"><span class="fact fact-repo"><svg class="icon"><use href="#i-branch"/></svg>${E}</span>`
      + `<button type="button" class="fact fact-file" data-action="open-file" data-path="/x/${E}" title="/x/${E}"><svg class="icon"><use href="#i-key"/></svg>${E}</button>`
      + `<span class="fact fact-dest" title="${E}"><svg class="icon"><use href="#i-globe"/></svg>${E}</span>`
      + '<span class="fact fact-dest" title="1.1.1.1, 2.2.2.2"><svg class="icon"><use href="#i-globe"/></svg>Org · 2 addresses</span>'
      + '<span class="fact fact-dest" title="fe80::1"><svg class="icon"><use href="#i-globe"/></svg>IPv6 address</span>'
      + '<span class="fact fact-dest" title="fe80::2"><svg class="icon"><use href="#i-globe"/></svg>V6 address</span>'
      + '<span class="fact fact-dest" title="h.example"><svg class="icon"><use href="#i-globe"/></svg>n · h.example</span></div>'],
  'factChipsHTML relative file': [() => ctx.factChipsHTML({ agent: 'a', explain: { subject: { display: H, path: 'relative' } } }, 'a'),
    `<div class="facts"><span class="fact fact-file"><svg class="icon"><use href="#i-doc"/></svg>${E}</span></div>`],
  'factChipsHTML none': [() => ctx.factChipsHTML({}, ''), ''],
};

for (const [name, [render, expected]] of Object.entries(cases)) {
  test(`lib markup: ${name}`, () => {
    assert.equal(render(), expected);
  });
}

test('lib markup: endpointDetailHTML escapes a served count', () => {
  assert.equal(ctx.endpointDetailHTML({ host: 'h', count: H }),
    endpointBody('h', 'Unknown endpoint', `<p class="endpoint-facts"><b>${E}×</b> in 7d</p>`, '', '', noSessions, noEvents));
});
