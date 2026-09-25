// Secure Agent console — pure logic. No DOM access in this file.
//
// Loaded as a classic script before app.js (top-level functions become page
// globals), and unit-tested under `node --test` by evaluating the file in a
// fresh VM context (packaging/test/console/lib.test.mjs). Keep it free of
// window/document references so both consumers work.

function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// applyInlineMetrics: the console CSP (style-src 'self') drops style
// attributes parsed from markup, so renderers carry sizes in data attributes
// (data-left / data-w / data-h in percent, data-harness-color) and callers apply them
// here after each innerHTML assignment — CSSOM writes from script are
// allowed under that policy. Touches only the subtree it is handed.
function applyInlineMetrics(root) {
  if (!root) return;
  root.querySelectorAll('[data-left]').forEach(el => el.style.setProperty('left', el.dataset.left + '%'));
  root.querySelectorAll('[data-w]').forEach(el => el.style.setProperty('width', el.dataset.w + '%'));
  root.querySelectorAll('[data-h]').forEach(el => el.style.setProperty('height', el.dataset.h + '%'));
  root.querySelectorAll('[data-harness-color]').forEach(el => el.style.setProperty('--harness-color', el.dataset.harnessColor));
}

// patchList: keyed reconcile of a container's children, so a re-render keeps
// every node whose markup did not change — focus, <details> open state,
// scroll and hover survive. opts: key(item) → string; html(item) → one root
// element; hash(item) → the content that drives the markup (default: the
// html); empty → the markup for zero items. A changed item is rebuilt and
// swapped in place (a replaced <details> keeps its open state); a missing key
// is removed; order is enforced by moving nodes, which keeps identity. Key and
// hash ride on the nodes as properties, so the serialized markup is exactly
// what the renderer wrote. Touches only the container it is handed.
function patchList(container, items, opts) {
  if (!container) return;
  if (!items.length) {
    if (container._saEmpty !== opts.empty) {
      container.innerHTML = opts.empty || '';
      container._saEmpty = opts.empty;
    }
    return;
  }
  container._saEmpty = undefined;
  const keyed = items.map(item => [String(opts.key(item)), item]);
  const wanted = new Set(keyed.map(k => k[0]));
  const old = new Map();
  for (const n of Array.from(container.childNodes)) {
    if (n.nodeType === 1 && n._saKey !== undefined && wanted.has(n._saKey) && !old.has(n._saKey)) old.set(n._saKey, n);
    else n.remove();
  }
  const box = container.ownerDocument.createElement('div');
  let at = container.firstChild;
  for (const [key, item] of keyed) {
    const markup = opts.html(item);
    const hash = opts.hash ? String(opts.hash(item)) : markup;
    let node = old.get(key);
    old.delete(key);
    if (!node || node._saHash !== hash) {
      box.innerHTML = markup.trim();
      applyInlineMetrics(box);
      const fresh = box.firstElementChild;
      if (!fresh) continue;
      fresh._saKey = key;
      fresh._saHash = hash;
      if (node) {
        if (node.tagName === 'DETAILS' && fresh.tagName === 'DETAILS') fresh.open = node.open;
        if (node === at) at = fresh;
        node.replaceWith(fresh);
      }
      node = fresh;
    }
    if (node === at) at = node.nextSibling;
    else container.insertBefore(node, at);
  }
}

// fmtTime: deterministic local HH:MM:SS. toLocaleTimeString varies by locale
// (zero-padding, a "24:00" midnight quirk in some), which can re-wrap the
// 68px timeline column — build the string by hand instead.
function fmtTime(d) {
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// fmtDayClock: deterministic local "Fri 3:10 PM", built by hand like
// fmtTime.
function fmtDayClock(d) {
  const h = d.getHours() % 12 || 12;
  const m = String(d.getMinutes()).padStart(2, '0');
  return `${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][d.getDay()]} ${h}:${m} ${d.getHours() < 12 ? 'AM' : 'PM'}`;
}

// eventTime: an Events row's time — HH:MM:SS for today, "Mon DD HH:MM" for
// any other day (local time), so an old row never reads as today's.
const EVENT_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function eventTime(d, now) {
  now = now || new Date();
  if (d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate()) {
    return fmtTime(d);
  }
  const p = (n) => String(n).padStart(2, '0');
  return `${EVENT_MONTHS[d.getMonth()]} ${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

// eventsNewestFirst: rows by ts, newest first (a copy; ties keep their order).
function eventsNewestFirst(events) {
  const t = (e) => { const v = Date.parse(e.ts); return isNaN(v) ? 0 : v; };
  return (events || []).slice().sort((a, b) => t(b) - t(a));
}

// EVENT_KIND_LABELS: the Events row label per event kind
// (daemon/internal/event/event.go); other kinds read "EVENT".
const EVENT_KIND_LABELS = {
  0: 'OPEN', 1: 'WRITE', 2: 'DELETE', 3: 'EXEC', 5: 'CONN', 6: 'CONN',
  8: 'TOOL USE', 9: 'PROXY HIT', 12: 'TOOL', 13: 'TURN', 14: 'MODEL',
};

// eventCostLabel: a model call's cost, else its price class — "plan" and
// "local" have no per-call price; anything else unpriced reads "unpriced".
function eventCostLabel(e) {
  const usd = Number(e.cost_usd) || 0;
  if (usd > 0) return usd < 0.01 ? '$' + usd.toFixed(4) : fmtUSD(usd);
  if (e.price_class === 'plan' || e.price_class === 'local') return e.price_class;
  if (e.price_class === 'priced') return fmtUSD(0);
  return 'unpriced';
}

// eventRow: an Events row's label, CSS class and detail, all from the fields
// /events returns.
function eventRow(e) {
  const hostPort = e.remote_host ? `${e.remote_host}:${e.remote_port}` : '';
  const fallback = e.detail || e.path || hostPort;
  const k = Number(e.kind);
  const cls = (k === 8 || k === 12) ? 'tool' : k === 9 ? 'proxy' : (k === 5 || k === 6) ? 'conn' : '';
  let detail = fallback;
  if (k === 0 || k === 1 || k === 2) detail = e.path || fallback;
  else if (k === 3) detail = e.exe_path || fallback;
  else if (k === 5 || k === 6) detail = hostPort || fallback;
  else if (k === 12) {
    detail = [e.tool, e.tool_status, e.duration_ms ? fmtDurationMs(e.duration_ms) : ''].filter(Boolean).join(' · ');
  } else if (k === 13) detail = '';
  else if (k === 14) {
    detail = [e.model || 'unknown model',
      `${fmtCompact(e.tokens_in)} in / ${fmtCompact(e.tokens_out)} out`, eventCostLabel(e)].join(' · ');
  }
  return { label: EVENT_KIND_LABELS[k] || 'EVENT', cls, detail };
}

// eventWho: the Events row's who column. A trace row (pid 0) names its
// session — the harness and sessionTitle of the session the console holds,
// else the short id; any other row is "agent · PID n", else "PID n".
function eventWho(e, sessions, agentName) {
  if (!Number(e.pid) && e.session_id) {
    const s = (sessions || []).find(x => x && x.id === e.session_id);
    return s
      ? { text: sessionTitle(s), title: `${harnessMeta(s.harness).label} session ${e.session_id}`, harness: s.harness }
      : { text: `session ${sessionShort(e.session_id)}`, title: `session ${e.session_id}`, harness: '' };
  }
  return { text: agentName ? `${agentName} · PID ${e.pid}` : `PID ${e.pid}`, title: `PID ${e.pid}`, harness: '' };
}

// eventKey: a stable identity for a rendered Events row. Trace rows (pid 0)
// share a ts across several calls in one turn (Hermes writes them at one
// timestamp), so the default ts|pid|kind|detail shape collapses them into
// one row: tool_call keys on its own call id, turn and model_call key on
// session + ts + model + tokens. Every other kind keeps the default shape.
function eventKey(e) {
  const k = Number(e.kind);
  if (k === 12) return `12|${e.session_id || ''}|${e.call_id || ''}`;
  if (k === 13 || k === 14) {
    return `${k}|${e.session_id || ''}|${e.ts}|${e.model || ''}|${e.tokens_in || 0}|${e.tokens_out || 0}`;
  }
  return `${e.ts}|${e.pid}|${e.kind}|${e.detail || e.path || e.remote_host || ''}`;
}

// advisorAdviceHTML: the advisor's recommendation on a blocked guard prompt.
// Advisory only — it never resolves the prompt; it informs the human's choice.
// assessment (benign|suspicious|malicious) maps to allow|look|deny.
function advisorAdviceHTML(advice) {
  if (!advice || !advice.rationale) return '';
  const verdict = advice.assessment === 'benign' ? 'allow'
    : advice.assessment === 'malicious' ? 'deny' : 'look';
  const pct = Math.round((Number(advice.confidence) || 0) * 100);
  return `<span class="advisor-advice ${verdict}">`
    + `<b>Advisor suggests ${verdict === 'look' ? 'you look first' : verdict}</b>`
    + `${pct ? ` (${pct}% conf)` : ''} — ${escapeHTML(advice.rationale)}</span>`;
}

// eventClock: RFC3339 → local HH:MM:SS, '' when unparseable. Shared by the
// endpoint drill-down; the timeline's own helper is local to that builder.
function eventClock(s) {
  const d = Date.parse(s);
  return isNaN(d) ? '' : fmtTime(new Date(d));
}

// endpointIdentityLine: one plain sentence naming what an endpoint is, so an
// operator can decide whether an agent's connection is rightful. Pure.
function endpointIdentityLine(identity) {
  if (!identity) return 'Unknown endpoint';
  const org = identity.org || '';
  const name = identity.name || '';
  const isIP = identity.kind === 'ipv6' || identity.kind === 'ipv4';
  if (isIP && org && name) return `${org} address (${name})`;
  if (isIP && org) return `${org} address`;
  if (isIP && name) return `Resolves to ${name}`;
  if (isIP) return 'No owner identified — may be a private or unroutable address';
  if (org) return `${org} (${name})`;
  return name || 'Unknown endpoint';
}

// endpointDetailHTML: the endpoint evidence drawer. Pure function — the DOM
// tests drive it headless.
function endpointDetailHTML(detail, clickedAgent) {
  if (!detail || !detail.host) {
    return '<div class="empty"><span>No endpoint data</span></div>';
  }
  const id = detail.identity || {};
  const kindChip = id.kind === 'ipv6' ? 'IPv6' : id.kind === 'ipv4' ? 'IPv4' : 'hostname';
  const facts = [
    detail.count ? `<b>${detail.count}×</b> in 7d` : '',
    detail.last_seen ? `last ${fmtAge(detail.last_seen, Date.now())} ago` : '',
    detail.first_seen ? `first seen ${fmtAge(detail.first_seen, Date.now())} ago` : '',
  ].filter(Boolean).join(' · ');

  const agents = (detail.agents || []).map(a => {
    const isClicked = clickedAgent && a === clickedAgent;
    return `<button type="button" class="btn btn-ghost btn-sm${isClicked ? ' active' : ''}" data-action="allow-host" data-agent="${escapeHTML(a)}" data-host="${escapeHTML(detail.host)}">Allow for ${escapeHTML(a)}</button>`;
  }).join('');

  const sessions = (detail.sessions || []).map(s => `
    <div class="endpoint-session">
      <strong>${escapeHTML(s.harness || 'agent')}</strong>
      <span>${escapeHTML(s.repo ? `${s.repo}${s.branch ? '@' + s.branch : ''}` : (s.workspace || 'unknown workspace'))}</span>
      <span class="endpoint-session-id">${escapeHTML(String(s.id || '').slice(0, 8))}</span>
    </div>`).join('') || '<div class="resource-detail-empty">No session attribution on these connections.</div>';

  const events = (detail.events || []).slice(0, 20).map(e => `
    <div class="endpoint-event">
      <span class="endpoint-event-time">${escapeHTML(eventClock(e.ts))}</span>
      <span class="endpoint-event-port">:${escapeHTML(String(e.remote_port || ''))}</span>
      <span class="endpoint-event-agent">${escapeHTML(e.session_id ? 'session ' + String(e.session_id).slice(0, 8) : (e.exe_path ? String(e.exe_path).split('/').pop() : 'agent'))}</span>
    </div>`).join('') || '<div class="resource-detail-empty">No recorded connections.</div>';

  const allowed = (detail.allowed || []).length
    ? `<div class="endpoint-allowed">Already trusted for ${(detail.allowed || []).map(a => escapeHTML(a.agent)).join(', ')} — this endpoint stops being flagged for them.</div>`
    : '';

  return `
    <div class="endpoint-head">
      <div class="endpoint-host">${escapeHTML(detail.host)}</div>
      <span class="endpoint-kind">${escapeHTML(kindChip)}</span>
    </div>
    <p class="endpoint-identity">${escapeHTML(endpointIdentityLine(id))}</p>
    ${facts ? `<p class="endpoint-facts">${facts}</p>` : ''}
    ${allowed}
    <div class="endpoint-actions">${agents || ''}</div>
    <section class="endpoint-section"><h4>Reached by</h4>${sessions}</section>
    <section class="endpoint-section"><h4>Recent connections</h4>${events}</section>`;
}

// fileDetailHTML: the evidence file drawer — facts, the masked excerpt around
// each secret, who touched it, and Reveal / Open. Pure function — the node
// and DOM tests drive it.
function fileDetailHTML(d, nowMs) {
  if (!d || !d.path) {
    return '<div class="empty"><span>No file data</span></div>';
  }
  const now = nowMs || Date.now();
  const s = d.subject || {};
  const facts = [
    d.exists ? fmtRSS(d.size) || '0 B' : 'deleted since it was flagged',
    d.exists && d.mod_time ? `modified ${fmtAge(d.mod_time, now)} ago` : '',
    d.exists && !d.owned_by_user ? 'owned by another user' : '',
  ].filter(Boolean).join(' · ');
  const actions = d.exists ? `
    <button type="button" class="btn btn-ghost btn-sm" data-action="file-reveal" data-path="${escapeHTML(d.path)}">Reveal in Finder</button>
    <button type="button" class="btn btn-ghost btn-sm" data-action="file-open" data-path="${escapeHTML(d.path)}">Open in editor</button>` : '';
  const sess = d.session ? `
    <div class="endpoint-session">
      <strong>${escapeHTML(familyTitle(d.session.harness || 'agent'))}</strong>
      <span>${escapeHTML(d.session.repo ? d.session.repo + (d.session.branch ? '@' + d.session.branch : '') : (d.session.workspace || ''))}</span>
      <span class="endpoint-session-id">${escapeHTML(sessionShort(d.session.id))}</span>
    </div>` : '';
  const excerpt = d.excerpt
    ? `<pre class="file-excerpt">${escapeHTML(d.excerpt)}</pre>`
    : d.excerpt_withheld ? `<p class="file-withheld">${escapeHTML(d.excerpt_withheld)}</p>` : '';
  const findings = (d.findings || []).map(f => `
    <div class="endpoint-event">
      <span class="endpoint-event-time">${escapeHTML(fmtAge(f.ts, now))} ago</span>
      <span>${escapeHTML(f.kind === 'incident' ? 'Incident · ' + (f.risk || '') : ruleTitle(f.rule))}</span>
      ${f.kind === 'incident'
        ? `<button type="button" class="btn btn-ghost btn-sm endpoint-event-agent" data-action="open-incident" data-id="${escapeHTML(f.id)}">Open</button>`
        : `<span class="endpoint-event-agent">${escapeHTML(f.acknowledged ? 'reviewed' : familyTitle(f.agent || ''))}</span>`}
    </div>`).join('');
  const accesses = (d.accesses || []).map(a => `
    <div class="endpoint-event">
      <span class="endpoint-event-time">${escapeHTML(fmtAge(a.ts, now))} ago</span>
      <span>${escapeHTML(String(a.kind || '').replace('file-', ''))}</span>
      <span class="endpoint-event-agent">${escapeHTML((a.exe_path ? String(a.exe_path).split('/').pop() + ' · ' : '') + 'session ' + sessionShort(a.session_id))}</span>
    </div>`).join('');
  return `
    <div class="endpoint-head">
      <div class="endpoint-host">${escapeHTML(d.display || d.path)}</div>
      ${s.category_label ? `<span class="endpoint-kind">${escapeHTML(s.category_label)}</span>` : ''}
    </div>
    ${s.owner_label ? `<p class="endpoint-identity">${escapeHTML(s.owner_label)}</p>` : ''}
    <p class="endpoint-facts">${escapeHTML(facts)}</p>
    <div class="endpoint-actions">${actions}</div>
    ${sess ? `<section class="endpoint-section"><h4>Session</h4>${sess}</section>` : ''}
    ${excerpt ? `<section class="endpoint-section"><h4>Around the secret</h4>${excerpt}</section>` : ''}
    ${findings ? `<section class="endpoint-section"><h4>Findings</h4>${findings}</section>` : ''}
    ${accesses ? `<section class="endpoint-section"><h4>Agent access</h4>${accesses}</section>` : ''}`;
}

// ---------- playbook and advisor plan ----------

const PLAN_STEP_KINDS = {
  'guard-rule': 'Guard rule', config: 'Setting', 'secret-hygiene': 'Secrets',
  'agent-instruction': 'Agent instructions', workflow: 'Workflow',
};

// planSlotHTML: where a surface shows the playbook and the advisor's plan
// for subject ("flag:<id>", "incident:<id>", "file:<path>").
function planSlotHTML(subject) {
  return `<section class="endpoint-section"><h4>What to do</h4>`
    + `<div class="plan-slot" data-plan-subject="${escapeHTML(subject)}"><div class="loading-spinner">Loading the playbook…</div></div></section>`;
}

// labelsLineHTML: the operator's earlier judgments on the same case, "" when
// there are none.
function labelsLineHTML(summary) {
  if (!summary) return '';
  const parts = [];
  if (summary.ok) parts.push(`${summary.ok} as routine`);
  if (summary.not_ok) parts.push(`${summary.not_ok} as not ok`);
  if (!parts.length) return '';
  return `<p class="finding-labels">You marked similar cases ${escapeHTML(parts.join(' and '))}.</p>`;
}

// markButtonsHTML: Mark as routine / Mark as not ok for a subject.
function markButtonsHTML(subject) {
  const s = escapeHTML(subject);
  return `<button class="btn btn-ghost btn-sm" data-action="mark-label" data-subject="${s}" data-label="ok">Mark as routine</button>`
    + `<button class="btn btn-ghost btn-sm" data-action="mark-label" data-subject="${s}" data-label="not_ok">Mark as not ok</button>`;
}

// labelsHTML: the What to do drawer's history — summary, similar judgments,
// the suggestion consistent labels earn (its action as the finding's served
// button when offered), and the mark buttons.
function labelsHTML(resp, nowMs) {
  const l = resp && resp.labels;
  if (!l) return '';
  const now = nowMs || Date.now();
  const flag = resp.flag;
  const similar = (l.similar || []).map(x => `<li>${escapeHTML(x.label === 'ok' ? 'Routine' : 'Not ok')} · ${escapeHTML(x.source)} · `
    + `${escapeHTML(fmtAge(x.created_at, now))} ago${x.pattern ? ' · ' + escapeHTML(x.pattern) : ''}${x.reason ? ' · ' + escapeHTML(x.reason) : ''}</li>`).join('');
  let suggestion = '';
  if (l.suggestion) {
    const a = flag && flag.explain && (flag.explain.actions || []).find(x => x.id === l.suggestion.action_id);
    const btn = a && EXPLAIN_CONSOLE_ACTIONS.includes(a.id)
      ? `<button class="btn btn-primary btn-sm" data-action="explain-act" data-flag-id="${escapeHTML(flag.id)}" data-action-id="${escapeHTML(a.id)}"`
        + `${a.body && typeof a.body.host === 'string' ? ` data-host="${escapeHTML(a.body.host)}"` : ''} title="${escapeHTML(a.consequence)}">${escapeHTML(explainActionLabel(flag, a))}</button>`
      : '';
    suggestion = `<div class="plan-suggestion"><p>${escapeHTML(l.suggestion.text)}</p>${btn}</div>`;
  }
  return `
    <div class="plan-labels">
      <h5>Your history</h5>
      ${labelsLineHTML(l.summary) || '<p class="plan-status">No earlier judgments on cases like this.</p>'}
      ${similar ? `<ul class="plan-list">${similar}</ul>` : ''}
      ${suggestion}
      <div class="endpoint-actions">${markButtonsHTML(resp.subject)}</div>
    </div>`;
}

// planHTML renders a /advisor/plan response: the advisor's plan when there is
// one (why, prevention, behavior, remediation, recommended actions as
// buttons), the rule's playbook, and the ask button. Pure; everything is
// escaped.
function planHTML(resp, nowMs) {
  if (!resp || !resp.playbook) return '';
  const pb = resp.playbook;
  const p = resp.plan;
  const flag = resp.flag;
  const list = (items, tag) => (items && items.length)
    ? `<${tag || 'ul'} class="plan-list">${items.map(x => `<li>${escapeHTML(x)}</li>`).join('')}</${tag || 'ul'}>` : '';
  const steps = items => (items && items.length) ? `<ul class="plan-list">${items.map(s =>
    `<li><span class="plan-kind">${escapeHTML(PLAN_STEP_KINDS[s.kind] || s.kind)}</span> <strong>${escapeHTML(s.step)}</strong>. ${escapeHTML(s.detail)}</li>`).join('')}</ul>` : '';

  const status = {
    pending: 'The advisor is writing a plan from this finding\'s local context…',
    stale: 'Written before newer evidence arrived. Ask again for an updated plan.',
    disabled: resp.reason || 'The local advisor is off.',
  }[resp.status] || '';

  let advisor = '';
  if (p) {
    const offered = (flag && flag.explain && flag.explain.actions) || [];
    const acts = (p.actions || []).map(id => offered.find(a => a.id === id))
      .filter(a => a && EXPLAIN_CONSOLE_ACTIONS.includes(a.id));
    const buttons = acts.map(a => {
      const host = a.body && typeof a.body.host === 'string' ? a.body.host : '';
      return `<button class="btn ${a.id === 'kill' ? 'btn-danger' : 'btn-ghost'} btn-sm" data-action="explain-act" data-flag-id="${escapeHTML(flag.id)}"`
        + ` data-action-id="${escapeHTML(a.id)}"${host ? ` data-host="${escapeHTML(host)}"` : ''} title="${escapeHTML(a.consequence)}">${escapeHTML(explainActionLabel(flag, a))}</button>`;
    }).join('');
    advisor = `
      <div class="plan-advisor">
        <p class="plan-summary"><span class="plan-risk plan-risk-${escapeHTML(p.risk)}">${escapeHTML(p.risk)} risk</span> ${escapeHTML(p.summary)}</p>
        ${p.why && p.why.length ? `<h5>Why it happened</h5>${list(p.why)}` : ''}
        ${p.remediate && p.remediate.length ? `<h5>Do now</h5>${list(p.remediate, 'ol')}` : ''}
        ${p.prevent && p.prevent.length ? `<h5>Prevent it</h5>${steps(p.prevent)}` : ''}
        ${p.behavior && p.behavior.length ? `<h5>Change how you work</h5>${list(p.behavior)}` : ''}
        ${buttons ? `<div class="endpoint-actions">${buttons}</div>` : ''}
        <p class="plan-meta">Local advisor${p.model ? ' · ' + escapeHTML(p.model) : ''}${p.created_at ? ' · ' + escapeHTML(fmtAge(p.created_at, nowMs || Date.now())) + ' ago' : ''}</p>
      </div>`;
  }

  const playbook = `
    <p class="plan-why">${escapeHTML(pb.why)}</p>
    ${pb.now && pb.now.length ? `<h5>Do now</h5>${list(pb.now, 'ol')}` : ''}
    ${pb.prevent && pb.prevent.length ? `<h5>Prevent it</h5>${steps(pb.prevent)}` : ''}`;

  const canAsk = resp.advisor_ready && resp.status !== 'pending';
  const ask = `<button class="btn btn-primary btn-sm" data-action="ask-plan" data-subject="${escapeHTML(resp.subject)}"${canAsk ? '' : ' disabled'}>`
    + `${p ? 'Ask the advisor again' : 'Ask the advisor for a plan'}</button>`;

  return `
    <div class="plan">
      ${status ? `<p class="plan-status plan-status-${escapeHTML(resp.status)}">${escapeHTML(status)}</p>` : ''}
      ${advisor}
      ${p ? `<details class="plan-playbook"><summary>Playbook: ${escapeHTML(pb.title)}</summary>${playbook}</details>` : `<div class="plan-playbook">${playbook}</div>`}
      <div class="plan-ask">${ask}</div>
      ${labelsHTML(resp, nowMs)}
    </div>`;
}

// linkEvidencePaths turns each inline code span holding an absolute path into
// a file-drawer link. Input is parseMarkdownToHTML output, already escaped,
// so the captured text is safe as the attribute and the label.
function linkEvidencePaths(html) {
  return String(html || '').replace(/<code class="md-inline-code">(\/[^<]*)<\/code>/g,
    (_, p) => `<button type="button" class="file-link" data-action="open-file" data-path="${p}">${p}</button>`);
}

// shared by the flag card chip and the timeline filter chip.
function sessionShort(id) {
  return String(id || '').slice(0, 8);
}

// harnessMeta: per-harness identity for the console — display name, brand
// color, and the sprite symbol of its mark (index.html, #logo-*). Needles
// match the harness names the daemon reports by substring, first match wins,
// so "cursor-ide" is listed before "cursor". Infra entries (IDEs, local model
// servers) are tracked but shown apart and never counted as agents. Known
// harnesses without a mark keep a text glyph. Colors must match the .hk-<key>
// rules in style.css. Pure: returns data, no DOM.
const HARNESS_TABLE = [
  { needle: 'claude', key: 'claude', label: 'Claude Code', color: '#D97757', logo: 'logo-claude' },
  { needle: 'cursor-ide', key: 'cursor-ide', label: 'Cursor', color: '#000000', logo: 'logo-cursor', tile: 'light', infra: true },
  { needle: 'cursor', key: 'cursor', label: 'Cursor', color: '#000000', logo: 'logo-cursor', tile: 'light' },
  { needle: 'codex', key: 'codex', label: 'Codex', color: '#10A37F', logo: 'logo-codex' },
  { needle: 'opencode', key: 'opencode', label: 'opencode', color: '#000000', logo: 'logo-opencode' },
  { needle: 'openclaw', key: 'openclaw', label: 'OpenClaw', color: 'hsl(342 62% 62%)', glyph: 'O' },
  { needle: 'antigravity', key: 'agy', label: 'Antigravity', color: '#8E75B2', logo: 'logo-gemini' },
  { needle: 'agy', key: 'agy', label: 'Antigravity', color: '#8E75B2', logo: 'logo-gemini' },
  { needle: 'gemini', key: 'gemini', label: 'Gemini', color: '#8E75B2', logo: 'logo-gemini' },
  { needle: 'windsurf', key: 'windsurf', label: 'Windsurf', color: '#0B100F', logo: 'logo-windsurf' },
  { needle: 'aider', key: 'aider', label: 'Aider', color: 'hsl(20 90% 58%)', glyph: '◉' },
  { needle: 'codeium', key: 'codeium', label: 'Codeium', color: 'hsl(201 88% 46%)', glyph: '◈' },
  { needle: 'copilot', key: 'copilot', label: 'GitHub Copilot', color: 'hsl(220 12% 60%)', glyph: '◍' },
  { needle: 'ollama', key: 'ollama', label: 'Ollama', color: '#000000', logo: 'logo-ollama', infra: true },
  { needle: 'lm-studio', key: 'lm-studio', label: 'LM Studio', color: '#000000', logo: 'logo-lm-studio', infra: true },
  { needle: 'lmstudio', key: 'lm-studio', label: 'LM Studio', color: '#000000', logo: 'logo-lm-studio', infra: true },
];

function harnessMeta(name) {
  const key = String(name || '').toLowerCase();
  for (const h of HARNESS_TABLE) {
    if (!key.includes(h.needle)) continue;
    return {
      key: h.key, label: h.label, color: h.color, logo: h.logo || '',
      glyph: h.glyph || '', tile: h.tile || '', infra: !!h.infra, known: true,
    };
  }
  // Unknown harness: deterministic hue from the name, first letter as glyph.
  let h = 2166136261;
  for (const b of key) h = (h ^ b.charCodeAt(0)) >>> 0, h = Math.imul(h, 16777619) >>> 0;
  return {
    key: key.trim() || 'agent', label: familyTitle(String(name || '').trim() || 'agent'),
    color: `hsl(${h % 360} 62% 62%)`, logo: '',
    glyph: (name || '?').trim().slice(0, 1).toUpperCase() || '?',
    tile: '', infra: false, known: false,
  };
}

// harnessChipHTML: the harness mark for list rows and group heads. A known
// mark renders white on its brand tile (Cursor dark on a light tile); the
// tile color comes from the .hk-<key> class because the console CSP
// (style-src 'self') drops inline style attributes. Unknown harnesses keep
// the hashed-hue initial, applied by applyInlineMetrics. opts.label appends
// the display name as text.
function harnessChipHTML(name, opts) {
  const m = harnessMeta(name);
  let mark;
  if (m.logo) {
    mark = `<span class="harness-tile hk-${escapeHTML(m.key)}${m.tile === 'light' ? ' light' : ''}" aria-hidden="true">`
      + `<svg class="harness-logo" aria-hidden="true"><use href="#${escapeHTML(m.logo)}"/></svg></span>`;
  } else if (m.known) {
    mark = `<span class="harness-glyph hk-${escapeHTML(m.key)}" aria-hidden="true">${escapeHTML(m.glyph)}</span>`;
  } else {
    mark = `<span class="harness-glyph" data-harness-color="${escapeHTML(m.color)}" aria-hidden="true">${escapeHTML(m.glyph)}</span>`;
  }
  const label = opts && opts.label ? `<span class="harness-label">${escapeHTML(m.label)}</span>` : '';
  return `<span class="harness-chip" title="${escapeHTML(m.known ? m.label : (name || 'agent'))}">${mark}${label}</span>`;
}

// filterEventsBySession: the timeline's session drill-down. Client-side over
// the already-fetched window — the events API has no session filter, and the
// loaded window is what the timeline can show anyway.
function filterEventsBySession(events, sessionId) {
  if (!sessionId) return events || [];
  return (events || []).filter(e => e.session_id === sessionId);
}

function filterEventsByPids(events, pids) {
  if (!pids || !pids.length) return events || [];
  const set = new Set(pids.map(Number));
  return (events || []).filter(e => set.has(Number(e.pid)));
}

function scopedBySession(items, sessionId, pids) {
  if (sessionId) return filterEventsBySession(items, sessionId);
  if (pids && pids.length) return filterEventsByPids(items, pids);
  return items || [];
}

// Scope bar under the tabs: names the session (or process family) Events,
// Flags and Incidents are narrowed to, with its counts; '' when unscoped.
function scopeBarHTML({ session, pids, pidLabel, events, flags }) {
  const n = Number(events) || 0;
  const m = Number(flags) || 0;
  const counts = ` · ${n} event${n === 1 ? '' : 's'} · ${m} flag${m === 1 ? '' : 's'}`;
  const clear = '<button type="button" class="btn btn-ghost btn-sm" data-action="clear-scope">Clear</button>';
  if (session) return `<span>Scoped to session <b>${escapeHTML(sessionShort(session))}</b>${counts}</span>${clear}`;
  if (pids && pids.length) {
    const k = pids.length;
    return `<span>Scoped to <b>${escapeHTML(pidLabel || 'PID ' + pids[0])}</b> (${k} process${k === 1 ? '' : 'es'})${counts}</span>${clear}`;
  }
  return '';
}

// The Attention badge counts what the hero counts: /posture needs_you, which
// the daemon keeps equal to the grouped items.
function attentionCount(posture) {
  return (posture && Number(posture.needs_you)) || 0;
}

// Drawer back-stack: a drawer opened from inside another carries back
// ({ label, reopen }); the head shows "‹ label" before the title and the
// click re-runs the previous opener, so that drawer re-renders from live
// data. Without back the button is removed.
function paintDrawerBack(head, title, back) {
  const old = head.querySelector('#btn-drawer-back');
  if (old) old.remove();
  if (!back) return null;
  const btn = head.ownerDocument.createElement('button');
  btn.type = 'button';
  btn.id = 'btn-drawer-back';
  btn.className = 'btn btn-ghost drawer-back';
  btn.textContent = '‹ ' + back.label;
  btn.title = 'Back to ' + back.label;
  btn.addEventListener('click', () => back.reopen());
  head.insertBefore(btn, title);
  return btn;
}

function filterSessionRows(rows, q) {
  const s = String(q || '').trim().toLowerCase();
  if (!s) return rows || [];
  return (rows || []).filter(r => {
    const label = String((r && r.label) || '').toLowerCase();
    const cwd = String((r && r.root && r.root.cwd) || '').toLowerCase();
    const name = String((r && r.root && r.root.name) || '').toLowerCase();
    return label.includes(s) || cwd.includes(s) || name.includes(s);
  });
}

// groupSessionsByHarness: the Sessions rail, harness-first. One group per
// harness with its live families (active before idle, newest first) and an
// ended tail. A session whose parent_id names another listed session nests
// one level under its top-most listed ancestor, walking up only while the
// ancestor sits in the same group and the same live/ended half. Groups order
// by their most recent live activity; groups with nothing live sink to the
// bottom. Infra (by harness, or by the /status agent kind) never joins the
// rail: it folds into one trailing "Infrastructure" group of RSS totals.
// Pure; the console and the tests both consume it.
function groupSessionsByHarness(sessions, trees, agents) {
  const list = (sessions || []).filter(Boolean);
  const infraKeys = new Set();
  for (const a of agents || []) if (a && a.kind === 'infra') infraKeys.add(harnessMeta(a.name).key);
  const isInfra = (m) => m.infra || infraKeys.has(m.key);
  const statusOf = (s) => (s.status === 'ended' || s.status === 'idle' ? s.status : 'active');
  const isLive = (s) => statusOf(s) !== 'ended';
  const seenOf = (s) => String(s.last_seen_at || '');
  const keyOf = new Map(list.map(s => [s, harnessMeta(s.harness).key]));
  const byId = new Map(list.map(s => [s.id, s]));

  // A parent_id cycle has no top: its members stay top-level.
  const topOf = (s) => {
    let cur = s;
    const visited = new Set([s]);
    for (;;) {
      const p = cur.parent_id ? byId.get(cur.parent_id) : null;
      if (p && visited.has(p)) return s;
      if (!p || keyOf.get(p) !== keyOf.get(s) || isLive(p) !== isLive(s)) return cur;
      visited.add(p);
      cur = p;
    }
  };

  const groups = new Map();
  const families = new Map();
  for (const s of list) {
    const m = harnessMeta(s.harness);
    if (isInfra(m)) continue;
    if (!groups.has(m.key)) groups.set(m.key, { key: m.key, label: m.label, infra: false, live: [], ended: [], lastLive: '', lastSeen: '' });
    const g = groups.get(m.key);
    if (seenOf(s) > g.lastSeen) g.lastSeen = seenOf(s);
    if (isLive(s) && seenOf(s) > g.lastLive) g.lastLive = seenOf(s);
    const top = topOf(s);
    if (!families.has(top)) {
      const fam = { session: top, children: [] };
      families.set(top, fam);
      (isLive(top) ? g.live : g.ended).push(fam);
    }
    if (top !== s) families.get(top).children.push(s);
  }

  const byRecency = (a, b) => (seenOf(b) > seenOf(a) ? 1 : seenOf(b) < seenOf(a) ? -1 : 0);
  const famSeen = (f) => [f.session, ...f.children].map(seenOf).sort().pop();
  const famRank = (f) => ([f.session, ...f.children].some(s => statusOf(s) === 'active') ? 0 : 1);
  for (const g of groups.values()) {
    for (const f of [...g.live, ...g.ended]) f.children.sort(byRecency);
    g.live.sort((a, b) => famRank(a) - famRank(b) || (famSeen(b) > famSeen(a) ? 1 : famSeen(b) < famSeen(a) ? -1 : 0));
    g.ended.sort((a, b) => (famSeen(b) > famSeen(a) ? 1 : famSeen(b) < famSeen(a) ? -1 : 0));
  }
  const ordered = [...groups.values()].sort((a, b) => {
    if (!!a.lastLive !== !!b.lastLive) return a.lastLive ? -1 : 1;
    const ka = a.lastLive || a.lastSeen, kb = b.lastLive || b.lastSeen;
    if (ka !== kb) return kb > ka ? 1 : -1;
    return a.key.localeCompare(b.key);
  });

  // Infra totals: live process trees when the daemon sends them, else the
  // flat /status agent list.
  const infra = new Map();
  const bump = (m, rss) => {
    if (!infra.has(m.key)) infra.set(m.key, { key: m.key, label: m.label, rss: 0 });
    infra.get(m.key).rss += rss;
  };
  if (trees && trees.length) {
    for (const t of trees) {
      const r = (t && t.root) || {};
      const m = harnessMeta(r.name);
      if (isInfra(m) || r.kind === 'infra') bump(m, Number(t.rss_bytes || 0));
    }
  } else {
    for (const a of agents || []) {
      const m = harnessMeta(a && a.name);
      if (a && (isInfra(m) || a.kind === 'infra')) bump(m, Number(a.rss_bytes || 0));
    }
  }
  if (infra.size) {
    const items = [...infra.values()].sort((a, b) => b.rss - a.rss || a.key.localeCompare(b.key));
    ordered.push({
      key: 'infra', label: 'Infrastructure', infra: true, live: [], ended: [],
      items, rss: items.reduce((n, it) => n + it.rss, 0),
    });
  }
  return ordered;
}

// sessionMatchesText: the text filter's fields — repo, branch, repo@branch,
// workspace, and the spawning agent (originAgent and the raw origin),
// case-insensitive. An empty query matches everything.
function sessionMatchesText(s, text) {
  const q = String(text || '').trim().toLowerCase();
  if (!q) return true;
  const repoBranch = s.repo ? `${s.repo}${s.branch ? '@' + s.branch : ''}` : '';
  return [s.repo, s.branch, repoBranch, s.workspace, originAgent(s), s.origin]
    .some(f => String(f || '').toLowerCase().includes(q));
}

// applySessionFilters: the rail's filter row over groupSessionsByHarness
// output. opts.harnesses maps a harness key to false when its pill is off;
// opts.text keeps a family when any member matches; opts.liveOnly drops
// groups with nothing live. The infra group carries totals, not sessions, and
// is never filtered. Pure; returns new group objects.
function applySessionFilters(groups, opts) {
  const o = opts || {};
  const off = o.harnesses || {};
  const keep = (fams) => fams.filter(f => [f.session, ...f.children].some(s => sessionMatchesText(s, o.text)));
  const out = [];
  for (const g of groups || []) {
    if (g.infra) { out.push(g); continue; }
    if (off[g.key] === false) continue;
    const live = keep(g.live);
    const ended = keep(g.ended);
    if (!live.length && !ended.length) continue;
    if (o.liveOnly && !live.length) continue;
    out.push({ ...g, live, ended });
  }
  return out;
}

// familySize: sessions in a list of families, sub-sessions included.
function familySize(fams) {
  return (fams || []).reduce((n, f) => n + 1 + f.children.length, 0);
}

// sessionGroupCounts: the group head's "3 active · 1 idle · 12 ended".
function sessionGroupCounts(g) {
  const c = { active: 0, idle: 0, ended: 0 };
  for (const f of [...(g.live || []), ...(g.ended || [])]) {
    for (const s of [f.session, ...f.children]) {
      c[s.status === 'ended' || s.status === 'idle' ? s.status : 'active']++;
    }
  }
  return ['active', 'idle', 'ended'].filter(k => c[k]).map(k => `${c[k]} ${k}`).join(' · ');
}

// sessionCountStrip: the rail's one-line census — live sessions, harnesses
// with live work, and the daemon's coverage (/status.coverage) when it has a
// live harness count.
function sessionCountStrip(groups, coverage) {
  let n = 0;
  let k = 0;
  for (const g of groups || []) {
    if (g.infra) continue;
    const live = familySize(g.live);
    n += live;
    if (live) k++;
  }
  const parts = [`Sessions ${n}`, `Harnesses ${k}`];
  if (coverage && coverage.harnesses_active > 0) parts.push(`seeing ${coverage.harnesses_seen}/${coverage.harnesses_active}`);
  return parts.join(' · ');
}

// harnessPillsHTML: one toggle pill per harness, shared by the Sessions and
// Agents filter rows. harnesses[key] === false renders the pill off.
function harnessPillsHTML(keys, harnesses) {
  const off = harnesses || {};
  return (keys || []).map(k => {
    const on = off[k] !== false;
    return `<button type="button" class="harness-pill${on ? '' : ' off'}" data-action="toggle-harness" data-harness="${escapeHTML(k)}" aria-pressed="${on}">${harnessChipHTML(k, { label: true })}</button>`;
  }).join('');
}

// middleTruncate: keep both ends of a long path — the root says where, the
// tail says which — and elide the middle.
function middleTruncate(str, max) {
  const s = String(str || '');
  if (s.length <= max) return s;
  const keep = max - 1;
  return s.slice(0, Math.ceil(keep / 2)) + '…' + s.slice(s.length - Math.floor(keep / 2));
}

function unactedLast24h(flags, nowMs) {
  const cutoff = nowMs - 24 * 3600e3;
  return (flags || []).filter(f => {
    if (!f || f.acknowledged || (f.severity || 0) < 2) return false;
    const t = Date.parse(f.ts);
    return Number.isFinite(t) && t >= cutoff;
  });
}

// flagHost extracts the egress destination host from a flag's evidence
// (the host a mute/disposition applies to), or '' for hostless rules.
// Structured items (kind "connect") carry it directly; legacy rows from
// older daemons arrive as {kind:"text"} and keep the string fallback.
function flagHost(flag) {
  for (const ev of (flag && flag.evidence) || []) {
    if (ev && ev.kind === 'connect' && ev.label) return String(ev.label).split(':')[0];
    const s = typeof ev === 'string' ? ev : (ev && ev.text) || '';
    const m = s.match(/connected to ([^:\s]+):\d+/) || s.match(/connecting to ([^:\s]+):\d+/);
    if (m) return m[1];
  }
  return '';
}

// ---------- sparkline (rolling events/sec window) ----------

// Age the bucket ring by `steps` seconds (newest bucket is last). Steps
// beyond the window length reset the whole ring.
function advanceBuckets(buckets, steps) {
  const n = Math.min(steps, buckets.length);
  for (let i = 0; i < n; i++) { buckets.shift(); buckets.push(0); }
  return buckets;
}

// Map an event timestamp onto a bucket index. Events older than the window
// clamp into the OLDEST bucket: the shape still reflects "something happened"
// without inventing recency.
function bucketIndexFor(nowMs, tsMs, bucketCount) {
  if (!tsMs) return bucketCount - 1;
  const ageSec = Math.floor((nowMs - tsMs) / 1000);
  return Math.max(0, bucketCount - 1 - ageSec);
}

// Polyline points for the masthead sparkline SVG. Baseline is y=baseY; values
// scale to at most `span` pixels above it. maxFloor keeps a quiet line flat
// instead of amplifying noise.
function sparkPoints(buckets, width, baseY, span, maxFloor) {
  const max = Math.max(maxFloor || 2, ...buckets);
  const n = buckets.length;
  return buckets.map((v, i) => {
    const x = (i / (n - 1)) * width;
    const y = baseY - (v / max) * span;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

// ---------- incident report markdown ----------

function parseMarkdownToHTML(md) {
  if (!md) return '';
  let html = escapeHTML(md);

  // Code blocks
  html = html.replace(/```([\s\S]*?)```/g, (_, code) => `<pre class="md-codeblock"><code>${code}</code></pre>`);
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="md-inline-code">$1</code>');
  // Headers
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');
  // Bold
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Bullet lists
  html = html.replace(/^\- (.*$)/gim, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
  // Paragraphs
  html = html.replace(/\n\n/g, '<br/><br/>');

  return `<div class="markdown-view">${html}</div>`;
}

// ---------- rollup chart ----------

// rollupSeries shapes hourly rollup points into zero-filled per-bucket totals
// covering exactly `hours` buckets ending at the current UTC hour. Event kinds
// ("event:…") and flag kinds ("flag:sN") are separated so the chart can draw
// activity bars with flag markers.
function rollupSeries(points, hours, nowMs) {
  const HOUR = 3600000;
  const nowHour = Math.floor(nowMs / HOUR);
  const firstHour = nowHour - hours + 1;
  const events = new Array(hours).fill(0);
  const flags = new Array(hours).fill(0);
  const labels = new Array(hours).fill('');
  for (const p of points || []) {
    const h = Math.floor(Date.parse(p.bucket + ':00:00Z') / HOUR);
    const idx = h - firstHour;
    if (isNaN(h) || idx < 0 || idx >= hours) continue;
    if (String(p.kind).startsWith('flag:')) flags[idx] += p.count;
    else events[idx] += p.count;
  }
  for (let i = 0; i < hours; i++) {
    const d = new Date((firstHour + i) * HOUR);
    labels[i] = hours <= 48
      ? String(d.getHours()).padStart(2, '0') + ':00'
      : d.toLocaleDateString([], { month: 'numeric', day: 'numeric' });
  }
  return { labels, events, flags };
}

// Render the flag's evidence items as causal nodes (sensitive read → egress
// connection → …) and append a severity-colored verdict node. Evidence is
// structured daemon-side; only legacy rows (kind "text") render as raw text.
// ---------- evidence chain ----------

const EVIDENCE_ICONS = {
  read:      { icon: 'i-key',    cls: 'cn-read' },
  connect:   { icon: 'i-globe',  cls: 'cn-egress' },
  keychain:  { icon: 'i-key',    cls: 'cn-read' },
  exec:      { icon: 'i-power',  cls: 'cn-read' },
  tcc:       { icon: 'i-alert',  cls: 'cn-read' },
  violation: { icon: 'i-shield', cls: 'cn-read' },
  text:      { icon: 'i-alert',  cls: '' },
};

function buildEvidenceChain(flag) {
  const nodes = [];
  const ts = (s) => {
    const d = Date.parse(s);
    return isNaN(d) ? '' : fmtTime(new Date(d));
  };
  for (const ev of (flag.evidence || [])) {
    if (typeof ev === 'string') { // pre-structured wire rows
      nodes.push({ icon: 'i-alert', cls: '', label: ev, sub: '' });
      continue;
    }
    const style = EVIDENCE_ICONS[ev.kind] || EVIDENCE_ICONS.text;
    const when = ev.ts ? ` · ${ts(ev.ts)}` : '';
    const sub = ev.kind === 'text' ? '' : (ev.sub || '') + when;
    nodes.push({ icon: style.icon, cls: style.cls, label: ev.label || ev.text || '', sub });
  }
  if (nodes.length === 0) return nodes;
  nodes.push({
    icon: flag.severity >= 3 ? 'i-alert' : 'i-shield',
    cls: flag.severity >= 3 ? 'cn-verdict-bad' : 'cn-verdict-warn',
    label: flag.severity >= 3 ? 'Critical flag raised' : 'Flag raised',
    sub: flag.rule || ''
  });
  return nodes;
}

// ---------- finding card: the daemon's served explanation ----------

const DISPOSITION_CLASS = {
  acknowledged: 'disp-acknowledged',
  'benign-likely': 'disp-benign',
  warning: 'disp-warning',
  critical: 'disp-critical',
};

// fmtGap: read→connect seconds as "3 s" / "2 min" / "1 h". The sign (which
// came first) is in the served sentence, not here.
function fmtGap(sec) {
  const s = Math.abs(Math.round(Number(sec) || 0));
  if (s < 60) return s + ' s';
  if (s < 3600) return Math.round(s / 60) + ' min';
  return Math.round(s / 3600) + ' h';
}

// explainLines: the finding card's lines from flag.explain — who (agent and
// repo@branch, never a pid), meta (read→connect gap and age), what (the
// served sentence), verdict (the one disposition) and its disp-* class. null
// when the daemon did not explain the flag (older daemon, acknowledged, or
// past the 25-flag cap): the caller keeps the raw card. gap_seconds is 0
// without a read item, so there is no gap without a subject.
function explainLines(flag, nowMs) {
  const ex = flag && flag.explain;
  if (!ex) return null;
  const c = ex.context || {};
  const agent = flag.agent || 'agent';
  const who = c.repo ? `${agent} · ${c.repo}${c.branch ? '@' + c.branch : ''}`
    : c.harness && c.harness !== agent ? `${agent} · ${c.harness}` : agent;
  const eg = (ex.egress || [])[0];
  const age = fmtAge(flag.ts, nowMs);
  const meta = [eg && ex.subject ? fmtGap(eg.gap_seconds) + ' gap' : '', age ? age + ' ago' : '']
    .filter(Boolean).join(' · ');
  const d = ex.disposition || {};
  return {
    who, meta, what: ex.what || '',
    verdict: (d.text || '') + (d.why ? ': ' + d.why : ''),
    cls: DISPOSITION_CLASS[d.state] || 'disp-warning',
  };
}

// Served action ids the console performs; each posts the served
// method/path/body on the proxy listener.
const EXPLAIN_CONSOLE_ACTIONS = ['allow-host', 'allow-path', 'mute-rule-host', 'mute-class', 'open-incident', 'dismiss', 'kill'];

// explainActionLabel: the served label, except where it carries a pid (kill)
// or an IPv6 literal (allow-host) — those stay in Details and the tooltip.
function explainActionLabel(flag, a) {
  const agent = flag.agent || 'agent';
  if (a.id === 'kill') return `Kill ${agent}`;
  const host = a.body && typeof a.body.host === 'string' ? a.body.host : '';
  if (a.id === 'allow-host' && host.includes(':')) {
    const eg = ((flag.explain && flag.explain.egress) || []).find(e => e.host === host);
    const org = eg && (eg.org || eg.name);
    return `Allow this ${org ? org + ' ' : ''}address for ${agent}`;
  }
  return a.label || a.id;
}

// explainActionsHTML: one button per served action, the recommended one
// first. The click handler reads the request from the served explanation
// (flag id + action id + host), never from the markup.
function explainActionsHTML(flag) {
  const ex = flag && flag.explain;
  if (!ex) return '';
  const acts = (ex.actions || []).filter(a => a && EXPLAIN_CONSOLE_ACTIONS.includes(a.id));
  return acts.filter(a => a.recommended).concat(acts.filter(a => !a.recommended)).map(a => {
    const host = a.body && typeof a.body.host === 'string' ? a.body.host : '';
    const cls = a.id === 'kill' ? 'btn-danger' : a.recommended ? 'btn-primary' : 'btn-ghost';
    return `<button class="btn ${cls} btn-sm" data-action="explain-act" data-flag-id="${escapeHTML(flag.id)}"`
      + ` data-action-id="${escapeHTML(a.id)}"${host ? ` data-host="${escapeHTML(host)}"` : ''}`
      + ` title="${escapeHTML(a.consequence)}">${escapeHTML(explainActionLabel(flag, a))}</button>`;
  }).join('');
}

// ---------- agent families ----------

function familyTitle(name) {
  const s = String(name || 'unknown');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Operator-facing rule titles come from the daemon (flag.title); this table
// is only the fallback for rows from older daemons.
var RULE_TITLES = {
  'proxy-secret-leak': 'Secret leaving in agent traffic',
  'sensitive-read-then-connect': 'Secret read, then connected out',
  'keychain-access': 'Keychain file access',
  'keychain-security-cli': 'Keychain CLI (security tool)',
  'tcc-tamper': 'Privacy permissions (TCC) tamper',
  'proxy-prompt-injection': 'Prompt injection in a response',
  'secret-in-transcript': 'Secret appeared in an agent transcript',
};

function ruleTitle(rule) {
  // Prefer the daemon-served title on any loaded flag carrying this rule.
  const flags = (window.SA && window.SA.t && window.SA.t.flags) || [];
  for (const f of flags) { if (f.rule === rule && f.title) return f.title; }
  return RULE_TITLES[rule] || String(rule || 'unknown');
}

// hbarsHTML renders a ranked horizontal-bar list — the readable chart for
// "which of these is biggest" without axes or a plotting dependency.
// rows: [{label, value, sub, cls}], value compared against the max.
function hbarsHTML(rows, opts) {
  opts = opts || {};
  const max = Math.max(1, ...rows.map(r => r.value));
  return rows.map(r => hbarRowHTML(r, max, opts.format)).join('');
}

// hbarRowHTML: one hbarsHTML row, its fill scaled against max; fmt formats
// the value (default String).
function hbarRowHTML(r, max, fmt) {
  fmt = fmt || (v => String(v));
  const pct = Math.max(2, (r.value / max) * 100);
  return `<div class="hbar-row">
      <span class="hbar-label" title="${escapeHTML(r.titleAttr || r.label)}">${escapeHTML(r.label)}</span>
      <span class="hbar-track"><span class="hbar-fill ${r.cls || ''}" data-w="${pct.toFixed(1)}"></span></span>
      <span class="hbar-val">${escapeHTML(fmt(r.value))}</span>
      ${r.sub ? `<span class="hbar-sub">${escapeHTML(r.sub)}</span>` : ''}
    </div>`;
}


function fmtRSS(n) {
  n = Number(n);
  if (!n || n < 0) return '';
  if (n < 1024) return Math.round(n) + ' B';
  if (n < 1048576) return Math.round(n / 1024) + ' KB';
  if (n < 1073741824) {
    const mb = n / 1048576;
    return (mb >= 10 ? mb.toFixed(0) : mb.toFixed(1)) + ' MB';
  }
  return (n / 1073741824).toFixed(1) + ' GB';
}

// fmtUSD: dollars with two decimals and thousands separators. A non-zero
// amount under a cent reads "<$0.01" so real spend never renders as $0.00.
function fmtUSD(n) {
  n = Number(n) || 0;
  if (n > 0 && n < 0.01) return '<$0.01';
  const [whole, frac] = n.toFixed(2).split('.');
  return '$' + whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',') + '.' + frac;
}

// topCostRows: the n most expensive /costs rows (cost desc, then calls desc).
// Tolerates a missing report or rows.
function topCostRows(report, n) {
  const rows = report && Array.isArray(report.rows) ? report.rows.slice() : [];
  rows.sort((a, b) => (Number(b.cost_usd) || 0) - (Number(a.cost_usd) || 0)
    || (Number(b.calls) || 0) - (Number(a.calls) || 0));
  return rows.slice(0, n);
}

function fmtCPU(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '';
  const n = Number(value);
  return n.toFixed(1).replace(/\.0$/, '') + '%';
}

// A score of 1 means the session is at the first-slice warning threshold:
// either 4 GiB resident memory or one full CPU core.
function resourceImpact(session) {
  if (!session) return 0;
  const memory = Math.max(0, Number(session.rss_bytes) || 0) / (4 * 1024 ** 3);
  const cpu = Math.max(0, Number(session.cpu_percent) || 0) / 100;
  return Math.max(memory, cpu);
}

function resourceSparkPoints(samples, field, width, height) {
  const values = (samples || [])
    .filter(sample => sample && sample[field] !== null && sample[field] !== undefined && Number.isFinite(Number(sample[field])))
    .map(sample => Number(sample[field]));
  if (!values.length) return '';
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;
  return values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width;
    const y = range === 0 ? height / 2 : height - ((value - min) / range) * height;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

function resourceDiagnosisText(diagnosis) {
  if (!diagnosis) return '';
  const fallbacks = {
    'heavy-memory': 'Heavy memory use',
    'heavy-cpu': 'High CPU use',
    'rapid-growth': 'Memory is growing quickly',
    'idle-heavy': 'Idle session retains substantial memory',
    'runaway-child': 'One child dominates session memory',
    'orphan-drift': 'Detached processes are still consuming resources',
  };
  return escapeHTML(diagnosis.summary || fallbacks[diagnosis.code] || 'Resource pressure detected');
}

// familyLabel: a resource family by what it works on, never by pid. The
// family's root pid joins the durable sessions (/sessions): harness · agent
// when an agent spawned the session (originAgent), else harness ·
// repo@branch, else harness · workspace folder (the session's, then the
// family's own), else the harness display name. A numeric folder reads as a
// pid, so it never names a family.
function familyLabel(family, sessions) {
  const f = family || {};
  const pid = Number(f.root_pid) || 0;
  const s = pid ? (sessions || []).find(x => x && Number(x.root_pid) === pid) : null;
  const harness = harnessMeta((s && s.harness) || f.name).label;
  const agent = originAgent(s);
  if (agent) return `${harness} · ${agent}`;
  if (s && s.repo) return `${harness} · ${s.repo}${s.branch ? '@' + s.branch : ''}`;
  const folder = (p) => {
    const l = p && p !== '/' ? cwdLabel(p) : '';
    return /^\d+$/.test(l) ? '' : l;
  };
  const where = folder(s && s.workspace) || folder(f.workspace);
  return where ? `${harness} · ${where}` : harness;
}

// collapseFamilyRows: one Resources harness group's rows with families of
// an identical label folded into { dup: true, key: 'group:<harness>|<label>',
// label, families (by memory), rss_bytes, cpu_percent, process_count } at
// the place of its first member; a row with orchestrated children never
// folds and stays { dup: false, key: <family key>, row }. labelOf(family) →
// the family label. Pure.
function collapseFamilyRows(rows, harness, labelOf) {
  const list = rows || [];
  const labels = new Map();
  const byLabel = new Map();
  for (const r of list) {
    if (r.children.length) continue;
    const l = labelOf(r.family);
    labels.set(r, l);
    if (!byLabel.has(l)) byLabel.set(l, []);
    byLabel.get(l).push(r.family);
  }
  const out = [];
  const placed = new Set();
  for (const r of list) {
    const l = labels.get(r);
    const same = l === undefined ? null : byLabel.get(l);
    if (!same || same.length < 2) {
      out.push({ dup: false, key: String(r.family.key), row: r });
      continue;
    }
    if (placed.has(l)) continue;
    placed.add(l);
    const families = [...same].sort((a, b) => Number(b.rss_bytes || 0) - Number(a.rss_bytes || 0));
    const sum = (k) => families.reduce((n, f) => n + Number(f[k] || 0), 0);
    out.push({
      dup: true, key: `group:${harness}|${l}`, label: l, families,
      rss_bytes: sum('rss_bytes'), cpu_percent: sum('cpu_percent'), process_count: sum('process_count'),
    });
  }
  return out;
}

// cappedList: one pattern for long lists — the first `limit` items, then a
// "Show N more" button (data-action="show-more", data-key=key) that reveals
// the rest in place. expanded is the console's Set of opened list keys, so a
// re-render keeps an opened list whole. renderRow is optional: callers that
// patch rows themselves read shown/hidden/more. Pure.
function cappedList(items, limit, renderRow, key, expanded) {
  const list = items || [];
  const open = !!(expanded && expanded.has(key));
  const shown = open ? list : list.slice(0, Math.max(0, limit));
  const hidden = list.length - shown.length;
  const more = hidden > 0
    ? `<button type="button" class="btn btn-ghost btn-sm show-more" data-action="show-more" data-key="${escapeHTML(key)}">Show ${hidden} more</button>`
    : '';
  return { shown, hidden, more, html: (renderRow ? shown.map(renderRow).join('') : '') + more };
}

// resourceNeedsAttention: the families the Resources tab leads with — any
// served diagnosis (heavy memory or CPU, rapid growth, idle retention,
// runaway child, orphan drift; a family within its thresholds carries none),
// never infra, highest resourceImpact first, at most n (default 5).
function resourceNeedsAttention(families, n) {
  const cap = n == null ? 5 : n;
  return (families || [])
    .filter(f => f && f.kind !== 'infra' && (f.diagnoses || []).some(d => d && d.code))
    .sort((a, b) => resourceImpact(b) - resourceImpact(a) || Number(b.rss_bytes || 0) - Number(a.rss_bytes || 0))
    .slice(0, cap);
}

// resourceFamilyGroups: the Resources tab's families by harness. A family
// whose durable session (joined by root pid) has a parent_id resolving to
// another family's session nests under that family's row — one indent: a
// grandchild lands under the top-most family, and a parent_id cycle keeps
// its members top-level. Rows sort by memory; groups by total memory
// (children included). Infra (kind=infra) is one trailing "Infrastructure"
// group that never nests, never parents and never counts as families.
// Group: { key, label, infra, rows: [{ family, children }], families, rss, cpu }.
function resourceFamilyGroups(families, sessions) {
  const list = (families || []).filter(Boolean);
  const byPid = new Map();
  for (const s of sessions || []) {
    if (s && s.root_pid && !byPid.has(Number(s.root_pid))) byPid.set(Number(s.root_pid), s);
  }
  const sessionOf = (f) => byPid.get(Number(f.root_pid)) || null;
  const famBySession = new Map();
  for (const f of list) {
    const s = sessionOf(f);
    if (s && s.id && f.kind !== 'infra') famBySession.set(s.id, f);
  }
  const parentOf = (f) => {
    const s = sessionOf(f);
    const p = s && s.parent_id ? famBySession.get(s.parent_id) : null;
    return p && p !== f ? p : null;
  };
  const topOf = (f) => {
    let cur = f;
    const seen = new Set([f]);
    for (;;) {
      const p = parentOf(cur);
      if (!p) return cur;
      if (seen.has(p)) return f;
      seen.add(p);
      cur = p;
    }
  };
  const rss = (f) => Number(f.rss_bytes || 0);
  const cpu = (f) => Number(f.cpu_percent || 0);
  const byMemory = (a, b) => rss(b) - rss(a);

  const rows = new Map();
  const infra = [];
  for (const f of list) {
    if (f.kind === 'infra') { infra.push({ family: f, children: [] }); continue; }
    const top = topOf(f);
    if (!rows.has(top)) rows.set(top, { family: top, children: [] });
    if (top !== f) rows.get(top).children.push(f);
  }
  const groups = new Map();
  for (const row of rows.values()) {
    row.children.sort(byMemory);
    const s = sessionOf(row.family);
    const m = harnessMeta((s && s.harness) || row.family.name);
    if (!groups.has(m.key)) groups.set(m.key, { key: m.key, label: m.label, infra: false, rows: [], families: 0, rss: 0, cpu: 0 });
    const g = groups.get(m.key);
    g.rows.push(row);
    for (const f of [row.family, ...row.children]) {
      g.families++;
      g.rss += rss(f);
      g.cpu += cpu(f);
    }
  }
  const ordered = [...groups.values()];
  for (const g of ordered) g.rows.sort((a, b) => byMemory(a.family, b.family));
  ordered.sort((a, b) => b.rss - a.rss || a.key.localeCompare(b.key));
  if (infra.length) {
    infra.sort((a, b) => byMemory(a.family, b.family));
    ordered.push({
      key: 'infra', label: 'Infrastructure', infra: true, rows: infra, families: 0,
      rss: infra.reduce((n, r) => n + rss(r.family), 0), cpu: infra.reduce((n, r) => n + cpu(r.family), 0),
    });
  }
  return ordered;
}

function fmtAge(iso, nowMs) {
  const t = Date.parse(iso);
  if (!isFinite(t)) return '';
  const sec = Math.max(0, Math.floor(((nowMs || Date.now()) - t) / 1000));
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec / 60) + 'm';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return m ? `${h}h${m}m` : `${h}h`;
}

function isFamilyRoot(a, members) {
  if (a.root_pid) return Number(a.root_pid) === Number(a.pid);
  return !members.some(m => Number(m.pid) === Number(a.ppid));
}

function childrenOf(root, members) {
  const rid = Number(root.pid);
  return (members || []).filter(m => Number(m.pid) !== rid && Number(m.root_pid || m.ppid) === rid);
}

// groupAgentsByHarness: the Agents tab, harness-first like the Sessions
// rail. One group per harness holding its instances (process-tree roots,
// most recent activity first) with their helper processes. Groups order by
// most recent activity. A group is infra when the harness is (IDEs, model
// servers) or the daemon tags a member kind=infra; callers show infra apart
// and never count it as agents. Pure.
function groupAgentsByHarness(agents) {
  const byKey = new Map();
  for (const a of agents || []) {
    if (!a) continue;
    const m = harnessMeta(a.name);
    if (!byKey.has(m.key)) byKey.set(m.key, { key: m.key, label: m.label, infra: m.infra, members: [], lastSeen: '' });
    const g = byKey.get(m.key);
    if (a.kind === 'infra') g.infra = true;
    if (a.last_seen_at && a.last_seen_at > g.lastSeen) g.lastSeen = a.last_seen_at;
    g.members.push(a);
  }
  const newest = (x, y) => (x > y ? -1 : x < y ? 1 : 0);
  const groups = [...byKey.values()].map(g => {
    const instances = g.members
      .filter(a => isFamilyRoot(a, g.members))
      .map(root => ({ root, children: childrenOf(root, g.members) }))
      .sort((x, y) => newest(String(x.root.last_seen_at || ''), String(y.root.last_seen_at || '')));
    return { key: g.key, label: g.label, infra: g.infra, lastSeen: g.lastSeen, instances };
  });
  return groups.sort((a, b) => newest(a.lastSeen, b.lastSeen) || a.key.localeCompare(b.key));
}

// agentGroupTotals: the group head's figures over the instances shown —
// instances, processes, RSS, CPU (null when no process reports it), last
// seen, leftovers.
function agentGroupTotals(g) {
  const t = { instances: g.instances.length, processes: 0, rss: 0, cpu: null, lastSeen: '', orphans: 0 };
  for (const inst of g.instances) {
    for (const a of [inst.root, ...inst.children]) {
      t.processes++;
      t.rss += Number(a.rss_bytes || 0);
      if (a.cpu_percent !== null && a.cpu_percent !== undefined && Number.isFinite(Number(a.cpu_percent))) {
        t.cpu = (t.cpu || 0) + Number(a.cpu_percent);
      }
      if (a.last_seen_at && a.last_seen_at > t.lastSeen) t.lastSeen = a.last_seen_at;
      if (a.is_orphan) t.orphans++;
    }
  }
  return t;
}

// applyAgentFilters: the Agents filter row, the same pill and text state as
// the Sessions rail. Text matches an instance's repo, branch, workspace or
// cwd; helpers ride along with their instance. Infra groups are never
// filtered. Pure; returns new group objects.
function applyAgentFilters(groups, opts) {
  const o = opts || {};
  const off = o.harnesses || {};
  const hit = a => sessionMatchesText(a, o.text) || sessionMatchesText({ workspace: a.cwd }, o.text);
  const out = [];
  for (const g of groups || []) {
    if (g.infra) { out.push(g); continue; }
    if (off[g.key] === false) continue;
    const instances = g.instances.filter(i => [i.root, ...i.children].some(hit));
    if (instances.length) out.push({ ...g, instances });
  }
  return out;
}

function cwdLabel(cwd) {
  if (!cwd) return '';
  const s = String(cwd).replace(/\/+$/, '');
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  return i >= 0 ? s.slice(i + 1) : s;
}

// Session-first timeline: a waterfall of tool calls (bars spanning
// start→result), model calls (token rows), and file/network/guard dots on
// the same axis. Pure function — the DOM tests drive it headless.
function sessionWaterfallHTML(events) {
  const toolCalls = (events || []).filter(e => e.kind === 12);
  const modelCalls = (events || []).filter(e => e.kind === 14);
  const dots = (events || []).filter(e => e.kind !== 12 && e.kind !== 13 && e.kind !== 14);
  if (!events || events.length === 0) {
    return '<div class="empty"><span>No trace events for this session yet</span></div>';
  }
  const startOf = e => Date.parse(e.ts) || 0;
  const endOf = e => startOf(e) + (Number(e.duration_ms) || 0);
  let lo = Infinity, hi = -Infinity;
  for (const e of events) {
    lo = Math.min(lo, startOf(e));
    hi = Math.max(hi, endOf(e));
  }
  if (hi <= lo) hi = lo + 1000; // degenerate single-instant window
  const span = hi - lo;
  const pct = t => Math.max(0, Math.min(100, (t - lo) / span * 100));
  const wid = (a, b) => Math.max(0.4, (b - a) / span * 100);

  const fmtClock = t => {
    const d = new Date(t);
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') + ':' + String(d.getSeconds()).padStart(2, '0');
  };

  const bars = toolCalls.map(e => {
    const err = e.tool_status === 'error' ? ' error' : '';
    const dur = e.duration_ms ? fmtDurationMs(e.duration_ms) : '';
    return `<div class="wf-row"><span class="wf-name">${escapeHTML(e.tool || 'tool')}<span class="wf-dur">${escapeHTML(dur)}</span></span><span class="wf-track"><span class="wf-bar${err}" data-left="${pct(startOf(e)).toFixed(2)}" data-w="${wid(startOf(e), endOf(e)).toFixed(2)}"></span></span></div>`;
  }).join('');

  const dotCls = e => {
    if (e.kind === 5 || e.kind === 6) return 'conn';
    if (e.kind === 10 || e.kind === 11) return 'guard';
    return '';
  };
  const dotRow = dots.length
    ? `<div class="wf-row"><span class="wf-name">file · net · guard</span><span class="wf-track">${dots.map(e => `<span class="wf-dot ${dotCls(e)}" data-left="${pct(startOf(e)).toFixed(2)}"></span>`).join('')}</span></div>`
    : '';

  const modelRows = modelCalls.map(e => {
    const tok = `${fmtCompact(e.tokens_in || 0)} in · ${fmtCompact(e.tokens_out || 0)} out`;
    const cost = e.cost_usd ? `$${e.cost_usd.toFixed(4)}` : '';
    return `<div class="wf-model"><span><b>${escapeHTML(e.model || 'model')}</b> · ${escapeHTML(fmtClock(startOf(e)))}</span><span>${escapeHTML(tok)}${cost ? ' · ' + escapeHTML(cost) : ''}</span></div>`;
  }).join('');

  return `<div class="wf">
    <div class="wf-axis"><span>${escapeHTML(fmtClock(lo))}</span><span>${escapeHTML(fmtClock(hi))}</span></div>
    ${bars}${dotRow}${modelRows}
  </div>`;
}

function fmtDurationMs(ms) {
  ms = Number(ms) || 0;
  if (ms < 1000) return ms + 'ms';
  if (ms < 60000) return (ms / 1000).toFixed(1).replace(/\.0$/, '') + 's';
  return Math.floor(ms / 60000) + 'm ' + Math.round((ms % 60000) / 1000) + 's';
}

function fmtCompact(n) {
  n = Number(n) || 0;
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

// sessionTitle: what a session is working on — repo@branch, else the
// workspace folder, else the live process tree's folder (a provisional
// session's workspace can be "/"), else the short id — then " · <agent>"
// when an agent spawned it (originAgent). No harness prefix: the rail group
// and the detail head name the harness beside it.
function sessionTitle(s, liveCwd) {
  const work = s.repo
    ? `${s.repo}${s.branch ? '@' + s.branch : ''}`
    : cwdLabel(s.workspace) || cwdLabel(liveCwd) || sessionShort(s.id);
  const agent = originAgent(s);
  return agent ? `${work} · ${agent}` : work;
}

// originAgent: the agent that spawned a session, from its origin
// ("martina (openclaw)" → "martina"); "" for the user's own sessions.
function originAgent(s) {
  return String((s && s.origin) || '').replace(/ \(openclaw\)$/, '');
}

// fmtHHMM: a timestamp's local wall-clock HH:MM; "" when unparseable.
function fmtHHMM(ts) {
  const d = new Date(ts || '');
  if (isNaN(d.getTime())) return '';
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}

// collapseSessionFamilies: one half (live or ended) of a rail harness group
// as rows. Families without sub-sessions whose titles are identical fold into
// one row { dup: true, key: 'group:<harness>|<title>', title, sessions
// (newest start first), status (the most active member's) } at the place of
// its first member; every other family is { dup: false, key: <session id>,
// family }. titleOf(session) → the rail title. Pure.
function collapseSessionFamilies(fams, harness, titleOf) {
  const rank = { active: 0, idle: 1, ended: 2 };
  const statusOf = (s) => (s.status === 'ended' || s.status === 'idle' ? s.status : 'active');
  const list = fams || [];
  const titles = new Map();
  const byTitle = new Map();
  for (const f of list) {
    if (f.children.length) continue;
    const t = titleOf(f.session);
    titles.set(f, t);
    if (!byTitle.has(t)) byTitle.set(t, []);
    byTitle.get(t).push(f.session);
  }
  const rows = [];
  const placed = new Set();
  for (const f of list) {
    const t = titles.get(f);
    const same = t === undefined ? null : byTitle.get(t);
    if (!same || same.length < 2) {
      rows.push({ dup: false, key: String(f.session.id), family: f });
      continue;
    }
    if (placed.has(t)) continue;
    placed.add(t);
    const sessions = [...same].sort((a, b) => {
      const sa = String(a.started_at || ''), sb = String(b.started_at || '');
      return sa !== sb ? (sb > sa ? 1 : -1) : String(a.id).localeCompare(String(b.id));
    });
    const status = sessions.map(statusOf).sort((a, b) => rank[a] - rank[b])[0];
    rows.push({ dup: true, key: `group:${harness}|${t}`, title: t, sessions, status });
  }
  return rows;
}

// matchesSearch: the global-search lens. Free text (already lowercased by the
// caller) matched against the human-visible fields of any row kind — agent,
// rule, host, path, detail, evidence. A missing term matches everything.
function matchesSearch(term, ...fields) {
  if (!term) return true;
  for (const f of fields) {
    if (f == null) continue;
    const s = Array.isArray(f) ? f.join(' ') : String(f);
    if (s.toLowerCase().includes(term)) return true;
  }
  return false;
}

// hostSuffix groups endpoints for bulk decisions: the registrable-ish tail
// (last two labels) for names, the address itself for IPs/short hosts.
// Approximate by design — no public-suffix list ships with the console; the
// button always names exactly what it will allow.
function hostSuffix(host) {
  const h = String(host || '');
  if (!h || h.includes(':') || /^[\d.]+$/.test(h)) return h;
  const parts = h.split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : h;
}

function sessionRows(agents, trees) {
  if (trees && trees.length) {
    return trees.map(t => {
      const root = t.root || {};
      const children = t.children || [];
      return {
        root,
        children,
        label: cwdLabel(root.cwd) || familyTitle(root.name),
        rss: Number(t.rss_bytes || 0),
        lastSeen: t.last_seen_at || '',
        pids: [Number(root.pid), ...children.map(k => Number(k.pid))],
      };
    });
  }
  const list = agents || [];
  const roots = list.filter(a => isFamilyRoot(a, list));
  const rows = roots.map(root => {
    const children = childrenOf(root, list);
    let rss = Number(root.rss_bytes || 0);
    let lastSeen = root.last_seen_at || '';
    for (const k of children) {
      rss += Number(k.rss_bytes || 0);
      if (k.last_seen_at && k.last_seen_at > lastSeen) lastSeen = k.last_seen_at;
    }
    return {
      root,
      children,
      label: cwdLabel(root.cwd) || familyTitle(root.name),
      rss,
      lastSeen,
      pids: [Number(root.pid), ...children.map(k => Number(k.pid))],
    };
  });
  rows.sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''));
  return rows;
}

function sessionStripRows(rows, n) {
  const cap = n == null ? 3 : Number(n);
  return (rows || []).slice(0, cap > 0 ? cap : 0);
}

function sessionNeedsYou(row, flags) {
  const pids = new Set((row && row.pids ? row.pids : []).map(Number));
  let n = 0;
  for (const f of flags || []) {
    if (f.acknowledged) continue;
    if (pids.has(Number(f.pid))) n++;
  }
  return n;
}

function sessionStripHTML(rows, total, now, flags) {
  rows = rows || [];
  if (!rows.length) return '';
  const items = rows.map(row => {
    const need = sessionNeedsYou(row, flags);
    const rss = fmtRSS(row.rss);
    const seen = row.lastSeen ? fmtAge(row.lastSeen, now) : '';
    return `<button type="button" class="session-strip-row" data-action="goto-tab" data-tab="sessions">
      <span class="session-strip-label">${escapeHTML(row.label)}</span>
      ${rss ? `<span class="session-strip-meta">${escapeHTML(rss)}</span>` : ''}
      ${seen ? `<span class="session-strip-meta">${escapeHTML(seen)}</span>` : ''}
      ${need ? `<span class="session-strip-need">${need}</span>` : ''}
    </button>`;
  }).join('');
  const more = Number(total) > rows.length
    ? `<button type="button" class="session-strip-more" data-action="goto-tab" data-tab="sessions">View all ${Number(total)}</button>`
    : '';
  return `<div class="session-strip">${items}${more}</div>`;
}

function renderProcessRow(a, now, nested) {
  const abs = a.started_at ? fmtTime(new Date(a.started_at)) : '';
  const age = a.started_at ? fmtAge(a.started_at, now) : '';
  const seenAge = a.last_seen_at ? fmtAge(a.last_seen_at, now) : '';
  const stale = a.last_seen_at
    ? (now - Date.parse(a.last_seen_at)) > 10 * 60 * 1000
    : true;
  const rss = fmtRSS(a.rss_bytes);
  const cwd = a.cwd ? `<div class="agent-cwd">${escapeHTML(a.cwd)}</div>` : '';
  const status = a.is_orphan
    ? '<span class="agent-status orphan">leftover</span>'
    : '<span class="agent-status live">live</span>';
  return `
      <div class="agent-instance${nested ? ' nested' : ''}${a.is_orphan ? ' orphan' : ''}${stale ? ' stale' : ''}">
        <div class="agent-info">
          <div class="agent-name">
            <span class="agent-pid">PID ${a.pid}</span>
            ${status}
            ${abs ? `<span class="agent-meta-item" title="started ${escapeHTML(a.started_at)}">${escapeHTML(abs)}${age ? ' · ' + age : ''}</span>` : ''}
            ${seenAge ? `<span class="agent-meta-item agent-lastseen" title="last event ${escapeHTML(a.last_seen_at)}">active ${escapeHTML(seenAge)} ago</span>` : `<span class="agent-meta-item agent-lastseen">no activity</span>`}
            ${rss ? `<span class="agent-meta-item">${escapeHTML(rss)}</span>` : ''}
          </div>
          ${cwd}
        </div>
        <button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="${a.pid}" data-started="${escapeHTML(a.started_at || '')}" data-family="${escapeHTML(a.name || '')}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>
      </div>`;
}

function sessionBoardHTML(rows, now, helpOpen) {
  helpOpen = helpOpen || {};
  return rows.map(row => {
    const a = row.root;
    const rss = fmtRSS(row.rss);
    const seenAge = row.lastSeen ? fmtAge(row.lastSeen, now) : '';
    const stale = row.lastSeen ? (now - Date.parse(row.lastSeen)) > 10 * 60 * 1000 : true;
    const open = helpOpen[a.pid] ? ' open' : '';
    const helpers = row.children.length
      ? `<details class="session-helpers"${open} data-pid="${a.pid}"><summary class="session-helpers-sum">${row.children.length} helper${row.children.length === 1 ? '' : 's'}</summary>${row.children.map(c => renderProcessRow(c, now, true)).join('')}</details>`
      : '';
    return `
      <div class="session-row${a.is_orphan ? ' orphan' : ''}${stale ? ' stale' : ''}">
        <button type="button" class="session-main" data-action="filter-pids" data-pids="${escapeHTML(row.pids.join(','))}" data-label="${escapeHTML(row.label)}" title="${escapeHTML(a.cwd || '')}">
          <span class="session-label">${escapeHTML(row.label)}</span>
          <span class="agent-pid">${escapeHTML(a.name)} · PID ${a.pid}</span>
          ${seenAge ? `<span class="agent-meta-item agent-lastseen">active ${escapeHTML(seenAge)} ago</span>` : `<span class="agent-meta-item agent-lastseen">no activity</span>`}
          ${rss ? `<span class="agent-meta-item">${escapeHTML(rss)}</span>` : ''}
        </button>
        <button type="button" class="btn btn-danger btn-sm" data-action="kill" data-pid="${a.pid}" data-started="${escapeHTML(a.started_at || '')}" data-family="${escapeHTML(a.name || '')}"><svg class="icon"><use href="#i-power"/></svg><span>Terminate</span></button>
        ${helpers}
      </div>`;
  }).join('');
}

function monitorVendorKeyIDs(stats) {
  return Object.keys(stats || {}).filter(id =>
    stats[id] && stats[id].type === 'vendor-key' && stats[id].mode !== 'block'
  ).sort();
}

function inspectionVisible(status, audit) {
  return {
    fleet: !!(status && status.fleet_configured),
    advisor: !!(status && status.advisor_enabled),
    audit: Array.isArray(audit) && audit.length > 0,
  };
}

function vendorKeyPromoteHTML(ids) {
  if (!ids || !ids.length) return '';
  const n = ids.length;
  return `<div class="fw-promote-vendor">
    <div class="fw-rule-main">
      <span class="fw-rule-id">Catch secrets</span>
      <div class="fw-metrics"><span class="fw-metric">${n} vendor-key rule${n === 1 ? '' : 's'} still in monitor — they report leaks but do not stop them</span></div>
    </div>
    <button class="btn btn-primary btn-sm" data-action="promote-vendor-keys"><svg class="icon"><use href="#i-arrow"/></svg><span>Promote vendor keys to block</span></button>
  </div>`;
}
// sseNeedsSnapshot: which EventSource kinds must refetch GET /snapshot.
// file/conn/transcript noise only bumps the sparkline — a 400ms snapshot
// after every ES file-open is the leftover hot-path tax.
function sseNeedsSnapshot(kind) {
  return kind === 'exec' || kind === 'guard-prompt' || kind === 'guard-resolved' || kind === 'proxy-hit';
}
// attentionItemKind: the group-item kind a /posture headline item belongs to.
function attentionItemKind(kind) {
  return { guard_pending: 'guard', resource_pressure: 'resource', uninspected_egress: 'egress' }[kind] || kind;
}
// mapPostureAttention: the posture after an optimistic attention change. fn
// maps each group item (null drops it); a dropped item leaves posture.items
// too and needs_you is items.length, so the count, the headline items and
// the groups agree until the next snapshot. state and summary stay the
// daemon's.
function mapPostureAttention(p, fn) {
  if (!p || !p.groups) return p;
  const dropped = new Set();
  const groups = p.groups.map(g => ({
    ...g,
    items: g.items.map(it => {
      const out = fn(it);
      if (!out) dropped.add(it.kind + '|' + it.id);
      return out;
    }).filter(Boolean),
  })).filter(g => g.items.length);
  const items = (p.items || []).filter(it => !dropped.has(attentionItemKind(it.kind) + '|' + it.id));
  return { ...p, groups, items, needs_you: items.length };
}

// ---------- console navigation ----------
// Four tabs; Sessions holds five sub-views. Old tab ids (menu bar deep
// links, saved views, the stored tab, in-page links) resolve through one
// alias table.
const CONSOLE_TABS = ['home', 'sessions', 'egress', 'policy'];
const SESSIONS_SUBS = ['board', 'processes', 'resources', 'worktrees', 'events'];
const TAB_ALIASES = {
  overview: { tab: 'home' },
  findings: { tab: 'home', focus: 'attention' },
  agents: { tab: 'sessions', sub: 'processes' },
  resources: { tab: 'sessions', sub: 'resources' },
  history: { tab: 'sessions', sub: 'resources' },
  worktrees: { tab: 'sessions', sub: 'worktrees' },
  events: { tab: 'sessions', sub: 'events' },
};

// isConsoleRoute: whether id (a tab, "sessions/<sub>", an old tab id, with
// or without "#") names a console view.
function isConsoleRoute(id) {
  const head = String(id || '').replace(/^#/, '').split('/')[0];
  return CONSOLE_TABS.includes(head) || Object.prototype.hasOwnProperty.call(TAB_ALIASES, head);
}

// resolveConsoleRoute: any route → { tab, sub, focus }. sub is the Sessions
// sub-view ('board' by default, '' on other tabs); focus 'attention' scrolls
// the attention panel into view. Unknown → Home.
function resolveConsoleRoute(id) {
  const [head, rest] = String(id || '').replace(/^#/, '').split('/');
  if (Object.prototype.hasOwnProperty.call(TAB_ALIASES, head)) {
    const a = TAB_ALIASES[head];
    return { tab: a.tab, sub: a.tab === 'sessions' ? a.sub : '', focus: a.focus || '' };
  }
  if (!CONSOLE_TABS.includes(head)) return { tab: 'home', sub: '', focus: '' };
  if (head === 'sessions') return { tab: 'sessions', sub: SESSIONS_SUBS.includes(rest) ? rest : 'board', focus: '' };
  return { tab: head, sub: '', focus: '' };
}

// routeKey: "tab" or "sessions/<sub>" — what the stored tab and saved views keep.
function routeKey(r) {
  return r.tab === 'sessions' ? 'sessions/' + (r.sub || 'board') : r.tab;
}

// consoleRouteHash: the address-bar form, "#sessions/<sub>" for a sub-view
// and "#sessions" for the board.
function consoleRouteHash(r) {
  return '#' + (r.tab === 'sessions' && r.sub && r.sub !== 'board' ? 'sessions/' + r.sub : r.tab);
}

// consoleBootState: 'ended' when the page has no console token — none in
// the #ct= fragment and none kept for this tab — else 'normal'.
function consoleBootState(hashToken, storedToken) {
  return hashToken || storedToken ? 'normal' : 'ended';
}

// policyListHTML: one read-only Policy list — guard decisions ('guard'),
// file exceptions ('path'), muted flag classes ('mute'). st carries the
// loading and error state; each empty list says what fills it.
function policyListHTML(kind, rows, st) {
  const s = st || {};
  if (!rows) {
    if (s.error) return `<div class="empty"><span>${escapeHTML(s.error)}</span></div>`;
    return `<div class="loading">Loading…</div>`;
  }
  const EMPTY = {
    guard: 'No guard decisions yet. Answering a guard prompt with Always allow or Always deny stores one here.',
    path: 'No file exceptions yet. Always allow this file, on a finding, adds one here.',
    mute: 'No muted flag classes. Stop flagging this, on a finding, adds one here.',
  };
  if (!rows.length) return `<div class="empty"><span>${EMPTY[kind]}</span></div>`;
  const row = (main, sub, meta) => `<div class="policy-row"><div class="policy-row-main">${main}</div>`
    + `<div class="policy-row-sub">${sub}</div>${meta ? `<span class="policy-row-meta">${meta}</span>` : ''}</div>`;
  const when = r => r.created_at ? escapeHTML(String(r.created_at).slice(0, 10)) : '';
  const items = rows.map(r => {
    if (kind === 'guard') {
      return row(`<span class="policy-decision ${r.decision === 'deny' ? 'deny' : 'allow'}">${escapeHTML(r.decision || '')}</span> `
        + `<b>${escapeHTML(r.rule_id || '')}</b> for ${escapeHTML(r.agent || '')}`, escapeHTML(r.source || ''), when(r));
    }
    if (kind === 'path') {
      return row(`<code>${escapeHTML(r.path || '')}</code>`, `${escapeHTML(r.rule_id || '')} for ${escapeHTML(r.agent || '')}`, when(r));
    }
    const scope = (r.host === '*' ? 'all hosts' : escapeHTML(r.host || '')) + ' · ' + (r.agent ? escapeHTML(r.agent) : 'all agents');
    return row(`<b>${escapeHTML(r.title || r.rule || '')}</b>`, scope, '');
  });
  return `<div class="policy-list" data-policy="${kind}">${items.join('')}</div>`;
}
