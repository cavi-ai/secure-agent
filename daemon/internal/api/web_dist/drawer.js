// The detail drawer: one slide-over replaces every native <dialog>. A native
// modal's backdrop is painted by the UA from the SYSTEM color-scheme, which
// inverted fg/bg when the page theme was pinned to the other scheme. This
// surface is plain DOM styled only from our tokens, so it always matches the
// page.
//
// The drawer is a single reusable surface: title + body + optional footer
// actions. Only one is open at a time; closing restores focus to the opener.
// createDrawer builds one state object; the drawer* functions below read and
// write it.

// Match the CSS dock breakpoints, including browser viewport emulation:
// the main column keeps 720px beside the drawer, with the navigation
// sidebar shown or collapsed.
const DRAWER_DOCK_WIDTHS = { narrow: [1700, 1410], wide: [1860, 1580] };

function createDrawer({ request, toast, markDirty, closeAgentDock, auth, attention, family, plan, flag, session }) {
  const drawer = document.getElementById('drawer');
  const s = {
    drawer,
    body: document.getElementById('drawer-body'),
    foot: document.getElementById('drawer-foot'),
    title: document.getElementById('drawer-title-text'),
    titleIcon: document.querySelector('#drawer-title use'),
    closeButton: document.getElementById('btn-drawer-close'),
    copyButton: document.getElementById('btn-drawer-copy'),
    head: drawer && drawer.querySelector('.drawer-head'),
    titleEl: document.getElementById('drawer-title'),
    request, toast, markDirty, closeAgentDock, auth, attention, family, plan, flag, session,
    opener: null,
    openerNeedKey: null,
    openerAction: null,
    onClose: null,
    backTarget: null,
    // Bumped on every open: an async opener writes its body only while its
    // drawer is still the one showing.
    seq: 0,
    selection: null,
    modal: false,
    inertBefore: new Map(),
    dockMedia: DRAWER_DOCK_WIDTHS.narrow.map(w => window.matchMedia?.(`(min-width: ${w}px)`)),
    wideDockMedia: DRAWER_DOCK_WIDTHS.wide.map(w => window.matchMedia?.(`(min-width: ${w}px)`)),
    // The drawer is shared by several views: the incident report (markdown,
    // with a Copy button) and the uninspected-egress drill-down (row actions,
    // no Copy). mode tracks which one is open so action handlers can re-render
    // the right content after a mutation.
    mode: null, // 'incident' | 'endpoint' | 'file' | 'flag' | 'plan' | 'uninspected' | 'family' | 'policy' | 'review-result' | 'permissions' | null
    fileDetail: '',
    planSubject: '',
    flagId: '',
    incidentId: '',
    endpoint: null,
    familyKey: '',
    reviewResult: null,
    rawMarkdown: ''
  };
  drawerListen(s);

  return {
    root: drawer, body: s.body, foot: s.foot, title: s.title, closeButton: s.closeButton,
    open: opts => drawerOpen(s, opts),
    close: () => drawerClose(s),
    back: () => drawerBack(s),
    sessionBack: el => drawerSessionBack(s, el),
    setCopyVisible: visible => drawerSetCopyVisible(s, visible),
    syncMode: () => drawerSyncMode(s),
    openReviewResult: result => drawerOpenReviewResult(s, result),
    openIncidentReport: (id, opts) => drawerOpenIncidentReport(s, id, opts),
    openEndpointDetail: (host, agent, opts) => drawerOpenEndpointDetail(s, host, agent, opts),
    openFileDetail: (path, opts) => drawerOpenFileDetail(s, path, opts),
    openPlanDrawer: (subject, opts) => drawerOpenPlan(s, subject, opts),
    openFlagDetail: (id, opts) => drawerOpenFlagDetail(s, id, opts),
    openUninspected: opts => drawerOpenUninspected(s, opts),
    openFamilyDrawer: (key, opts) => drawerOpenFamily(s, key, opts),
    refillUninspected: () => drawerRefillUninspected(s),
    refillUninspectedDrawer: () => drawerRefillUninspectedDrawer(s),
    fillFamily: () => drawerFillFamily(s),
    isFlagOpen: id => s.mode === 'flag' && s.flagId === id && !!drawer && !drawer.hidden,
    isIncidentOpen: id => s.mode === 'incident' && s.incidentId === id,
    mode: () => s.mode,
    setMode: next => { s.mode = next; },
    seq: () => s.seq,
    selection: () => s.selection,
    clearSelection: () => { s.selection = null; },
    returnTarget: () => s.backTarget,
    afterClose: fn => {
      const previous = s.onClose;
      s.onClose = () => {
        if (previous) previous();
        fn();
      };
    },
    reviewResult: () => s.reviewResult,
    setReviewResult: next => { s.reviewResult = next; }
  };
}

function drawerSyncMode(s) {
  const { drawer, auth, dockMedia, wideDockMedia, inertBefore } = s;
  if (!drawer || auth.ended()) return;
  const wide = drawer.classList.contains('resource-policy');
  const collapsed = document.body?.classList.contains('sidebar-collapsed') ? 1 : 0;
  const media = (wide ? wideDockMedia : dockMedia)[collapsed];
  const docked = media ? media.matches : (document.documentElement?.clientWidth || window.innerWidth) >= DRAWER_DOCK_WIDTHS[wide ? 'wide' : 'narrow'][collapsed];
  const isModal = !drawer.hidden && !docked;
  s.modal = isModal;
  drawer.setAttribute('role', isModal ? 'dialog' : 'complementary');
  drawer.setAttribute('aria-labelledby', 'drawer-title');
  if (isModal) drawer.setAttribute('aria-modal', 'true'); else drawer.removeAttribute('aria-modal');
  drawer.dataset.modal = String(isModal);
  if (isModal) {
    document.querySelectorAll('.app > *').forEach(el => {
      if (el.contains(drawer) || el.id === 'confirm-layer' || el.id === 'session-ended') return;
      if (!inertBefore.has(el)) inertBefore.set(el, el.inert);
      el.inert = true;
    });
  } else {
    for (const [el, previous] of inertBefore) el.inert = previous;
    inertBefore.clear();
  }
}

function drawerListen(s) {
  const { drawer, closeButton, copyButton, auth, toast, dockMedia, wideDockMedia } = s;
  window.addEventListener('resize', () => drawerSyncMode(s));
  for (const media of [...dockMedia, ...wideDockMedia]) media?.addEventListener('change', () => drawerSyncMode(s));

  if (closeButton) closeButton.addEventListener('click', () => drawerClose(s));
  if (drawer) {
    document.addEventListener('keydown', (e) => {
      if (auth.ended()) return;
      const confirmLayer = document.getElementById('confirm-layer');
      if (e.key === 'Escape' && drawer && !drawer.hidden && (!confirmLayer || confirmLayer.hidden)) drawerClose(s);
      if (e.key === 'Tab' && s.modal && !drawer.hidden && (!confirmLayer || confirmLayer.hidden)) {
        const controls = Array.from(drawer.querySelectorAll('button, input, select, textarea, a[href], summary, [tabindex="0"]')).filter(el => !el.disabled && !el.hidden && el.getClientRects().length);
        const first = controls[0], last = controls[controls.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
      }
    });
  }
  if (copyButton) {
    copyButton.addEventListener('click', async () => {
      if (!s.rawMarkdown || s.mode !== 'incident' || auth.ended()) return;
      const mine = s.seq;
      try {
        await navigator.clipboard.writeText(s.rawMarkdown);
        if (mine !== s.seq || auth.ended()) return;
        toast('Incident report copied to clipboard!', 'success');
      } catch (err) {
        if (mine !== s.seq || auth.ended()) return;
        toast('Failed to copy report: ' + err, 'danger');
      }
    });
  }
}

function drawerOpen(s, { title: heading, icon, body: html, foot: footHTML, variant, onClose: closeHook, back, attentionOrigin }) {
  const { drawer, head, titleEl, title, titleIcon, body, foot, closeButton, closeAgentDock } = s;
  if (!drawer) return false;
  s.rawMarkdown = '';
  drawerSetCopyVisible(s, false);
  closeAgentDock();
  // A drawer opened from inside the open one keeps the original opener, so
  // closing still returns focus to the page.
  if (drawer.hidden) {
    s.opener = document.activeElement;
    s.openerNeedKey = s.opener?.closest?.('[data-need-key]')?.dataset.needKey;
    s.openerAction = s.opener?.dataset?.action ? JSON.stringify(Object.entries(s.opener.dataset).sort(([a], [b]) => a.localeCompare(b))) : null;
  }
  s.selection = attentionOrigin || back?.attentionOrigin || null;
  s.onClose = closeHook || null;
  s.backTarget = back || null;
  s.seq++;
  if (head && titleEl) paintDrawerBack(head, titleEl, s.backTarget);
  title.textContent = heading || 'Details';
  if (icon && titleIcon) titleIcon.setAttribute('href', '#i-' + icon);
  body.innerHTML = html || '';
  foot.innerHTML = footHTML || '';
  foot.hidden = !footHTML;
  drawer.className = 'drawer' + (variant ? ' ' + variant : '');
  drawer.hidden = false;
  drawerSyncMode(s);
  if (s.modal || back?.sessionReturn) closeButton?.focus({ preventScroll: true });
  // Reserve room so the panel docks beside the content instead of covering
  // it — this is an inspector, not a modal.
  const app = document.querySelector('.app');
  if (app) {
    app.classList.add('drawer-open');
    app.classList.toggle('drawer-wide', !!variant);
  }
  return true;
}

function drawerClose(s) {
  const { drawer, head, titleEl, body, foot, attention } = s;
  if (!drawer || drawer.hidden) return;
  const inspectedKey = s.selection?.key;
  drawer.hidden = true;
  s.rawMarkdown = '';
  drawerSetCopyVisible(s, false);
  s.seq++;
  s.selection = null;
  attention.bumpGeneration();
  drawerSyncMode(s);
  body.innerHTML = '';
  foot.innerHTML = '';
  foot.hidden = true;
  s.backTarget = null;
  if (head && titleEl) paintDrawerBack(head, titleEl, null);
  const app = document.querySelector('.app');
  if (app) app.classList.remove('drawer-open', 'drawer-wide');
  const fn = s.onClose;
  s.onClose = null;
  const { opener, openerNeedKey, openerAction } = s;
  const rows = openerNeedKey || inspectedKey ? Array.from(document.querySelectorAll('#attention-list [data-need-key]')) : [];
  const replacement = openerNeedKey && rows.find(row => row.dataset.needKey === openerNeedKey);
  const inspected = inspectedKey && rows.find(row => row.dataset.needKey === inspectedKey);
  const equivalent = replacement && Array.from(replacement.querySelectorAll('[data-action]'))
    .find(el => JSON.stringify(Object.entries(el.dataset).sort(([a], [b]) => a.localeCompare(b))) === openerAction && !el.disabled);
  const candidates = [opener?.isConnected ? opener : null, equivalent, replacement?.querySelector('.need-head'),
    inspected?.querySelector('.need-head'), document.querySelector('#attention-list .need-head'),
    document.getElementById('attention-summary-title'), document.getElementById('session-daily-title')];
  const restored = candidates.find(control => {
    if (!control || typeof control.focus !== 'function' || control.disabled || control.matches?.(':disabled')
      || control.closest?.('[hidden], [inert], [aria-hidden="true"]')) return false;
    // The close click/Escape also closes More menus. Return to the same
    // row's header instead of focusing an action that will become hidden.
    if (openerNeedKey && control.closest?.('details.act-more')) return false;
    for (let part = control; part; part = part.parentElement) {
      const style = typeof getComputedStyle === 'function' ? getComputedStyle(part) : null;
      if (style && (style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse')) return false;
    }
    // A refreshed action menu starts closed. Reveal the same choice before
    // restoring focus; focusing a descendant of closed <details> is ignored.
    for (let part = control.closest?.('details'); part; part = part.parentElement?.closest('details')) part.open = true;
    return (!control.checkVisibility || control.checkVisibility()) && (!control.getClientRects || control.getClientRects().length > 0);
  });
  restored?.focus({ preventScroll: true });
  s.opener = null;
  s.openerNeedKey = s.openerAction = null;
  if (fn) fn();
}

function drawerSetCopyVisible(s, visible) {
  if (s.copyButton) s.copyButton.hidden = !visible;
}

function drawerOpenReviewResult(s, result) {
  if (!result || s.auth.ended()) return;
  s.mode = 'review-result';
  s.reviewResult = result;
  drawerOpen(s, { title: reviewResultLabel(result.receipt), icon: 'shield',
    body: reviewResultHTML(result, true), foot: '', onClose: () => {
      if (s.mode === 'review-result') { s.mode = null; s.reviewResult = null; }
    } });
}

async function drawerOpenIncidentReport(s, id, { back } = {}) {
  const { drawer, body, request, plan } = s;
  if (!drawer) return;
  s.mode = 'incident';
  s.incidentId = id;
  drawerOpen(s, {
    title: `Incident report — ${id}`,
    icon: 'doc',
    body: html`<div class="loading-spinner">Fetching incident report…</div>`,
    onClose: () => { s.mode = null; },
    back,
  });
  const mine = s.seq;

  try {
    const url = `/incidents?id=${encodeURIComponent(id)}`;
    const [res, detail] = await Promise.all([request(url + '&format=markdown'), request(url)]);
    if (mine !== s.seq) return;
    if (res.ok && detail.ok) {
      const [text, report] = await Promise.all([res.text(), detail.json()]);
      if (mine !== s.seq) return;
      s.rawMarkdown = text;
      drawerSetCopyVisible(s, !!text);
      id = report.incident && report.incident.id || id;
      s.incidentId = id;
      body.innerHTML = incidentReportHTML(id, report.workflow, text, report.incident && report.incident.remediation);
      plan.load('incident:' + id);
    } else {
      const message = res.status === 404 || detail.status === 404
        ? 'This incident report is no longer available. Its source may have expired; the retained session summary does not replace the report.'
        : 'Failed to load the incident report.';
      body.innerHTML = html`<div class="empty" role="status"><svg class="icon"><use href="#i-doc"/></svg><span>${message}</span></div>`;
    }
  } catch (err) {
    if (mine !== s.seq) return;
    body.innerHTML = html`<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Error: ${err.message}</span></div>`;
  }
}

// Endpoint detail: "what IS this address?" The Evidence action opens this so
// an unknown IPv6 is explained (owner org, PTR name, which agents/sessions
// reached it, recent connections) instead of being a bare address that looks
// safe to block.
async function drawerOpenEndpointDetail(s, host, agent, { back } = {}) {
  const { drawer, body, request } = s;
  if (!drawer) return;
  s.mode = 'endpoint';
  s.endpoint = { host, agent };
  drawerSetCopyVisible(s, false);
  drawerOpen(s, {
    title: 'Endpoint detail',
    icon: 'globe',
    onClose: () => { s.mode = null; },
    back,
  });
  const mine = s.seq;
  body.innerHTML = html`<div class="loading-spinner">Identifying ${host}…</div>`;
  try {
    const res = await request(`/egress/endpoint?host=${encodeURIComponent(host)}`);
    if (!res.ok) throw new Error((await res.text()).trim() || 'lookup failed');
    const detail = await res.json();
    if (mine !== s.seq) return;
    body.innerHTML = endpointDetailHTML(detail, agent);
  } catch (err) {
    if (mine !== s.seq) return;
    body.innerHTML = html`<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>Could not identify this endpoint: ${err.message || err}</span></div>`;
  }
}

// File detail: an evidence path opens what the daemon knows about the file —
// facts, the masked excerpt around each secret, findings and agent access —
// with Reveal in Finder and Open in editor.
async function drawerOpenFileDetail(s, path, { back } = {}) {
  const { drawer, body, request, plan } = s;
  if (!drawer) return;
  s.mode = 'file';
  s.fileDetail = path;
  drawerSetCopyVisible(s, false);
  drawerOpen(s, {
    title: 'File',
    icon: 'doc',
    onClose: () => { s.mode = null; },
    back,
  });
  const mine = s.seq;
  body.innerHTML = html`<div class="loading-spinner">Reading ${path}…</div>`;
  try {
    const res = await request(`/files/detail?path=${encodeURIComponent(path)}`);
    if (!res.ok) throw new Error((await res.text()).trim() || 'lookup failed');
    const detail = await res.json();
    if (mine !== s.seq) return;
    body.innerHTML = fileDetailHTML(detail) + planSlotHTML('file:' + path);
    plan.load('file:' + path);
  } catch (err) {
    if (mine !== s.seq) return;
    body.innerHTML = html`<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Could not read this file: ${err.message || err}</span></div>`;
  }
}

function drawerOpenPlan(s, subject, { back } = {}) {
  const { drawer, body, plan } = s;
  if (!drawer) return;
  s.mode = 'plan';
  s.planSubject = subject;
  drawerSetCopyVisible(s, false);
  drawerOpen(s, { title: 'What to do', icon: 'doc', onClose: () => { s.mode = null; }, back });
  body.innerHTML = html`<div class="plan-slot" data-plan-subject="${subject}"><div class="loading-spinner">Loading the playbook…</div></div>`;
  plan.load(subject);
}

async function drawerOpenFlagDetail(s, id, { back } = {}) {
  const { drawer, title, body, request, flag, plan } = s;
  if (!drawer) return;
  s.mode = 'flag';
  s.flagId = id;
  drawerSetCopyVisible(s, false);
  drawerOpen(s, { title: 'Security flag', icon: 'alert', body: '<div class="loading-spinner">Loading flag evidence…</div>',
    onClose: () => { if (s.mode === 'flag') s.mode = null; s.flagId = ''; }, back });
  const mine = s.seq;
  const summary = flag.summary?.(id);
  let missing = false;
  try {
    const res = await request(`/flags/${encodeURIComponent(id)}/explain`);
    missing = res.status === 404;
    if (missing) throw new Error('Finding evidence is no longer available. Its source may have expired; the retained session summary does not replace the evidence.');
    if (!res.ok) throw new Error((await res.text()).trim() || 'flag unavailable');
    const f = await res.json();
    if (mine !== s.seq) return;
    // The drawer can open a flag outside the current telemetry window. Its
    // served actions must still be available to the click handler now.
    flag.cache(f);
    const subject = 'flag:' + f.id;
    const evidence = (f.evidence || []).map(ev => html`<li>${typeof ev === 'string' ? ev : ev.text || (ev.sub ? `${ev.label || ''} (${ev.sub})` : ev.label || '')}</li>`).join('');
    const advisor = f.advisor ? html`<p><b>Advisor:</b> ${f.advisor.assessment || 'unrated'} · ${f.advisor.rationale || ''}</p>` : '';
    const reading = explainLines(f);
    title.textContent = f.title || ruleTitle(f.rule);
    body.innerHTML = html`<div class="panel-body flag-inspector">
      <p>${f.title || ruleTitle(f.rule)} · severity ${Number(f.severity) || 0} · ${f.agent || 'unknown agent'}</p>
      <dl class="finding-facts"><dt>Raised</dt><dd>${new Date(f.ts).toLocaleString()}</dd><dt>Process</dt><dd>PID ${Number(f.pid) || 0}</dd>
        <dt>Session</dt><dd>${f.session_id || 'unknown'}</dd><dt>Workspace</dt><dd>${f.workspace || 'unknown'}</dd><dt>Flag ID</dt><dd>${f.id}</dd></dl>
      ${reading ? raw(html`<p class="finding-what">${reading.what || ''}</p>${raw(factChipsHTML(f, ''))}<p class="finding-verdict">${reading.verdict || ''}</p>`) : ''}
      ${raw(f.explain?.assessment ? assessmentHTML(f.explain.assessment) : advisor)}<h4>Recorded evidence</h4>${evidence ? raw(html`<ul class="plan-list">${raw(evidence)}</ul>`) : raw('<p>No evidence rows were recorded for this flag.</p>')}
      <div class="flag-actions-row">${f.explain
        ? raw(explainActionsHTML(f, flag.advisorEnabled() ? [{ label: 'Re-run advisor', attrs: html`data-action="retriage" data-id="${f.id}"` }] : []))
        : raw(html`<button type="button" class="btn btn-ghost btn-sm" data-action="dismiss-flag" data-id="${f.id}">Dismiss flag</button>`)}</div>
      <h4>What to do</h4><div class="plan-slot" data-plan-subject="${subject}"><div class="loading-spinner">Loading the playbook…</div></div>
    </div>`;
    plan.load(subject);
  } catch (err) {
    if (mine !== s.seq) return;
    title.textContent = summary?.title || 'Security flag';
    const facts = [['Flag ID', id], ['Rule', summary?.rule], ['Session', summary?.session_id], ['Workspace', summary?.group?.workspace]].filter(([, value]) => value);
    body.innerHTML = html`<div class="panel-body flag-inspector">
        <h3>${missing ? 'Evidence unavailable' : 'Evidence could not be loaded'}</h3>
        ${summary ? raw(html`<p>${summary.detail || summary.title}</p><p>This is the queued summary, not the source evidence.</p>`) : ''}
        <p role="status">${err.message || err}</p>
        <dl class="finding-facts">${facts.map(([label, value]) => raw(html`<dt>${label}</dt><dd>${value}</dd>`))}</dl>
        ${summary || !missing ? raw(html`<div class="flag-actions-row">
          <button type="button" class="btn btn-ghost btn-sm" data-action="open-flag" data-id="${id}">Retry evidence</button>
          <button type="button" class="btn btn-ghost btn-sm" data-action="refresh-finding-queue">Refresh queue</button>
          ${!missing && summary ? raw(html`<button type="button" class="btn btn-ghost btn-sm" data-action="dismiss-flag" data-id="${id}">Dismiss flag</button>`) : ''}
        </div>`) : ''}
        <p>${missing ? (summary ? 'Refresh the queue to reconcile this missing record.' : 'The retained history does not replace the missing source evidence.') : 'Dismissing marks the flag reviewed. The rule keeps watching.'}</p>
      </div>`;
  }
}

function drawerFillUninspectedBody(s) {
  fillUninspected(s.body);
}

function drawerOpenUninspected(s, { back } = {}) {
  if (!s.drawer) return;
  s.mode = 'uninspected';
  drawerSetCopyVisible(s, false);
  drawerOpen(s, {
    title: 'Uninspected egress — last 24h',
    icon: 'globe',
    onClose: () => { s.mode = null; },
    back,
  });
  drawerFillUninspectedBody(s);
}

function drawerRefillUninspectedDrawer(s) {
  if (s.mode === 'uninspected' && s.drawer && !s.drawer.hidden) drawerFillUninspectedBody(s);
}
function drawerRefillUninspected(s) {
  s.markDirty('endpoints');
  drawerRefillUninspectedDrawer(s);
}

// Family drawer: View family on the Resources board opens the docked
// inspector for one process family — no tab switch. The 30s reconcile
// refills it in place (fetchTelemetry); the process table's Show more
// state lives in expandedLists. Open in Events is the way out to the full
// timeline.
function drawerOpenFamily(s, key, { back } = {}) {
  const { drawer, foot, family } = s;
  const fam = family.byKey(key);
  if (!drawer || !fam) return;
  // View family on the family already showing keeps its own way back.
  if (s.mode === 'family' && s.familyKey === key && !drawer.hidden) back = s.backTarget;
  s.mode = 'family';
  s.familyKey = key;
  family.select(key);
  drawerSetCopyVisible(s, false);
  drawerOpen(s, {
    title: family.label(fam),
    icon: 'activity',
    onClose: () => { s.mode = null; s.familyKey = ''; },
    back,
  });
  foot._saFoot = undefined;
  drawerFillFamily(s);
}

function drawerFillFamily(s) {
  const { drawer, title, body, foot, family } = s;
  if (s.mode !== 'family' || !drawer || drawer.hidden) return;
  const fam = family.byKey(s.familyKey);
  if (!fam) {
    body.innerHTML = html`<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>This family is no longer running.</span></div>`;
    foot.innerHTML = '';
    foot._saFoot = undefined;
    foot.hidden = true;
    return;
  }
  const label = family.label(fam);
  title.textContent = label;
  patchList(body, family.sections(fam), { key: p => p.key, html: p => p.html });
  const footHTML = familyDrawerFootHTML(fam, label);
  if (foot._saFoot !== footHTML) {
    foot.innerHTML = footHTML;
    foot._saFoot = footHTML;
  }
  foot.hidden = false;
}

function drawerSessionBack(s, el) {
  const { session } = s;
  const st = session.capture(el);
  return st ? { label: 'session', sessionReturn: st, reopen: () => session.restore(st) } : null;
}

// The open drawer as a way back to it. Reopening refreshes live evidence
// readers; saved results retain the evidence belonging to their decision.
// The policy editor has no back target because reopening would drop its draft.
function drawerBack(s) {
  const { drawer, auth, attention, family } = s;
  if (!drawer || drawer.hidden) return null;
  const previous = s.backTarget || undefined;
  const wrap = target => ({ ...target, sessionReturn: previous?.sessionReturn, attentionOrigin: s.selection || previous?.attentionOrigin });
  switch (s.mode) {
    case 'review-result': {
      const result = s.reviewResult;
      const generation = auth.generation();
      return result ? wrap({ label: 'Review result', reopen: () => {
        if (generation === auth.generation()) drawerOpenReviewResult(s, result);
      } }) : null;
    }
    case 'attention': {
      const key = s.selection?.key;
      return wrap({ label: 'Needs you', reopen: () => attention.select(key) });
    }
    case 'uninspected':
      return wrap({ label: 'Uninspected egress', reopen: () => drawerOpenUninspected(s, { back: previous }) });
    case 'endpoint': {
      const { host, agent } = s.endpoint;
      return wrap({ label: 'Endpoint detail', reopen: () => drawerOpenEndpointDetail(s, host, agent, { back: previous }) });
    }
    case 'incident': {
      const id = s.incidentId;
      return wrap({ label: 'Incident report', reopen: () => drawerOpenIncidentReport(s, id, { back: previous }) });
    }
    case 'file': {
      const p = s.fileDetail;
      return wrap({ label: 'File', reopen: () => drawerOpenFileDetail(s, p, { back: previous }) });
    }
    case 'plan': {
      const subject = s.planSubject;
      return wrap({ label: 'What to do', reopen: () => drawerOpenPlan(s, subject, { back: previous }) });
    }
    case 'flag': {
      const id = s.flagId;
      return wrap({ label: 'Security flag', reopen: () => drawerOpenFlagDetail(s, id, { back: previous }) });
    }
    case 'family': {
      const key = s.familyKey;
      const fam = family.byKey(key);
      return wrap({ label: fam ? family.label(fam) : 'Process family', reopen: () => drawerOpenFamily(s, key, { back: previous }) });
    }
  }
  return null;
}
