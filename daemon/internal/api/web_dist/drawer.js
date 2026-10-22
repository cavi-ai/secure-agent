// The detail drawer: one slide-over replaces every native <dialog>. A native
// modal's backdrop is painted by the UA from the SYSTEM color-scheme, which
// inverted fg/bg when the page theme was pinned to the other scheme. This
// surface is plain DOM styled only from our tokens, so it always matches the
// page.
//
// The drawer is a single reusable surface: title + body + optional footer
// actions. Only one is open at a time; closing restores focus to the opener.
function createDrawer({ request, toast, markDirty, closeAgentDock, auth, attention, family, plan, flag, session }) {
  const drawer = document.getElementById('drawer');
  const body = document.getElementById('drawer-body');
  const foot = document.getElementById('drawer-foot');
  const title = document.getElementById('drawer-title-text');
  const titleIcon = document.querySelector('#drawer-title use');
  const closeButton = document.getElementById('btn-drawer-close');
  const copyButton = document.getElementById('btn-drawer-copy');
  const head = drawer && drawer.querySelector('.drawer-head');
  const titleEl = document.getElementById('drawer-title');

  let opener = null;
  let openerNeedKey = null;
  let openerAction = null;
  let onClose = null;
  let backTarget = null;
  // Bumped on every open: an async opener writes its body only while its
  // drawer is still the one showing.
  let seq = 0;
  let selection = null;
  let modal = false;
  const inertBefore = new Map();
  // Match the CSS dock breakpoints, including browser viewport emulation.
  const dockMedia = window.matchMedia?.('(min-width: 1180px)');
  const wideDockMedia = window.matchMedia?.('(min-width: 1340px)');

  // The drawer is shared by several views: the incident report (markdown,
  // with a Copy button) and the uninspected-egress drill-down (row actions,
  // no Copy). mode tracks which one is open so action handlers can re-render
  // the right content after a mutation.
  let mode = null; // 'incident' | 'endpoint' | 'file' | 'flag' | 'plan' | 'uninspected' | 'family' | 'policy' | 'review-result' | 'permissions' | null
  let fileDetail = '';
  let planSubject = '';
  let flagId = '';
  let incidentId = '';
  let endpoint = null;
  let familyKey = '';
  let reviewResult = null;
  let rawMarkdown = '';

  function syncMode() {
    if (!drawer || auth.ended()) return;
    const wide = drawer.classList.contains('resource-policy');
    const media = wide ? wideDockMedia : dockMedia;
    const docked = media ? media.matches : (document.documentElement?.clientWidth || window.innerWidth) >= (wide ? 1340 : 1180);
    const isModal = !drawer.hidden && !docked;
    modal = isModal;
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
  window.addEventListener('resize', syncMode);
  dockMedia?.addEventListener('change', syncMode);
  wideDockMedia?.addEventListener('change', syncMode);

  function open({ title: heading, icon, body: html, foot: footHTML, variant, onClose: closeHook, back, attentionOrigin }) {
    if (!drawer) return false;
    closeAgentDock();
    // A drawer opened from inside the open one keeps the original opener, so
    // closing still returns focus to the page.
    if (drawer.hidden) {
      opener = document.activeElement;
      openerNeedKey = opener?.closest?.('[data-need-key]')?.dataset.needKey;
      openerAction = opener?.dataset?.action ? JSON.stringify(Object.entries(opener.dataset).sort(([a], [b]) => a.localeCompare(b))) : null;
    }
    selection = attentionOrigin || back?.attentionOrigin || null;
    onClose = closeHook || null;
    backTarget = back || null;
    seq++;
    if (head && titleEl) paintDrawerBack(head, titleEl, backTarget);
    title.textContent = heading || 'Details';
    if (icon && titleIcon) titleIcon.setAttribute('href', '#i-' + icon);
    body.innerHTML = html || '';
    foot.innerHTML = footHTML || '';
    foot.hidden = !footHTML;
    drawer.className = 'drawer' + (variant ? ' ' + variant : '');
    drawer.hidden = false;
    syncMode();
    if (modal || back?.sessionReturn) closeButton?.focus({ preventScroll: true });
    // Reserve room so the panel docks beside the content instead of covering
    // it — this is an inspector, not a modal.
    const app = document.querySelector('.app');
    if (app) {
      app.classList.add('drawer-open');
      app.classList.toggle('drawer-wide', !!variant);
    }
    return true;
  }

  function close() {
    if (!drawer || drawer.hidden) return;
    const inspectedKey = selection?.key;
    drawer.hidden = true;
    seq++;
    selection = null;
    attention.bumpGeneration();
    syncMode();
    body.innerHTML = '';
    foot.innerHTML = '';
    foot.hidden = true;
    backTarget = null;
    if (head && titleEl) paintDrawerBack(head, titleEl, null);
    const app = document.querySelector('.app');
    if (app) app.classList.remove('drawer-open', 'drawer-wide');
    const fn = onClose;
    onClose = null;
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
    opener = null;
    openerNeedKey = openerAction = null;
    if (fn) fn();
  }

  if (closeButton) closeButton.addEventListener('click', close);
  if (drawer) {
    document.addEventListener('keydown', (e) => {
      if (auth.ended()) return;
      const confirmLayer = document.getElementById('confirm-layer');
      if (e.key === 'Escape' && drawer && !drawer.hidden && (!confirmLayer || confirmLayer.hidden)) close();
      if (e.key === 'Tab' && modal && !drawer.hidden && (!confirmLayer || confirmLayer.hidden)) {
        const controls = Array.from(drawer.querySelectorAll('button, input, select, textarea, a[href], summary, [tabindex="0"]')).filter(el => !el.disabled && !el.hidden && el.getClientRects().length);
        const first = controls[0], last = controls[controls.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
      }
    });
  }
  if (copyButton) {
    copyButton.addEventListener('click', async () => {
      if (!rawMarkdown) return;
      try {
        await navigator.clipboard.writeText(rawMarkdown);
        toast('Incident report copied to clipboard!', 'success');
      } catch (err) {
        toast('Failed to copy report: ' + err, 'danger');
      }
    });
  }

  function setCopyVisible(visible) {
    if (copyButton) copyButton.hidden = !visible;
  }

  function openReviewResult(result) {
    if (!result || auth.ended()) return;
    mode = 'review-result';
    reviewResult = result;
    open({ title: reviewResultLabel(result.receipt), icon: 'shield',
      body: reviewResultHTML(result, true), foot: '', onClose: () => {
        if (mode === 'review-result') { mode = null; reviewResult = null; }
      } });
  }

  async function openIncidentReport(id, { back } = {}) {
    if (!drawer) return;
    mode = 'incident';
    incidentId = id;
    setCopyVisible(true);
    open({
      title: `Incident report — ${id}`,
      icon: 'doc',
      body: `<div class="loading-spinner">Fetching incident report…</div>`,
      onClose: () => { mode = null; },
      back,
    });
    const mine = seq;

    try {
      const url = `/incidents?id=${encodeURIComponent(id)}`;
      const [res, detail] = await Promise.all([request(url + '&format=markdown'), request(url)]);
      if (mine !== seq) return;
      if (res.ok && detail.ok) {
        const [text, report] = await Promise.all([res.text(), detail.json()]);
        if (mine !== seq) return;
        rawMarkdown = text;
        id = report.incident && report.incident.id || id;
        incidentId = id;
        body.innerHTML = incidentReportHTML(id, report.workflow, text, report.incident && report.incident.remediation);
        plan.load('incident:' + id);
      } else {
        const message = res.status === 404 || detail.status === 404
          ? 'This incident report is no longer available. Its source may have expired; the retained session summary does not replace the report.'
          : 'Failed to load the incident report.';
        body.innerHTML = `<div class="empty" role="status"><svg class="icon"><use href="#i-doc"/></svg><span>${message}</span></div>`;
      }
    } catch (err) {
      if (mine !== seq) return;
      body.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Error: ${escapeHTML(err.message)}</span></div>`;
    }
  }

  // Endpoint detail: "what IS this address?" The Evidence action opens this so
  // an unknown IPv6 is explained (owner org, PTR name, which agents/sessions
  // reached it, recent connections) instead of being a bare address that looks
  // safe to block.
  async function openEndpointDetail(host, agent, { back } = {}) {
    if (!drawer) return;
    mode = 'endpoint';
    endpoint = { host, agent };
    setCopyVisible(false);
    open({
      title: 'Endpoint detail',
      icon: 'globe',
      onClose: () => { mode = null; },
      back,
    });
    const mine = seq;
    body.innerHTML = `<div class="loading-spinner">Identifying ${escapeHTML(host)}…</div>`;
    try {
      const res = await request(`/egress/endpoint?host=${encodeURIComponent(host)}`);
      if (!res.ok) throw new Error((await res.text()).trim() || 'lookup failed');
      const detail = await res.json();
      if (mine !== seq) return;
      body.innerHTML = endpointDetailHTML(detail, agent);
    } catch (err) {
      if (mine !== seq) return;
      body.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-globe"/></svg><span>Could not identify this endpoint: ${escapeHTML(err.message || err)}</span></div>`;
    }
  }

  // File detail: an evidence path opens what the daemon knows about the file —
  // facts, the masked excerpt around each secret, findings and agent access —
  // with Reveal in Finder and Open in editor.
  async function openFileDetail(path, { back } = {}) {
    if (!drawer) return;
    mode = 'file';
    fileDetail = path;
    setCopyVisible(false);
    open({
      title: 'File',
      icon: 'doc',
      onClose: () => { mode = null; },
      back,
    });
    const mine = seq;
    body.innerHTML = `<div class="loading-spinner">Reading ${escapeHTML(path)}…</div>`;
    try {
      const res = await request(`/files/detail?path=${encodeURIComponent(path)}`);
      if (!res.ok) throw new Error((await res.text()).trim() || 'lookup failed');
      const detail = await res.json();
      if (mine !== seq) return;
      body.innerHTML = fileDetailHTML(detail) + planSlotHTML('file:' + path);
      plan.load('file:' + path);
    } catch (err) {
      if (mine !== seq) return;
      body.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-doc"/></svg><span>Could not read this file: ${escapeHTML(err.message || err)}</span></div>`;
    }
  }

  function openPlanDrawer(subject, { back } = {}) {
    if (!drawer) return;
    mode = 'plan';
    planSubject = subject;
    setCopyVisible(false);
    open({ title: 'What to do', icon: 'doc', onClose: () => { mode = null; }, back });
    body.innerHTML = `<div class="plan-slot" data-plan-subject="${escapeHTML(subject)}"><div class="loading-spinner">Loading the playbook…</div></div>`;
    plan.load(subject);
  }

  async function openFlagDetail(id, { back } = {}) {
    if (!drawer) return;
    mode = 'flag';
    flagId = id;
    setCopyVisible(false);
    open({ title: 'Security flag', icon: 'alert', body: '<div class="loading-spinner">Loading flag evidence…</div>',
      onClose: () => { if (mode === 'flag') mode = null; flagId = ''; }, back });
    const mine = seq;
    const summary = flag.summary?.(id);
    let missing = false;
    try {
      const res = await request(`/flags/${encodeURIComponent(id)}/explain`);
      missing = res.status === 404;
      if (missing) throw new Error('Finding evidence is no longer available. Its source may have expired; the retained session summary does not replace the evidence.');
      if (!res.ok) throw new Error((await res.text()).trim() || 'flag unavailable');
      const f = await res.json();
      if (mine !== seq) return;
      // The drawer can open a flag outside the current telemetry window. Its
      // served actions must still be available to the click handler now.
      flag.cache(f);
      const subject = 'flag:' + f.id;
      const evidence = (f.evidence || []).map(ev => `<li>${escapeHTML(typeof ev === 'string' ? ev : ev.text || (ev.sub ? `${ev.label || ''} (${ev.sub})` : ev.label || ''))}</li>`).join('');
      const advisor = f.advisor ? `<p><b>Advisor:</b> ${escapeHTML(f.advisor.assessment || 'unrated')} · ${escapeHTML(f.advisor.rationale || '')}</p>` : '';
      const reading = explainLines(f);
      title.textContent = f.title || ruleTitle(f.rule);
      body.innerHTML = `<div class="panel-body flag-inspector">
      <p>${escapeHTML(f.title || ruleTitle(f.rule))} · severity ${Number(f.severity) || 0} · ${escapeHTML(f.agent || 'unknown agent')}</p>
      <dl class="finding-facts"><dt>Raised</dt><dd>${escapeHTML(new Date(f.ts).toLocaleString())}</dd><dt>Process</dt><dd>PID ${Number(f.pid) || 0}</dd>
        <dt>Session</dt><dd>${escapeHTML(f.session_id || 'unknown')}</dd><dt>Workspace</dt><dd>${escapeHTML(f.workspace || 'unknown')}</dd><dt>Flag ID</dt><dd>${escapeHTML(f.id)}</dd></dl>
      ${reading ? `<p class="finding-what">${escapeHTML(reading.what || '')}</p>${factChipsHTML(f, '')}<p class="finding-verdict">${escapeHTML(reading.verdict || '')}</p>` : ''}
      ${f.explain?.assessment ? assessmentHTML(f.explain.assessment) : advisor}<h4>Recorded evidence</h4>${evidence ? `<ul class="plan-list">${evidence}</ul>` : '<p>No evidence rows were recorded for this flag.</p>'}
      <div class="flag-actions-row">${f.explain
        ? explainActionsHTML(f, flag.advisorEnabled() ? [{ label: 'Re-run advisor', attrs: `data-action="retriage" data-id="${escapeHTML(f.id)}"` }] : [])
        : `<button type="button" class="btn btn-ghost btn-sm" data-action="dismiss-flag" data-id="${escapeHTML(f.id)}">Dismiss flag</button>`}</div>
      <h4>What to do</h4><div class="plan-slot" data-plan-subject="${escapeHTML(subject)}"><div class="loading-spinner">Loading the playbook…</div></div>
    </div>`;
      plan.load(subject);
    } catch (err) {
      if (mine !== seq) return;
      title.textContent = summary?.title || 'Security flag';
      const facts = [['Flag ID', id], ['Rule', summary?.rule], ['Session', summary?.session_id], ['Workspace', summary?.group?.workspace]].filter(([, value]) => value);
      body.innerHTML = `<div class="panel-body flag-inspector">
        <h3>${missing ? 'Evidence unavailable' : 'Evidence could not be loaded'}</h3>
        ${summary ? `<p>${escapeHTML(summary.detail || summary.title)}</p><p>This is the queued summary, not the source evidence.</p>` : ''}
        <p role="status">${escapeHTML(err.message || err)}</p>
        <dl class="finding-facts">${facts.map(([label, value]) => `<dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd>`).join('')}</dl>
        ${summary || !missing ? `<div class="flag-actions-row">
          <button type="button" class="btn btn-ghost btn-sm" data-action="open-flag" data-id="${escapeHTML(id)}">Retry evidence</button>
          <button type="button" class="btn btn-ghost btn-sm" data-action="refresh-finding-queue">Refresh queue</button>
          ${!missing && summary ? `<button type="button" class="btn btn-ghost btn-sm" data-action="dismiss-flag" data-id="${escapeHTML(id)}">Dismiss flag</button>` : ''}
        </div>` : ''}
        <p>${missing ? (summary ? 'Refresh the queue to reconcile this missing record.' : 'The retained history does not replace the missing source evidence.') : 'Dismissing marks the flag reviewed. The rule keeps watching.'}</p>
      </div>`;
    }
  }

  function fillUninspectedBody() {
    fillUninspected(body);
  }

  function openUninspected({ back } = {}) {
    if (!drawer) return;
    mode = 'uninspected';
    setCopyVisible(false);
    open({
      title: 'Uninspected egress — last 24h',
      icon: 'globe',
      onClose: () => { mode = null; },
      back,
    });
    fillUninspectedBody();
  }

  function refillUninspectedDrawer() {
    if (mode === 'uninspected' && drawer && !drawer.hidden) fillUninspectedBody();
  }
  function refillUninspected() {
    markDirty('endpoints');
    refillUninspectedDrawer();
  }

  // Family drawer: View family on the Resources board opens the docked
  // inspector for one process family — no tab switch. The 30s reconcile
  // refills it in place (fetchTelemetry); the process table's Show more
  // state lives in expandedLists. Open in Events is the way out to the full
  // timeline.
  function openFamilyDrawer(key, { back } = {}) {
    const fam = family.byKey(key);
    if (!drawer || !fam) return;
    // View family on the family already showing keeps its own way back.
    if (mode === 'family' && familyKey === key && !drawer.hidden) back = backTarget;
    mode = 'family';
    familyKey = key;
    family.select(key);
    setCopyVisible(false);
    open({
      title: family.label(fam),
      icon: 'activity',
      onClose: () => { mode = null; familyKey = ''; },
      back,
    });
    foot._saFoot = undefined;
    fillFamily();
  }

  function fillFamily() {
    if (mode !== 'family' || !drawer || drawer.hidden) return;
    const fam = family.byKey(familyKey);
    if (!fam) {
      body.innerHTML = `<div class="empty"><svg class="icon"><use href="#i-activity"/></svg><span>This family is no longer running.</span></div>`;
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

  function sessionBack(el) {
    const st = session.capture(el);
    return st ? { label: 'session', sessionReturn: st, reopen: () => session.restore(st) } : null;
  }

  // The open drawer as a way back to it. Reopening refreshes live evidence
  // readers; saved results retain the evidence belonging to their decision.
  // The policy editor has no back target because reopening would drop its draft.
  function back() {
    if (!drawer || drawer.hidden) return null;
    const previous = backTarget || undefined;
    const wrap = target => ({ ...target, sessionReturn: previous?.sessionReturn, attentionOrigin: selection || previous?.attentionOrigin });
    switch (mode) {
      case 'review-result': {
        const result = reviewResult;
        const generation = auth.generation();
        return result ? wrap({ label: 'Review result', reopen: () => {
          if (generation === auth.generation()) openReviewResult(result);
        } }) : null;
      }
      case 'attention': {
        const key = selection?.key;
        return wrap({ label: 'Needs you', reopen: () => attention.select(key) });
      }
      case 'uninspected':
        return wrap({ label: 'Uninspected egress', reopen: () => openUninspected({ back: previous }) });
      case 'endpoint': {
        const { host, agent } = endpoint;
        return wrap({ label: 'Endpoint detail', reopen: () => openEndpointDetail(host, agent, { back: previous }) });
      }
      case 'incident': {
        const id = incidentId;
        return wrap({ label: 'Incident report', reopen: () => openIncidentReport(id, { back: previous }) });
      }
      case 'file': {
        const p = fileDetail;
        return wrap({ label: 'File', reopen: () => openFileDetail(p, { back: previous }) });
      }
      case 'plan': {
        const s = planSubject;
        return wrap({ label: 'What to do', reopen: () => openPlanDrawer(s, { back: previous }) });
      }
      case 'flag': {
        const id = flagId;
        return wrap({ label: 'Security flag', reopen: () => openFlagDetail(id, { back: previous }) });
      }
      case 'family': {
        const key = familyKey;
        const fam = family.byKey(key);
        return wrap({ label: fam ? family.label(fam) : 'Process family', reopen: () => openFamilyDrawer(key, { back: previous }) });
      }
    }
    return null;
  }

  return {
    root: drawer, body, foot, title, closeButton,
    open, close, back, sessionBack, setCopyVisible, syncMode,
    openReviewResult, openIncidentReport, openEndpointDetail, openFileDetail,
    openPlanDrawer, openFlagDetail, openUninspected, openFamilyDrawer,
    refillUninspected, refillUninspectedDrawer, fillFamily,
    isFlagOpen: id => mode === 'flag' && flagId === id && !!drawer && !drawer.hidden,
    isIncidentOpen: id => mode === 'incident' && incidentId === id,
    mode: () => mode,
    setMode: next => { mode = next; },
    seq: () => seq,
    selection: () => selection,
    clearSelection: () => { selection = null; },
    returnTarget: () => backTarget,
    afterClose: fn => {
      const previous = onClose;
      onClose = () => {
        if (previous) previous();
        fn();
      };
    },
    reviewResult: () => reviewResult,
    setReviewResult: next => { reviewResult = next; }
  };
}
