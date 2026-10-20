// Observations belong to durable sessions. Process detections without that
// identity remain inspectable, but never borrow another session's evidence.
function monitoringModel(data, query = '', health = {}) {
  const coverage = data.status?.coverage;
  const source = coverage && coverage.sessions == null && data.status.active_agents === 0 ? [] : coverage?.sessions;
  const available = Array.isArray(source) && source.every(validSessionCoverage);
  const stale = !!health.error || coverage?.sessions_stale === true;
  const sessions = new Map((data.sessions || []).map(s => [s.id, s]));
  const rows = (available ? source : []).map(item => {
    const id = item.session_id?.trim() ? item.session_id : '';
    const session = id ? sessions.get(id) || null : null;
    const workspace = item.workspace?.trim() || '';
    const title = session?.repo || (workspace && workspace !== '/' ? workspace.split('/').filter(Boolean).pop() : '') || 'Workspace not identified';
    return { ...item, id, session, title, key: id ? 'session:' + id : 'process:' + item.root_pid };
  });
  const matches = row => matchesSearch(String(query).trim().toLowerCase(), row.title, row.workspace,
    row.harness, harnessMeta(row.harness).label, row.id, row.root_pid, row.session?.branch);
  return { available, stale, truncated: coverage?.sessions_truncated === true, rows,
    linkedCount: rows.filter(r => r.id).length, unlinkedCount: rows.filter(r => !r.id).length,
    linked: rows.filter(r => r.id && matches(r)), unlinked: rows.filter(r => !r.id && matches(r)),
    issues: data.posture?.coverage_items || [], historyIncomplete: data.status?.es_service?.losing === true
      || (data.posture?.coverage_items || []).some(item => ['event_loss', 'storage_loss', 'hook_evidence_gap'].includes(item.kind)), health };
}

function monitoringSelection(model, key) {
  return key === null ? model.rows.find(row => row.id) || null : model.rows.find(row => row.key === key) || null;
}

function monitoringPath(path = {}, key, stale = false) {
  if (stale || path.state === 'stale') return { label: 'Last-known observation', tone: 'neutral', detail: 'Refresh before relying on current coverage.' };
  const neutral = (label, detail) => ({ label, detail, tone: 'neutral' });
  if (path.state === 'unsupported' || path.supported === false) return neutral('Not supported', 'This source does not support this observation path.');
  if (path.state === 'observed') return { label: 'Observed', tone: 'observed', detail: {
    guard: 'A guard hook outcome or decision was recorded for this session.',
    trace: 'Tool, turn, or model activity was attributed to this session.',
    payload: 'An inspection finding was attributed to this session.',
  }[key] };
  if (path.state === 'not-observed') return key === 'payload'
    ? neutral('No linked evidence', 'No session-linked inspection finding was recorded. Machine-wide traffic is separate.')
    : neutral('No recent activity', key === 'trace' ? 'No recent activity was recorded. An idle session can be quiet.' : 'No recent guard invocation was recorded for this session.');
  if (path.state === 'unattributed') return neutral('Session not linked', 'No durable session matches this process and its start time.');
  if (path.state === 'off') return neutral('Inspection off', 'Traffic inspection is off. Historical observations do not establish current inspection.');
  return neutral('Unknown', 'This source did not provide a recognized observation state.');
}

function monitoringStateHTML(state) {
  return `<span class="monitoring-state ${state.tone}"><span aria-hidden="true"></span>${escapeHTML(state.label)}</span>`;
}

function monitoringRowHTML(row, selected, stale) {
  const state = monitoringPath(row.trace, 'trace', stale);
  return `<button type="button" class="monitoring-row" data-monitoring-key="${escapeHTML(row.key)}" aria-pressed="${row.key === selected}" aria-controls="monitoring-detail">
    ${harnessChipHTML(row.harness)}<span class="monitoring-row-name"><strong title="${escapeHTML(row.title)}">${escapeHTML(row.title)}</strong><span>${escapeHTML(harnessMeta(row.harness).label)}${row.id ? '' : ` · Process ${row.root_pid}`}</span></span>
    ${monitoringStateHTML(row.id ? state : { label: 'Not linked', tone: 'neutral' })}</button>`;
}

function monitoringDetailHTML(row, model) {
  if (!row) return `<div class="monitoring-empty"><h2>${model.rows.length ? 'Choose a session or process' : model.available ? 'No sessions detected' : 'Session observations unavailable'}</h2>
    <p>${model.available ? 'Select an item to review its own observations and identity.' : 'Refresh to check whether the daemon can provide session observations.'}</p></div>`;
  const paths = [['guard', 'File guard', 'shield'], ['trace', 'Recorded activity', 'activity'], ['payload', 'Traffic inspection', 'globe']];
  const identity = row.id ? 'Session linked' : 'Session not linked';
  return `<header class="monitoring-detail-heading">${harnessChipHTML(row.harness)}<div><h2>${escapeHTML(row.title)}</h2><p>${escapeHTML(harnessMeta(row.harness).label)}<span class="monitoring-identity-state">${escapeHTML(identity)}</span></p></div></header>
    ${!row.id ? '<p class="monitoring-unlinked-note">This is a detected process, not an identified session. Its working directory may belong to a plugin or helper. Session-specific evidence cannot be credited until identity is resolved.</p>' : ''}
    <div class="monitoring-paths">${paths.map(([key, title, icon]) => {
      const source = row[key] || {};
      const path = !row.id && source.supported !== false && source.state !== 'off'
        ? { ...source, state: 'unattributed', last_seen: '' } : source;
      const state = monitoringPath(path, key, model.stale);
      return `<article class="monitoring-path" data-monitoring-path="${key}"><svg class="icon" aria-hidden="true"><use href="#i-${icon}"/></svg><h3>${title}</h3><div>${monitoringStateHTML(state)}<p>${escapeHTML(state.detail || '')}</p>${path.last_seen ? `<time datetime="${escapeHTML(path.last_seen)}">Last observed ${escapeHTML(new Date(path.last_seen).toLocaleString())}</time>` : ''}</div></article>`;
    }).join('')}</div>
    <p class="monitoring-caveat">An observation does not prove every tool call is guarded. Machine-wide traffic does not establish this session’s inspection.</p>
    ${row.id ? `<button type="button" id="monitoring-open" class="btn btn-primary monitoring-open" data-monitoring-action="open"${model.stale ? ' disabled' : ''}>Open session evidence<svg class="icon" aria-hidden="true"><use href="#i-arrow"/></svg></button>${model.stale ? '<p class="monitoring-muted">Refresh observations before opening current session evidence.</p>' : ''}` : ''}
    <details class="monitoring-identity" id="monitoring-identity"><summary id="monitoring-identity-summary">Identity and technical details</summary><dl>
      ${[['Session', row.id || 'Not identified'], ['Harness', row.harness], ['Workspace', row.workspace && row.workspace !== '/' ? row.workspace : 'Not identified'], ['Root process', String(row.root_pid)], ['Attribution', row.identity_basis || 'unresolved'], ['Branch', row.session?.branch || 'Not recorded']].map(([name, value]) => `<div><dt>${name}</dt><dd>${escapeHTML(value)}</dd></div>`).join('')}
      </dl><details id="monitoring-source"><summary id="monitoring-source-summary">Source observation details</summary>${paths.map(([key, title]) => `<p><strong>${title}</strong> ${escapeHTML(row[key]?.detail || 'No detail provided.')}</p>`).join('')}</details></details>`;
}

function createMonitoringController({ root, data, health, openSession, retry, openTraffic }) {
  let selected = null, query = '', current = null, issuesOpen = false;
  const rendered = new Map();
  const element = id => root?.querySelector('#' + id);
  const html = (id, value) => {
    if (rendered.get(id) === value) return;
    const target = element(id);
    if (!target) return;
    const focused = document.activeElement?.closest('[data-monitoring-key]')?.dataset.monitoringKey;
    const focusedId = target.contains(document.activeElement) ? document.activeElement.id : '';
    const expanded = id === 'monitoring-detail' ? [...target.querySelectorAll('details[open]')].map(details => details.id) : [];
    target.innerHTML = value;
    rendered.set(id, value);
    for (const detailsId of expanded) { const details = element(detailsId); if (details) details.open = true; }
    if (focusedId) element(focusedId)?.focus({ preventScroll: true });
    if (focused) [...target.querySelectorAll('[data-monitoring-key]')].find(el => el.dataset.monitoringKey === focused)?.focus({ preventScroll: true });
  };
  function render() {
    if (!root) return;
    current = monitoringModel(data(), query, health());
    const row = monitoringSelection(current, selected);
    if (selected === null && row) selected = row.key;
    const incomplete = current.historyIncomplete;
    const warning = current.stale || !current.available || current.issues.length > 0;
    const title = current.stale ? 'Observations are stale' : !current.available ? 'Session observations unavailable'
      : incomplete ? 'Monitoring history is incomplete' : current.issues.length ? 'Monitoring needs attention' : 'Session observations';
    html('monitoring-notice', `<div class="monitoring-notice${warning ? ' warning' : ''}" role="status"><svg class="icon" aria-hidden="true"><use href="#i-${warning ? 'alert' : 'activity'}"/></svg><div><strong>${title}</strong><p>${current.stale ? 'Showing last-known data. Refresh before relying on current coverage.' : current.issues.length ? escapeHTML(current.issues.slice(0, 2).map(item => item.title).join(' · ')) : current.available ? 'Observations describe recorded activity, not a guarantee of protection.' : 'The daemon has not provided a current per-session report.'}</p></div><button type="button" class="link-btn" data-monitoring-action="${current.stale || !current.available ? 'retry' : 'issues'}"${!warning ? ' hidden' : ''}>${current.stale || !current.available ? 'Retry' : 'Review issues'}</button></div>`);
    element('monitoring-issues').hidden = !current.issues.length || !issuesOpen;
    html('monitoring-issue-list', current.issues.map(item => `<li><strong>${escapeHTML(item.title)}</strong><p>${escapeHTML(item.detail || '')}</p>${item.kind === 'uninspected_egress' ? '<button type="button" class="link-btn" data-monitoring-action="traffic">Review machine-wide traffic</button>' : ''}</li>`).join(''));
    element('monitoring-count').textContent = `Linked sessions · ${current.linkedCount}${current.stale ? ' · last known' : ''}`;
    html('monitoring-sessions', current.linked.map(item => monitoringRowHTML(item, selected, current.stale)).join('') || `<p class="monitoring-muted">${query ? 'No linked sessions match your search.' : 'No running session has been linked yet.'}</p>`);
    element('monitoring-other-count').textContent = `Other detections · ${current.unlinkedCount} not linked`;
    html('monitoring-other-list', current.unlinked.map(item => monitoringRowHTML(item, selected, current.stale)).join('') || '<p class="monitoring-muted">No other detections match.</p>');
    element('monitoring-other').hidden = current.unlinkedCount === 0;
    element('monitoring-truncated').hidden = !current.truncated;
    html('monitoring-detail', monitoringDetailHTML(row, current));
  }
  root?.addEventListener('input', event => {
    if (event.target.id !== 'monitoring-search') return;
    query = event.target.value;
    render();
  });
  root?.addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button || !root.contains(button)) return;
    if (button.dataset.monitoringKey) {
      selected = button.dataset.monitoringKey;
      rendered.delete('monitoring-detail');
      element('monitoring-detail')?.querySelectorAll('details').forEach(details => { details.open = false; });
      render();
      if (window.matchMedia('(max-width: 800px)').matches) {
        const sidebar = document.querySelector('.sidebar');
        const inset = sidebar && getComputedStyle(sidebar).position === 'sticky' ? sidebar.getBoundingClientRect().height : 0;
        window.scrollTo({ top: Math.max(0, element('monitoring-detail').getBoundingClientRect().top + window.scrollY - inset - 16), behavior: 'auto' });
      }
    }
    const action = button.dataset.monitoringAction;
    if (action === 'retry') retry();
    if (action === 'issues') {
      const details = element('monitoring-issues');
      issuesOpen = !issuesOpen;
      details.hidden = !issuesOpen;
      details.open = issuesOpen;
      if (issuesOpen) details.querySelector('summary').focus();
    }
    if (action === 'traffic') openTraffic();
    if (action === 'open') {
      const latest = monitoringModel(data(), query, health());
      const row = monitoringSelection(latest, selected);
      if (row?.id && !latest.stale) openSession(row.id);
    }
  });
  return { render };
}
