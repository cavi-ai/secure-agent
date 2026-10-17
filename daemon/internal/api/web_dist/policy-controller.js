// Read each policy list independently; retained records never become current
// merely because a different endpoint succeeds.
function createConsolePolicy({ state, actions }) {
  const reports = [
    { key: 'guardRules', kind: 'guard', path: '/guard/rules', label: 'Guard decisions', fields: ['agent', 'rule_id', 'decision'] },
    { key: 'pathAllows', kind: 'path', path: '/guard/path-allow', label: 'File exceptions', fields: ['agent', 'rule_id', 'path'] },
    { key: 'mutes', kind: 'mute', path: '/mute', label: 'Muted flag classes', fields: ['rule', 'host'] },
    { key: 'expected', kind: 'expected', path: '/expected', label: 'Expected secret reads', fields: ['key', 'agent', 'reader', 'path', 'dest'] },
    { key: 'scopes', kind: 'scope', path: '/decision-scopes', label: 'Scoped permissions' },
  ];
  let generation = 0;
  const now = actions.now || Date.now;
  const initial = () => Object.fromEntries(reports.map(r => [r.key, { kind: r.kind, label: r.label, loading: false, error: '', lastSuccessAt: null, version: 0 }]));
  state.policyState.reports = initial();

  function validRows(report, rows) {
    if (!Array.isArray(rows)) return false;
    if (report.kind === 'expected') return actions.validExpectedPatterns(rows);
    if (report.kind === 'scope') {
      try { actions.decisionPermissionRows({ ids: [] }, rows); return true; } catch { return false; }
    }
    const valid = rows.every(row => row && report.fields.every(field => typeof row[field] === 'string' && row[field]) &&
      ['agent', 'title', 'source', 'created_at', 'scope'].every(field => row[field] == null || typeof row[field] === 'string') &&
      (report.kind !== 'guard' || ['allow', 'deny'].includes(row.decision)) &&
      (report.kind !== 'expected' || row.scope == null || row.scope === '' || row.scope === 'file'));
    return valid && (report.kind !== 'expected' || new Set(rows.map(row => row.key)).size === rows.length);
  }

  function reset() {
    generation++;
    for (const report of reports) state.policyState[report.key] = null;
    state.policyState.scopeMutations?.clear();
    state.policyState.expectedMutations?.clear();
    state.policyState.expectedRemoval = null;
    Object.assign(state.policyState, { loading: false, error: '', reports: initial(), scopeWorkspace: 'all', scopeStatus: 'all' });
    actions.markDirty('policy');
  }

  function invalidate(kind) {
    const report = reports.find(r => r.kind === kind);
    if (!report) return;
    const status = state.policyState.reports[report.key];
    status.version++;
    status.loading = false;
    state.policyState.loading = Object.values(state.policyState.reports).some(r => r.loading);
  }

  function ready(kind) {
    const report = reports.find(r => r.kind === kind);
    const status = report && state.policyState.reports[report.key];
    return !!status && !state.sessionEnded && !status.loading && !status.error && state.policyState[report.key] !== null;
  }

  async function load(kind) {
    if (state.sessionEnded) return;
    const selected = reports.filter(r => (!kind || r.kind === kind) && !state.policyState.reports[r.key].loading);
    if (!selected.length) return;
    const auth = state.handoffGeneration, epoch = generation;
    const current = (report, version) => !state.sessionEnded && auth === state.handoffGeneration && epoch === generation && state.policyState.reports[report.key].version === version;
    await Promise.all(selected.map(async report => {
      const status = state.policyState.reports[report.key], version = ++status.version;
      status.loading = true;
      state.policyState.loading = true;
      actions.markDirty('policy');
      try {
        const response = await actions.apiFetch(report.path);
        if (!response.ok) throw new Error('Read unavailable');
        const rows = await response.json();
        if (!validRows(report, rows)) throw new Error('Invalid records');
        if (!current(report, version)) return;
        state.policyState[report.key] = rows;
        status.error = '';
        status.lastSuccessAt = now();
        const mutations = report.kind === 'scope' ? state.policyState.scopeMutations
          : report.kind === 'expected' ? state.policyState.expectedMutations : null;
        if (mutations) for (const [key, mutation] of mutations) {
          if (mutation.status === 'unconfirmed') mutations.delete(key);
        }
      } catch (error) {
        if (!current(report, version)) return;
        status.error = error?.message === 'Invalid records' ? 'The daemon returned invalid records.' : 'The list could not be refreshed.';
      } finally {
        if (current(report, version)) {
          status.loading = false;
          state.policyState.loading = Object.values(state.policyState.reports).some(r => r.loading);
          actions.markDirty('policy');
        }
      }
    }));
  }

  return { load, reset, ready, invalidate };
}

// Workspace identity is the exact recorded path; missing identity is never
// assigned to a nearby project. Categories describe saved records, not live access.
function workspacePermissionReview(records, workspace = 'all', status = 'all', mutations) {
  const rows = (records || []).filter(r => workspace === 'all' || (workspace === 'unassigned' ? !r.workspace : 'workspace:' + r.workspace === workspace));
  const groups = [
    { key:'saved', label:'Session & timed permissions', rows:[] },
    { key:'unknown', label:'Status unknown', rows:[] },
    { key:'expired', label:'Expired', rows:[] },
    { key:'revoked', label:'Revoked', rows:[] },
  ];
  for (const r of rows) {
    const label = mutations?.get(r.id)?.status === 'saved' ? 'Revoked' : decisionScopeApplicability(r).label;
    const key = label === 'Revoked' ? 'revoked' : label === 'Expired' ? 'expired'
      : ['Session permission','Timed permission'].includes(label) ? 'saved' : 'unknown';
    groups.find(g => g.key === key).rows.push(r);
  }
  for (const group of groups) group.rows.sort((a,b) => (Date.parse(b.created_at) || 0) - (Date.parse(a.created_at) || 0) || a.id.localeCompare(b.id));
  const shown = groups.filter(g => (status === 'all' || g.key === status) && g.rows.length);
  return { groups:shown, rows:shown.flatMap(g => g.rows) };
}

function permissionWorkspaceOptions(records, selected = 'all') {
  const workspaces = new Set((records || []).map(r => r.workspace).filter(Boolean));
  if (selected.startsWith('workspace:')) workspaces.add(selected.slice(10));
  return [['all','All workspaces'],['unassigned','Workspace not recorded'], ...[...workspaces].sort().map(p => ['workspace:'+p,p])]
    .map(([value,label]) => `<option value="${escapeHTML(value)}"${value === selected ? ' selected' : ''}>${escapeHTML(label)}</option>`).join('');
}

function workspacePermissionsHTML(records, filters, state) {
  const st = state || {}, workspace = filters.workspace || 'all', status = filters.status || 'all';
  if (!records) return policyListHTML('scope', records, {...st,label:'Saved permissions'});
  const review = workspacePermissionReview(records, workspace, status, st.scopeMutations);
  const readAt = Number.isFinite(st.lastSuccessAt) ? localTimestampHTML(st.lastSuccessAt) : 'Unavailable';
  const health = st.error ? '<div class="policy-read-status" role="status"><p>Refresh failed. Showing last known records; current status is unavailable. Revocation is unavailable until a successful refresh.</p><button type="button" class="btn btn-ghost btn-sm" data-action="policy-refresh-report" data-kind="scope">Refresh saved permissions</button></div>'
    : st.loading ? '<p role="status">Refreshing saved permissions… Showing the last successful read.</p>' : '';
  const context = workspace === 'all' ? 'All recorded workspaces' : workspace === 'unassigned' ? 'Workspace not recorded' : workspace.slice(10);
  const feedback = status !== 'all' && status !== 'revoked' ? workspacePermissionReview(records,workspace,'revoked',st.scopeMutations).rows
    .filter(r => st.scopeMutations?.get(r.id)?.status === 'saved')
    .map(r => `<p role="status">Revocation saved for <code>${escapeHTML(r.resource_path)}</code> (permission ${escapeHTML(r.id)}). Other permissions and policies may still apply.</p>`).join('') : '';
  const empty = st.error ? '<p>Matching records are unavailable for the current read.</p>'
    : `<div class="empty"><span>${records.length ? 'No saved permissions match this workspace and status.' : 'No saved permissions recorded in this read.'}${workspace !== 'all' || status !== 'all' ? ' <button type="button" class="link-btn" data-action="permission-filter-clear">Clear filters</button>' : ''}</span></div>`;
  return `<div class="permission-read-context"><p><strong>${escapeHTML(context)}</strong> · ${review.rows.length} of ${records.length} saved records</p><p>Last successful read: ${readAt}</p>${health}${feedback}</div>`
    + (review.groups.length ? review.groups.map(g => `<section class="permission-group" data-permission-status="${g.key}"><h3>${g.label}<span class="badge">${g.rows.length}</span></h3>${policyListHTML('scope',g.rows,{...st,hideNotice:true})}</section>`).join('')
      : empty);
}
