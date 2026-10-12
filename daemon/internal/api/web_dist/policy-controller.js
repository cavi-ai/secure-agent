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
    Object.assign(state.policyState, { loading: false, error: '', reports: initial() });
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
