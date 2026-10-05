// Validate the containers consumed by console renderers before publishing state.
// Optional fields may be absent (older daemons) or null (Go nil slices), and
// unknown fields remain compatible. This is not a full wire-schema validator.
function isConsoleReport(key, value) {
  const record = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  const rows = v => Array.isArray(v) && v.every(record);
  const optionalRows = (v, name) => v[name] == null || rows(v[name]);
  const optionalArray = (v, name) => v[name] == null || Array.isArray(v[name]);
  const optionalRecord = (v, name) => v[name] == null || record(v[name]);
  const session = v => record(v) && ['processes', 'samples', 'diagnoses'].every(name => optionalRows(v, name))
    && optionalRecord(v, 'control');
  const numericFields = (v, names) => names.every(name => v[name] === undefined
    || (typeof v[name] === 'number' && Number.isFinite(v[name])));

  if (key === 'spend' || key === 'spend card') {
    const costRow = v => record(v) && numericFields(v, ['calls', 'sessions', 'tokens_in', 'tokens_out',
      'cost_usd', 'unpriced_calls', 'unknown_model_calls', 'unpriced_model_calls', 'plan_calls', 'local_calls']);
    return record(value) && costRow(value.total) && optionalRows(value, 'rows')
      && (value.rows || []).every(costRow) && (value.refreshing == null || typeof value.refreshing === 'boolean');
  }
  if (key === 'spend plans') {
    return record(value) && optionalRows(value, 'plans') && (value.plans || []).every(plan =>
      optionalRows(plan, 'windows') && (plan.windows || []).every(window => numericFields(window, ['used_percent', 'window_minutes'])));
  }

  if (['audit', 'firewall sources', 'activity rollup', 'uninspected egress', 'allowlist'].includes(key)) return rows(value);
  if (key === 'fleet') {
    const node = v => record(v) && optionalRows(v, 'agents');
    return Array.isArray(value) ? value.every(node) : node(value);
  }
  if (key === 'resources') {
    return record(value) && optionalRecord(value, 'host') && optionalRecord(value, 'control')
      && optionalRows(value, 'sessions') && (value.sessions || []).every(session)
      && (!value.control || ['pending', 'workspace_overrides', 'interventions'].every(name => optionalRows(value.control, name)));
  }
  if (key === 'resource episodes') {
    return rows(value) && value.every(v => optionalRecord(v, 'host') && optionalRecord(v, 'session')
      && (!v.session || session(v.session)) && optionalRows(v, 'activities') && optionalRows(v, 'correlations')
      && optionalArray(v, 'diagnosis_codes'));
  }
  if (key === 'notification rules') return record(value) && optionalRecord(value, 'overrides') && optionalRows(value, 'scopes');
  if (key === 'recurring egress') {
    return record(value) && optionalRows(value, 'episodes') && (value.episodes || []).every(v =>
      optionalRecord(v, 'observed') && (!v.observed || (optionalRecord(v.observed, 'scope')
        && optionalArray(v.observed, 'intervals') && optionalArray(v.observed, 'session_ids'))));
  }
  if (key === 'expected egress') return record(value) && optionalRows(value, 'rules');

  if (key === 'guard decisions') {
    return rows(value) && value.every(row => typeof row.id === 'string' && row.id.length > 0);
  }
  if (key === 'flags' || key === 'events') return rows(value);
  if (key !== 'snapshot') return value !== null && typeof value === 'object';

  if (!record(value) || !record(value.status) || typeof value.status.uptime !== 'string') return false;
  for (const name of ['flags', 'patterns', 'incidents', 'events', 'suggestions', 'mutes', 'sessions']) {
    if (!optionalRows(value, name)) return false;
  }
  for (const name of ['agents', 'trees', 'collectors']) {
    if (!optionalRows(value.status, name)) return false;
  }
  if (!optionalRecord(value.status, 'coverage')) return false;
  if (value.status.coverage && !optionalRows(value.status.coverage, 'harnesses')) return false;
  if (!optionalRecord(value, 'posture')) return false;
  if (value.posture) {
    for (const name of ['items', 'coverage_items', 'groups']) {
      if (!optionalRows(value.posture, name)) return false;
    }
    if ((value.posture.groups || []).some(group => !optionalRows(group, 'items'))) return false;
  }
  return true;
}
