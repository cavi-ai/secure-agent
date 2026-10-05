// Validate the containers consumed by hot renderers before publishing state.
// Optional fields may be absent (older daemons) or null (Go nil slices), and
// unknown fields remain compatible. This is not a full wire-schema validator.
function isConsoleHotReport(key, value) {
  const record = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  const rows = v => Array.isArray(v) && v.every(record);
  const optionalRows = (v, name) => v[name] == null || rows(v[name]);
  const optionalRecord = (v, name) => v[name] == null || record(v[name]);

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
