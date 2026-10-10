// Refresh health is independent of retained report data and render scheduling.
function createConsoleReportHealth({ now = Date.now } = {}) {
  const reports = new Map();
  return {
    reset(key) {
      reports.delete(key);
    },
    success(key) {
      reports.set(key, { lastSuccessAt: now(), error: null });
    },
    failure(key, error) {
      const prior = reports.get(key);
      reports.set(key, { lastSuccessAt: prior ? prior.lastSuccessAt : null, error });
    },
    failures(keys) {
      return keys.flatMap(key => {
        const report = reports.get(key);
        return report && report.error ? [{ key, ...report,
          state: report.lastSuccessAt === null ? 'unavailable' : 'stale' }] : [];
      });
    }
  };
}

function consoleReportHealthText(failures, formatTime = ms => new Date(ms).toLocaleString()) {
  return failures.map(report => {
    const labels = { snapshot: 'Live telemetry', flags: 'Filtered findings', events: 'Filtered events',
      'activity rollup': 'Activity history', 'resource episodes': 'Resource history',
      'uninspected egress': 'Uninspected connections', 'spend card': 'Spend detail' };
    const label = labels[report.key] || report.key[0].toUpperCase() + report.key.slice(1);
    const state = report.state === 'stale'
      ? `Stale — showing data last refreshed at ${formatTime(report.lastSuccessAt)}`
      : 'Unavailable — no successful refresh yet';
    return `${label}: ${state}. ${report.error}; retrying.`;
  }).join(' ');
}

// A quiet posture is meaningful only after a complete snapshot is published.
// Known risks remain actionable even while that snapshot cannot be refreshed.
function consolePosturePresentation(posture, { lastSnapshotAt = 0, error = '' } = {},
  formatTime = ms => new Date(ms).toLocaleString()) {
  const p = posture || {};
  const needs = attentionCount(p);
  const coverage = Number(p.coverage_count) || 0;
  const critical = p.state === 'critical';
  const attention = needs > 0 || coverage > 0 || p.state === 'attention';
  const current = lastSnapshotAt > 0 && !error && p.state === 'all-clear';
  const state = critical ? 'critical' : attention ? 'attention' : current ? 'all-clear' : 'unknown';
  const title = critical ? 'Critical' : attention ? (!needs && coverage ? 'Monitoring needs attention' : 'Needs attention')
    : error ? (lastSnapshotAt ? 'Status stale' : 'Telemetry unavailable')
    : current ? 'No pending decisions' : lastSnapshotAt ? 'Status unavailable' : 'Waiting for telemetry';
  let pill = needs ? `${needs} need${needs === 1 ? 's' : ''} you`
    : critical ? 'Critical observations' : coverage ? 'Monitoring gap' : title;
  if (error && (critical || attention)) pill += ' · refresh failed';
  const health = error ? (lastSnapshotAt
    ? `Status stale — last complete telemetry at ${formatTime(lastSnapshotAt)}. Retained observations may have changed.`
    : 'No complete telemetry snapshot has loaded. Current status and coverage are unavailable.')
    : !lastSnapshotAt ? 'Waiting for a complete telemetry snapshot; known observations remain visible.'
    : !p.state ? 'Current telemetry did not include a posture report.' : '';
  return { state, title, pill, health, retry: !!error, summary: state === 'unknown' ? '' : p.summary || '' };
}
