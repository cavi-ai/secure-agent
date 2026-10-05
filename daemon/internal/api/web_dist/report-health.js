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
