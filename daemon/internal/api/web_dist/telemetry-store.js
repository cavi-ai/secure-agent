// The telemetry the console was served and the generations that decide which
// in-flight response may still publish into it. Refreshes, the expectation
// inspector and the credential handoff reach the generations only through
// these methods.
const SNAPSHOT_REPORTS = ['patterns', 'routine', 'incidents', 'events', 'posture', 'suggestions', 'mutes', 'sessions'];
const SLOW_LIST_REPORTS = ['fleet', 'audit', 'sources', 'rollup', 'uninspected', 'episodes', 'allowlist'];

function createTelemetryStore(data = {}) {
  let fetchGen = 0, slowGen = 0, expectedEgressGen = 0;
  let lastSnapshotAt = 0, uptimeSec = 0, notifyHash = '';
  return {
    data,
    get lastSnapshotAt() { return lastSnapshotAt; },
    // beginRefresh supersedes every earlier refresh's hot reports and, for a
    // slow refresh, its slow reports and expected-egress read.
    beginRefresh(slow) {
      const gen = ++fetchGen;
      const slowTicket = slow ? ++slowGen : 0;
      const egressTicket = slow ? ++expectedEgressGen : 0;
      return {
        current: () => gen === fetchGen,
        currentSlow: () => !!slow && slowTicket === slowGen,
        ownsExpectedEgress: () => egressTicket === expectedEgressGen
      };
    },
    // beginExpectedEgressRead supersedes every earlier expected-egress read.
    beginExpectedEgressRead() {
      const ticket = ++expectedEgressGen;
      return () => ticket === expectedEgressGen;
    },
    // invalidate makes every refresh in flight obsolete.
    invalidate() { fetchGen++; slowGen++; },
    // applySnapshot publishes a validated snapshot; true when the daemon's
    // uptime went backwards, which means it restarted. A paged review list
    // (keepReviews) is not replaced by the snapshot's first page.
    applySnapshot(snap, { uptime = 0, keepReviews = false } = {}) {
      lastSnapshotAt = Date.now();
      let restarted = false;
      if (snap.status) {
        restarted = uptimeSec > 0 && uptime < uptimeSec - 5;
        uptimeSec = uptime;
        data.status = snap.status;
      }
      if (snap.flags) data.flags = snap.flags.filter(f => !f.acknowledged);
      if (snap.reviews && !keepReviews) data.reviews = snap.reviews;
      for (const key of SNAPSHOT_REPORTS) if (snap[key]) data[key] = snap[key];
      return restarted;
    },
    // applySlowReports publishes the slow reports that arrived; true when the
    // notification config differs from the last one published.
    applySlowReports(reports, ownsExpectedEgress) {
      for (const key of SLOW_LIST_REPORTS) if (reports[key]) data[key] = reports[key];
      if (reports.egressEpisodes) data.egressEpisodes = reports.egressEpisodes.episodes || [];
      if (reports.expectedEgress && ownsExpectedEgress) data.expectedEgress = reports.expectedEgress.rules || [];
      if (!reports.notifyCfg) return false;
      const hash = JSON.stringify(reports.notifyCfg);
      if (hash === notifyHash) return false;
      notifyHash = hash;
      data.notifyCfg = reports.notifyCfg;
      return true;
    }
  };
}
