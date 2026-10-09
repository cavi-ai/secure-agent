// Owns the console's stream and refresh timers. Delta handlers still own
// telemetry and rendering; stopping this controller ends all future delivery.
function createConsoleLiveUpdates({ refresh, streamURL, handlers = {}, EventSourceImpl = globalThis.EventSource, timers = globalThis }) {
  let started = false, stopped = false;
  let source = null, slowTimer = null, pollTimer = null;
  let guardTimer = null, flagTimer = null;
  let failures = 0;

  const refreshFull = () => { if (!stopped) refresh(); };
  const stopPolling = () => {
    if (pollTimer !== null) timers.clearInterval(pollTimer);
    pollTimer = null;
  };
  const startPolling = () => {
    if (!stopped && pollTimer === null) pollTimer = timers.setInterval(refreshFull, 2000);
  };
  // Guard decisions coalesce for 400ms from the first frame of a burst.
  const scheduleGuard = () => {
    if (stopped || guardTimer !== null) return;
    guardTimer = timers.setTimeout(() => {
      guardTimer = null;
      if (!stopped) refresh({ slow: false });
    }, 400);
  };
  // Flag patterns reconcile two seconds after the last frame of a burst.
  const scheduleFlag = () => {
    if (stopped) return;
    if (flagTimer !== null) timers.clearTimeout(flagTimer);
    flagTimer = timers.setTimeout(() => {
      flagTimer = null;
      if (!stopped) refresh({ slow: false });
    }, 2000);
  };

  return {
    start() {
      if (started || stopped) return;
      started = true;
      refreshFull();
      if (stopped) return;
      slowTimer = timers.setInterval(refreshFull, 30000);
      if (!EventSourceImpl) { startPolling(); return; }
      source = new EventSourceImpl(streamURL);
      source.onopen = () => {
        if (stopped) return;
        failures = 0;
        stopPolling();
        // Every connection may have missed deltas, including the initial
        // snapshot-to-subscription window. Refresh once the stream is live.
        refreshFull();
      };
      source.onerror = () => {
        if (stopped) return;
        failures++;
        // CONNECTING streams reconnect themselves; fall back only when
        // hard-closed or after more than five consecutive failures.
        if (source.readyState === EventSourceImpl.CLOSED || failures > 5) startPolling();
      };
      for (const kind of ['event', 'flag', 'incident', 'session', 'posture']) {
        source.addEventListener(kind, message => {
          if (stopped) return;
          if (handlers[kind]) handlers[kind](message);
          if (kind === 'flag') scheduleFlag();
        });
      }
      for (const kind of ['guard-prompt', 'guard-resolved']) source.addEventListener(kind, scheduleGuard);
    },
    stop() {
      if (stopped) return;
      stopped = true;
      timers.clearInterval(slowTimer);
      stopPolling();
      timers.clearTimeout(guardTimer);
      timers.clearTimeout(flagTimer);
      if (source) source.close();
    }
  };
}
