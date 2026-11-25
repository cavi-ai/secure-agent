// Owns the console's stream and refresh timers. Delta handlers still own
// telemetry and rendering; stopping this controller ends all future delivery.
function createConsoleLiveUpdates({ refresh, connectStream, handlers = {}, timers = globalThis }) {
  let started = false, stopped = false;
  let source = null, slowTimer = null, pollTimer = null;
  let guardTimer = null, flagTimer = null;
  let failures = 0;

  const refreshFull = () => { if (!stopped) refresh(); };
  // Polling fallback: the fast set every two seconds (the 30 s slow timer
  // keeps the rest), and never a new cycle over an unfinished one — a newer
  // cycle supersedes the older, so overlapping slow cycles never publish.
  let polling = false;
  const pollFast = () => {
    if (stopped || polling) return;
    polling = true;
    new Promise(resolve => resolve(refresh({ slow: false }))).finally(() => { polling = false; });
  };
  const stopPolling = () => {
    if (pollTimer !== null) timers.clearInterval(pollTimer);
    pollTimer = null;
  };
  const startPolling = () => {
    if (!stopped && pollTimer === null) pollTimer = timers.setInterval(pollFast, 2000);
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
      if (!connectStream) { startPolling(); return; }
      openStream();
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

  function openStream() {
    if (stopped) return;
    source = connectStream();
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
      if (source.closed || failures > 5) startPolling();
    };
    for (const kind of ['event', 'flag', 'incident', 'session', 'posture', 'review']) {
      source.addEventListener(kind, message => {
        if (stopped) return;
        if (handlers[kind]) handlers[kind](message);
        if (kind === 'flag') scheduleFlag();
      });
    }
    for (const kind of ['guard-prompt', 'guard-resolved']) source.addEventListener(kind, scheduleGuard);
  }
}

// The console stream uses the same token header as the other API requests.
// Its server sends LF-delimited frames with JSON on one data line.
function connectConsoleStream(fetchStream, timers = globalThis) {
  const controller = new AbortController();
  const listeners = new Map();
  let retryTimer;
  const source = {
    closed: false,
    addEventListener(kind, handler) { listeners.set(kind, handler); },
    close() {
      source.closed = true;
      controller.abort();
      timers.clearTimeout(retryTimer);
    }
  };

  async function connect() {
    try {
      const response = await fetchStream('/events/stream', {
        headers: { Accept: 'text/event-stream' },
        credentials: 'omit',
        signal: controller.signal
      });
      if (source.closed) return;
      if (!response.ok || !response.body || !response.headers.get('content-type')?.startsWith('text/event-stream')) {
        source.close();
        source.onerror();
        return;
      }
      source.onopen();
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      try {
        while (!source.closed) {
          const { value, done } = await reader.read();
          if (done || source.closed) break;
          buffer += decoder.decode(value, { stream: true });
          let end;
          while (!source.closed && (end = buffer.indexOf('\n\n')) !== -1) {
            const frame = buffer.slice(0, end);
            buffer = buffer.slice(end + 2);
            const fields = /^event: ([^\n]+)\ndata: ([^\n]*)$/.exec(frame);
            if (fields) listeners.get(fields[1])?.({ data: fields[2] });
          }
        }
      } finally {
        void reader.cancel().catch(() => {});
        reader.releaseLock();
      }
    } catch {
      // An interrupted stream is retried without replaying any mutations.
    }
    if (source.closed) return;
    source.onerror();
    retryTimer = timers.setTimeout(connect, 3000);
  }

  void connect();
  return source;
}
