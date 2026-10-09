// Own the credential and its request lifetime. Replacement never replays a
// mutation, and responses from the previous credential cannot update a view.
function createConsoleAuth({ token = '', fetchImpl = globalThis.fetch, onRejected = () => {} }) {
  let generation = 0;
  const pending = new Set();
  const cancelled = () => new DOMException('Console access paused', 'AbortError');
  const replaceToken = next => {
    generation++;
    token = next || '';
    for (const controller of pending) controller.abort();
    pending.clear();
  };
  const wrap = (response, current, controller, timeoutMs) => new Proxy(response, {
    get(target, key) {
      if (key === 'clone') return () => wrap(target.clone(), current, controller, timeoutMs);
      if (['json', 'text', 'blob', 'arrayBuffer', 'formData'].includes(key)) return async (...args) => {
        if (!current()) throw cancelled();
        // Headers can arrive while the body stalls. Keep parsing bounded too,
        // and abort a body read immediately when its credential is replaced.
        let abort;
        const stopped = new Promise((_, reject) => { abort = () => reject(cancelled()); });
        controller.signal.addEventListener('abort', abort, { once: true });
        pending.add(controller);
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
          if (controller.signal.aborted) throw cancelled();
          const body = await Promise.race([target[key](...args), stopped]);
          if (!current()) throw cancelled();
          return body;
        } finally {
          clearTimeout(timer);
          controller.signal.removeEventListener('abort', abort);
          pending.delete(controller);
        }
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    }
  });
  return {
    replaceToken,
    async fetch(path, opts = {}) {
      if (!token) throw cancelled();
      // Credentials stay on this listener, including when an endpoint redirects.
      if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\\x00-\x20]/.test(path)) throw new Error('Invalid console endpoint');
      const epoch = generation;
      const current = () => epoch === generation && !!token;
      const { timeoutMs = 5000, ...init } = opts;
      const controller = new AbortController();
      pending.add(controller);
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const headers = new Headers(init.headers);
      headers.set('X-SecureAgent-Console-Token', token);
      try {
        const response = await fetchImpl(path, { ...init, headers, signal: controller.signal, redirect: 'error' });
        if (!current() || controller.signal.aborted) throw cancelled();
        if (response.status === 403) {
          // A method/peer permission denial also uses 403. Only the listener's
          // credential challenge ends access; other denials reach their caller.
          let body;
          try { body = await response.clone().json(); } catch { /* non-JSON denial */ }
          if (!current()) throw cancelled();
          if (body?.error === 'console token required') {
            replaceToken('');
            onRejected();
            throw cancelled();
          }
        }
        return wrap(response, current, controller, timeoutMs);
      } finally {
        clearTimeout(timer);
        pending.delete(controller);
      }
    }
  };
}
