// DOM test stub: replaces fetch + EventSource with deterministic telemetry so
// the REAL console (index.html + lib.js + app.js + style.css) can be asserted
// end-to-end in headless Chrome. Loaded between lib.js and app.js.
//
// Auto-actions (driven by ?domtest-flags):
//   sessiondemo — after 4s, filter the timeline to session 7f3a9c21…
(() => {
  const now = Date.now();
  const iso = (msAgo) => new Date(now - msAgo).toISOString();

  const data = {
    '/status': {
      running: true,
      version: 'v9.9.9-domtest',
      uptime: '4h 12m 8s',
      active_agents: 3,
      agents: [
        { pid: 5821, name: 'claude', cwd: '/Users/dev/workspace/api-service', ppid: 1, root_pid: 5821, started_at: '2026-09-09T14:00:00Z', last_seen_at: iso(60000), rss_bytes: 120000000 },
        { pid: 5822, name: 'claude', ppid: 5821, root_pid: 5821, started_at: '2026-09-09T14:01:00Z', last_seen_at: iso(120000), rss_bytes: 40000000 },
        { pid: 6033, name: 'cursor', cwd: '/Users/dev/projects/web-app', ppid: 1, root_pid: 6033, started_at: '2026-09-09T15:00:00Z', last_seen_at: iso(3600000), rss_bytes: 89000000, is_orphan: true }
      ],
      proxy_enabled: true,
      proxy_port: 8443,
      uninspected_egress: 2,
      advisor_enabled: true,
      fleet_configured: true,
      unacted_flags_24h: 2,
      advisor_health: { enabled: true, queue_depth: 0, model: 'qwen3:8b' },
      firewall_stats: {
        'anthropic-key':  { type: 'vendor-key', mode: 'monitor', would_block: 5, blocked: 0, legit: 12 },
        'aws-key':        { type: 'cloud-key', mode: 'block',   would_block: 2, blocked: 1, legit: 0 },
        'db-conn-string': { type: 'env-value', mode: 'monitor', would_block: 1, blocked: 0, legit: 0 }
      }
    },
    '/posture': {
      state: 'critical',
      summary: '1 critical flag and 1 open incident need review',
      items: [
        { severity: 3, kind: 'flag', title: 'proxy-secret-leak — cursor sent an anthropic-key to logs.example.com' },
        { severity: 3, kind: 'incident', id: 'inc-20260907-6033-a1b2', title: 'sensitive-read-then-connect — cursor (PID 6033)' },
        { severity: 2, kind: 'uninspected_egress', title: '2 endpoints reached without inspection' },
        { severity: 2, kind: 'collector_down', title: 'File monitoring is off', detail: 'usually missing Full Disk Access — open Setup & Permissions in the menu bar' }
      ]
    },
    '/flags': [
      {
        id: 'flag-1',
        rule: 'proxy-secret-leak', agent: 'cursor', pid: 6033, severity: 3,
        session_id: 'b81d4fae-7dec-11d0-a765-00a0c91e6bf6',
        evidence: ["Local proxy detected security violation 'proxy-secret-leak: anthropic-key' while connecting to logs.example.com:443"],
        advisor: { assessment: 'suspicious', confidence: 0.7, rationale: 'host is not a known vendor; first time this session', suggested_action: 'review once' }
      },
      {
        id: 'flag-2',
        rule: 'sensitive-read-then-connect', agent: 'cursor', pid: 6033, severity: 3,
        session_id: '7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77',
        evidence: [
          'cursor (pid 6033) read ~/.aws/credentials at 2026-09-07T16:04:57Z',
          'then connected to logs.example.com:443 at 2026-09-07T16:05:01Z'
        ],
        advisor: { assessment: 'benign', confidence: 0.8, rationale: 'registry host matches this project\'s normal workflow', suggested_action: 'none' }
      },
      {
        id: 'flag-3',
        rule: 'keychain-access', agent: 'codex', pid: 9012, severity: 1,
        evidence: ['codex (pid 9012) accessed keychain file /Users/dev/Library/Keychains/login.keychain-db at 2026-09-07T15:55:00Z']
      }
    ],
    '/incidents': [
      {
        id: 'inc-20260907-6033-a1b2',
        rule: 'sensitive-read-then-connect', agent: 'cursor', pid: 6033,
        risk: 'CRITICAL',
        summary: 'Agent read ~/.aws/credentials, then opened a connection to an unrecognized host.',
        rotate_list: [{ name: 'AWS_ACCESS_KEY', category: 'cloud' }],
        workflow: { status: 'acknowledged' },
        advisor_narrative: 'Cursor read the AWS credentials file and seconds later connected to an unrecognized host — a classic exfiltration shape. Rotate the key first, then review the session.'
      }
    ],
    '/events': [
      { kind: 9, ts: iso(4000),  pid: 6033, detail: 'proxy-secret-leak: anthropic-key', session_id: 'b81d4fae-7dec-11d0-a765-00a0c91e6bf6' },
      { kind: 8, ts: iso(6000),  pid: 5821, detail: 'Read ~/.aws/credentials', session_id: '7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77' },
      { kind: 5, ts: iso(7000),  pid: 6033, remote_host: 'logs.example.com', remote_port: 443, session_id: '7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77' },
      { kind: 8, ts: iso(21000), pid: 5821, detail: 'Bash → npm install' },
      { kind: 5, ts: iso(29000), pid: 5821, remote_host: 'api.anthropic.com', remote_port: 443 },
      { kind: 9, ts: iso(34000), pid: 5821, detail: 'proxy-scan: POST /v1/messages (clean)' }
    ],
    // REAL /fleet shape: a single node-status OBJECT, not an array. (The old
    // array fixture let the console assume .map was safe — it crashed on the
    // real endpoint and took half the page down with it.)
    '/fleet': {
      hostname: 'ci-runner-02', os: 'darwin', arch: 'arm64', version: 'v9.9.9-domtest',
      running: true, uptime: '4h 12m 8s', active_agents: 3, recent_flags: 2,
      proxy_enabled: true, proxy_port: 8443
    },
    '/audit': [
      { ts: iso(300000), action: 'rule-mode', rule: 'aws-key', from_mode: 'monitor', to_mode: 'block', detail: '' },
      { ts: iso(3600000), action: 'fingerprint-ingest', detail: 'registered 6 secrets from ~/.aws/credentials' }
    ],
    '/firewall/sources': [
      { source: '~/.aws/credentials', origin: 'config' },
      { source: '~/workspace/api-service/.env.production', origin: 'user' }
    ],
    '/allowlist/suggestions': [
      { agent: 'cursor', host: 'registry.npmjs.org', count: 14, assessment: 'benign', confidence: 0.9, rationale: 'npm registry is routine for JS projects' }
    ],
    '/mute': [
      { rule: 'proxy-prompt-injection', host: 'blog.example.com' },
      { rule: 'keychain-security-cli', host: '*' }
    ],
    '/egress/uninspected': [
      { agent: 'cursor', host: 'registry.npmjs.org', count: 14, last_seen: iso(300000), assessment: 'benign', rationale: 'npm registry is routine for JS projects' },
      { agent: 'claude', host: 'statsig.example.com', count: 3, last_seen: iso(900000) }
    ],
    '/notify/rules': {
      default_min_severity: 3,
      overrides: { 'keychain-access': false }
    },
    '/stats/rollup': (() => {
      const pts = [];
      const bucket = (h) => new Date(Math.floor((now - h * 3600000) / 3600000) * 3600000).toISOString().slice(0, 13);
      for (let h = 0; h < 24; h++) {
        pts.push({ bucket: bucket(h), kind: 'event:tool', count: (h * 7) % 9 });
      }
      pts.push({ bucket: bucket(2), kind: 'flag:s3', count: 1 });
      return pts;
    })()
  };

  // ---------- failure-mode simulation ----------
  // These modes reproduce the exact "trouble connecting" regressions:
  //   authfail     — every API call answers 403 (dead/rotated token): the
  //                  console must say "Session expired", NOT "daemon down".
  //   netfail      — every API call throws (daemon/proxy gone): the console
  //                  must say "can't reach the daemon" and keep last state.
  //   requiretoken — the mock validates the console-token header, so the
  //                  token-persistence flow is exercised for real.
  //   tokenseed    — pre-seed sessionStorage (simulates a RELOADED tab: no
  //                  #ct fragment, token must come from storage).
  const MODE = location.search;
  const REQUIRE_TOKEN = MODE.includes('requiretoken');
  if (MODE.includes('tokenseed')) {
    try { sessionStorage.setItem('sa.console-token', 'test-token'); } catch { /* ignored */ }
  }

  // Stateful POST handling: mutations change the fixture so the DOM tests
  // can assert that actions VISIBLY update the lists (the "allow does
  // nothing" / "dismiss does nothing" regressions).
  const handlePost = (p, opts) => {
    let body = {};
    try { body = JSON.parse((opts && opts.body) || '{}'); } catch { /* ignored */ }
    if (p === '/allowlist') {
      data['/allowlist/suggestions'] = data['/allowlist/suggestions'].filter(s => s.host !== body.host);
      data['/egress/uninspected'] = data['/egress/uninspected'].filter(e => e.host !== body.host);
      return { status: 'ok' };
    }
    if (p === '/flags/acknowledge') {
      data['/flags'] = data['/flags'].filter(f => f.id !== body.flag_id);
      return { status: 'ok', acknowledged: true };
    }
    if (p === '/advisor/retriage') {
      // The model "answers" shortly after the request: the flag's verdict
      // changes, which the pending state must pick up and surface.
      setTimeout(() => {
        const f = data['/flags'].find(x => x.id === body.flag_id);
        if (f) {
          f.advisor = { assessment: 'benign', confidence: 0.9, rationale: 're-triage complete: routine vendor traffic', suggested_action: 'none' };
        }
      }, 1200);
      return { status: 'ok', queued: true };
    }
    return { status: 'ok' };
  };

  window.fetch = async (path, opts) => {
    const p = String(path).split('?')[0];
    // Failure modes apply to API paths only (assets are served statically).
    if (MODE.includes('netfail')) {
      throw new TypeError('Failed to fetch');
    }
    const token = (opts && opts.headers && opts.headers['X-SecureAgent-Console-Token']) || '';
    if (MODE.includes('authfail') || (REQUIRE_TOKEN && token !== 'test-token')) {
      return {
        ok: false, status: 403,
        json: async () => ({ error: 'console token required' }),
        text: async () => '{"error":"console token required"}'
      };
    }
    if (opts && opts.method && opts.method !== 'GET') {
      const out = handlePost(p, opts);
      return {
        ok: true, status: 200,
        json: async () => out,
        text: async () => JSON.stringify(out)
      };
    }
    if (p === '/snapshot') {
      const body = {
        status: data['/status'],
        flags: data['/flags'],
        incidents: data['/incidents'],
        events: data['/events'],
        posture: data['/posture'],
        suggestions: data['/allowlist/suggestions'],
        mutes: data['/mute']
      };
      return {
        ok: true, status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body)
      };
    }
    const body = data[p];
    return {
      ok: body !== undefined,
      status: body !== undefined ? 200 : 404,
      json: async () => body,
      text: async () => JSON.stringify(body !== undefined ? body : null)
    };
  };

  // SSE stub: drip live events so liveness paths (sparkline, fresh rows,
  // firewall flash) execute during the virtual-time window.
  window.EventSource = class {
    constructor() {
      this.readyState = 1;
      this._listeners = {};
      setTimeout(() => this.onopen && this.onopen(), 0);
      const drip = [
        ['conn-open', { kind: 5, pid: 5821, remote_host: 'api.anthropic.com', remote_port: 443 }],
        ['proxy-hit', { kind: 9, pid: 5821, detail: 'proxy-scan: POST /v1/messages (clean)' }],
        ['exec',      { kind: 8, pid: 6033, detail: 'Bash → git status' }]
      ];
      let i = 0;
      this._timer = setInterval(() => {
        const [kind, ev] = drip[i % drip.length];
        i++;
        ev.ts = new Date().toISOString();
        data['/events'].unshift({ ...ev });
        (this._listeners[kind] || []).forEach(fn => fn({ data: JSON.stringify(ev) }));
      }, 900);
    }
    addEventListener(kind, fn) { (this._listeners[kind] = this._listeners[kind] || []).push(fn); }
    close() { clearInterval(this._timer); }
  };

  // Auto-action: exercise the session drill-down like a user click would.
  if (location.search.includes('sessiondemo')) {
    setTimeout(() => window.filterTimelineToSession('7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77'), 4000);
  }
  // Auto-action: open the uninspected-egress drill-down modal.
  if (location.search.includes('uninspecteddemo')) {
    setTimeout(() => window.openUninspected(), 4000);
  }
  // Auto-action: open the notification preferences popover.
  if (location.search.includes('notifydemo')) {
    setTimeout(() => document.getElementById('btn-notify').click(), 4000);
  }
  // Auto-action: allow the suggested host — the suggestion must disappear.
  if (location.search.includes('allowdemo')) {
    setTimeout(() => document.querySelector('.fw-suggestion [data-action="allow-host"]').click(), 4000);
  }
  // Auto-action: dismiss the keychain flag — the card must leave the list.
  if (location.search.includes('dismissdemo')) {
    setTimeout(() => document.querySelector('[data-action="dismiss-flag"][data-id="flag-3"]').click(), 4000);
  }
  // Auto-action: re-run the advisor on the first flag — the pending state
  // must show, then the fresh verdict must land and replace the chip.
  if (location.search.includes('retriagedemo')) {
    setTimeout(() => document.querySelector('[data-action="retriage"][data-id="flag-1"]').click(), 4000);
  }
  // Advisor-down variant: the circuit breaker is open — retriage must render
  // as an honest "Advisor offline" state, not a clickable dead button.
  if (location.search.includes('advisordown')) {
    data['/status'].advisor_health = { enabled: true, circuit_open: true, last_error: 'context deadline exceeded', queue_depth: 0, model: 'qwen3:8b' };
  }

  // Auto-action: switch to the Egress tab — panels must hide/show correctly.
  if (location.search.includes('tabdemo')) {
    setTimeout(() => document.querySelector('[data-tab="egress"]').click(), 4000);
  }
})();
