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
    // Durable sessions (the P1 spine) — drives the session-first rail.
    '/sessions': [
      {
        id: 'sess-claude-1', harness: 'claude', workspace: '/Users/dev/workspace/api-service',
        repo: 'api-service', branch: 'main', root_pid: 5821,
        started_at: '2026-09-09T14:00:00Z', last_seen_at: iso(60000),
        status: 'active', confidence: 'hook',
        _timeline: [
          { kind: 12, ts: iso(120000), session_id: 'sess-claude-1', tool: 'Bash', tool_status: 'ok', duration_ms: 31000 },
          { kind: 12, ts: iso(60000), session_id: 'sess-claude-1', tool: 'Read', tool_status: 'error', duration_ms: 400 },
          { kind: 14, ts: iso(90000), session_id: 'sess-claude-1', model: 'claude-sonnet-4-5', tokens_in: 46220, tokens_out: 812, cost_usd: 0.0002 },
          { kind: 5, ts: iso(30000), session_id: 'sess-claude-1', remote_host: 'api.anthropic.com', remote_port: 443 }
        ]
      },
      {
        id: 'sess-cursor-2', harness: 'cursor', workspace: '/Users/dev/projects/web-app',
        repo: '', branch: '', root_pid: 6033,
        started_at: '2026-09-09T15:00:00Z', ended_at: '2026-09-09T17:30:00Z', last_seen_at: iso(3600000),
        status: 'ended', confidence: 'process-tree'
      }
    ],
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
    '/resources': {
      observed_at: iso(0),
      host: {
        total_memory_bytes: 17179869184,
        free_memory_bytes: 2147483648,
        available_memory_bytes: 4294967296,
        compressed_memory_bytes: 1073741824,
        used_memory_bytes: 12884901888,
        agent_memory_bytes: 5905580032,
        non_agent_memory_bytes: 6979321856,
        swap_total_bytes: 8589934592,
        swap_used_bytes: 2147483648,
        headroom_percent: 25,
        agent_memory_percent: 34.4,
        system_cpu_percent: 75,
        agent_cpu_percent: 16.6,
        non_agent_cpu_percent: 58.4,
        load_1: 5.5,
        logical_cpu_count: 8,
        memory_pressure: 'normal',
        thermal_state: 'nominal',
        headroom_score: 25,
        capacity: 'constrained'
      },
      rss_bytes: 5995580032,
      cpu_percent: 142.5,
      process_count: 3,
      session_count: 2,
      control: {
        mode: 'prompt', max_rss_bytes: 4294967296, max_cpu_percent: 100,
        sustain_seconds: 30, cooldown_seconds: 300,
		interventions: [{ action: 'notify', after_seconds: 0 }, { action: 'lower_priority', after_seconds: 30, nice: 10 }, { action: 'pause', after_seconds: 60 }, { action: 'terminate', after_seconds: 120 }],
        workspace_overrides: [{ cwd_prefix: '/Users/dev/workspace', mode: 'observe', max_rss_bytes: 6442450944, max_cpu_percent: 200, sustain_seconds: 60, cooldown_seconds: 600 }],
		pending: [{ id: 'resource-1', session_key: '5821:1789480800000000000', root_pid: 5821, action: 'pause' }]
      },
      sessions: [
        {
          key: '5821:1789480800000000000', name: 'claude', workspace: '/Users/dev/workspace/api-service',
          root_pid: 5821, root_started_at: '2026-09-09T14:00:00Z', last_seen_at: iso(60000),
          rss_bytes: 5905580032, cpu_percent: 132.5, process_count: 2, orphan_count: 0,
          estimated_reclaim_bytes: 1610612736,
          control: {
            mode: 'prompt', state: 'approval-required', pending_id: 'resource-1',
			next_action: 'pause', last_action: 'lower_priority', applied_actions: ['notify', 'lower_priority'],
            policy_source: 'workspace', policy_scope: '/Users/dev/workspace',
            violations: [{ metric: 'rss_bytes', actual: 5905580032, limit: 4294967296 }]
          },
          processes: [
            { pid: 5821, ppid: 1, name: 'claude', cwd: '/Users/dev/workspace/api-service', rss_bytes: 4294967296, cpu_percent: 92.5 },
            { pid: 5822, ppid: 5821, name: 'claude', rss_bytes: 1610612736, cpu_percent: 40 }
          ],
          samples: [
            { at: iso(900000), rss_bytes: 4400000000, cpu_percent: 82 },
            { at: iso(450000), rss_bytes: 5100000000, cpu_percent: 110 },
            { at: iso(0), rss_bytes: 5905580032, cpu_percent: 132.5 }
          ],
          diagnoses: [{
            code: 'rapid-growth', severity: 'warning',
            summary: 'Memory grew 1.4 GB in 15 minutes.',
            evidence: ['15-minute growth: 1505580032 bytes (34.2%)'],
            threshold: '15-minute growth >= 1 GiB and >= 25%', confidence: 'high',
            estimated_reclaim_bytes: 1505580032
          }]
        },
        {
          key: '6033:1789484400000000000', name: 'cursor', workspace: '/Users/dev/projects/web-app',
          root_pid: 6033, root_started_at: '2026-09-09T15:00:00Z', last_seen_at: iso(3600000),
          rss_bytes: 90000000, cpu_percent: 10, process_count: 1, orphan_count: 1,
		  control: { mode: 'prompt', state: 'paused', policy_source: 'default', paused: true, last_action: 'pause', last_error: 'rollback failed: permission denied', violations: [] },
          processes: [{ pid: 6033, ppid: 1, name: 'cursor', cwd: '/Users/dev/projects/web-app', rss_bytes: 90000000, cpu_percent: 10, is_orphan: true }],
          samples: [{ at: iso(0), rss_bytes: 90000000, cpu_percent: 10 }],
          diagnoses: [{ code: 'orphan-drift', severity: 'warning', summary: 'Attributed processes remain after their parent disappeared.' }]
        }
      ],
      episodes: [{
        id: 7, captured_at: iso(1800000), severity: 'critical', diagnosis_codes: ['heavy-memory', 'runaway-child'],
        host: {
          total_memory_bytes: 17179869184, available_memory_bytes: 1073741824,
          memory_pressure: 'critical', thermal_state: 'serious',
          headroom_score: 6, capacity: 'critical'
        },
        correlations: [{
          summary: 'Memory rose 3.0 GiB in 10m while node started.', confidence: 'observed-correlation',
          from: iso(2400000), to: iso(1800000), rss_delta_bytes: 3221225472, activity_count: 3
        }],
        activities: [
          { at: iso(2250000), kind: 'tool', pid: 4412, process: 'codex', summary: 'Bash tool ran' },
          { at: iso(2100000), kind: 'process-start', pid: 4419, process: 'node', summary: 'node started' },
          { at: iso(1950000), kind: 'network', pid: 4419, process: 'node', summary: 'connected to api.openai.com:443' }
        ],
        session: {
          key: '4412:1789470000000000000', name: 'codex', workspace: '/Users/dev/workspace/data-pipeline',
          root_pid: 4412, rss_bytes: 7516192768, cpu_percent: 88, process_count: 3,
          processes: [
            { pid: 4412, name: 'codex', rss_bytes: 1073741824, cpu_percent: 18 },
            { pid: 4419, ppid: 4412, name: 'node', rss_bytes: 5905580032, cpu_percent: 65 },
            { pid: 4420, ppid: 4412, name: 'rg', rss_bytes: 536870912, cpu_percent: 5 }
          ],
          samples: [
            { at: iso(2400000), rss_bytes: 4294967296, cpu_percent: 42 },
            { at: iso(1800000), rss_bytes: 7516192768, cpu_percent: 88 }
          ],
          diagnoses: [{
            code: 'runaway-child', severity: 'critical', summary: 'One child process dominated session memory.',
            evidence: ['PID 4419: 5905580032 bytes (79%)']
          }]
        }
      }]
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
      proxy_enabled: true, proxy_port: 8443, fleet_configured: true
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
    '/allowlist': [
      { agent: 'cursor', host: 'artifacts.example.com' }
    ],
    '/mute': [
      { rule: 'proxy-prompt-injection', host: 'blog.example.com' },
      { rule: 'keychain-security-cli', host: '*' }
    ],
    '/egress/uninspected': [
      { agent: 'cursor', host: 'registry.npmjs.org', count: 14, first_seen: iso(86400000), last_seen: iso(300000), session_id: 'sess-cursor-2', assessment: 'benign', rationale: 'npm registry is routine for JS projects' },
      { agent: 'claude', host: 'statsig.example.com', count: 3, first_seen: iso(7200000), last_seen: iso(900000), session_id: 'sess-claude-1' },
      { agent: 'claude', host: 'telemetry.example.com', count: 5, first_seen: iso(5400000), last_seen: iso(600000), session_id: 'sess-claude-1' },
      { agent: 'cursor', host: '2606:4700:4408::ac40:9bd1', count: 56, last_seen: iso(600000), infra: 'Cloudflare' },
      { agent: 'codex', host: 'ec2-98-90-104-193.compute-1.amazonaws.com', count: 11, last_seen: iso(700000), infra: 'AWS' }
    ],
    '/notify/rules': {
      default_min_severity: 3,
      overrides: { 'keychain-access': false }
    },
    '/guard/pending': [{
      id: 'guard-1', agent: 'claude', tool: 'Read', path: '/workspace/api-service/.env',
      rule_id: 'cloud-creds', ts: iso(30000),
      scope_text: 'Allow Always approves every path under rule "cloud-creds" for agent "claude", not just this one.'
    }],
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
    if (p === '/allowlist' && opts && opts.method === 'DELETE') {
      data['/allowlist'] = data['/allowlist'].filter(x => !(x.agent === body.agent && x.host === body.host));
      return { status: 'ok' };
    }
    if (p === '/firewall/mode') {
      const st = data['/status'].firewall_stats[body.rule];
      if (st) st.mode = body.mode;
      return { status: 'ok' };
    }
    if (p === '/allowlist') {
      data['/allowlist/suggestions'] = data['/allowlist/suggestions'].filter(s => s.host !== body.host);
      data['/egress/uninspected'] = data['/egress/uninspected'].filter(e => e.host !== body.host);
      return { status: 'ok' };
    }
    if (p === '/flags/acknowledge') {
      data['/flags'] = data['/flags'].filter(f => f.id !== body.flag_id);
      return { status: 'ok', acknowledged: true };
    }
    if (p === '/guard/resolve') {
      data['/guard/pending'] = data['/guard/pending'].filter(prompt => prompt.id !== body.id);
    }
    if (p === '/advisor/assess-host') {
      // Cached verdict for a known host; a fresh (unknown) host queues.
      const out = { status: 'ok', queued: true };
      if (body.host === 'registry.npmjs.org') {
        out.verdict = { assessment: 'benign', rationale: 'npm registry is routine for JS projects' };
      }
      // Reflect the verdict into the uninspected fixture so the row re-renders
      // with guidance (the poll path the console uses).
      const row = data['/egress/uninspected'].find(e => e.host === body.host);
      if (row && out.verdict) { row.assessment = out.verdict.assessment; row.rationale = out.verdict.rationale; }
      return out;
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
        mutes: data['/mute'],
        sessions: data['/sessions']
      };
      return {
        ok: true, status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body)
      };
    }
    // Session timeline: /sessions/<id>/timeline
    const tlMatch = p.match(/^\/sessions\/([^/]+)\/timeline/);
    if (tlMatch) {
      const sid = decodeURIComponent(tlMatch[1]);
      const sess = (data['/sessions'] || []).find(s => s.id === sid);
      const body = sess ? (sess._timeline || []) : null;
      return {
        ok: body !== null, status: body !== null ? 200 : 404,
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

  // SSE stub: drip live deltas so liveness paths (sparkline, fresh rows,
  // firewall flash) execute during the virtual-time window. The stream is
  // typed envelopes: one "event" delta per persisted event.
  window.EventSource = class {
    constructor() {
      this.readyState = 1;
      this._listeners = {};
      setTimeout(() => this.onopen && this.onopen(), 0);
      const drip = [
        { kind: 5, pid: 5821, remote_host: 'api.anthropic.com', remote_port: 443 },
        { kind: 9, pid: 5821, detail: 'proxy-scan: POST /v1/messages (clean)' },
        { kind: 8, pid: 6033, detail: 'Bash → git status' }
      ];
      let i = 0;
      this._timer = setInterval(() => {
        const ev = drip[i % drip.length];
        i++;
        ev.ts = new Date().toISOString();
        data['/events'].unshift({ ...ev });
        (this._listeners['event'] || []).forEach(fn => fn({ data: JSON.stringify(ev) }));
      }, 900);
    }
    addEventListener(kind, fn) { (this._listeners[kind] = this._listeners[kind] || []).push(fn); }
    close() { clearInterval(this._timer); }
  };

  // Auto-action: exercise the session drill-down like a user click would.
  if (location.search.includes('sessiondemo')) {
    setTimeout(() => window.filterTimelineToSession('7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77'), 4000);
  }
  // Auto-action: select a session in the session-first rail so the trace
  // waterfall renders.
  if (location.search.includes('raildemo')) {
    setTimeout(() => window.selectSession('sess-claude-1'), 4000);
  }
  // Auto-action: resolve the guard request once; the unified queue must
  // refresh and remove that blocked tool call. The styled confirm dialog
  // opens first — accept it.
  if (location.search.includes('guarddemo')) {
    const clickResolve = () => {
      const btn = document.querySelector('[data-action="guard-resolve"][data-scope="once"]');
      if (btn) btn.click();
    };
    const acceptDialog = () => {
      // Poll for the styled confirm dialog (it opens in the click handler),
      // then accept it; the queue refresh follows.
      let n = 0;
      const iv = setInterval(() => {
        n++;
        const ok = document.getElementById('confirm-ok');
        if (ok && ok.closest('dialog') && ok.closest('dialog').open) {
          ok.click();
          clearInterval(iv);
        } else if (n > 20) {
          clearInterval(iv);
        }
      }, 100);
    };
    setTimeout(() => { clickResolve(); acceptDialog(); }, 4000);
  }
  // Auto-action: open the uninspected-egress drill-down modal.
  if (location.search.includes('uninspecteddemo')) {
    setTimeout(() => window.openUninspected(), 4000);
  }
  // Auto-action: open the egress modal, then fire a toast from inside it —
  // proves the toast renders above the open modal (native <dialog> is in the
  // browser top layer, which no root-level z-index can paint over). Fires
  // late so the toast is still on screen when the DOM is dumped.
  if (location.search.includes('toastdemo')) {
    setTimeout(() => {
      window.openUninspected();
      document.getElementById('btn-refresh').click();
    }, 9000);
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
  // No-fleet variant: no collector webhooks configured — the fleet panel must
  // hide entirely instead of carrying a permanently-empty placeholder.
  if (location.search.includes('nofleetdemo')) {
    data['/fleet'] = { ...data['/fleet'], fleet_configured: false };
  }
  // Post-mortem variant: every live session has exited, but persisted pressure
  // episodes must remain visible.
  if (location.search.includes('noresourcesdemo')) {
    data['/resources'] = { ...data['/resources'], rss_bytes: 0, cpu_percent: 0, process_count: 0, session_count: 0, sessions: [] };
  }

  // Auto-action: demote a blocking rule — it must flip back to Promote.
  if (location.search.includes('demotedemo')) {
    setTimeout(() => document.querySelector('[data-action="demote"][data-rule="aws-key"]').click(), 4000);
  }
  // Auto-action: remove an allowlist entry — the row must leave the list.
  if (location.search.includes('allowlistdemo')) {
    setTimeout(() => document.querySelector('[data-action="allowlist-remove"]').click(), 4000);
  }

  // Auto-action: switch to the Egress tab — panels must hide/show correctly.
  if (location.search.includes('tabdemo')) {
    setTimeout(() => document.querySelector('[data-tab="egress"]').click(), 4000);
  }
  // Auto-action: select a session, open the resource policy editor, and add
  // its workspace as an override through the real delegated click path.
  if (location.search.includes('policydemo')) {
    setTimeout(() => {
      document.querySelector('[data-action="resource-session"]').click();
      document.querySelector('[data-action="edit-resource-policy"]').click();
      document.querySelector('[data-action="add-resource-override"][data-source="current"]').click();
      document.querySelector('[data-policy-default="true"] [data-policy-field="mode"]').value = 'terminate';
      document.getElementById('btn-save-resource-policy').click();
    }, 4000);
  }
})();
