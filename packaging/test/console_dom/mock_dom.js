// DOM test stub: replaces fetch + EventSource with deterministic telemetry so
// the REAL console (index.html + lib.js + app.js + style.css) can be asserted
// end-to-end in headless Chrome. Loaded between lib.js and app.js.
//
// Auto-actions (driven by ?domtest-flags):
//   sessiondemo — after 4s, filter the timeline to session 7f3a9c21…
//   exportdemo  — with raildemo: stub the clipboard, click Export at 9s
(() => {
  const now = Date.now();
  const iso = (msAgo) => new Date(now - msAgo).toISOString();
  let bookCleanup = () => {};

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
      },
      // Sub-agent of sess-claude-1: nests under its parent in the rail.
      {
        id: 'sess-claude-sub', harness: 'claude', parent_id: 'sess-claude-1',
        workspace: '/Users/dev/workspace/api-service/packages/auth',
        started_at: '2026-09-09T14:05:00Z', last_seen_at: iso(90000),
        status: 'idle', confidence: 'hook'
      },
      // Finished claude run: the collapsed ended tail of the claude group.
      {
        id: 'sess-claude-0', harness: 'claude', workspace: '/Users/dev/workspace/docs-site',
        repo: 'docs-site', branch: 'main',
        started_at: '2026-09-09T09:00:00Z', ended_at: '2026-09-09T11:00:00Z', last_seen_at: iso(7200000),
        status: 'ended', confidence: 'hook'
      },
      {
        id: 'sess-codex-3', harness: 'codex', workspace: '/Users/dev/workspace/data-pipeline',
        repo: 'data-pipeline', branch: 'feat/etl', root_pid: 4412,
        started_at: '2026-09-09T13:00:00Z', last_seen_at: iso(20000),
        status: 'active', confidence: 'transcript'
      },
      // Local model server: infra, never a rail card.
      {
        id: 'sess-ollama-4', harness: 'ollama', workspace: '/', root_pid: 7001,
        started_at: '2026-09-09T08:00:00Z', last_seen_at: iso(5000),
        status: 'active', confidence: 'process-tree'
      }
    ],
    '/status': {
      running: true,
      version: 'v9.9.9-domtest',
      uptime: '4h 12m 8s',
      active_agents: 3,
      infra_count: 1,
      coverage: { harnesses_active: 3, harnesses_seen: 2 },
      agents: [
        { pid: 5821, name: 'claude', cwd: '/Users/dev/workspace/api-service', ppid: 1, root_pid: 5821, started_at: '2026-09-09T14:00:00Z', last_seen_at: iso(60000), rss_bytes: 120000000, cpu_percent: 14.5, repo: 'api-service', branch: 'main', workspace: '/Users/dev/workspace/api-service' },
        { pid: 5822, name: 'claude', ppid: 5821, root_pid: 5821, started_at: '2026-09-09T14:01:00Z', last_seen_at: iso(120000), rss_bytes: 40000000 },
        { pid: 6033, name: 'cursor', cwd: '/Users/dev/projects/web-app', ppid: 1, root_pid: 6033, started_at: '2026-09-09T15:00:00Z', last_seen_at: iso(3600000), rss_bytes: 89000000, is_orphan: true },
        { pid: 4412, name: 'codex', cwd: '/Users/dev/workspace/data-pipeline', ppid: 1, root_pid: 4412, started_at: '2026-09-09T13:00:00Z', last_seen_at: iso(20000), rss_bytes: 210000000, cpu_percent: 22, repo: 'data-pipeline', branch: 'feat/etl', workspace: '/Users/dev/workspace/data-pipeline' },
        { pid: 7001, name: 'ollama', kind: 'infra', ppid: 1, root_pid: 7001, started_at: '2026-09-09T08:00:00Z', last_seen_at: iso(5000), rss_bytes: 820000000, cpu_percent: 3 }
      ],
      // Live process trees, joined to sessions by root pid (RSS, kill).
      trees: [
        { root: { pid: 5821, name: 'claude', kind: 'agent', cwd: '/Users/dev/workspace/api-service', started_at: '2026-09-09T14:00:00Z' }, children: [{ pid: 5822, name: 'claude' }], rss_bytes: 160000000, cpu_percent: 16, last_seen_at: iso(60000) },
        { root: { pid: 4412, name: 'codex', kind: 'agent', cwd: '/Users/dev/workspace/data-pipeline', started_at: '2026-09-09T13:00:00Z' }, children: [], rss_bytes: 210000000, cpu_percent: 22, last_seen_at: iso(20000) },
        { root: { pid: 6033, name: 'cursor', kind: 'agent', cwd: '/Users/dev/projects/web-app', started_at: '2026-09-09T15:00:00Z', is_orphan: true }, children: [], rss_bytes: 89000000, last_seen_at: iso(3600000) },
        { root: { pid: 7001, name: 'ollama', kind: 'infra', started_at: '2026-09-09T08:00:00Z' }, children: [], rss_bytes: 820000000, cpu_percent: 3, last_seen_at: iso(5000) }
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
    // The daemon's invariant: every item sits in exactly one group and the
    // group items sum to needs_you (= items.length).
    '/posture': {
      state: 'critical',
      needs_you: 10,
      summary: '10 items need you — first: proxy-secret-leak — cursor sent an anthropic-key to logs.example.com — act now.',
      items: [
        { severity: 3, kind: 'flag', id: 'flag-1', title: 'proxy-secret-leak — cursor sent an anthropic-key to logs.example.com' },
        { severity: 3, kind: 'flag', id: 'flag-2', title: 'Agent read a secret, then connected out' },
        { severity: 3, kind: 'flag', id: 'flag-4', title: 'Agent modified macOS privacy permissions (TCC)' },
        { severity: 2, kind: 'flag', id: 'flag-5', title: 'Agent touched the keychain' },
        { severity: 1, kind: 'guard_pending', id: 'guard-1', title: 'claude wants .env' },
        { severity: 2, kind: 'collector_down', id: 'eslogger', title: 'File monitoring is off', detail: 'usually missing Full Disk Access — open Setup & Permissions in the menu bar' },
        { severity: 1, kind: 'uninspected_egress', id: 'uninspected-egress:session:5821:1789480800000000000', title: '7 connections bypassed the egress firewall — claude' },
        { severity: 2, kind: 'uninspected_egress', id: 'uninspected-egress:agent:codex', title: '2 endpoints reached without inspection' },
        { severity: 3, kind: 'incident', id: 'inc-20260907-6033-a1b2', title: 'sensitive-read-then-connect — cursor (PID 6033)' },
        { severity: 1, kind: 'resource_pressure', id: 'resource-1', title: 'Resource pressure: api-service' }
      ],
      // The attention tab renders this served queue verbatim — the daemon
      // groups it; the console never re-derives it.
      groups: [
        {
          key: 'session:5821:1789480800000000000', label: 'api-service', agent: 'claude',
          workspace: '/Users/dev/workspace/api-service', rootPid: 5821, pids: [5821, 5822],
          rssBytes: 5905580032, cpuPercent: 132.5, processCount: 2,
          items: [
            { kind: 'guard', priority: 5, id: 'guard-1', title: 'Guard decision',
              detail: 'Read wants access to /workspace/api-service/.env',
              rule: 'cloud-creds', path: '/workspace/api-service/.env',
              scopeText: 'Allow Always approves every path under rule "cloud-creds" for agent "claude", not just this one.' },
            { kind: 'resource', priority: 4, id: 'resource-1', action: 'pause',
              title: 'Resource pressure', detail: 'Memory grew 1.4 GB in 15 minutes.' },
            { kind: 'egress', priority: 1, id: 'uninspected-egress:session:5821:1789480800000000000', title: 'Uninspected egress', count: 7,
              hosts: ['registry.npmjs.org'],
              detail: '7 connections across 1 endpoint bypassed inspection.' }
          ]
        },
        {
          key: 'session:6033:1789484400000000000', label: 'web-app', agent: 'cursor',
          workspace: '/Users/dev/projects/web-app', rootPid: 6033, pids: [6033],
          rssBytes: 90000000, cpuPercent: 10, processCount: 1,
          items: [
            { kind: 'incident', priority: 3, id: 'inc-20260907-6033-a1b2', status: 'open',
              title: 'Critical incident', detail: 'Credential read followed by network access.' },
            { kind: 'flag', priority: 2, id: 'flag-1',
              title: 'Critical finding', detail: 'proxy-secret-leak — anthropic-key in request body' },
            { kind: 'flag', priority: 2, id: 'flag-2',
              title: 'Critical finding', detail: 'sensitive-read-then-connect — credentials then egress' },
            { kind: 'flag', priority: 2, id: 'flag-4',
              title: 'Critical finding', detail: 'tcc-tamper — modified TCC service' },
            { kind: 'flag', priority: 1, id: 'flag-5',
              title: 'Agent touched the keychain', detail: 'keychain-access — security find-generic-password',
              disposition: { state: 'warning', text: 'Needs a look' } }
          ]
        },
        {
          key: 'machine', label: 'This machine', agent: '',
          items: [
            { kind: 'collector_down', priority: 2, id: 'eslogger', title: 'File monitoring is off',
              detail: 'usually missing Full Disk Access — open Setup & Permissions in the menu bar' }
          ]
        },
        {
          key: 'agent:codex', label: 'codex activity', agent: 'codex',
          items: [
            { kind: 'egress', priority: 1, id: 'uninspected-egress:agent:codex', title: 'Uninspected egress', count: 2,
              hosts: ['example.com'],
              detail: '2 connections across 1 endpoint bypassed inspection.' }
          ]
        }
      ]
    },
    '/flags': [
      {
        id: 'flag-1',
        rule: 'proxy-secret-leak', agent: 'cursor', pid: 6033, severity: 3,
        session_id: 'b81d4fae-7dec-11d0-a765-00a0c91e6bf6',
        evidence: [
          { kind: 'violation', label: 'proxy-secret-leak: anthropic-key', sub: 'payload inspection' },
          { kind: 'connect', label: 'logs.example.com:443', sub: 'destination' }
        ],
        advisor: { assessment: 'suspicious', confidence: 0.7, rationale: 'host is not a known vendor; first time this session', suggested_action: 'review once' }
      },
      {
        id: 'flag-2',
        rule: 'sensitive-read-then-connect', agent: 'cursor', pid: 6033, severity: 3,
        session_id: '7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77',
        evidence: [
          { kind: 'read', label: '~/.aws/credentials', sub: 'sensitive read', ts: '2026-09-07T16:04:57Z' },
          { kind: 'connect', label: 'logs.example.com:443', sub: 'egress', ts: '2026-09-07T16:05:01Z' }
        ],
        advisor: { assessment: 'benign', confidence: 0.8, rationale: 'registry host matches this project\'s normal workflow', suggested_action: 'none' }
      },
      {
        id: 'flag-3',
        rule: 'keychain-access', agent: 'codex', pid: 9012, severity: 1,
        evidence: [{ kind: 'keychain', label: '/Users/dev/Library/Keychains/login.keychain-db', sub: 'keychain access', ts: '2026-09-07T15:55:00Z' }]
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
      { agent: 'cursor', host: 'registry.npmjs.org', count: 14, first_seen: iso(86400000), last_seen: iso(300000), session_id: 'sess-cursor-2', assessment: 'benign', rationale: 'npm registry is routine for JS projects', identity: { kind: 'hostname', name: 'registry.npmjs.org' } },
      { agent: 'claude', host: 'statsig.example.com', count: 3, first_seen: iso(7200000), last_seen: iso(900000), session_id: 'sess-claude-1', identity: { kind: 'hostname', name: 'statsig.example.com' } },
      { agent: 'claude', host: 'telemetry.example.com', count: 5, first_seen: iso(5400000), last_seen: iso(600000), session_id: 'sess-claude-1', identity: { kind: 'hostname', name: 'telemetry.example.com' } },
      { agent: 'cursor', host: '2606:4700:4408::ac40:9bd1', count: 56, last_seen: iso(600000), infra: 'Cloudflare', identity: { kind: 'ipv6', org: 'Cloudflare', class: 'cloud', ip: '2606:4700:4408::ac40:9bd1' } },
      { agent: 'codex', host: 'ec2-98-90-104-193.compute-1.amazonaws.com', count: 11, last_seen: iso(700000), infra: 'AWS', identity: { kind: 'hostname', name: 'ec2-98-90-104-193.compute-1.amazonaws.com', org: 'AWS', class: 'cloud' } },
      { agent: 'claude', host: '2600:1901:0:9e23::', count: 2, last_seen: iso(400000), identity: { kind: 'ipv6', org: 'Google Cloud', class: 'cloud', ip: '2600:1901:0:9e23::' } },
      { agent: 'openclaw', host: '2607:6bc0::10', count: 94, first_seen: iso(3600000), last_seen: iso(60000), identity: { kind: 'ipv6', org: 'Anthropic', class: 'vendor', ip: '2607:6bc0::10' } }
    ],
    '/advisor/plan': {
      subject: 'file:/Users/dev/.codex/sessions/2026/09/23/rollout-2026-09-23T12-53-26-demo.jsonl',
      status: 'ready', advisor_ready: true,
      playbook: { rule: 'secret-in-transcript', title: 'Secret in an agent transcript', why: 'A secret appeared in text the agent saw.',
        now: ['Rotate the secret.'], prevent: [{ kind: 'guard-rule', step: 'Deny commands that print secrets', detail: 'Refuse env for this agent.' }], actions: ['open-incident', 'dismiss'] },
      plan: { summary: 'Codex printed an API key from an env dump.', why: ['A tool call ran env.'], risk: 'high',
        prevent: [{ kind: 'agent-instruction', step: 'Tell codex not to echo keys', detail: 'Add a line to AGENTS.md.' }],
        behavior: ['Reference keys by variable name.'], remediate: ['Rotate the key.'], actions: ['dismiss'], confidence: 0.8,
        model: 'qwen3.8:27b-mlx', created_at: iso(120000) },
      labels: { summary: { ok: 3, not_ok: 0 }, similar: [{ label: 'ok', source: 'mark', pattern: '/Users/dev/.codex/sessions/2026/09/23/rollout-2026-09-23T12-53-26-demo.jsonl', reason: 'my own test key', created_at: iso(86400000) }],
        suggestion: { label: 'ok', text: 'You marked this 3 times as routine for codex.', action_id: 'dismiss' } },
      flag: { id: 'flag-t1', agent: 'codex', rule: 'secret-in-transcript', explain: { actions: [
        { id: 'dismiss', label: 'Dismiss this flag', consequence: 'marks it reviewed', method: 'POST', path: '/flags/acknowledge', body: { flag_id: 'flag-t1' } }] } }
    },
    '/files/detail': {
      path: '/Users/dev/.codex/sessions/2026/09/23/rollout-2026-09-23T12-53-26-demo.jsonl',
      display: '~/.codex/sessions/2026/09/23/rollout-2026-09-23T12-53-26-demo.jsonl',
      exists: true, size: 2400000, mod_time: iso(600000), owned_by_user: true,
      subject: { path: '/Users/dev/.codex/sessions/2026/09/23/rollout-2026-09-23T12-53-26-demo.jsonl', category: 'transcript', category_label: 'agent transcript', owner_label: 'Codex transcript' },
      session: { id: 'sess-codex-1', harness: 'codex', workspace: '/Users/dev/workspace/api-service', repo: 'api-service', branch: 'main' },
      findings: [
        { kind: 'flag', id: 'flag-t1', rule: 'secret-in-transcript', severity: 3, ts: iso(500000), agent: 'codex', evidence_kind: 'transcript', evidence_rule: 'fp1', offset: 4096 },
        { kind: 'incident', id: 'inc-file-1', rule: 'secret-in-transcript', risk: 'high', ts: iso(500000), agent: 'codex', status: 'open' }
      ],
      accesses: [{ kind: 'file-write', ts: iso(520000), pid: 4242, exe_path: '/usr/local/bin/codex', session_id: 'sess-codex-1' }],
      hits: [{ flag_id: 'flag-t1', rule: 'fp1', offset: 4096, ts: iso(500000) }],
      excerpt: '{"type":"function_call_output","output":"TOKEN=[REDACTED:fp1] ok"}'
    },
    '/egress/endpoint': {
      host: '2600:1901:0:9e23::',
      identity: { kind: 'ipv6', org: 'Google Cloud' },
      agents: ['claude'],
      count: 2, first_seen: iso(7200000), last_seen: iso(400000),
      sessions: [{ id: 'sess-claude-1', harness: 'claude', workspace: '/Users/dev/workspace/api-service', repo: 'api-service', branch: 'main' }],
      events: [{ ts: iso(400000), remote_port: 443, session_id: 'sess-claude-1' }],
      allowed: []
    },
    '/notify/rules': {
      default_min_severity: 3,
      overrides: { 'keychain-access': false },
      scopes: [{ workspace: '/Users/dev/work/prod', rule: 'proxy-secret-leak', notify: true }]
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
    })(),
    // /costs (24h, by repo): six rows, deliberately unsorted; the top 5 by
    // cost render, and the 0-cost 'docs' row (fewer calls) is dropped.
    '/costs': {
      since: iso(24 * 3600000), until: iso(0), by: 'repo',
      total: { key: '', calls: 40, sessions: 7, tokens_in: 912000, tokens_out: 48000, cost_usd: 36.674, unpriced_calls: 2 },
      rows: [
        { key: 'web-console', harness: 'codex', calls: 9, sessions: 2, tokens_in: 210000, tokens_out: 9000, cost_usd: 8.124, unpriced_calls: 0 },
        { key: 'docs', harness: 'claude', calls: 1, sessions: 1, tokens_in: 1000, tokens_out: 100, cost_usd: 0, unpriced_calls: 0 },
        { key: 'api-service', harness: 'claude', calls: 18, sessions: 2, tokens_in: 560000, tokens_out: 30000, cost_usd: 24.5, unpriced_calls: 0 },
        { key: 'scratch', harness: 'cursor', calls: 3, sessions: 1, tokens_in: 20000, tokens_out: 1900, cost_usd: 0.85, unpriced_calls: 0 },
        { key: '(no repo)', calls: 2, sessions: 1, tokens_in: 1000, tokens_out: 0, cost_usd: 0, unpriced_calls: 2 },
        { key: 'infra-tools', harness: 'opencode', calls: 7, sessions: 1, tokens_in: 120000, tokens_out: 7000, cost_usd: 3.2, unpriced_calls: 0 }
      ]
    },
    // /costs/plans: no plan headroom reported (plansdemo fills it).
    '/costs/plans': { plans: [] },
    // /costs keyed by the query's `by` (the fetch stub below): the Spend
    // card's provider and day views.
    '/costs?by=provider': {
      since: iso(24 * 3600000), until: iso(0), by: 'provider',
      total: { key: '', calls: 40, sessions: 7, tokens_in: 912000, tokens_out: 48000, cost_usd: 36.674, unpriced_calls: 2 },
      rows: [
        { key: 'anthropic', harness: 'claude', calls: 21, sessions: 3, tokens_in: 600000, tokens_out: 32000, cost_usd: 28.35, unpriced_calls: 0 },
        { key: 'openai-codex', harness: 'codex', calls: 9, sessions: 2, tokens_in: 210000, tokens_out: 9000, cost_usd: 8.124, unpriced_calls: 0 },
        { key: 'openai', harness: 'opencode', calls: 7, sessions: 1, tokens_in: 100000, tokens_out: 7000, cost_usd: 0.2, unpriced_calls: 0 },
        { key: '(unknown)', harness: 'codex', calls: 3, sessions: 1, tokens_in: 2000, tokens_out: 0, cost_usd: 0, unpriced_calls: 3 }
      ]
    },
    '/costs?by=day': {
      since: iso(7 * 24 * 3600000), until: iso(0), by: 'day',
      total: { key: '', calls: 70, sessions: 12, tokens_in: 4000000, tokens_out: 200000, cost_usd: 2194.1, unpriced_calls: 0 },
      rows: ['2026-09-17', '2026-09-18', '2026-09-19', '2026-09-20', '2026-09-21', '2026-09-22', '2026-09-23'].map((key, i) => ({
        key, harness: 'claude', calls: 10, sessions: 2, tokens_in: 500000, tokens_out: 25000,
        cost_usd: [120.5, 210, 88.25, 0, 335.84, 676.54, 449.74][i], unpriced_calls: 0
      }))
    }
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

  // explaindemo: flag-2 carries the daemon's served explanation (the S2
  // shape: Cloudflare over IPv6, advisor benign at 0.93, allow-host
  // recommended) and its attention item the benign-likely disposition.
  // flag-1 and flag-3 stay raw, as rows from an older daemon or past the
  // 25-flag cap do.
  if (MODE.includes('explaindemo')) {
    // Findings is opened first, as a user must: hidden panels do not render.
    setTimeout(() => openTab('findings'), 1500);
    const cfHost = '2606:4700::6810:84e5';
    const f2 = data['/flags'].find(f => f.id === 'flag-2');
    Object.assign(f2, {
      title: 'Agent read a secret, then connected out',
      ts: '2026-09-22T16:05:01Z',
      evidence: [
        { kind: 'read', label: '/Users/dev/.aws/credentials', sub: 'sensitive read', ts: '2026-09-22T16:04:58Z' },
        { kind: 'connect', label: `[${cfHost}]:443`, sub: 'egress', ts: '2026-09-22T16:05:01Z' }
      ],
      advisor: { assessment: 'benign', confidence: 0.93, rationale: 'Cloudflare fronts the package registry this project installs from.', suggested_action: 'allow-host' },
      explain: {
        what: 'Cursor read AWS credentials (~/.aws/credentials), then reached Cloudflare 3 s later.',
        subject: { path: '/Users/dev/.aws/credentials', display: '~/.aws/credentials', basename: 'credentials',
          category: 'aws_credentials', category_label: 'AWS credentials', rule: 'cloud-creds', owner_label: 'home directory' },
        egress: [{ host: cfHost, port: 443, org: 'Cloudflare', kind: 'ipv6', allowlisted: false, gap_seconds: 3 }],
        context: { session_id: '7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77', harness: 'cursor', repo: 'web-app', branch: 'main',
          tool: 'Read', tool_status: 'ok', tool_at: '2026-09-22T16:04:57Z' },
        disposition: { state: 'benign-likely', text: 'Likely benign (advisor 93 %)', why: 'Cloudflare fronts the package registry this project installs from.' },
        actions: [
          { id: 'allow-host', label: `Allow ${cfHost} (Cloudflare) for cursor`, recommended: true,
            consequence: `Future connections from cursor to ${cfHost} are trusted and stop being flagged.`,
            method: 'POST', path: '/allowlist', body: { agent: 'cursor', host: cfHost } },
          { id: 'allow-path', label: 'Always allow this file for cursor',
            consequence: 'cursor may open ~/.aws/credentials without a guard prompt; other files under the cloud-creds rule still ask.',
            method: 'POST', path: '/guard/path-allow', body: { agent: 'cursor', rule_id: 'cloud-creds', path: '/Users/dev/.aws/credentials' } },
          { id: 'dismiss', label: 'Dismiss this flag',
            consequence: 'The flag is marked reviewed and stops counting as needing action; the rule keeps watching for the next one.',
            method: 'POST', path: '/flags/acknowledge', body: { flag_id: 'flag-2' } },
          { id: 'kill', label: 'Kill cursor (pid 6033)',
            consequence: 'The agent process tree is terminated now; unsaved work in it is lost.',
            method: 'POST', path: '/kill', body: { pid: 6033 } }
        ]
      }
    });
    for (const g of data['/posture'].groups) {
      for (const it of g.items) {
        if (it.kind === 'flag' && it.id === 'flag-2') {
          Object.assign(it, { priority: 1, title: 'Finding, likely benign',
            detail: 'Likely benign (advisor 93 %) — sensitive-read-then-connect — credentials then egress',
            disposition: f2.explain.disposition });
        }
      }
    }
  }
  // patterndemo: a 323-flag codex keychain storm served as one pattern
  // covering fixture flags flag-6 and flag-7; /posture carries one pattern
  // item for it in the codex group instead of flag items.
  const PATTERN_KEY = 'codex|keychain-access|/Users/dev/Library/Keychains/login.keychain-db';
  if (MODE.includes('patterndemo')) {
    // Findings is opened first, as a user must: hidden panels do not render.
    setTimeout(() => openTab('findings'), 1500);
    const kc = (id, pid, msAgo) => ({
      id, rule: 'keychain-access', severity: 2, ts: iso(msAgo), pid, agent: 'codex', session_id: 'sess-codex-9',
      title: 'Agent touched the keychain',
      evidence: [{ kind: 'keychain', label: '/Users/dev/Library/Keychains/login.keychain-db', sub: 'keychain access' }]
    });
    data['/flags'].push(kc('flag-6', 40844, 120000), kc('flag-7', 51364, 60000));
    data['/patterns'] = [{
      key: PATTERN_KEY, agent: 'codex', rule: 'keychain-access', title: 'Agent touched the keychain',
      subject: { kind: 'keychain', label: '~/Library/Keychains/login.keychain-db', sub: 'keychain' },
      count: 323, unacked: 323, first: iso(9 * 60000), last: iso(60000),
      median_gap_s: 1.4, bursts: 320, cadence: 'in bursts a few seconds apart',
      hourly: Array.from({ length: 24 }, (_, i) => (i === 23 ? 323 : 0)),
      pids: [40844, 51364], pid_count: 2, sessions: ['sess-codex-9'], session_count: 1,
      disposition: { state: 'warning', text: 'Needs a look', why: 'Agent touched the keychain' },
      summary: 'codex touched the login keychain 323 times between 03:00 and 03:08 (2 processes, 1 session), in bursts a few seconds apart.',
      actions: [
        { id: 'mute-class', label: 'Dismiss this flag class', method: 'POST', path: '/mute',
          consequence: '"Agent touched the keychain" stops raising flags for every agent.', body: { rule: 'keychain-access', host: '*' } },
        { id: 'dismiss-all', label: 'Dismiss all 2 open', method: 'POST', path: '/flags/acknowledge',
          consequence: 'These flags are marked reviewed.', body: { flag_ids: ['flag-7', 'flag-6'] } }
      ],
      flag_ids: ['flag-7', 'flag-6']
    }];
    const post = data['/posture'];
    post.items.push({ severity: 2, kind: 'pattern', id: PATTERN_KEY, title: 'Agent touched the keychain — 323×' });
    post.needs_you = post.items.length;
    post.groups.find(g => g.key === 'agent:codex').items.unshift({
      kind: 'pattern', priority: 1, id: PATTERN_KEY, count: 323, rule: 'keychain-access',
      title: 'Agent touched the keychain', detail: data['/patterns'][0].summary,
      disposition: data['/patterns'][0].disposition
    });
  }
  // ?theme=dark|light pins the console theme (screenshots); app.js reads it
  // from the same storage key the masthead toggle writes.
  const theme = new URLSearchParams(MODE).get('theme');
  if (theme === 'dark' || theme === 'light') {
    try { localStorage.setItem('sa-theme', theme); } catch { /* ignored */ }
  }
  // ?themefirst (served under the CSP): store 'light', reload once, then
  // record data-theme as it stands when this script runs — after
  // theme-init.js, before app.js.
  if (MODE.includes('themefirst')) {
    let seeded = null;
    try { seeded = sessionStorage.getItem('sa-themefirst'); } catch { /* ignored */ }
    if (!seeded) {
      try { localStorage.setItem('sa-theme', 'light'); sessionStorage.setItem('sa-themefirst', '1'); } catch { /* ignored */ }
      location.reload();
    } else {
      const themeBeforeApp = document.documentElement.dataset.theme || 'unset';
      setTimeout(() => stamp('theme-first', `before-app=${themeBeforeApp}`), 1500);
    }
  }
  // Every mode but notoken runs as a tab that holds a console token (the
  // console shows only the ended state without one).
  if (MODE.includes('tokenseed') || !MODE.includes('notoken')) {
    try { sessionStorage.setItem('sa.console-token', 'test-token'); } catch { /* ignored */ }
  }
  // Policy lists (GET /guard/rules, /guard/path-allow; /mute is above).
  data['/guard/rules'] = [
    { id: 1, agent: 'claude', rule_id: 'env-file', decision: 'allow', source: 'prompt', created_at: '2026-09-20T10:00:00Z' },
    { id: 2, agent: 'codex', rule_id: 'ssh-keys', decision: 'deny', source: 'onboarding', created_at: '2026-09-21T10:00:00Z' },
  ];
  data['/guard/path-allow'] = [
    { agent: 'claude', rule_id: 'env-file', path: '/Users/dev/workspace/api-service/.env.example', created_at: '2026-09-22T10:00:00Z' },
  ];
  if (MODE.includes('emptypolicy')) {
    data['/guard/rules'] = [];
    data['/guard/path-allow'] = [];
    data['/mute'] = [];
  }
  // spenddaydemo: a tab whose saved Spend view is by day over 7d (a reload).
  if (MODE.includes('spenddaydemo')) {
    try { sessionStorage.setItem('sa.spend-view', JSON.stringify({ by: 'day', since: '7d' })); } catch { /* ignored */ }
  }

  // Stateful POST handling: mutations change the fixture so the DOM tests
  // can assert that actions VISIBLY update the lists (the "allow does
  // nothing" / "dismiss does nothing" regressions).
  const handlePost = (p, opts) => {
    let body = {};
    try { body = JSON.parse((opts && opts.body) || '{}'); } catch { /* ignored */ }
    if (p === '/cleanup/advise') {
      data['/cleanup'].advice = { ...(data['/cleanup'].advice || {}), [body.project]: { rationale: 'Caches are small; nothing urgent.', suggested_action: 'Run go clean -cache' } };
      return { status: 'ok', queued: true, subject: 'project:' + body.project };
    }
    if (p === '/cleanup/trash') {
      return { status: 'ok', result: { bytes: 1048576, trash_path: '/Users/dev/.Trash/.tmp' } };
    }
    if (p === '/worktrees/trash') {
      const rep = data['/worktrees'];
      for (const r of rep.repos) r.worktrees = r.worktrees.filter(w => w.path !== body.path);
      rep.repos = rep.repos.filter(r => !r.error || r.worktrees.length);
      rep.errors = (rep.errors || []).filter(e => rep.repos.some(r => e.startsWith(r.path + ': ')));
      return { status: 'ok', result: { path: body.path, bytes: 52428800, trash_path: '/Users/dev/.Trash/ctnj' } };
    }
    if (p === '/worktrees/remove') {
      if (MODE.includes('removecadence')) window.__removePostedAt = Date.now();
      // The daemon removes in the background: running now, the outcome
      // lands in GET /worktrees removals (removerunning: never finishes;
      // removefaildemo: git fails).
      const rep = data['/worktrees'];
      const running = { path: body.path, state: 'running', phase: 'deleting', step: 'deleting', started_at: iso(0), step_at: iso(0),
        bytes: 1610612736, files: 184203 };
      rep.removals = { ...(rep.removals || {}), [body.path]: running };
      if (!MODE.includes('removerunning')) {
        setTimeout(() => {
          if (MODE.includes('removefaildemo')) {
            rep.removals[body.path] = { ...running, state: 'failed', step: '', finished_at: iso(0),
              error: 'git worktree: <b>fatal</b> could not remove (the worktree is still on disk and registered with git)' };
            return;
          }
          const size = 1610612736;
          for (const r of rep.repos) r.worktrees = r.worktrees.filter(w => w.path !== body.path);
          Object.assign(rep.summary, { worktrees: rep.summary.worktrees - 1, remove: rep.summary.remove - 1,
            size_bytes: rep.summary.size_bytes - size, removable_bytes: rep.summary.removable_bytes - size });
          rep.repos[0].size_bytes -= size;
          Object.assign(rep.reclaimed, { bytes: rep.reclaimed.bytes + size, count: rep.reclaimed.count + 1,
            bytes_30d: rep.reclaimed.bytes_30d + size, count_30d: rep.reclaimed.count_30d + 1 });
          bookCleanup({ ts: new Date().toISOString(), action: 'worktree-remove', path: body.path, repo: WT_REPO, bytes: size,
            detail: 'branch kept; merged into origin/main (squash)' });
          rep.removals[body.path] = { ...running, state: 'removed', phase: '', step: '', step_at: undefined, bytes: size,
            branch: body.path.split('/').pop() === 'done' ? 'feat/done' : 'feat/' + body.path.split('/').pop(), finished_at: iso(0) };
        }, 2000);
      }
      return { status: 'accepted', removal: running };
    }
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
      if (!data['/allowlist'].some(x => x.agent === body.agent && x.host === body.host)) {
        data['/allowlist'].push({ agent: body.agent, host: body.host });
      }
      data['/allowlist/suggestions'] = data['/allowlist/suggestions'].filter(s => s.host !== body.host);
      data['/egress/uninspected'] = data['/egress/uninspected'].filter(e => e.host !== body.host);
      return { status: 'ok' };
    }
    if (p === '/flags/acknowledge') {
      const ids = new Set(body.flag_ids || [body.flag_id]);
      data['/flags'] = data['/flags'].filter(f => !ids.has(f.id));
      // A pattern whose open flags were all acknowledged is served at 0
      // open without its dismiss-all, and leaves the attention queue.
      for (const pat of data['/patterns'] || []) {
        if (!(pat.flag_ids || []).every(id => ids.has(id))) continue;
        Object.assign(pat, { unacked: 0, disposition: { state: 'acknowledged', text: 'Reviewed', why: pat.title },
          actions: pat.actions.filter(a => a.id !== 'dismiss-all') });
        const post = data['/posture'];
        post.groups = post.groups.map(g => ({ ...g, items: g.items.filter(it => !(it.kind === 'pattern' && it.id === pat.key)) }))
          .filter(g => g.items.length);
        post.items = post.items.filter(it => !(it.kind === 'pattern' && it.id === pat.key));
        post.needs_you = post.items.length;
      }
      return { status: 'ok', acknowledged: true, count: ids.size };
    }
    if (p === '/guard/resolve') {
      data['/guard/pending'] = data['/guard/pending'].filter(prompt => prompt.id !== body.id);
      // The served attention queue reflects the resolution too — the console
      // re-reads posture.groups after the POST.
      for (const g of (data['/posture'].groups || [])) {
        g.items = g.items.filter(item => !(item.kind === 'guard' && item.id === body.id));
      }
      data['/posture'].groups = (data['/posture'].groups || []).filter(g => g.items.length > 0);
      data['/posture'].items = data['/posture'].items.filter(item => !(item.kind === 'guard_pending' && item.id === body.id));
      data['/posture'].needs_you = data['/posture'].items.length;
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
    if (p === '/notify/rules') {
      // Workspace scope set/clear against the fixture so the popover re-renders.
      if (body.workspace) {
        data['/notify/rules'].scopes = data['/notify/rules'].scopes || [];
        data['/notify/rules'].scopes = data['/notify/rules'].scopes.filter(
          s => !(s.workspace === body.workspace && s.rule === body.rule));
        if (body.notify !== null && body.notify !== undefined) {
          data['/notify/rules'].scopes.push({ workspace: body.workspace, rule: body.rule, notify: !!body.notify });
        }
      } else if (body.notify === null || body.notify === undefined) {
        delete data['/notify/rules'].overrides[body.rule];
      } else {
        data['/notify/rules'].overrides[body.rule] = !!body.notify;
      }
      return { status: 'ok' };
    }
    if (p === '/advisor/retriage') {
      // The model "answers" shortly after the request: the flag's verdict
      // changes, which the pending state must pick up and surface.
      setTimeout(() => {
        const f = data['/flags'].find(x => x.id === body.flag_id);
        if (f) {
          f.advisor = { assessment: 'benign', confidence: 0.9, rationale: 're-triage complete: routine vendor traffic', suggested_action: 'none' };
          // The daemon publishes the updated flag on the stream.
          if (window.__sse) window.__sse.emit('flag', f);
        }
      }, 1200);
      return { status: 'ok', queued: true };
    }
    return { status: 'ok' };
  };

  // Request log: every mutating request as "METHOD /path", stamped into a
  // hidden <pre id="mock-requests"> so a dump can assert what was sent. A POST
  // /allowlist also records whether the allowlist row for its host was
  // already on screen when the request left (row=1: optimistic render).
  const reqLog = [];
  const costLog = [];
  const stamp = (id, text) => {
    const put = () => {
      let el = document.getElementById(id);
      if (!el) { el = document.createElement('pre'); el.id = id; el.hidden = true; document.body.appendChild(el); }
      el.textContent = text;
    };
    if (document.body) put(); else document.addEventListener('DOMContentLoaded', put);
  };

  // Every fetch the console issues is counted on <pre id="fetch-count">.
  let fetchCount = 0;
  stamp('fetch-count', '0');
  window.fetch = async (path, opts) => {
    fetchCount++;
    stamp('fetch-count', String(fetchCount));
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
      let line = `${opts.method} ${p}`;
      if (p === '/allowlist' && opts.method === 'POST') {
        let host = '';
        try { host = JSON.parse(opts.body).host; } catch { /* ignored */ }
        line += ' row=' + (document.querySelector(`#firewall-container [data-action="allowlist-remove"][data-host="${host}"]`) ? 1 : 0);
      }
      if ((MODE.includes('explaindemo') || MODE.includes('patterndemo') || MODE.includes('rawmute')) && opts.body) line += ' body=' + opts.body;
      if (MODE.includes('rawmute') && p === '/mute' && opts.method === 'POST') data['/mute'].push(JSON.parse(opts.body));
      reqLog.push(line);
      stamp('mock-requests', reqLog.join('\n'));
      if (MODE.includes('resolvedemo') && p === '/incidents/status') {
        const text = id => (document.getElementById(id) || {}).textContent;
        const queued = !!document.querySelector('#attention-center [data-id="inc-20260907-6033-a1b2"]');
        stamp('resolve-probe', `badge=${text('badge-attention-count')} tab=${text('tab-badge-home')} queued=${queued}`);
      }
      // postfail: POST /allowlist answers 500 (the act-in-place revert path).
      if (MODE.includes('postfail') && p === '/allowlist') {
        return { ok: false, status: 500, json: async () => ({}), text: async () => 'mock failure' };
      }
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
        patterns: data['/patterns'] || [],
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
    // Session report: /sessions/<id>/report?format=md (markdown text)
    const repMatch = p.match(/^\/sessions\/([^/]+)\/report$/);
    if (repMatch) {
      const sid = decodeURIComponent(repMatch[1]);
      const sess = (data['/sessions'] || []).find(s => s.id === sid);
      const md = sess ? `# ${sess.harness} · ${sess.repo}@${sess.branch} — 2026-09-09 14:00 → live (1h 0m)\n` +
        `Session \`${sess.id}\` · ${sess.status} · identity: ${sess.confidence}\n\n## Summary\n- Turns 1 · tool calls 2 (1 errors)\n` : 'session not found';
      return {
        ok: !!sess, status: sess ? 200 : 404,
        json: async () => { throw new SyntaxError('not JSON'); },
        text: async () => md
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
    // Incident report as markdown: its Accessed Files paths become file links.
    if (p === '/incidents' && String(path).includes('format=markdown')) {
      const md = '# Incident\n\n## Blast Radius Activity\n\n### Accessed Files\n' +
        '- `/Users/dev/.codex/sessions/2026/09/23/rollout-2026-09-23T12-53-26-demo.jsonl`\n\n### Egress Connections\n- `api.openai.com:443`\n';
      return { ok: true, status: 200, json: async () => { throw new SyntaxError('not JSON'); }, text: async () => md };
    }
    // removecadence: the gap between starting a removal and the next
    // /worktrees read lands on <pre id="remove-cadence">.
    if (MODE.includes('removecadence') && p === '/worktrees' && window.__removePostedAt && !window.__removeGap) {
      window.__removeGap = Date.now() - window.__removePostedAt;
      stamp('remove-cadence', String(window.__removeGap));
    }
    let body = data[p];
    // /costs answers by its `by` query; every /costs query lands, in order,
    // on <pre id="mock-costs">.
    if (p === '/costs') {
      const by = new URLSearchParams(String(path).split('?')[1] || '').get('by');
      if (by && data['/costs?by=' + by]) body = data['/costs?by=' + by];
      costLog.push(String(path).split('?')[1] || '');
      stamp('mock-costs', costLog.join('\n'));
      // spendcachedemo: the first two rounds (tile + card each) answer from
      // the usage cache — a 3 h old report being recomputed — then the fresh
      // one, $1 more.
      if (MODE.includes('spendcachedemo') && body) {
        body = costLog.length <= 4
          ? { ...body, refreshing: true, generated_at: iso(3 * 3600000) }
          : { ...body, generated_at: iso(0), total: { ...body.total, cost_usd: body.total.cost_usd + 1 } };
      }
      // spendslowdemo: every /costs answer takes 6 s (a report computed cold).
      if (MODE.includes('spendslowdemo')) await new Promise(r => setTimeout(r, 6000));
    }
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
      window.__sse = this;
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
    emit(kind, obj) { (this._listeners[kind] || []).forEach(fn => fn({ data: JSON.stringify(obj) })); }
    close() { clearInterval(this._timer); this.readyState = 2; stamp('sse-state', 'closed'); }
  };

  // openTab: open a view by its old or new id through the console's alias
  // table (resolveConsoleRoute), clicking the tab and sub-view buttons a
  // user would. The old Attention tab ('findings') also held the flags and
  // incidents, and the old Overview the charts: those ids expand Findings
  // history and Trends.
  const openTab = (id) => {
    const r = resolveConsoleRoute(id);
    document.querySelector(`.tab-btn[data-tab="${r.tab}"]`).click();
    if (r.sub) document.querySelector(`.subtab-btn[data-subtab="${r.sub}"]`).click();
    const group = document.getElementById({ findings: 'home-findings', overview: 'home-trends' }[id] || '');
    if (group && !group.open) group.open = true;
    return r;
  };

  // Auto-action: the plain default dump (no query string, no hash — every
  // other dump adds one or the other) is the one many checks below read for
  // content across every tab, sub-view and Home group at once. Since
  // renderAll() now only marks panels dirty and lets panelOnScreen gate the
  // actual render (a hidden panel stays unrendered until shown), that
  // single dump only has real content where a real user would: tour every
  // view once, exactly as openTab's callers do elsewhere in this file, so
  // each panel's dirty bit is cleared by an on-screen render before the
  // dump. A panel's rendered DOM persists after switching away (only the
  // `hidden` attribute toggles), so the tour then lands back on Home with
  // both groups closed — the boot-default checks (active tab, closed
  // groups, hidden tabpanels) read the same dump and must still see it.
  if (location.search === '' && location.hash === '') {
    setTimeout(() => {
      openTab('findings');
      openTab('overview');
      openTab('sessions/board');
      openTab('sessions/processes');
      openTab('sessions/resources');
      openTab('sessions/events');
      openTab('sessions/worktrees');
      openTab('egress');
      openTab('policy');
      openTab('home');
      const findings = document.getElementById('home-findings');
      const trends = document.getElementById('home-trends');
      if (findings) findings.open = false;
      if (trends) trends.open = false;
    }, 1500);
  }

  // Auto-action: exercise the session drill-down like a user click would.
  // sessionlinkdemo: flag-1 belongs to the durable session sess-claude-1;
  // open Findings, then click its "View session in timeline".
  if (location.search.includes('sessionlinkdemo')) {
    data['/flags'].find(f => f.id === 'flag-1').session_id = 'sess-claude-1';
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => document.querySelector('[data-action="filter-session"][data-session="sess-claude-1"]')?.click(), 5000);
  }
  if (location.search.includes('sessiondemo')) {
    setTimeout(() => window.filterTimelineToSession('7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77'), 4000);
  }
  // Auto-action: select a session in the session-first rail so the trace
  // waterfall renders. The Sessions tab is not the default, and the rail
  // only renders on screen, so open it before selecting.
  if (location.search.includes('raildemo')) {
    setTimeout(() => openTab('sessions'), 1500);
    setTimeout(() => window.selectSession('sess-claude-1'), 4000);
  }
  // Auto-action: Export the selected session's report into a stubbed
  // clipboard; the copied text lands on body[data-clipboard]. Fires late so
  // the toast is still on screen when the DOM is dumped.
  if (location.search.includes('exportdemo')) {
    const record = (t) => { document.body.dataset.clipboard = t; };
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (t) => record(t),
        write: async (items) => record(await (await items[0].getType('text/plain')).text())
      }
    });
    setTimeout(() => document.querySelector('.session-detail-head [data-action="copy-report"]').click(), 9000);
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
      // Poll for the drawer-hosted confirm (it opens in the click handler),
      // then accept it; the queue refresh follows.
      let n = 0;
      const iv = setInterval(() => {
        n++;
        const ok = document.getElementById('confirm-ok');
        if (ok && ok.closest('#confirm-layer') && !ok.closest('#confirm-layer').hidden) {
          ok.click();
          clearInterval(iv);
        } else if (n > 20) {
          clearInterval(iv);
        }
      }, 100);
    };
    setTimeout(() => { clickResolve(); acceptDialog(); }, 4000);
  }
  // resolvedemo: Resolve the incident from its card and accept the note
  // prompt; POST /incidents/status stamps <pre id="resolve-probe"> with the
  // attention counts and whether the queue still lists the incident — the
  // optimistic render, before any reconciliation.
  if (MODE.includes('resolvedemo')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => {
      document.querySelector('#incidents-container [data-action="incident-status"][data-status="resolved"]').click();
      let n = 0;
      const iv = setInterval(() => {
        const ok = document.getElementById('confirm-ok');
        if (ok && ok.closest('#confirm-layer') && !ok.closest('#confirm-layer').hidden) {
          ok.click();
          clearInterval(iv);
        } else if (++n > 20) {
          clearInterval(iv);
        }
      }, 100);
    }, 4500);
  }
  // stickydemo: Attention tab, scroll 5000 px; <pre id="sticky-probe"> gets
  // the tablist's top, whether the posture pill shows, and its text.
  if (MODE.includes('stickydemo')) {
    setTimeout(() => openTab('findings'), 4000);
    // Virtual time runs no frames, so the browser never dispatches the scroll
    // event a real scroll fires; dispatch it after scrolling.
    setTimeout(() => { window.scrollTo(0, 5000); window.dispatchEvent(new Event('scroll')); }, 4500);
    setTimeout(() => {
      const nav = document.querySelector('nav.tabs[role="tablist"]');
      const pill = document.getElementById('tabs-posture');
      const shown = pill && !pill.hidden && getComputedStyle(pill).display !== 'none' && pill.getBoundingClientRect().height > 0;
      stamp('sticky-probe', `top=${Math.round(nav.getBoundingClientRect().top)} scroll=${Math.round(window.scrollY)} `
        + `stuck=${document.getElementById('tabs-bar').classList.contains('is-stuck')} pill=${shown ? 'visible' : 'hidden'}:${pill ? pill.textContent.trim() : ''}`);
    }, 5500);
  }
  // drawerbackdemo: Uninspected drawer → first Evidence → Back; <pre
  // id="drawer-back-probe"> gets the back button after the chained open and
  // the drawer after the click.
  if (MODE.includes('drawerbackdemo')) {
    setTimeout(() => window.openUninspected(), 4000);
    setTimeout(() => document.querySelector('#drawer-body [data-action="endpoint-detail"]').click(), 4500);
    setTimeout(() => {
      const back = document.getElementById('btn-drawer-back');
      const chained = `chained: back=${back ? back.textContent : 'none'} title=${document.getElementById('drawer-title-text').textContent}`;
      if (back) back.click();
      setTimeout(() => {
        const rows = document.querySelectorAll('#drawer-body .egress-row').length;
        stamp('drawer-back-probe', `${chained} | back: title=${document.getElementById('drawer-title-text').textContent} rows=${rows} `
          + `button=${document.getElementById('btn-drawer-back') ? 'present' : 'absent'} open=${!document.getElementById('drawer').hidden}`);
      }, 500);
    }, 5500);
  }
  // scopedemo: Attention → first "View session in timeline" (Sessions tab),
  // then Events, then Clear on the scope bar; <pre id="scope-probe"> gets the
  // bar on Sessions, the scoped Events rows, and the bar and rows after Clear.
  if (MODE.includes('scopedemo')) {
    const bar = () => document.getElementById('scope-bar');
    const barState = () => `${bar().hidden ? 'hidden' : 'visible'}:${bar().textContent.trim()}`;
    const rows = () => document.querySelectorAll('#events-container .timeline-item').length;
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => document.querySelector('[data-action="filter-session"]').click(), 4500);
    setTimeout(() => {
      const onSessions = `tab=${document.querySelector('.tab-btn.active').dataset.tab} bar=${barState()}`;
      openTab('events');
      setTimeout(() => {
        const scoped = rows();
        document.querySelector('#scope-bar [data-action="clear-scope"]').click();
        setTimeout(() => stamp('scope-probe', `${onSessions} | scoped rows=${scoped} | cleared bar=${barState()} rows=${rows()} `
          + `chip=${document.getElementById('session-filter').hidden ? 'hidden' : 'visible'}`), 500);
      }, 500);
    }, 5500);
  }
  // Auto-action: open the uninspected-egress drill-down modal.
  if (location.search.includes('uninspecteddemo')) {
    setTimeout(() => window.openUninspected(), 4000);
  }
  // Auto-action: open the drill-down, open a vendor disclosure, then Allow an
  // unknown row. The refill that follows must keep the disclosure open.
  if (location.search.includes('keepopendemo')) {
    setTimeout(() => window.openUninspected(), 4000);
    setTimeout(() => {
      const d = document.querySelector('#drawer-body details[data-key^="vendor:"]');
      d.querySelector('summary').click();
      d.dataset.before = '1';
      document.querySelector('#drawer-body .egress-agent-group [data-action="allow-host"][data-host="statsig.example.com"]').click();
    }, 5000);
    setTimeout(() => {
      const d = document.querySelector('#drawer-body details[data-key^="vendor:"]');
      stamp('keepopen', `key=${d.dataset.key} rebuilt=${d.dataset.before ? 0 : 1} open=${d.open ? 1 : 0}`);
    }, 9000);
  }
  // Auto-action: open the endpoint Evidence detail for the unattributed IPv6.
  // Auto-action: open an incident report, then click its accessed file — the
  // file drawer opens with a way back to the report.
  if (location.search.includes('filedemo')) {
    setTimeout(() => window.openIncidentReport('inc-file-1'), 3000);
    setTimeout(() => {
      const link = document.querySelector('#drawer [data-action="open-file"]');
      stamp('file-link', link ? link.getAttribute('data-path') : 'none');
      if (link) link.click();
    }, 5000);
  }
  if (location.search.includes('endpointdemo')) {
    setTimeout(() => window.openEndpointDetail('2600:1901:0:9e23::', 'claude'), 4000);
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
  // notifyfocusdemo: typing a workspace path in the add-scope form must
  // survive a telemetry reconcile that actually changes notifyCfg — the add
  // form is static DOM outside the patched list, and 'notify' now holds
  // focus (PANEL_EL) the same as any other panel.
  if (location.search.includes('notifyfocusdemo')) {
    setTimeout(() => {
      openTab('policy');
      const input = document.getElementById('notify-scope-path');
      input.focus();
      input.value = 'in-progress-edit';
      input.dataset.probe = '1';
      data['/notify/rules'] = {
        ...data['/notify/rules'],
        overrides: { ...(data['/notify/rules'].overrides || {}), 'keychain-access': true }
      };
      document.getElementById('btn-refresh').click();
      setTimeout(() => {
        const same = document.getElementById('notify-scope-path');
        stamp('notify-focus-probe',
          `same=${same === input} value=${same.value} focused=${document.activeElement === same} probe=${same.dataset.probe}`);
      }, 2000);
    }, 1500);
  }
  // Auto-action: allow the suggested host — the suggestion must disappear.
  if (location.search.includes('allowdemo')) {
    setTimeout(() => document.querySelector('.fw-suggestion [data-action="allow-host"]').click(), 4000);
  }
  // Auto-action: dismiss the keychain flag — the card must leave the list.
  if (location.search.includes('dismissdemo')) {
    // Findings is opened first, as a user must: hidden panels do not render.
    setTimeout(() => openTab('findings'), 1500);
    setTimeout(() => document.querySelector('[data-action="dismiss-flag"][data-id="flag-3"]').click(), 4000);
  }
  // Auto-action: re-run the advisor on the first flag — the pending state
  // must show, then the fresh verdict must land and replace the chip.
  if (location.search.includes('retriagedemo')) {
    // Findings is opened first, as a user must: hidden panels do not render.
    setTimeout(() => {
      openTab('findings');
      document.querySelector('[data-action="retriage"][data-id="flag-1"]').click();
    }, 4000);
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
    // The fleet panel lives on Sessions/Processes, not the default Home tab.
    setTimeout(() => openTab('sessions/processes'), 1500);
  }
  // spenddemo: switch the Spend card to by provider, then a full refresh
  // re-renders every panel; the probe records the select and the saved view
  // after that re-render on <pre id="spend-probe">.
  if (MODE.includes('spenddemo')) {
    setTimeout(() => {
      const sel = document.getElementById('spend-by');
      sel.value = 'provider';
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    }, 4000);
    setTimeout(() => document.getElementById('btn-refresh').click(), 5000);
    setTimeout(() => {
      let saved = '';
      try { saved = sessionStorage.getItem('sa.spend-view') || ''; } catch { /* ignored */ }
      stamp('spend-probe', `select=${document.getElementById('spend-by').value} saved=${saved}`);
    }, 6000);
  }
  // spendkeepdemo (with spenddaydemo): the slow refresh keeps the Spend
  // card's nodes. Mark the first day column and scroll the narrowed day bars,
  // refresh; then switch to by repo, mark the first list row, refresh again.
  // The results land on <pre id="spend-keep-probe">.
  if (MODE.includes('spendkeepdemo')) {
    const q = sel => document.querySelector('#spend-card ' + sel);
    const costFetches = () => ((document.getElementById('mock-costs') || {}).textContent || '').split('\n').length;
    const out = [];
    let col, bars, left, fetches, row;
    setTimeout(() => {
      bars = q('.spend-bars');
      col = q('.spend-day');
      bars.style.width = '80px';
      bars.scrollLeft = 60;
      left = bars.scrollLeft;
      fetches = costFetches();
      document.getElementById('btn-refresh').click();
    }, 4000);
    setTimeout(() => {
      const now = q('.spend-bars');
      out.push(`day same=${q('.spend-day') === col && now === bars} left=${left}->${now ? now.scrollLeft : -1} refetched=${costFetches() > fetches}`);
      const sel = document.getElementById('spend-by');
      sel.value = 'repo';
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    }, 5000);
    setTimeout(() => {
      row = q('.spend-row');
      fetches = costFetches();
      document.getElementById('btn-refresh').click();
    }, 6000);
    setTimeout(() => {
      out.push(`list same=${!!row && q('.spend-row') === row} refetched=${costFetches() > fetches}`);
      stamp('spend-keep-probe', out.join('\n'));
    }, 7000);
  }
  // spendcachedemo: at 1 s (the first answers came from the usage cache)
  // record the card's notice and the tile's line on <pre id="spend-cache-probe">.
  // spendslowdemo: at 3 s (the /costs answers are still out) record the
  // agents KPI and the Spend card's text on <pre id="spend-slow-probe">.
  if (MODE.includes('spendcachedemo')) {
    setTimeout(() => {
      const n = document.getElementById('spend-cache');
      stamp('spend-cache-probe', `notice=${n.hidden ? '' : n.textContent} hint=${document.getElementById('hint-spend').textContent}`);
    }, 1000);
  }
  if (MODE.includes('spendslowdemo')) {
    setTimeout(() => {
      stamp('spend-slow-probe', `agents=${document.getElementById('count-agents').textContent} `
        + `spend=${document.getElementById('spend-card').textContent.trim()}`);
    }, 3000);
  }
  // No-spend variant: an empty /costs report — the tile reads an em dash and
  // the card shows its empty state.
  if (location.search.includes('nocostsdemo')) {
    data['/costs'] = { ...data['/costs'], total: { key: '', calls: 0, sessions: 0, tokens_in: 0, tokens_out: 0, cost_usd: 0, unpriced_calls: 0 }, rows: [] };
  }
  // plansdemo: /costs/plans reports a Codex Pro weekly window and the 24h
  // total counts plan calls — the Spend card heads its rows with the plan
  // line and bar; the stat strip says how many calls ran on plans.
  if (location.search.includes('plansdemo')) {
    data['/costs/plans'] = { plans: [{ harness: 'codex', home: 'codex', plan_type: 'pro', limit_id: 'codex',
      windows: [{ window_minutes: 10080, used_percent: 52, resets_at: iso(-3 * 24 * 3600000) }], unlimited: false, seen_at: iso(0) }] };
    data['/costs'] = { ...data['/costs'], total: { ...data['/costs'].total, plan_calls: 12 } };
  }
  // memfamilydemo: three claude sessions share root 5821 — Memory by family
  // shows one bar for that family with its session count, and the badge
  // counts agent families (5821, 4412, 6033), not sessions or infra (7001).
  if (MODE.includes('memfamilydemo')) {
    // Memory by family is a Trends chart, under the Home:Trends group.
    setTimeout(() => openTab('overview'), 1500);
    for (const n of [5, 6]) {
      data['/sessions'].push({
        id: `sess-claude-${n}`, harness: 'claude', workspace: '/Users/dev/workspace/api-service',
        repo: 'api-service', branch: 'main', root_pid: 5821,
        started_at: '2026-09-09T14:10:00Z', last_seen_at: iso(45000),
        status: 'active', confidence: 'hook'
      });
    }
  }
  // Post-mortem variant: every live session has exited, but persisted pressure
  // episodes must remain visible.
  if (location.search.includes('noresourcesdemo')) {
    data['/resources'] = { ...data['/resources'], rss_bytes: 0, cpu_percent: 0, process_count: 0, session_count: 0, sessions: [] };
    // The resource board and its flight recorder live on Sessions/Resources.
    setTimeout(() => openTab('sessions/resources'), 1500);
  }
  // familiesdemo: the Resources board at scale — twelve families: nine agent
  // families (claude 5821 and cursor 6033 need attention; two codex runs are
  // orchestrated by an OpenClaw session) and three infra, joined to /sessions
  // by root pid. The data-pipeline codex family carries twenty processes (the
  // drawer's capped table), one leftover, events and a finding.
  if (MODE.includes('familiesdemo')) {
    const GB = 1024 ** 3, MB = 1024 ** 2;
    const fam = (pid, name, workspace, rss, cpu, extra) => ({
      key: `${pid}:1789470000000000000`, name, root_pid: pid, root_started_at: '2026-09-09T13:00:00Z',
      workspace, last_seen_at: iso(30000), rss_bytes: rss, cpu_percent: cpu, process_count: 1, orphan_count: 0,
      processes: [{ pid, ppid: 1, name, rss_bytes: rss, cpu_percent: cpu, started_at: '2026-09-09T13:00:00Z' }],
      samples: [{ at: iso(1800000), rss_bytes: Math.round(rss * 0.8), cpu_percent: cpu }, { at: iso(0), rss_bytes: rss, cpu_percent: cpu }],
      diagnoses: [], ...(extra || {})
    });
    const procs = [{ pid: 4412, ppid: 1, name: 'codex', rss_bytes: 400 * MB, cpu_percent: 6, started_at: '2026-09-09T13:00:00Z' }];
    for (let i = 1; i < 20; i++) {
      procs.push({ pid: 4412 + i, ppid: i === 19 ? 777 : 4412, name: i % 2 ? 'node' : 'rg', rss_bytes: (40 + i) * MB,
        cpu_percent: i / 2, started_at: '2026-09-09T13:05:00Z', ...(i === 19 ? { is_orphan: true } : {}) });
    }
    const pipeline = fam(4412, 'codex', '/Users/dev/workspace/data-pipeline', procs.reduce((n, p) => n + p.rss_bytes, 0), 15.5,
      { processes: procs, process_count: 20, orphan_count: 1 });
    const r = data['/resources'];
    r.sessions = [
      ...r.sessions,
      pipeline,
      fam(8100, 'openclaw', '/Users/dev/.openclaw', 300 * MB, 2),
      fam(8201, 'codex', '/Users/dev/.openclaw/workspace-demo-app', 700 * MB, 12),
      fam(8202, 'codex', '/Users/dev/.openclaw/workspace-bot', 250 * MB, 4),
      fam(5950, 'claude', '/Users/dev/dev', 180 * MB, 1),
      fam(4500, 'codex', '/Users/dev/scratch', 120 * MB, 0.5),
      fam(9100, 'opencode', '/Users/dev/workspace/web-console', 90 * MB, 0.2),
      fam(7001, 'ollama', '/', 10 * GB, 3, { kind: 'infra' }),
      fam(7100, 'lm-studio', '/Applications/LM Studio.app', 3 * GB, 1, { kind: 'infra' }),
      fam(7200, 'cursor-ide', '/Applications/Cursor.app', 2 * GB, 4, { kind: 'infra' })
    ];
    r.session_count = 9;
    r.infra_count = 3;
    data['/sessions'].push(
      { id: 'sess-openclaw-1', harness: 'openclaw', workspace: '/Users/dev/.openclaw', root_pid: 8100,
        started_at: '2026-09-09T12:00:00Z', last_seen_at: iso(15000), status: 'active', confidence: 'process-tree' },
      { id: 'sess-oc-career', harness: 'codex', workspace: '/Users/dev/.openclaw/workspace-demo-app', repo: 'demo-app', branch: 'main',
        root_pid: 8201, parent_id: 'sess-openclaw-1', started_at: '2026-09-09T12:10:00Z', last_seen_at: iso(16000), status: 'active', confidence: 'transcript' },
      { id: 'sess-oc-bot', harness: 'codex', workspace: '/Users/dev/.openclaw/workspace-bot',
        root_pid: 8202, parent_id: 'sess-openclaw-1', started_at: '2026-09-09T12:20:00Z', last_seen_at: iso(17000), status: 'active', confidence: 'transcript' }
    );
    data['/events'].splice(3, 0,
      { kind: 8, ts: iso(8000), pid: 4413, detail: 'Bash → pytest -q' },
      { kind: 5, ts: iso(9000), pid: 4412, remote_host: 'api.openai.com', remote_port: 443 });
    data['/flags'].push({ id: 'flag-5', rule: 'keychain-access', agent: 'codex', pid: 4415, severity: 2, ts: iso(60000),
      evidence: [{ kind: 'keychain', label: '/Users/dev/Library/Keychains/login.keychain-db', sub: 'keychain access' }] });
    // View family on the data-pipeline row; stamp the drawer's table before
    // expanding it (or, with familyevents, follow Open in Events).
    setTimeout(() => {
      document.querySelector(`#resource-board [data-action="view-family"][data-key="${pipeline.key}"]`)?.click();
      setTimeout(() => {
        const rows = document.querySelectorAll('#drawer-body .family-proc-row').length;
        const more = document.querySelector('#drawer-body [data-action="show-more"]');
        stamp('family-probe', `rows=${rows} more=${more ? more.textContent.trim() : 'none'}`);
        if (MODE.includes('familyevents')) document.querySelector('#drawer-body [data-action="family-events"]')?.click();
        else if (more) more.click();
      }, 800);
    }, 4000);
  }
  // Phone-frame stress: the widest Resources text the board must hold at
  // 375px — a 60-character unbroken folder label, a 5-digit process count,
  // 128.0 GB of memory and 100.0% CPU on the machine strip.
  if (MODE.includes('phoneframe')) {
    const GB = 1024 ** 3;
    const r = data['/resources'];
    r.host = { ...r.host, total_memory_bytes: 128 * GB, system_cpu_percent: 100, agent_cpu_percent: 100, non_agent_cpu_percent: 100,
      swap_total_bytes: 128 * GB, swap_used_bytes: 128 * GB };
    r.sessions = [...r.sessions, {
      key: '9900:1789470000000000000', name: 'claude', root_pid: 9900, root_started_at: '2026-09-09T13:00:00Z',
      workspace: '/Users/dev/workspace/' + 'a-very-long-monorepo-folder-name-for-phone-width-stress-test'.padEnd(60, 'x'),
      last_seen_at: iso(30000), rss_bytes: 128 * GB, cpu_percent: 100, process_count: 12345, orphan_count: 0,
      estimated_reclaim_bytes: 128 * GB,
      samples: [{ at: iso(1800000), rss_bytes: 100 * GB, cpu_percent: 100 }, { at: iso(0), rss_bytes: 128 * GB, cpu_percent: 100 }],
      diagnoses: [{ code: 'heavy-memory', severity: 'critical', summary: 'Heavy memory use' }]
    }];
  }
  // manyevents: 120 loaded events — the Events tab shows the newest 50.
  if (MODE.includes('manyevents')) {
    for (let i = 0; i < 114; i++) {
      data['/events'].push({ kind: 0, ts: iso(40000 + i * 1000), pid: 5821, path: `/Users/dev/workspace/api-service/src/m${i}.ts` });
    }
  }
  // traceevents: a model_call and a tool_call as the trace collectors write
  // them — pid 0, a session id, no path or detail.
  if (MODE.includes('traceevents')) {
    data['/events'].push(
      { kind: 14, ts: iso(90000), pid: 0, session_id: 'sess-claude-1', model: 'claude-sonnet-4-5', tokens_in: 12000, tokens_out: 340, cost_usd: 0.0412, price_class: 'priced' },
      { kind: 12, ts: iso(91000), pid: 0, session_id: 'sess-claude-1', tool: 'Bash', tool_status: 'ok', duration_ms: 2500, call_id: 'c-1' });
  }
  // duptrace: two tool_call rows at the identical ts with different call
  // ids — eventKey must key on call_id, not collapse them into one row.
  if (MODE.includes('duptrace')) {
    data['/events'].push(
      { kind: 12, ts: iso(92000), pid: 0, session_id: 'sess-claude-1', tool: 'Read', tool_status: 'ok', duration_ms: 10, call_id: 'dup-1' },
      { kind: 12, ts: iso(92000), pid: 0, session_id: 'sess-claude-1', tool: 'Write', tool_status: 'ok', duration_ms: 20, call_id: 'dup-2' });
  }
  // eventsorderdemo: events arrive out of ts order, one stamped ~4 months
  // old — the render must sort them newest first and date the old row.
  if (MODE.includes('eventsorderdemo')) {
    data['/events'] = [
      { kind: 0, ts: iso(1000), pid: 5821, path: '/Users/dev/workspace/api-service/src/new.ts' },
      { kind: 0, ts: iso(4 * 30 * 86400000), pid: 5821, path: '/Users/dev/workspace/api-service/src/old.ts' },
      { kind: 0, ts: iso(2000), pid: 5821, path: '/Users/dev/workspace/api-service/src/mid.ts' },
    ];
  }
  // Episodes live on their own endpoint now.
  data['/resources/episodes'] = (data['/resources'].episodes || []);

  // Worktree hunter report: a row per state; one reason carries markup that
  // must render as text.
  const WT_REPO = '/Users/dev/workspace/api-service';
  data['/worktrees'] = {
    generated_at: iso(0), duration_ms: 4200, cached: false, stale_days: 14,
    summary: { repos: 1, worktrees: 4, remove: 1, review: 1, keep: 1, prune: 1, stale: 2, size_bytes: 1612709888, removable_bytes: 1610612736 },
    volumes: [{ mount: '/Volumes/Work', total_bytes: 2199023255552, free_bytes: 549755813888 }],
    reclaimed: { bytes: 3221225472, count: 3, bytes_30d: 1073741824, count_30d: 1 },
    repos: [{
      path: WT_REPO, source: 'session', default_branch: 'origin/main', size_bytes: 1612709888, worktrees: [
        { path: WT_REPO, branch: 'main', state: 'main', reasons: ['main worktree of the repository'], idle_days: 0 },
        { path: WT_REPO + '/.worktrees/done', branch: 'feat/done', state: 'remove', stale: true, last_activity: iso(21 * 86400000), idle_days: 21, size_bytes: 1610612736, reasons: ['merged into origin/main (squash)'] },
        { path: WT_REPO + '/.worktrees/evidence', branch: 'feat/evidence', state: 'review', last_activity: iso(3600000), idle_days: 0, reasons: ['ignored files that only live here: .tmp/ (3 files, 1.2 MB)', '<b>not bold</b>'] },
        { path: '/Users/dev/.codex/worktrees/ab12/api-service', branch: '', detached: true, state: 'keep', last_activity: iso(60000), idle_days: 0, reasons: ['2 uncommitted changes', 'an agent session is live here'] },
        { path: WT_REPO + '/.worktrees/gone', branch: 'feat/gone', state: 'prune', stale: true, idle_days: 0, reasons: ['directory is gone; git still lists it'] }
      ]
    }],
    errors: [],
    advice: {
      [WT_REPO + '/.worktrees/evidence']: { assessment: 'review', confidence: 0.6, rationale: '<i>look</i> at .tmp before removing' }
    },
    asks: {
      [WT_REPO + '/.worktrees/evidence']: { harness: 'claude', status: 'answered', verdict: 'pr', detail: 'https://github.com/o/r/pull/9', cost_usd: 0.21 }
    }
  };
  // Cleanup ledger: three rows (one older than the charted days); the daily
  // series is bucketed from the rows by local day, like the daemon's, and a
  // removal the mock completes books a row (bookCleanup).
  const ledgerEntries = [
    { id: 3, ts: iso(2 * 86400000), action: 'worktree-remove', path: WT_REPO + '/.worktrees/shipped', repo: WT_REPO, bytes: 1073741824, detail: 'branch feat/shipped kept; merged into origin/main (squash)' },
    { id: 2, ts: iso(2 * 86400000 + 60000), action: 'trash:orphan-worktree', path: '/Users/dev/.cursor/worktrees/api-service/ab', repo: WT_REPO, bytes: 52428800 },
    { id: 1, ts: iso(40 * 86400000), action: 'worktree-remove', path: WT_REPO + '/.worktrees/old', repo: WT_REPO, bytes: 2147483648, detail: '<b>branch</b> feat/old kept' },
  ];
  const ledgerTotals = { bytes: 3221225472, count: 2, bytes_30d: 1073741824, count_30d: 1, trashed_bytes: 52428800, trashed_count: 1 };
  bookCleanup = (e) => {
    ledgerEntries.unshift({ id: ledgerEntries.length + 1, ...e });
    ledgerTotals.bytes += e.bytes;
    ledgerTotals.count += 1;
    ledgerTotals.bytes_30d += e.bytes;
    ledgerTotals.count_30d += 1;
  };
  const localKey = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  Object.defineProperty(data, '/cleanup/ledger', { configurable: true, get: () => {
    const today = new Date();
    const daily = Array.from({ length: 30 }, (_, i) => ({
      day: localKey(new Date(today.getFullYear(), today.getMonth(), today.getDate() - 29 + i)), bytes: 0, trashed_bytes: 0, count: 0 }));
    for (const e of ledgerEntries) {
      const d = daily.find(x => x.day === localKey(new Date(e.ts)));
      if (!d) continue;
      if (e.action.startsWith('trash:')) { d.trashed_bytes += e.bytes; d.trashed_count = (d.trashed_count || 0) + 1; }
      else { d.bytes += e.bytes; d.count++; }
    }
    return { totals: { ...ledgerTotals }, daily, entries: ledgerEntries.slice() };
  } });

  // Clutter inventory: a repo .tmp, a tool cache with a clean command and a
  // list-only one whose note carries markup that must render as text.
  data['/cleanup'] = {
    generated_at: iso(0), sizing: false,
    items: [
      { id: 'tool-cache:/Users/dev/Library/Caches/go-build', kind: 'tool-cache', name: 'go build', path: '/Users/dev/Library/Caches/go-build', size_bytes: 8589934592, last_touched: iso(86400000), idle_days: 1, action: 'clean', command: 'go clean -cache' },
      { id: 'tmp:' + WT_REPO + '/.tmp', kind: 'tmp', name: '.tmp', path: WT_REPO + '/.tmp', project: WT_REPO, size_bytes: 1048576, last_touched: iso(22 * 86400000), idle_days: 22, action: 'trash' },
      { id: 'tool-cache:/Users/dev/.cache/huggingface', kind: 'tool-cache', name: 'Hugging Face models', path: '/Users/dev/.cache/huggingface', size_bytes: 1024, action: 'none', note: '<i>downloaded</i> models' },
    ],
    kinds: [{ kind: 'tmp', bytes: 1048576, count: 1 }, { kind: 'tool-cache', bytes: 8589935616, count: 2 }],
    projects: [],
    reclaimed: { bytes: 0, count: 0, bytes_30d: 0, count_30d: 0, trashed_bytes: 0, trashed_count: 0 },
    advice: { [WT_REPO]: { rationale: '<b>Old</b> scratch holds most of it.', suggested_action: 'Move .tmp to the Trash\nAsk the agent about feat/x' } },
  };
  // clutteradvise: Ask advisor on the machine group; the plan must appear
  // under it once the re-read sees it.
  if (MODE.includes('clutteradvise')) {
    const iv = setInterval(() => {
      const btn = document.querySelector('#clutter-container [data-action="clutter-advise"][data-project="machine"]');
      if (btn) { clearInterval(iv); btn.click(); }
    }, 200);
  }
  if (MODE.includes('clutterdemo')) {
    setTimeout(() => {
      const btn = document.querySelector('#clutter-container [data-action="clutter-trash"]');
      if (btn) btn.click();
      let n = 0;
      const iv = setInterval(() => {
        const ok = document.getElementById('confirm-ok');
        if (ok && ok.closest('#confirm-layer') && !ok.closest('#confirm-layer').hidden) {
          ok.click();
          clearInterval(iv);
        } else if (++n > 20) {
          clearInterval(iv);
        }
      }, 100);
    }, 4000);
  }
  // batchdemo: three removable worktrees in one repository; Remove all
  // removes them after one dialog.
  if (MODE.includes('batchdemo')) {
    const repo = data['/worktrees'].repos[0];
    const done = repo.worktrees.find(w => w.state === 'remove');
    repo.worktrees.push({ ...done, path: WT_REPO + '/.worktrees/old-a', branch: 'feat/old-a' }, { ...done, path: WT_REPO + '/.worktrees/old-b', branch: 'feat/old-b' });
    setTimeout(() => {
      const btn = document.querySelector('#worktrees-container [data-action="worktree-remove-all"]');
      if (btn) btn.click();
      let n = 0;
      const iv = setInterval(() => {
        const ok = document.getElementById('confirm-ok');
        if (ok && ok.closest('#confirm-layer') && !ok.closest('#confirm-layer').hidden) {
          ok.click();
          clearInterval(iv);
        } else if (++n > 20) {
          clearInterval(iv);
        }
      }, 100);
    }, 3000);
  }
  // orphandemo: a repository that moved away leaves a folder pointing at it;
  // orphantrash moves the folder to the Trash from its row.
  if (MODE.includes('orphandemo')) {
    const rep = data['/worktrees'];
    rep.repos.push({ path: '/Users/dev/gone-app', error: 'repository not found (moved or deleted)', size_bytes: 0, worktrees: [
      { path: '/Users/dev/.cursor/worktrees/gone-app/ctnj', state: 'review', orphan: true, reasons: ['directory is not registered with git; its files are the only copy'] },
    ] });
    rep.errors = ['/Users/dev/gone-app: repository not found (moved or deleted); 1 folder still points to it (listed first below)'];
    if (MODE.includes('orphantrash')) {
      setTimeout(() => {
        const btn = document.querySelector('#worktrees-container [data-action="worktree-trash-orphan"]');
        if (btn) btn.click();
        let n = 0;
        const iv = setInterval(() => {
          const ok = document.getElementById('confirm-ok');
          if (ok && ok.closest('#confirm-layer') && !ok.closest('#confirm-layer').hidden) {
            ok.click();
            clearInterval(iv);
          } else if (++n > 20) {
            clearInterval(iv);
          }
        }, 100);
      }, 4000);
    }
  }
  // refreshdemo: the first /worktrees and /cleanup answer from an old cached
  // scan while the daemon rescans; the tab must re-read until it lands.
  if (MODE.includes('refreshdemo')) {
    const freshW = data['/worktrees'];
    const oldW = JSON.parse(JSON.stringify(freshW));
    Object.assign(oldW, { cached: true, refreshing: true, generated_at: iso(3 * 3600000) });
    oldW.repos[0].worktrees = oldW.repos[0].worktrees.concat([{ ...oldW.repos[0].worktrees[1], path: WT_REPO + '/.worktrees/gone-since', branch: 'feat/gone' }]);
    let wReads = 0;
    Object.defineProperty(data, '/worktrees', { get: () => (wReads++ === 0 ? oldW : freshW) });
    const freshC = data['/cleanup'];
    const oldC = { ...JSON.parse(JSON.stringify(freshC)), refreshing: true };
    let cReads = 0;
    Object.defineProperty(data, '/cleanup', { get: () => (cReads++ === 0 ? oldC : freshC) });
  }
  // sizingdemo: the first /worktrees answers still sizing with no sizes;
  // the tab must re-read until the sizes land.
  if (MODE.includes('sizingdemo')) {
    const sized = data['/worktrees'];
    const pending = JSON.parse(JSON.stringify(sized));
    pending.sizing = true;
    pending.summary.size_bytes = 0;
    pending.summary.removable_bytes = 0;
    for (const r of pending.repos) { r.size_bytes = 0; for (const w of r.worktrees) delete w.size_bytes; }
    let reads = 0;
    Object.defineProperty(data, '/worktrees', { get: () => (reads++ === 0 ? pending : sized) });
  }
  // worktreedemo: Remove the removable worktree and accept the dialog; the
  // row must leave the tab without a rescan.
  if (MODE.includes('worktreedemo')) {
    setTimeout(() => {
      const btn = document.querySelector('#worktrees-container [data-action="worktree-remove"]');
      if (btn) btn.click();
      let n = 0;
      const iv = setInterval(() => {
        const ok = document.getElementById('confirm-ok');
        if (ok && ok.closest('#confirm-layer') && !ok.closest('#confirm-layer').hidden) {
          ok.click();
          clearInterval(iv);
        } else if (++n > 20) {
          clearInterval(iv);
        }
      }, 100);
    }, 4000);
  }

  // Confirm the next dialog (the console's saConfirm layer).
  const confirmNext = () => {
    let n = 0;
    const iv = setInterval(() => {
      const ok = document.getElementById('confirm-ok');
      if (ok && ok.closest('#confirm-layer') && !ok.closest('#confirm-layer').hidden) {
        ok.click();
        clearInterval(iv);
      } else if (++n > 20) {
        clearInterval(iv);
      }
    }, 100);
  };
  // removeremovabledemo: three removable rows in one repository and one in
  // another; the Removable now tile's Remove all removes all four.
  if (MODE.includes('removeremovabledemo')) {
    const repo = data['/worktrees'].repos[0];
    const done = repo.worktrees.find(w => w.state === 'remove');
    repo.worktrees.push({ ...done, path: WT_REPO + '/.worktrees/old-a', branch: 'feat/old-a' }, { ...done, path: WT_REPO + '/.worktrees/old-b', branch: 'feat/old-b' });
    data['/worktrees'].repos.push({ path: '/Users/dev/workspace/web-app', size_bytes: 1610612736, worktrees: [
      { path: '/Users/dev/workspace/web-app', branch: 'main', state: 'main', reasons: [] },
      { ...done, path: '/Users/dev/workspace/web-app/.worktrees/landed', branch: 'feat/landed' }] });
    setTimeout(() => {
      stamp('removable-tile', (document.querySelector('.rc-removable') || {}).textContent || '');
      const btn = document.querySelector('#worktrees-reclaim [data-action="worktrees-remove-removable"]');
      if (btn) btn.click();
      confirmNext();
    }, 3000);
  }
  // historydemo: History opens the cleanup history in the drawer; then the
  // Removed chip filters it. reclaimdaydemo: a chart column opens it at
  // that day.
  if (MODE.includes('historydemo')) {
    setTimeout(() => document.querySelector('[data-action="worktrees-history"]').click(), 3000);
    setTimeout(() => {
      stamp('history-all', (document.getElementById('drawer-body') || {}).innerHTML || '');
      const chip = document.querySelector('#drawer-body [data-action="history-kind"][data-kind="removed"]');
      if (chip) chip.click();
    }, 4500);
  }
  if (MODE.includes('reclaimdaydemo')) {
    setTimeout(() => {
      const col = document.querySelector('#worktrees-reclaim [data-action="reclaim-day"]');
      if (col) {
        col.dispatchEvent(new PointerEvent('pointerover', { bubbles: true }));
        const tip = document.getElementById('reclaim-tip');
        stamp('reclaim-tip-probe', tip && !tip.hidden ? tip.textContent : 'hidden');
        col.click();
      }
    }, 3000);
  }
  // wtsearchdemo: the search box keeps the rows whose branch, folder or
  // repository matches.
  if (MODE.includes('wtsearchdemo')) {
    setTimeout(() => {
      const input = document.getElementById('worktree-search');
      input.value = 'EVIDENCE';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }, 3000);
  }
  // removecadence: sizes never land, so a 5 s re-read is always pending;
  // Remove is clicked right after one. The removal's first re-read must
  // come on its own 1.5 s cadence, not the pending 5 s one.
  if (MODE.includes('removecadence')) {
    const rep = data['/worktrees'];
    rep.sizing = true;
    let clicked = false;
    let reads = 0;
    const orig = Object.getOwnPropertyDescriptor(data, '/worktrees');
    Object.defineProperty(data, '/worktrees', { configurable: true, get: () => {
      reads++;
      if (reads === 2 && !clicked) {
        clicked = true;
        setTimeout(() => {
          const btn = document.querySelector('#worktrees-container [data-action="worktree-remove"]');
          if (btn) btn.click();
          confirmNext();
        }, 50);
      }
      return orig && orig.get ? orig.get() : rep;
    } });
  }
  // adoptdemo: a removal started elsewhere is running when the tab opens;
  // the progress toast follows it without a click.
  if (MODE.includes('adoptdemo')) {
    const p = WT_REPO + '/.worktrees/done';
    data['/worktrees'].removals = { [p]: { path: p, state: 'running', phase: 'checking', step: 'checking it is still safe to remove', started_at: iso(5000), step_at: iso(1000) } };
  }

  // Auto-action: demote a blocking rule — it must flip back to Promote.
  if (location.search.includes('demotedemo')) {
    // The firewall rule list lives on the Egress tab, not the default Home tab.
    setTimeout(() => openTab('egress'), 1500);
    setTimeout(() => document.querySelector('[data-action="demote"][data-rule="aws-key"]').click(), 4000);
  }
  // Auto-action: remove an allowlist entry — the row must leave the list.
  if (location.search.includes('allowlistdemo')) {
    setTimeout(() => document.querySelector('[data-action="allowlist-remove"]').click(), 4000);
  }

  // Quiet machine: no sessions and no agents — the rail's empty state. The
  // Sessions tab is not active by default, and the rail only renders once
  // it is on screen (renderAll no longer paints hidden panels), so open it.
  if (location.search.includes('quietdemo')) {
    data['/sessions'] = [];
    data['/status'] = { ...data['/status'], agents: [], trees: [] };
    setTimeout(() => openTab('sessions'), 1500);
  }
  // Auto-action: type a filter that matches nothing — the rail must say so
  // and offer to clear it. Sessions is not the default tab, so open it
  // before typing: the rail only renders on screen.
  if (location.search.includes('nomatchdemo')) {
    setTimeout(() => openTab('sessions'), 1500);
    setTimeout(() => {
      const q = document.getElementById('session-cwd-filter');
      q.value = 'no-such-repo';
      q.dispatchEvent(new Event('input', { bubbles: true }));
    }, 4000);
  }
  // Auto-action: switch the claude harness pill off — its group must leave
  // the Sessions rail and the Agents list (one shared filter state). Both
  // live on the Sessions tab (board and processes sub-views), not the
  // default Home tab, so open both before the toggle click, and re-show the
  // board (where the pill itself lives) afterward so its state renders too.
  if (location.search.includes('pilldemo')) {
    setTimeout(() => { openTab('sessions/processes'); openTab('sessions/board'); }, 1500);
    setTimeout(() => document.querySelector('#session-harness-pills [data-action="toggle-harness"][data-harness="claude"]').click(), 4000);
    setTimeout(() => openTab('sessions/processes'), 4300);
  }
  // Phone-width probe. Headless Chrome will not size its window below 500px,
  // so ?phonedemo frames the console in a 375px iframe. The framed copy
  // (?phoneframe) opens Sessions, Agents, then Resources, measures how far any box in
  // the tab panel, or the page as a whole (posture banner included), reaches
  // past the viewport, and posts it back; the result lands on
  // <body data-hscroll="sessions:N,agents:N,resources:N"> (N in px, 0 = fits).
  if (MODE.includes('phoneframe')) {
    // Content inside a horizontal scroller (the Sessions sub-view control)
    // is clipped by it, so the scroller's own box is what must fit.
    const measure = (tab) => {
      const panel = document.getElementById('tab-' + openTab(tab).tab);
      const width = document.documentElement.clientWidth;
      let past = 0;
      for (const el of [panel, ...panel.querySelectorAll('*')]) {
        if (el.parentElement && el.parentElement.closest('.subtabs')) continue;
        const box = el.getBoundingClientRect();
        if (box.width) past = Math.max(past, box.right - width);
      }
      past = Math.max(past, document.documentElement.scrollWidth - width);
      return `${tab}:${Math.round(past)}`;
    };
    setTimeout(() => {
      const sessions = measure('sessions');
      setTimeout(() => {
        const agents = measure('agents');
        setTimeout(() => {
          const resources = measure('resources');
          // patterndemo: the Attention/Flags tab holding the pattern card.
          const done = findings => parent.postMessage({ hscroll: `${sessions},${agents},${resources}${findings}` }, '*');
          if (MODE.includes('patterndemo')) setTimeout(() => done(',' + measure('findings')), 300);
          else if (MODE.includes('spenddaydemo')) setTimeout(() => done(',' + measure('overview')), 300);
          else done('');
        }, 300);
      }, 300);
    }, 4000);
  } else if (MODE.includes('phonedemo')) {
    addEventListener('message', (e) => {
      if (e.data && e.data.hscroll) document.body.dataset.hscroll = e.data.hscroll;
    });
    document.addEventListener('DOMContentLoaded', () => {
      const frame = document.createElement('iframe');
      frame.width = '375';
      frame.height = '812';
      frame.src = 'harness.html?phoneframe&raildemo' + (MODE.includes('patterndemo') ? '&patterndemo' : '')
        + (MODE.includes('spenddaydemo') ? '&spenddaydemo' : '');
      document.body.prepend(frame);
    });
  }
  // CSP probe: run_dom_tests.py serves ?cspdemo&raildemo with the daemon's
  // Content-Security-Policy header. Once the rail has selected a session,
  // this opens the tab holding each percentage-sized bar and records its
  // rendered width as a percent of its track on <body data-csp-widths=
  // "wf-bar:N,hbar-fill:N,resource-host-segment:N"> — the first tool bar,
  // the smallest ranked bar, the agent memory segment.
  if (MODE.includes('cspdemo')) {
    const probes = [
      ['wf-bar', 'sessions', '.wf-bar'],
      ['hbar-fill', 'overview', '#chart-memory .hbar-row:last-child .hbar-fill'],
      ['resource-host-segment', 'resources', '.resource-host-segment.agent'],
    ];
    const widths = [];
    const next = () => {
      const [name, tab, sel] = probes[widths.length];
      openTab(tab);
      setTimeout(() => {
        const el = document.querySelector(sel);
        const pct = el ? el.getBoundingClientRect().width / el.parentElement.getBoundingClientRect().width * 100 : -1;
        widths.push(`${name}:${pct.toFixed(1)}`);
        if (widths.length < probes.length) next();
        else document.body.dataset.cspWidths = widths.join(',');
      }, 300);
    };
    setTimeout(next, 5000);
  }
  // Posture banner off Home: 3 items and "and N more"; the link lands on Home,
  // where the banner lists nothing.
  if (location.search.includes('posturemoredemo')) {
    const banner = () => {
      const ul = document.getElementById('posture-items');
      const more = ul.querySelector('.posture-more a');
      return `items=${ul.querySelectorAll('.posture-item').length} more=${more ? more.textContent : 'none'} hidden=${ul.hidden ? 1 : 0}`;
    };
    setTimeout(() => openTab('egress'), 1500);
    setTimeout(() => {
      stamp('posture-egress', banner());
      document.querySelector('#posture-items .posture-more a').click();
    }, 4000);
    setTimeout(() => stamp('posture-home', `tab=${document.querySelector('.tab-btn.active').dataset.tab} ${banner()}`), 6000);
  }
  // Egress fold: 2 rules with hits stay listed, 20 quiet rules fold into one
  // row; the open fold survives an SSE-driven refetch that changes its count.
  if (location.search.includes('folddemo')) {
    const fs = {
      'hit-a': { type: 'vendor-key', mode: 'monitor', would_block: 3, blocked: 0, legit: 1 },
      'hit-b': { type: 'cloud-key', mode: 'monitor', would_block: 0, blocked: 0, legit: 2 },
    };
    for (let i = 0; i < 20; i++) fs['quiet-' + String(i).padStart(2, '0')] = { type: 'env-value', mode: 'monitor', would_block: 0, blocked: 0, legit: 0 };
    data['/status'].firewall_stats = fs;
    const fold = () => document.querySelector('#firewall-container > details.fw-fold');
    const probe = () => {
      const c = document.getElementById('firewall-container');
      const d = fold();
      return `top=${c.querySelectorAll(':scope > .fw-rule [data-rule]').length} `
        + `fold=${d ? d.querySelector('summary').textContent : 'none'} inside=${d ? d.querySelectorAll('[data-action="promote"]').length : 0} `
        + `open=${d && d.open ? 1 : 0} rebuilt=${d && d.dataset.before ? 0 : 1}`;
    };
    let focusedPromote = null;
    setTimeout(() => openTab('egress'), 1500);
    setTimeout(() => {
      stamp('fold-before', probe());
      const d = fold();
      d.open = true;
      d.dataset.before = '1';
      // Focus an UNCHANGED quiet rule's Promote button, then change a
      // DIFFERENT quiet rule's counters (moving it out of the fold) — the
      // focused button must survive as the same node, still focused.
      focusedPromote = d.querySelector('[data-rule="quiet-01"][data-action="promote"]');
      if (focusedPromote) focusedPromote.focus();
      data['/status'].firewall_stats['quiet-00'].legit = 1;
      window.__sse.emit('guard-resolved', {});
    }, 4000);
    setTimeout(() => {
      stamp('fold-after', probe());
      const kept = !!focusedPromote && document.contains(focusedPromote) && document.activeElement === focusedPromote;
      stamp('fold-focus', `kept=${kept ? 1 : 0}`);
    }, 7000);
  }
  // Processes fills the width: panel width vs sub-view width at 1440 px.
  if (location.search.includes('procwidthdemo')) {
    setTimeout(() => openTab('sessions/processes'), 1500);
    setTimeout(() => {
      const sub = document.getElementById('sub-processes');
      const panel = sub.querySelector('.panel');
      stamp('proc-width', `panel=${Math.round(panel.getBoundingClientRect().width)} content=${Math.round(sub.getBoundingClientRect().width)} viewport=${window.innerWidth}`);
    }, 4000);
  }
  // Auto-action: switch to the Egress tab — panels must hide/show correctly.
  if (location.search.includes('tabdemo')) {
    setTimeout(() => openTab('egress'), 4000);
  }
  // Auto-action: switch to a named tab once telemetry has landed, then hold
  // long enough for a screenshot — ?tab=<name> for visual QA. ?shot also
  // hides everything above the tab bar so the tab fills the frame (headless
  // --screenshot captures from the top of the page and ignores scrolling).
  {
    const params = new URLSearchParams(location.search);
    const tab = params.get('tab');
    if (tab) {
      setTimeout(() => {
        openTab(tab);
        const bar = document.querySelector('.tabs-bar') || document.querySelector('nav.tabs');
        if (params.has('shot') && bar) {
          for (let el = bar.previousElementSibling; el; el = el.previousElementSibling) el.style.display = 'none';
        }
      }, 1500);
    }
  }
  // Auto-action: save a view, type a search, then apply the view — exercises
  // the saved-view + search paths through the real UI.
  if (location.search.includes('viewdemo')) {
    setTimeout(() => {
      document.getElementById('btn-views').click();
      document.getElementById('view-name').value = 'Prod leaks';
      document.querySelector('[data-action="save-view"]').click();
      setTimeout(() => {
        const s = document.getElementById('global-search');
        s.value = 'npm';
        s.dispatchEvent(new Event('input', { bubbles: true }));
        // Reopen the popover so the saved view is visible in the dump.
        document.getElementById('views-pop').hidden = false;
      }, 300);
    }, 4000);
  }
  // Auto-action: select a session, open the resource policy editor, and add
  // its workspace as an override through the real delegated click path.
  if (location.search.includes('policydemo')) {
    // The resource board (and its family drawer) lives on Sessions/Resources.
    setTimeout(() => openTab('sessions/resources'), 1500);
    setTimeout(() => {
      document.querySelector('[data-action="view-family"]').click();
      document.querySelector('[data-action="edit-resource-policy"]').click();
      document.querySelector('[data-action="add-resource-override"][data-source="current"]').click();
      document.querySelector('[data-policy-default="true"] [data-policy-field="mode"]').value = 'terminate';
      document.querySelector('#drawer-foot [data-action="policy-save"]').click();
    }, 4000);
  }

  // ---------- SSE burst (render engine) ----------
  // The live rate that rebuilt every panel ~8x/s: 300 kind-0 event frames
  // (distinct paths) and 3 flag frames over 2s of virtual time. extra(i) runs
  // with each flag frame (variants add session frames).
  const burst = (extra) => {
    const es = window.__sse;
    let n = 0;
    const iv = setInterval(() => {
      for (let k = 0; k < 3; k++, n++) {
        es.emit('event', { kind: 0, pid: 5821, ts: new Date().toISOString(), path: `/Users/dev/workspace/api-service/src/f${n}.ts` });
      }
      if (n >= 300) clearInterval(iv);
    }, 20);
    [500, 1000, 1500].forEach((t, i) => setTimeout(() => {
      es.emit('flag', { id: `flag-burst-${i}`, rule: 'proxy-secret-leak', agent: 'cursor', pid: 6033, severity: 2,
        evidence: [{ kind: 'connect', label: `burst${i}.example.com:443`, sub: 'destination' }] });
      if (extra) extra(i);
    }, t));
  };
  const renderCounts = () => (window.SA && window.SA.renderCounts) ? { ...window.SA.renderCounts } : null;
  // burstdemo: Findings open, burst; <pre id="render-counts"> gets the
  // per-panel render-count delta over the burst (or "missing").
  if (MODE.includes('burstdemo')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => {
      const before = renderCounts();
      burst();
      setTimeout(() => {
        const after = renderCounts();
        if (!before || !after) { stamp('render-counts', 'missing'); return; }
        const delta = {};
        for (const k of Object.keys(after)) delta[k] = after[k] - (before[k] || 0);
        stamp('render-counts', JSON.stringify(delta));
      }, 2600);
    }, 4500);
  }
  // memprobe: Overview open, every Memory by family row probed, then the same
  // session re-emitted three times. <pre id="mem-probe"> gets the chart-memory
  // renders in between and how many probed rows are still connected.
  if (MODE.includes('memprobe')) {
    setTimeout(() => openTab('overview'), 3500);
    setTimeout(() => {
      const rows = Array.from(document.querySelectorAll('#chart-memory .hbar-row'));
      rows.forEach(r => { r.dataset.probe = '1'; });
      const before = renderCounts();
      const s = { ...data['/sessions'].find(x => x.id === 'sess-claude-1') };
      delete s._timeline;
      [0, 400, 800].forEach(t => setTimeout(() => window.__sse.emit('session', s), t));
      setTimeout(() => {
        const after = renderCounts();
        const renders = before && after ? (after['chart-memory'] || 0) - (before['chart-memory'] || 0) : -1;
        stamp('mem-probe', `renders=${renders} kept=${rows.filter(r => r.isConnected).length}/${rows.length}`);
      }, 2000);
    }, 4300);
  }
  // dupdemo: five codex sessions spawned by the openclaw agent quill on one
  // repo@branch, and three by fennel with resource families. The rail folds
  // each set into one "×N" row. Sessions: the quill row is expanded, a
  // member selected, then session frames patch the rail; <pre id="dup-probe">
  // reports the row's patchList key, whether it stayed open and the selected
  // cards. With tab=resources the families fold the same way.
  if (MODE.includes('dupdemo')) {
    const MB = 1024 ** 2;
    for (let i = 1; i <= 5; i++) {
      data['/sessions'].push({ id: `sess-dup-${i}`, harness: 'codex', workspace: '/Users/dev/.openclaw/workspace-demo-app',
        repo: 'demo-app', branch: 'main', origin: 'quill (openclaw)',
        started_at: new Date(now - i * 600000).toISOString(), last_seen_at: iso(20000 + i * 1000),
        status: i === 2 ? 'active' : 'idle', confidence: 'transcript' });
    }
    for (let i = 1; i <= 3; i++) {
      const pid = 8300 + i;
      data['/sessions'].push({ id: `sess-marg-${i}`, harness: 'codex', workspace: '/Users/dev/.openclaw', origin: 'fennel (openclaw)',
        root_pid: pid, started_at: new Date(now - i * 900000).toISOString(), last_seen_at: iso(25000 + i * 1000),
        status: 'active', confidence: 'transcript' });
      data['/resources'].sessions.push({ key: `${pid}:1789470000000000000`, name: 'codex', root_pid: pid,
        root_started_at: '2026-09-09T13:00:00Z', workspace: '/Users/dev/.openclaw', last_seen_at: iso(30000),
        rss_bytes: 100 * i * MB, cpu_percent: i, process_count: i, orphan_count: 0,
        processes: [{ pid, ppid: 1, name: 'codex', rss_bytes: 100 * i * MB, cpu_percent: i }], samples: [], diagnoses: [] });
    }
    if (!MODE.includes('tab=resources') && !MODE.includes('foldpatch')) {
      const quill = 'group:codex|demo-app@main · quill';
      setTimeout(() => openTab('sessions'), 4000);
      setTimeout(() => {
        document.querySelector(`#session-rail [data-action="toggle-session-dup"][data-key="${quill}"]`)?.click();
        setTimeout(() => document.querySelector('#session-rail [data-action="select-session"][data-id="sess-dup-3"]')?.click(), 300);
        setTimeout(() => {
          const four = data['/sessions'].find(x => x.id === 'sess-dup-4');
          window.__sse.emit('session', { ...four, last_seen_at: new Date().toISOString(), status: 'active' });
          const claude = { ...data['/sessions'].find(x => x.id === 'sess-claude-1') };
          delete claude._timeline;
          window.__sse.emit('session', { ...claude, last_seen_at: new Date().toISOString() });
        }, 1200);
        setTimeout(() => {
          const row = Array.from(document.querySelectorAll('#session-rail .session-dup'))
            .find(n => n.querySelector(`[data-key="${quill}"]`));
          const selected = Array.from(document.querySelectorAll('#session-rail .session-card.selected [data-action="select-session"]')).map(b => b.dataset.id);
          stamp('dup-probe', JSON.stringify({ key: row ? row._saKey : null, open: !!(row && row.classList.contains('open')), selected }));
        }, 3000);
      }, 4300);
    }
  }
  // foldpatch (with dupdemo): two ended sessions share the live quill
  // title, so the codex group holds a live and an ended fold with one key.
  // The ended fold is expanded, the live fold's toggle focused, then a frame
  // ends another codex session; the probe waits out the render engine's
  // 3 s focus hold. <pre id="fold-probe">: focus kept, the group the same
  // open node, each fold's aria-expanded, the head counts around it.
  if (MODE.includes('dupdemo') && MODE.includes('foldpatch')) {
    for (let i = 6; i <= 7; i++) {
      data['/sessions'].push({ id: `sess-dup-${i}`, harness: 'codex', workspace: '/Users/dev/.openclaw/workspace-demo-app',
        repo: 'demo-app', branch: 'main', origin: 'quill (openclaw)',
        started_at: new Date(now - i * 600000).toISOString(), last_seen_at: iso(40000 + i * 1000),
        ended_at: iso(40000 + i * 1000), status: 'ended', confidence: 'transcript' });
    }
    const quill = 'group:codex|demo-app@main · quill';
    const rail = () => document.getElementById('session-rail');
    const fold = (bucket) => rail().querySelector(`[data-action="toggle-session-dup"][data-bucket="${bucket}"][data-key="${quill}"]`);
    setTimeout(() => openTab('sessions'), 4000);
    setTimeout(() => {
      rail().querySelector('[data-action="toggle-ended-sessions"][data-harness="codex"]')?.click();
      setTimeout(() => fold('ended')?.click(), 200);
      setTimeout(() => {
        const group = rail().querySelector('details.session-group[data-harness="codex"]');
        const btn = fold('live');
        if (group) group.dataset.probe = '1';
        if (btn) { btn.dataset.probe = '1'; btn.focus(); }
        const counts = () => { const g = rail().querySelector('details.session-group[data-harness="codex"] .session-group-counts'); return g ? g.textContent : ''; };
        const before = counts();
        const marg = data['/sessions'].find(x => x.id === 'sess-marg-1');
        window.__sse.emit('session', { ...marg, last_seen_at: new Date().toISOString(), ended_at: new Date().toISOString(), status: 'ended' });
        setTimeout(() => {
          const now2 = rail().querySelector('details.session-group[data-harness="codex"]');
          const exp = (b) => { const t = fold(b); return t ? t.getAttribute('aria-expanded') : 'missing'; };
          stamp('fold-probe', JSON.stringify({ focus: !!btn && btn.isConnected && document.activeElement === btn,
            group: !!group && now2 === group && group.open, live: exp('live'), ended: exp('ended'), before, after: counts() }));
        }, 4000);
      }, 900);
    }, 4300);
  }
  // familypatch (with dupdemo&tab=resources): the fennel fold expanded, a
  // View family button inside it focused, then a fourth codex family's
  // memory and CPU change. <pre id="family-probe">: focus kept, the group the
  // same open node, the fold still expanded, the head counts.
  if (MODE.includes('dupdemo') && MODE.includes('familypatch')) {
    data['/resources'].sessions.push({ key: '8400:1789470000000000000', name: 'codex', root_pid: 8400,
      root_started_at: '2026-09-09T13:00:00Z', workspace: '/Users/dev/workspace/etl-sidecar', last_seen_at: iso(30000),
      rss_bytes: 50 * 1024 ** 2, cpu_percent: 2, process_count: 1, orphan_count: 0,
      processes: [{ pid: 8400, ppid: 1, name: 'codex', rss_bytes: 50 * 1024 ** 2, cpu_percent: 2 }], samples: [], diagnoses: [] });
    const marg = 'group:codex|Codex · fennel';
    setTimeout(() => {
      const board = document.getElementById('resource-board');
      board.querySelector(`[data-action="toggle-family-dup"][data-key="${marg}"]`)?.click();
      setTimeout(() => {
        const group = board.querySelector('details.family-group[data-harness="codex"]');
        if (group) { group.open = true; group.dataset.probe = '1'; }
        const btn = board.querySelector('.family-dup [data-action="view-family"][data-key="8301:1789470000000000000"]');
        if (btn) { btn.dataset.probe = '1'; btn.focus(); }
        const counts = () => { const c = board.querySelector('details.family-group[data-harness="codex"] .family-group-counts'); return c ? c.textContent : ''; };
        const before = counts();
        const SA = window.SA;
        SA.t.resources = { ...SA.t.resources, sessions: SA.t.resources.sessions.map(f => f.key === '8400:1789470000000000000'
          ? { ...f, rss_bytes: Number(f.rss_bytes) + 512 * 1024 ** 2, cpu_percent: Number(f.cpu_percent) + 7 } : f) };
        renderResourceMissionControl();
        setTimeout(() => {
          const now2 = board.querySelector('details.family-group[data-harness="codex"]');
          const t = board.querySelector(`[data-action="toggle-family-dup"][data-key="${marg}"]`);
          stamp('family-probe', JSON.stringify({ focus: !!btn && btn.isConnected && document.activeElement === btn,
            group: !!group && now2 === group && group.open, fold: t ? t.getAttribute('aria-expanded') : 'missing', before, after: counts() }));
        }, 500);
      }, 400);
    }, 4300);
  }
  // railburst: Sessions open, the infra group opened and probed, then a burst
  // with session frames that change the claude group.
  if (MODE.includes('railburst')) {
    setTimeout(() => openTab('sessions'), 4000);
    setTimeout(() => {
      const d = document.querySelector('#session-rail details[data-harness="infra"]');
      if (d) { d.open = true; d.dataset.probe = '1'; }
      burst((i) => {
        const s = { ...data['/sessions'].find(x => x.id === 'sess-claude-1') };
        delete s._timeline;
        window.__sse.emit('session', { ...s, last_seen_at: new Date().toISOString(), status: i === 1 ? 'idle' : 'active' });
      });
    }, 4300);
  }
  // focusburst: Findings open, flag-2's head button probed and focused, then a
  // burst; <pre id="focus-probe"> says whether that node kept focus.
  if (MODE.includes('focusburst')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => {
      const card = document.querySelector('#flags-list [data-id="flag-2"]');
      const btn = card && card.closest('.flag-card').querySelector('.flag-head');
      if (btn) { btn.dataset.probe = '1'; btn.focus(); }
      burst();
      setTimeout(() => stamp('focus-probe', btn && btn.isConnected && document.activeElement === btn ? 'kept' : 'lost'), 2600);
    }, 4300);
  }
  // clickburst: press flag-3's Dismiss, burst, release and click the same
  // node 400ms later — a real click spans renders.
  if (MODE.includes('clickburst')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => {
      const btn = document.querySelector('#flags-list [data-action="dismiss-flag"][data-id="flag-3"]');
      const fire = (type, Ctor) => btn && btn.dispatchEvent(new Ctor(type, { bubbles: true, cancelable: true, composed: true }));
      fire('pointerdown', PointerEvent);
      fire('mousedown', MouseEvent);
      burst();
      setTimeout(() => { fire('pointerup', PointerEvent); fire('mouseup', MouseEvent); fire('click', MouseEvent); }, 400);
    }, 4300);
  }
  // rawmute: Home's Findings history open (openTab('findings')), focus the
  // blog.example.com unmute button in its Muted ledger, then press flag-3's
  // raw-card "Dismiss this flag class". The POST lands in the /mute fixture,
  // so the re-render adds a codex-scoped row beside the focused one.
  // <pre id="mute-focus-probe"> says whether focus stayed.
  if (MODE.includes('rawmute')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => {
      const un = document.querySelector('#flags-list [data-action="unmute"][data-host="blog.example.com"]');
      if (un) { un.dataset.probe = '1'; un.focus(); }
      const dismiss = document.querySelector('#flags-list [data-action="dismiss-flag"][data-id="flag-3"]');
      const mute = dismiss && dismiss.closest('.flag-card').querySelector('[data-action="mute-rule"]');
      if (mute) mute.click();
      setTimeout(() => stamp('mute-focus-probe',
        `${un && un.isConnected && document.activeElement === un ? 'kept' : 'lost'} rows=${document.querySelectorAll('#flags-list .mute-row').length}`), 2600);
    }, 4300);
  }
  // actdemo: Egress open, allow the suggested host late enough that the
  // inline note and the toast are still up at dump time (4s each).
  if (MODE.includes('actdemo')) {
    setTimeout(() => openTab('egress'), 4000);
    setTimeout(() => document.querySelector('.fw-suggestion [data-action="allow-host"]').click(), 9000);
  }
  // detailsprobe (with explaindemo): flag-2 raised seconds ago, so its age
  // changes on every render; Findings open, its Details opened and probed,
  // then a burst. <pre id="details-probe"> says whether that node stayed
  // connected and open, and its meta before | after.
  if (MODE.includes('detailsprobe')) {
    data['/flags'].find(f => f.id === 'flag-2').ts = new Date(Date.now() - 5000).toISOString();
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => {
      const d = document.querySelector('#flags-list .finding[data-flag-id="flag-2"] details');
      const meta = () => (d && d.closest('.finding') ? d.closest('.finding').querySelector('.finding-meta').textContent : '');
      const before = meta();
      if (d) { d.open = true; d.dataset.probe = '1'; }
      burst();
      setTimeout(() => stamp('details-probe', d && d.isConnected && d.open ? `kept ${before} | ${meta()}` : 'lost'), 2600);
    }, 4300);
  }
  // patternact (with patterndemo): Findings open, press the pattern card's
  // dismiss-all in the Attention queue.
  if (MODE.includes('patternact')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => document.querySelector('#attention-list .pattern-card [data-action-id="dismiss-all"]')?.click(), 9000);
  }
  // patternstream (with patterndemo): Findings open, then a third keychain
  // flag on the stream that the daemon folds into the codex pattern.
  // <pre id="pattern-stream-probe"> reads the Flags list 300 ms after the
  // frame (mid) and after the debounced reconcile (end).
  if (MODE.includes('patternstream')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => {
      const f = {
        id: 'flag-8', rule: 'keychain-access', severity: 2, ts: new Date().toISOString(), pid: 40844, agent: 'codex',
        session_id: 'sess-codex-9', title: 'Agent touched the keychain',
        evidence: [{ kind: 'keychain', label: '/Users/dev/Library/Keychains/login.keychain-db', sub: 'keychain access' }]
      };
      // New objects: the console holds the served ones until the reconcile.
      data['/flags'] = [...data['/flags'], f];
      const pat = data['/patterns'][0];
      data['/patterns'] = [{ ...pat, count: pat.count + 1, unacked: pat.unacked + 1, flag_ids: ['flag-8', ...pat.flag_ids] }];
      window.__sse.emit('flag', f);
      const probe = () => {
        const list = document.getElementById('flags-list');
        const cards = list ? list.querySelectorAll('.pattern-card') : [];
        const covered = cards.length === 1 && [...cards[0].querySelectorAll('.pattern-flag-list code')].some(c => c.textContent === 'flag-8');
        const row = list && list.querySelector('[data-id="flag-8"], [data-flag-id="flag-8"]');
        return `cards=${cards.length} covered=${covered ? 1 : 0} row=${row ? 1 : 0}`;
      };
      let mid = '';
      setTimeout(() => { mid = probe(); }, 300);
      setTimeout(() => stamp('pattern-stream-probe', `mid ${mid} | end ${probe()}`), 2600);
    }, 4500);
  }
  // attnkeep (with patterndemo): Findings open, the codex pattern card's
  // Individual flags opened and its first button focused, then a posture
  // frame with a new codex RSS, read after the 3 s focus hold lets the
  // panel render. <pre id="attn-probe"> says whether both survived and what
  // the group's metrics read.
  if (MODE.includes('attnkeep')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => {
      const card = document.querySelector('#attention-list .pattern-card');
      const d = card && card.querySelector('details');
      const btn = card && card.querySelector('.finding-actions button');
      if (d) d.open = true;
      if (btn) btn.focus();
      data['/posture'].groups.find(g => g.key === 'agent:codex').rssBytes = 734003200;
      window.__sse.emit('posture', data['/posture']);
      setTimeout(() => {
        const group = card && card.closest('.attention-group');
        const metrics = group ? group.querySelector('.attention-metrics').textContent : '';
        stamp('attn-probe', `open=${!!(d && d.isConnected && d.open)} focus=${!!(btn && document.activeElement === btn)} metrics=${metrics}`);
      }, 3600);
    }, 4500);
  }
  // trendsprobe: Home open, Trends closed; a burst of flags and a session
  // update lands. <pre id="trends-probe"> gets the Trends panels' render
  // delta while closed, then after the group is opened.
  if (MODE.includes('trendsprobe')) {
    const trendDelta = (a, b) => ['activity', 'chart-flags', 'chart-memory']
      .map(k => `${k}=${(b[k] || 0) - (a[k] || 0)}`).join(',');
    setTimeout(() => {
      const before = renderCounts();
      burst(() => window.__sse.emit('session', { ...data['/sessions'].find(x => x.id === 'sess-claude-1') }));
      setTimeout(() => {
        const closed = renderCounts();
        const open = document.getElementById('home-trends').open;
        document.querySelector('#home-trends > summary').click();
        setTimeout(() => stamp('trends-probe', `closed(open=${open}):${trendDelta(before, closed)} | opened:${trendDelta(closed, renderCounts())}`), 800);
      }, 2600);
    }, 4500);
  }
  // hiddenrenderprobe: renderAll() (boot, Refresh, search) must not paint a
  // panel that isn't on screen — Home is active by default, so the Trends
  // charts (closed group) and the Sessions/Resources sub-view stay hidden
  // throughout. <pre id="hidden-render-probe"> reports each panel's
  // absolute render count after boot, after Refresh, after a search, and
  // again once each panel is actually shown.
  if (MODE.includes('hiddenrenderprobe')) {
    const hidden = ['activity', 'chart-flags', 'chart-memory', 'resources'];
    const snap = () => hidden.map(k => `${k}=${(renderCounts() || {})[k] || 0}`).join(',');
    setTimeout(() => {
      const afterBoot = snap();
      document.getElementById('btn-refresh').click();
      setTimeout(() => {
        const afterRefresh = snap();
        const search = document.getElementById('global-search');
        search.value = 'nothing-matches-this';
        search.dispatchEvent(new Event('input', { bubbles: true }));
        setTimeout(() => {
          const afterSearch = snap();
          // The <details> "toggle" event queues as its own task, so it must
          // settle (and render Trends while Home is still the active tab)
          // before switching to Sessions for the resources sub-view.
          document.querySelector('#home-trends > summary').click();
          setTimeout(() => {
            openTab('sessions/resources');
            setTimeout(() => {
              stamp('hidden-render-probe',
                `boot:${afterBoot} | refresh:${afterRefresh} | search:${afterSearch} | shown:${snap()}`);
            }, 500);
          }, 300);
        }, 300);
      }, 300);
    }, 1000);
  }
  // policylists: the Policy tab, opened once telemetry has landed.
  if (MODE.includes('policylists')) {
    setTimeout(() => openTab('policy'), 4000);
  }
  // explainact: Findings open, press flag-2's first served action (the
  // recommended allow) late enough that the inline note and the toast are
  // still up at dump time.
  if (MODE.includes('explainact')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => document.querySelector('#flags-list .finding[data-flag-id="flag-2"] .finding-actions button')?.click(), 9000);
  }
  // allowpathact (with explaindemo): Findings open, press flag-2's allow-path
  // action specifically (not the first/recommended button) — proves the
  // request served for that action, not just whichever renders first.
  if (MODE.includes('allowpathact')) {
    setTimeout(() => openTab('findings'), 4000);
    setTimeout(() => document.querySelector('#flags-list .finding[data-flag-id="flag-2"] [data-action-id="allow-path"]')?.click(), 9000);
  }
})();
