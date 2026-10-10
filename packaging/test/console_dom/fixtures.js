// Fixture payloads are independent of the browser transport and interactions.
// Every create call returns fresh data; tests may replace wire payloads or
// patch baseline rows directly without adding a scenario branch to the driver.
(() => {
  const create = (spec = {}) => {
    const scenarios = new Set(spec.scenarios || []);
    const now = spec.now ?? (scenarios.has('cleanupmidnight') ? new Date().setHours(0, 0, 0, 0) : Date.now());
    const iso = msAgo => new Date(now - msAgo).toISOString();
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
    // group items sum to needs_you (= items.length). Warning findings, patterns
    // and recurring egress are never queued.
    '/posture': {
      state: 'critical',
      needs_you: 6,
      coverage_count: 2,
      summary: '6 decisions pending — first: proxy-secret-leak — cursor sent an anthropic-key to logs.example.com — act now.',
      coverage_items: [
        { severity: 2, kind: 'collector_down', id: 'eslogger', title: 'File monitoring is off', detail: 'usually missing Full Disk Access — open Setup & Permissions in the menu bar' },
        { severity: 1, kind: 'uninspected_egress', id: 'uninspected-egress', title: '2 connections bypassed inspection' }
      ],
      items: [
        { severity: 3, kind: 'flag', id: 'flag-1', title: 'proxy-secret-leak — cursor sent an anthropic-key to logs.example.com' },
        { severity: 3, kind: 'flag', id: 'flag-2', title: 'Sensitive file read near an outside connection' },
        { severity: 3, kind: 'flag', id: 'flag-4', title: 'Agent modified macOS privacy permissions (TCC)' },
        { severity: 1, kind: 'guard_pending', id: 'guard-1', title: 'claude wants .env' },
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
              available_scopes: [{kind:'once'},{kind:'session'},{kind:'exact',expiry:'24h'},{kind:'exact',expiry:'7d'}],
              scopeText: 'Future permissions cover this file, tool, workspace and observed executable path. Revoke in Policies.' },
            { kind: 'resource', priority: 4, id: 'resource-1', action: 'pause',
              title: 'Resource pressure', detail: 'Memory grew 1.4 GB in 15 minutes.' },
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
              title: 'Critical finding', detail: 'tcc-tamper — modified TCC service' }
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
    '/expected': [
      { key: 'claude|gh|/Users/dev/.config/gh/hosts.yml|GitHub', agent: 'claude', reader: 'gh', path: '/Users/dev/.config/gh/hosts.yml', dest: 'GitHub', hits: 4, created_at: '2026-09-25T10:00:00Z' }
    ],
    '/decision-scopes': [],
    '/egress/uninspected': [
      { agent: 'cursor', host: 'registry.npmjs.org', count: 14, first_seen: iso(86400000), last_seen: iso(300000), session_id: 'sess-cursor-2', assessment: 'benign', rationale: 'npm registry is routine for JS projects', identity: { kind: 'hostname', name: 'registry.npmjs.org' } },
      { agent: 'claude', host: 'statsig.example.com', count: 3, first_seen: iso(7200000), last_seen: iso(900000), session_id: 'sess-claude-1', identity: { kind: 'hostname', name: 'statsig.example.com' } },
      { agent: 'claude', host: 'telemetry.example.com', count: 5, first_seen: iso(5400000), last_seen: iso(600000), session_id: 'sess-claude-1', identity: { kind: 'hostname', name: 'telemetry.example.com' } },
      { agent: 'cursor', host: '2606:4700:4408::ac40:9bd1', count: 56, last_seen: iso(600000), infra: 'Cloudflare', identity: { kind: 'ipv6', org: 'Cloudflare', class: 'cloud', ip: '2606:4700:4408::ac40:9bd1' } },
      { agent: 'codex', host: 'ec2-98-90-104-193.compute-1.amazonaws.com', count: 11, last_seen: iso(700000), infra: 'AWS', identity: { kind: 'hostname', name: 'ec2-98-90-104-193.compute-1.amazonaws.com', org: 'AWS', class: 'cloud' } },
      { agent: 'claude', host: '2600:1901:0:9e23::', count: 2, last_seen: iso(400000), identity: { kind: 'ipv6', org: 'Google Cloud', class: 'cloud', ip: '2600:1901:0:9e23::' } },
      { agent: 'openclaw', host: '2607:6bc0::10', count: 94, first_seen: iso(3600000), last_seen: iso(60000), identity: { kind: 'ipv6', org: 'Anthropic', class: 'vendor', ip: '2607:6bc0::10' } }
    ],
    '/egress/episodes': { episodes: [
      { id: 'episode-routine', candidate: true, expected: false,
        observed: { id: 'episode-routine', host: 'updates.example.com', protocol: 'tcp', port: 443,
          count: 5, first_seen: iso(7200000), last_seen: iso(60000),
          intervals: [1800000000000, 1770000000000, 1830000000000, 1800000000000],
          session_ids: ['sess-claude-1'], recurring: true, scope_complete: true,
          scope: { agent: 'claude', exe_path: '/Applications/Claude.app', harness: 'claude', workspace: '/Users/dev/workspace/api-service' } },
        advisor_inference: { possible_purpose: 'Possibly an update check', confidence: 'medium', created_at: iso(120000) } },
      { id: 'episode-ambiguous', candidate: true, expected: false,
        observed: { id: 'episode-ambiguous', host: '203.0.113.4', protocol: 'tcp', port: 443,
          count: 5, first_seen: iso(7200000), last_seen: iso(60000),
          intervals: [1800000000000, 1800000000000, 1800000000000, 1800000000000],
          session_ids: [], recurring: true, scope_complete: false,
          scope: { agent: 'codex', exe_path: '/usr/local/bin/codex', harness: '', workspace: '' } } },
      { id: 'episode-expected', candidate: false, expected: true, expected_rule_id: 'expected-older',
        observed: { id: 'episode-expected', host: 'old.example.com', protocol: 'tcp', port: 443,
          count: 5, first_seen: iso(7200000), last_seen: iso(60000),
          intervals: [1800000000000, 1800000000000, 1800000000000, 1800000000000],
          session_ids: [], recurring: true, scope_complete: false,
          scope: { agent: 'cursor', exe_path: '', harness: '', workspace: '' } } }
    ] },
    '/expected-egress': { rules: [
      { id: 'expected-older', agent: 'cursor', kind: 'destination', host: 'old.example.com', port: 443,
        protocol: 'tcp', rationale: 'Routine update', created_by: 'local-operator',
        created_at: iso(86400000), revoked_at: null }
    ] },
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
      available_scopes: [{kind:'once'},{kind:'session'},{kind:'exact',expiry:'24h'},{kind:'exact',expiry:'7d'}],
      scope_text: 'Future permissions cover this file, tool, workspace and observed executable path. Revoke in Policies.'
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

  // Policy lists (GET /guard/rules, /guard/path-allow; /mute is above).
  data['/guard/rules'] = [
    { id: 1, agent: 'claude', rule_id: 'env-file', decision: 'allow', source: 'prompt', created_at: '2026-09-20T10:00:00Z' },
    { id: 2, agent: 'codex', rule_id: 'ssh-keys', decision: 'deny', source: 'onboarding', created_at: '2026-09-21T10:00:00Z' },
  ];
  data['/guard/path-allow'] = [
    { agent: 'claude', rule_id: 'env-file', path: '/Users/dev/workspace/api-service/.env.example', created_at: '2026-09-22T10:00:00Z' },
  ];

  // System agent defaults (Agent tab). Cases declare availability via patches.
  const AGENT_XSS = '<img src=x onerror=alert(1)>';
  data['/agent/status'] = {
    enabled: true, endpoint: 'http://127.0.0.1:11434', reachable: true, ollama_version: '0.15.1',
    model: 'qwen3:latest', harness_model: 'qwen3-coder', models: ['qwen3:latest', 'qwen3-coder:latest'],
    harnesses: [
      { id: 'claude', label: 'Claude Code', bin: 'claude', path: '/opt/homebrew/bin/claude', installed: true, ready: true },
      { id: 'codex', label: 'Codex', bin: 'codex', path: '/opt/homebrew/bin/codex', installed: true, ready: true },
      { id: 'openclaw', label: 'OpenClaw', bin: 'openclaw', installed: false, ready: false, reason: 'OpenClaw is not installed where the daemon can find it (openclaw)' },
      { id: 'hermes', label: 'Hermes Agent', bin: 'hermes', installed: false, ready: false, reason: 'Hermes Agent is not installed where the daemon can find it (hermes)' },
      { id: 'pi', label: 'Pi runner', bin: 'pi', installed: false, ready: false, reason: 'Pi runner is not installed where the daemon can find it (pi)' }
    ],
    skills: [
      { id: 'ssh', title: 'SSH keys and the SSH agent', summary: 'Create, load and authorize an SSH key.' },
      { id: 'git', title: 'Git identity and credentials', summary: 'Credentials in the keychain or gh.' },
      { id: 'signing', title: 'Commit and tag signing', summary: 'Sign commits and tags.' },
      { id: 'claude', title: 'Claude Code — sign-in, settings and local models', summary: 'Claude Code sign-in.' },
      { id: 'codex', title: 'Codex CLI — sign-in, config and local models', summary: 'Codex sign-in.' },
      { id: 'openclaw', title: 'OpenClaw — onboarding, provider auth and local models', summary: 'OpenClaw auth.' },
      { id: 'hermes', title: 'Hermes Agent — providers, keys and local models', summary: 'Hermes auth.' }
    ],
    chatting: false, terminal: true, home: '/Users/dev'
  };
  data['/agent/skills'] = data['/agent/status'].skills.map(k => ({ ...k, keywords: [k.id], body: 'Rules\n- ' + k.id + ' body ' + AGENT_XSS }));
  data['/agent/recommendations'] = [];
  data['/agent/chat'] = { chatting: false, messages: [
    { id: 1, ts: iso(600000), role: 'user', content: 'Set up SSH commit signing ' + AGENT_XSS, harness: 'codex', workdir: '/Users/dev/workspace/api-service' },
    { id: 2, ts: iso(590000), role: 'assistant', content: 'Signing needs your passphrase, so this runs in a terminal.', skills: ['signing', 'ssh'],
      proposal: { title: 'Sign commits with SSH', harness: 'codex', mode: 'terminal', workdir: '/Users/dev/workspace/api-service',
        task: 'Configure SSH commit signing ' + AGENT_XSS, steps: ['git config --global gpg.format ssh', 'gh ssh-key add --type signing'], skills: ['signing'] } },
    { id: 3, ts: iso(300000), role: 'user', content: 'Log OpenClaw into my provider', harness: 'openclaw', workdir: '' },
    { id: 4, ts: iso(290000), role: 'assistant', content: 'OpenClaw is not installed, so I saved this for later.', skills: ['openclaw'], plan_id: 2,
      proposal: { title: 'OpenClaw provider login', harness: 'openclaw', mode: 'terminal', workdir: '/Users/dev', task: 'openclaw models auth login --provider x', steps: [], skills: ['openclaw'] } },
    { id: 5, ts: iso(200000), role: 'note', content: 'The local model did not answer: timeout. Your message is kept.' }
  ] };
  data['/agent/plans'] = [
    { id: 2, created_at: iso(290000), source: 'agent', message_id: 4, title: 'OpenClaw provider login', harness: 'openclaw', mode: 'terminal',
      workdir: '/Users/dev', task: 'openclaw models auth login --provider x', steps: [], skills: ['openclaw'], status: 'saved',
      note: 'OpenClaw is not installed where the daemon can find it (openclaw)', ready: false, reason: 'OpenClaw is not installed where the daemon can find it (openclaw)' },
    { id: 1, created_at: iso(900000), source: 'operator', title: 'Rotate the Codex login ' + AGENT_XSS, harness: 'codex', mode: 'headless',
      workdir: '/Users/dev/workspace/api-service', task: 'codex logout, then codex login', steps: [], skills: ['codex'], status: 'saved', ready: true }
  ];
  data['/agent/runs'] = [
    { id: 2, plan_id: 1, ts: iso(120000), title: 'Rotate the Codex login', harness: 'codex', mode: 'terminal', model: 'qwen3-coder',
      workdir: '/Users/dev/workspace/api-service', status: 'manual', exit_code: 0, command: 'env CODEX_OSS_BASE_URL=http://127.0.0.1:11434/v1 codex --oss <task>',
      detail: "Run it in a terminal: sh '/Users/dev/.config/secure-agent/sysagent/terminal-1-1.sh'" },
    { id: 1, plan_id: 1, ts: iso(3600000), finished_at: iso(3500000), title: 'Rotate the Codex login', harness: 'codex', mode: 'headless', model: 'qwen3-coder',
      workdir: '/Users/dev/workspace/api-service', status: 'done', exit_code: 0, command: 'env codex exec <task>', output: 'Logged out. ' + AGENT_XSS }
  ];

    return { now, iso, data, scenarios, payloads: spec.payloads || {}, patches: spec.patches || [], responses: spec.responses || {} };
  };
  const matches = (row, selector) => Object.entries(selector).every(([key, value]) => row?.[key] === value);
  const selectorKey = (target, key) => {
    if (key !== null && typeof key === 'object') {
      if (!Array.isArray(target) || Array.isArray(key) || !Object.keys(key).length) throw new Error('Invalid fixture patch selector');
      const indices = target.flatMap((row, index) => matches(row, key) ? [index] : []);
      if (indices.length !== 1) throw new Error('Fixture patch selector must match exactly one row');
      return indices[0];
    }
    if (typeof key !== 'string' && typeof key !== 'number') throw new Error('Invalid fixture patch path');
    return key;
  };
  const apply = fixture => {
    Object.assign(fixture.data, structuredClone(fixture.payloads));
    for (const patch of fixture.patches) {
      const {route, path} = patch;
      const operations = ['value', 'append', 'remove'].filter(key => Object.hasOwn(patch, key));
      if (!Object.hasOwn(fixture.data, route) || !Array.isArray(path) || operations.length !== 1) throw new Error('Invalid fixture patch');
      let target = fixture.data;
      const keys = [route, ...path];
      for (const part of keys.slice(0, -1)) {
        target = target[selectorKey(target, part)];
        if (!target || typeof target !== 'object') throw new Error('Invalid fixture patch path');
      }
      const key = selectorKey(target, keys.at(-1));
      if (operations[0] === 'value') target[key] = structuredClone(patch.value);
      else if (operations[0] === 'append') {
        if (!Array.isArray(target[key]) || !Array.isArray(patch.append)) throw new Error('Invalid fixture patch append');
        target[key].push(...structuredClone(patch.append));
      } else {
        if (!Array.isArray(target[key]) || !patch.remove || typeof patch.remove !== 'object' || Array.isArray(patch.remove) || !Object.keys(patch.remove).length) throw new Error('Invalid fixture patch remove');
        if (!target[key].some(row => matches(row, patch.remove))) throw new Error('Fixture patch remove must match at least one row');
        target[key] = target[key].filter(row => !matches(row, patch.remove));
      }
    }
  };
  window.ConsoleFixtures = { create, apply };
})();
