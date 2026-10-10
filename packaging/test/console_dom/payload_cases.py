"""Wire payloads owned by individual console DOM cases.

The browser driver handles interactions; these fixtures declare their data.
Relative timestamps share the same explicit clock as the browser baseline.
"""
from datetime import datetime, timezone
import time


def _clock(now_ms):
    now = int(time.time() * 1000) if now_ms is None else now_ms
    def iso(ms_ago):
        return datetime.fromtimestamp((now - ms_ago) / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return now, iso


def _fields(route, path, values):
    return [{"route": route, "path": [*path, field], "value": value} for field, value in values.items()]


def disabled_agent(now_ms=None):
    now, _ = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/agent/status", "path": ["enabled"], "value": False}]}


def empty_spend(now_ms=None):
    now, _ = _clock(now_ms)
    return {"now": now, "patches": [
        {"route": "/costs", "path": ["total"], "value": {
            "key": "", "calls": 0, "sessions": 0, "tokens_in": 0,
            "tokens_out": 0, "cost_usd": 0, "unpriced_calls": 0,
        }},
        {"route": "/costs", "path": ["rows"], "value": []},
    ]}


def spend_plans(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [
        {"route": "/costs/plans", "path": ["plans"], "value": [{
            "harness": "codex", "home": "codex", "plan_type": "pro", "limit_id": "codex",
            "windows": [{"window_minutes": 10080, "used_percent": 52, "resets_at": iso(-3 * 24 * 3600000)}],
            "unlimited": False, "seen_at": iso(0),
        }]},
        {"route": "/costs", "path": ["total", "plan_calls"], "value": 12},
    ]}


def delayed_spend(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [
        {"route": "/costs/plans", "path": ["plans"], "value": [{
            "harness": "codex", "home": "shape-plan", "home_path": "/workspace/shape-plan",
            "plan_type": "pro", "limit_id": "codex", "unlimited": False, "seen_at": iso(0),
            "windows": [{"used_percent": 25, "window_minutes": 300, "resets_at": ""}],
        }]},
    ]}


def orphan_worktrees(now_ms=None):
    now, _ = _clock(now_ms)
    return {"now": now, "patches": [
        {"route": "/worktrees", "path": ["repos"], "append": [{
            "path": "/Users/dev/gone-app", "error": "repository not found (moved or deleted)",
            "size_bytes": 0, "worktrees": [{
                "path": "/Users/dev/.cursor/worktrees/gone-app/ctnj", "state": "review", "orphan": True,
                "reasons": ["directory is not registered with git; its files are the only copy"],
            }],
        }]},
        {"route": "/worktrees", "path": ["errors"], "value": [
            "/Users/dev/gone-app: repository not found (moved or deleted); 1 folder still points to it (listed first below)",
        ]},
    ]}


def batch_worktrees(now_ms=None, *, multiple_repos=False):
    now, iso = _clock(now_ms)
    repo = "/Users/dev/workspace/api-service"

    def removable(path, branch):
        return {"path": path, "branch": branch, "state": "remove", "stale": True,
                "last_activity": iso(21 * 86400000), "idle_days": 21, "size_bytes": 1610612736,
                "reasons": ["merged into origin/main (squash)"]}

    patches = [{"route": "/worktrees", "path": ["repos", {"path": repo}, "worktrees"], "append": [
        removable(repo + "/.worktrees/old-a", "feat/old-a"),
        removable(repo + "/.worktrees/old-b", "feat/old-b"),
    ]}]
    if multiple_repos:
        other = "/Users/dev/workspace/web-app"
        patches.append({"route": "/worktrees", "path": ["repos"], "append": [{
            "path": other, "size_bytes": 1610612736, "worktrees": [
                {"path": other, "branch": "main", "state": "main", "reasons": []},
                removable(other + "/.worktrees/landed", "feat/landed"),
            ],
        }]})
    return {"now": now, "patches": patches}


def shared_root_sessions(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/sessions", "path": [], "append": [
        {"id": f"sess-claude-{n}", "harness": "claude", "workspace": "/Users/dev/workspace/api-service",
         "repo": "api-service", "branch": "main", "root_pid": 5821,
         "started_at": "2026-09-09T14:10:00Z", "last_seen_at": iso(45000), "status": "active", "confidence": "hook"}
        for n in (5, 6)
    ]}]}


def postmortem_resources(now_ms=None):
    now, _ = _clock(now_ms)
    return {"now": now, "patches": _fields("/resources", [], {
        "rss_bytes": 0, "cpu_percent": 0, "process_count": 0, "session_count": 0, "sessions": [],
    })}


def resource_families(now_ms=None):
    now, iso = _clock(now_ms)
    gb, mb = 1024 ** 3, 1024 ** 2

    def family(pid, name, workspace, rss, cpu, **extra):
        return {
            "key": f"{pid}:1789470000000000000", "name": name, "root_pid": pid,
            "root_started_at": "2026-09-09T13:00:00Z", "workspace": workspace,
            "last_seen_at": iso(30000), "rss_bytes": rss, "cpu_percent": cpu,
            "process_count": 1, "orphan_count": 0,
            "processes": [{"pid": pid, "ppid": 1, "name": name, "rss_bytes": rss,
                           "cpu_percent": cpu, "started_at": "2026-09-09T13:00:00Z"}],
            "samples": [{"at": iso(1800000), "rss_bytes": int(rss * 0.8 + 0.5), "cpu_percent": cpu},
                        {"at": iso(0), "rss_bytes": rss, "cpu_percent": cpu}],
            "diagnoses": [], **extra,
        }

    processes = [{"pid": 4412, "ppid": 1, "name": "codex", "rss_bytes": 400 * mb,
                  "cpu_percent": 6, "started_at": "2026-09-09T13:00:00Z"}]
    processes.extend({
        "pid": 4412 + i, "ppid": 777 if i == 19 else 4412, "name": "node" if i % 2 else "rg",
        "rss_bytes": (40 + i) * mb, "cpu_percent": i / 2, "started_at": "2026-09-09T13:05:00Z",
        **({"is_orphan": True} if i == 19 else {}),
    } for i in range(1, 20))
    families = [
        family(4412, "codex", "/Users/dev/workspace/data-pipeline", sum(p["rss_bytes"] for p in processes),
               15.5, processes=processes, process_count=20, orphan_count=1),
        family(8100, "openclaw", "/Users/dev/.openclaw", 300 * mb, 2),
        family(8201, "codex", "/Users/dev/.openclaw/workspace-demo-app", 700 * mb, 12),
        family(8202, "codex", "/Users/dev/.openclaw/workspace-bot", 250 * mb, 4),
        family(5950, "claude", "/Users/dev/dev", 180 * mb, 1),
        family(4500, "codex", "/Users/dev/scratch", 120 * mb, 0.5),
        family(9100, "opencode", "/Users/dev/workspace/web-console", 90 * mb, 0.2),
        family(7001, "ollama", "/", 10 * gb, 3, kind="infra"),
        family(7100, "lm-studio", "/Applications/LM Studio.app", 3 * gb, 1, kind="infra"),
        family(7200, "cursor-ide", "/Applications/Cursor.app", 2 * gb, 4, kind="infra"),
    ]
    return {"now": now, "patches": [
        {"route": "/resources", "path": ["sessions"], "append": families},
        *_fields("/resources", [], {"session_count": 9, "infra_count": 3}),
        {"route": "/sessions", "path": [], "append": [
            {"id": "sess-openclaw-1", "harness": "openclaw", "workspace": "/Users/dev/.openclaw", "root_pid": 8100,
             "started_at": "2026-09-09T12:00:00Z", "last_seen_at": iso(15000), "status": "active", "confidence": "process-tree"},
            {"id": "sess-oc-career", "harness": "codex", "workspace": "/Users/dev/.openclaw/workspace-demo-app",
             "repo": "demo-app", "branch": "main", "root_pid": 8201, "parent_id": "sess-openclaw-1",
             "started_at": "2026-09-09T12:10:00Z", "last_seen_at": iso(16000), "status": "active", "confidence": "transcript"},
            {"id": "sess-oc-bot", "harness": "codex", "workspace": "/Users/dev/.openclaw/workspace-bot",
             "root_pid": 8202, "parent_id": "sess-openclaw-1", "started_at": "2026-09-09T12:20:00Z",
             "last_seen_at": iso(17000), "status": "active", "confidence": "transcript"},
        ]},
        {"route": "/events", "path": [3], "insert": [
            {"kind": 8, "ts": iso(8000), "pid": 4413, "detail": "Bash → pytest -q"},
            {"kind": 5, "ts": iso(9000), "pid": 4412, "remote_host": "api.openai.com", "remote_port": 443},
        ]},
        {"route": "/flags", "path": [], "append": [{
            "id": "flag-5", "rule": "keychain-access", "agent": "codex", "pid": 4415, "severity": 2, "ts": iso(60000),
            "evidence": [{"kind": "keychain", "label": "/Users/dev/Library/Keychains/login.keychain-db", "sub": "keychain access"}],
        }]},
    ]}


def many_events(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/events", "path": [], "append": [
        {"kind": 0, "ts": iso(40000 + i * 1000), "pid": 5821,
         "path": f"/Users/dev/workspace/api-service/src/m{i}.ts"}
        for i in range(114)
    ]}]}


def trace_events(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/events", "path": [], "append": [
        {"kind": 14, "ts": iso(90000), "pid": 0, "session_id": "sess-claude-1",
         "model": "claude-sonnet-4-5", "tokens_in": 12000, "tokens_out": 340,
         "cost_usd": 0.0412, "price_class": "priced"},
        {"kind": 12, "ts": iso(91000), "pid": 0, "session_id": "sess-claude-1",
         "tool": "Bash", "tool_status": "ok", "duration_ms": 2500, "call_id": "c-1"},
    ]}]}


def duplicate_trace_events(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/events", "path": [], "append": [
        {"kind": 12, "ts": iso(92000), "pid": 0, "session_id": "sess-claude-1",
         "tool": "Read", "tool_status": "ok", "duration_ms": 10, "call_id": "dup-1"},
        {"kind": 12, "ts": iso(92000), "pid": 0, "session_id": "sess-claude-1",
         "tool": "Write", "tool_status": "ok", "duration_ms": 20, "call_id": "dup-2"},
    ]}]}


def unordered_events(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/events", "path": [], "value": [
        {"kind": 0, "ts": iso(1000), "pid": 5821, "path": "/Users/dev/workspace/api-service/src/new.ts"},
        {"kind": 0, "ts": iso(4 * 30 * 86400000), "pid": 5821, "path": "/Users/dev/workspace/api-service/src/old.ts"},
        {"kind": 0, "ts": iso(2000), "pid": 5821, "path": "/Users/dev/workspace/api-service/src/mid.ts"},
    ]}]}


def grouped_sessions(now_ms=None, *, ended=False, sidecar=False):
    now, iso = _clock(now_ms)
    mb = 1024 ** 2
    workspace = "/Users/dev/.openclaw/workspace-demo-app"
    sessions = [{
        "id": f"sess-dup-{i}", "harness": "codex", "workspace": workspace,
        "repo": "demo-app", "branch": "main", "origin": "quill (openclaw)",
        "started_at": iso(i * 600000), "last_seen_at": iso(20000 + i * 1000),
        "status": "active" if i == 2 else "idle", "confidence": "transcript",
    } for i in range(1, 6)]
    families = []
    for i in range(1, 4):
        pid = 8300 + i
        sessions.append({
            "id": f"sess-marg-{i}", "harness": "codex", "workspace": "/Users/dev/.openclaw",
            "origin": "fennel (openclaw)", "root_pid": pid, "started_at": iso(i * 900000),
            "last_seen_at": iso(25000 + i * 1000), "status": "active", "confidence": "transcript",
        })
        families.append({
            "key": f"{pid}:1789470000000000000", "name": "codex", "root_pid": pid,
            "root_started_at": "2026-09-09T13:00:00Z", "workspace": "/Users/dev/.openclaw",
            "last_seen_at": iso(30000), "rss_bytes": 100 * i * mb, "cpu_percent": i,
            "process_count": i, "orphan_count": 0,
            "processes": [{"pid": pid, "ppid": 1, "name": "codex", "rss_bytes": 100 * i * mb, "cpu_percent": i}],
            "samples": [], "diagnoses": [],
        })
    if ended:
        sessions.extend({
            "id": f"sess-dup-{i}", "harness": "codex", "workspace": workspace,
            "repo": "demo-app", "branch": "main", "origin": "quill (openclaw)",
            "started_at": iso(i * 600000), "last_seen_at": iso(40000 + i * 1000),
            "ended_at": iso(40000 + i * 1000), "status": "ended", "confidence": "transcript",
        } for i in (6, 7))
    if sidecar:
        families.append({
            "key": "8400:1789470000000000000", "name": "codex", "root_pid": 8400,
            "root_started_at": "2026-09-09T13:00:00Z", "workspace": "/Users/dev/workspace/etl-sidecar",
            "last_seen_at": iso(30000), "rss_bytes": 50 * mb, "cpu_percent": 2,
            "process_count": 1, "orphan_count": 0,
            "processes": [{"pid": 8400, "ppid": 1, "name": "codex", "rss_bytes": 50 * mb, "cpu_percent": 2}],
            "samples": [], "diagnoses": [],
        })
    return {"now": now, "patches": [
        {"route": "/sessions", "path": [], "append": sessions},
        {"route": "/resources", "path": ["sessions"], "append": families},
    ]}


def scoped_review(now_ms=None):
    now, _ = _clock(now_ms)
    return {"now": now, "payloads": {"/reviews": {"reviews": [{
        "id": "review-scope", "revision": 3, "review_state": "unreviewed", "count": 1,
        "evidence_available": True, "evidence_flag_available": False,
        "context": {"rule": "sensitive-read-then-connect", "session_id": "sess-claude-1",
                    "workspace": "/Users/dev/workspace/api-service", "resources": ["/work/.env"],
                    "destinations": ["api.example.com:443"]},
        "available_scopes": [{"kind": "once"}, {"kind": "session"},
                             {"kind": "exact", "expiry": "24h"}, {"kind": "exact", "expiry": "7d"}],
        "source_ids": ["flag-1"], "incident_ids": [],
        "assessment": {"risk": "high", "control": "observed", "reason": "Recorded read and connection"},
    }], "degraded": False}}}


def routine_review(now_ms=None):
    now, _ = _clock(now_ms)
    return {"now": now, "payloads": {"/routine": [{
        "key": "routine|gh|/Users/dev/.config", "reader": "gh", "area": "~/.config/gh/hosts.yml",
        "files": 1, "count": 145, "agents": ["claude", "codex", "openclaw"],
        "destinations": [{"org": "GitHub", "host": "140.82.114.6", "count": 140}],
        "destination_count": 3, "expectable": 143,
        "disposition": {"state": "warning", "text": "Needs a look", "why": "w"},
        "summary": "gh read ~/.config/gh/hosts.yml, then connected to GitHub and 2 more — 145 times across 3 agents.",
        "actions": [
            {"id": "expect-all", "label": "Treat as routine",
             "consequence": "Each exact reader, file and destination these 143 flags cite is marked expected.",
             "method": "POST", "path": "/expected", "body": {"flag_ids": ["r1", "r2"]}},
            {"id": "dismiss-all", "label": "Dismiss all 145", "consequence": "c",
             "method": "POST", "path": "/flags/acknowledge", "body": {"flag_ids": ["r1", "r2", "r3"]}},
        ],
        "flag_ids": ["r1", "r2", "r3"],
    }]}}


def organization_allow(now_ms=None):
    now, _ = _clock(now_ms)
    hosts = ["142.250.1.1", "2607:f8b0:4002:c08::54", "uf-in-f84.1e100.net"]
    explain = {
        "what": "Cursor read a sensitive file in your home directory, then reached Google 2 s later.",
        "subject": {"path": "/Users/dev/.docker/config.json", "display": "~/.docker/config.json",
                    "basename": "config.json", "category": "other_sensitive",
                    "category_label": "sensitive file", "owner_label": "home directory"},
        "egress": [{"host": host, "port": 443, "org": "Google", "kind": "ip", "allowlisted": False,
                    "gap_seconds": 2} for host in hosts],
        "context": {"harness": "cursor"},
        "disposition": {"state": "warning", "text": "Needs a look",
                        "why": "A connection was observed to Google near the read."},
        "actions": [
            *[{"id": "allow-host", "label": f"Allow {host} for cursor", "consequence": "c",
               "method": "POST", "path": "/allowlist", "body": {"agent": "cursor", "host": host}} for host in hosts],
            {"id": "dismiss", "label": "Dismiss this flag", "consequence": "c",
             "method": "POST", "path": "/flags/acknowledge", "body": {"flag_id": "flag-1"}},
        ],
    }
    return {"now": now, "patches": [{"route": "/flags", "path": [{"id": "flag-1"}, "explain"], "value": explain}]}


def retriaged_finding(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/flags", "path": [{"id": "flag-1"}, "advisor"], "value": {
        "assessment": "benign", "confidence": 0.9, "rationale": "re-triage complete: routine vendor traffic",
        "suggested_action": "none", "created_at": iso(120000),
    }}]}


def offline_advisor(now_ms=None):
    now, _ = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/status", "path": ["advisor_health"], "value": {
        "enabled": True, "circuit_open": True, "last_error": "context deadline exceeded",
        "queue_depth": 0, "model": "qwen3:8b",
    }}]}


def unconfigured_fleet(now_ms=None):
    now, _ = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/fleet", "path": ["fleet_configured"], "value": False}]}


def agent_queue(now_ms=None):
    now, iso = _clock(now_ms)
    return {"now": now, "patches": [{"route": "/agent/recommendations", "path": [], "value": [
        {"id": 901, "ts": iso(60000), "role": "assistant", "origin": "analysis", "review_state": "pending",
         "content": "Review **SSH** configuration.",
         "local_command": {"command": "ssh-add -l", "workdir": "/Users/dev", "mode": "headless"}},
        {"id": 902, "ts": iso(60000), "role": "assistant", "origin": "analysis", "review_state": "saved",
         "plan_id": 2, "content": "Already saved."},
    ]}]}


def payload_outcomes(now_ms=None):
    now, iso = _clock(now_ms)
    payloads = {}
    patches = [
        *_fields('/flags', [{'id': 'flag-1'}], {'title': 'Outbound payload matched a secret',
         'explain': {'what': '',
                     'disposition': {'state': 'critical', 'text': 'Critical risk', 'why': ''},
                     'actions': [],
                     'assessment': {'evidence_basis': ['fingerprint-payload'],
                                    'risk': 'critical',
                                    'review_state': 'reviewed',
                                    'control': 'blocked',
                                    'residual_risk': 'transmission-attempt',
                                    'reason': 'Fixture: the local proxy rejected this request before '
                                              'forwarding.',
                                    'limits': ['Earlier exposure and external credential revocation are not '
                                               'verified.']}}}),
        *_fields('/incidents', [{'id': 'inc-20260907-6033-a1b2'}], {'rule': 'proxy-secret-leak',
         'summary': 'Fixture: an outbound payload matched a registered secret fingerprint.',
         'rotate_list': [],
         'workflow': {'status': 'resolved', 'resolution_note': 'Operator reported credential revocation.'},
         'advisor_narrative': '',
         'aggregate_count': 6,
         'payload_outcomes': {'blocked': 2, 'observed_only': 1, 'unknown': 3}}),
    ]
    return {"now": now, "payloads": payloads, "patches": patches}


def session_coverage(now_ms=None):
    now, iso = _clock(now_ms)
    payloads = {}
    patches = [
        *_fields('/status', [], {'coverage': {'harnesses_active': 1,
                      'harnesses_seen': 1,
                      'sessions': [{'session_id': 'session-observed',
                                    'harness': 'claude',
                                    'workspace': '/work/observed',
                                    'root_pid': 101,
                                    'identity_basis': 'hook',
                                    'guard': {'supported': True,
                                              'state': 'observed',
                                              'detail': 'This session only; other requests may be unobserved.'},
                                    'trace': {'supported': True,
                                              'state': 'observed',
                                              'detail': 'This session only; other requests may be unobserved.'},
                                    'payload': {'supported': True,
                                                'state': 'unattributed',
                                                'detail': 'This session only; other requests may be '
                                                          'unobserved.'}},
                                   {'session_id': 'session-silent',
                                    'harness': 'claude',
                                    'workspace': '/work/<silent>',
                                    'root_pid': 102,
                                    'identity_basis': 'hook',
                                    'guard': {'supported': True,
                                              'state': 'not-observed',
                                              'detail': 'This session only; other requests may be unobserved.'},
                                    'trace': {'supported': True,
                                              'state': 'not-observed',
                                              'detail': 'This session only; other requests may be unobserved.'},
                                    'payload': {'supported': True,
                                                'state': 'off',
                                                'detail': 'This session only; other requests may be '
                                                          'unobserved.'}}],
                      'probes': [{'harness': 'claude',
                                  'hook_path': '/Users/dev/.claude/hooks/secret_guard.py',
                                  'checked_at': iso(60000),
                                  'state': 'changed',
                                  'detail': 'Configuration changed. Run the check again.'}]}}),
        *_fields('/posture', [], {'state': 'all-clear',
         'needs_you': 0,
         'coverage_count': 0,
         'coverage_items': [],
         'items': [],
         'groups': []}),
    ]
    return {"now": now, "payloads": payloads, "patches": patches}


def explained_finding(now_ms=None):
    now, iso = _clock(now_ms)
    payloads = {}
    patches = [
        *_fields('/posture', [], {'needs_you': 5}),
        *_fields('/flags', [{'id': 'flag-2'}], {'evidence': [{'kind': 'read',
                       'label': '/Users/dev/.aws/credentials',
                       'sub': 'sensitive read',
                       'ts': '2026-09-22T16:04:58Z'},
                      {'kind': 'connect',
                       'label': '[2606:4700::6810:84e5]:443',
                       'sub': 'egress',
                       'ts': '2026-09-22T16:05:01Z'}],
         'advisor': {'assessment': 'benign',
                     'confidence': 0.93,
                     'rationale': 'Cloudflare fronts the package registry this project installs from.',
                     'suggested_action': 'allow-host'},
         'title': 'Sensitive file read near an outside connection',
         'ts': '2026-09-22T16:05:01Z',
         'explain': {'what': 'Cursor read AWS credentials (~/.aws/credentials), then reached Cloudflare 3 s '
                             'later.',
                     'subject': {'path': '/Users/dev/.aws/credentials',
                                 'display': '~/.aws/credentials',
                                 'basename': 'credentials',
                                 'category': 'aws_credentials',
                                 'category_label': 'AWS credentials',
                                 'rule': 'cloud-creds',
                                 'owner_label': 'home directory'},
                     'egress': [{'host': '2606:4700::6810:84e5',
                                 'port': 443,
                                 'org': 'Cloudflare',
                                 'kind': 'ipv6',
                                 'allowlisted': False,
                                 'gap_seconds': 3}],
                     'context': {'session_id': '7f3a9c21-4b2e-4a1d-9c55-2e8f0d1a3b77',
                                 'harness': 'cursor',
                                 'repo': 'web-app',
                                 'branch': 'main',
                                 'tool': 'Read',
                                 'tool_status': 'ok',
                                 'tool_at': '2026-09-22T16:04:57Z'},
                     'disposition': {'state': 'benign-likely',
                                     'text': 'Likely benign (advisor 93 %)',
                                     'why': 'Cloudflare fronts the package registry this project installs '
                                            'from.'},
                     'actions': [{'id': 'allow-host',
                                  'label': 'Allow 2606:4700::6810:84e5 (Cloudflare) for cursor',
                                  'recommended': True,
                                  'consequence': 'Future connections from cursor to 2606:4700::6810:84e5 are '
                                                 'trusted and stop being flagged.',
                                  'method': 'POST',
                                  'path': '/allowlist',
                                  'body': {'agent': 'cursor', 'host': '2606:4700::6810:84e5'}},
                                 {'id': 'allow-path',
                                  'label': 'Always allow this file for cursor',
                                  'consequence': 'cursor may open ~/.aws/credentials without a guard prompt; '
                                                 'other files under the cloud-creds rule still ask.',
                                  'method': 'POST',
                                  'path': '/guard/path-allow',
                                  'body': {'agent': 'cursor',
                                           'rule_id': 'cloud-creds',
                                           'path': '/Users/dev/.aws/credentials'}},
                                 {'id': 'dismiss',
                                  'label': 'Dismiss this flag',
                                  'consequence': 'The flag is marked reviewed and stops counting as needing '
                                                 'action; the rule keeps watching for the next one.',
                                  'method': 'POST',
                                  'path': '/flags/acknowledge',
                                  'body': {'flag_id': 'flag-2'}},
                                 {'id': 'kill',
                                  'label': 'Kill cursor (pid 6033)',
                                  'consequence': 'The agent process tree is terminated now; unsaved work in it '
                                                 'is lost.',
                                  'method': 'POST',
                                  'path': '/kill',
                                  'body': {'pid': 6033}}]}}),
        {'route': '/posture', 'path': ['items'], 'remove': {'kind': 'flag', 'id': 'flag-2'}},
        {'route': '/posture',
         'path': ['groups', {'agent': 'cursor'}, 'items'],
         'remove': {'kind': 'flag', 'id': 'flag-2'}},
    ]
    return {"now": now, "payloads": payloads, "patches": patches}


def keychain_pattern(now_ms=None):
    now, iso = _clock(now_ms)
    payloads = {'/patterns': [{'key': 'codex|keychain-access|/Users/dev/Library/Keychains/login.keychain-db',
                    'agent': 'codex',
                    'rule': 'keychain-access',
                    'title': 'Agent touched the keychain',
                    'subject': {'kind': 'keychain',
                                'label': '~/Library/Keychains/login.keychain-db',
                                'sub': 'keychain'},
                    'count': 323,
                    'unacked': 323,
                    'first': iso(540000),
                    'last': iso(60000),
                    'median_gap_s': 1.4,
                    'bursts': 320,
                    'cadence': 'in bursts a few seconds apart',
                    'hourly': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 323],
                    'pids': [40844, 51364],
                    'pid_count': 2,
                    'sessions': ['sess-codex-9'],
                    'session_count': 1,
                    'disposition': {'state': 'warning',
                                    'text': 'Needs a look',
                                    'why': 'Agent touched the keychain'},
                    'summary': 'codex touched the login keychain 323 times between 03:00 and 03:08 (2 '
                               'processes, 1 session), in bursts a few seconds apart.',
                    'actions': [{'id': 'mute-class',
                                 'label': 'Dismiss this flag class',
                                 'method': 'POST',
                                 'path': '/mute',
                                 'consequence': '"Agent touched the keychain" stops raising flags for every '
                                                'agent.',
                                 'body': {'rule': 'keychain-access', 'host': '*'}},
                                {'id': 'dismiss-all',
                                 'label': 'Dismiss all 2 open',
                                 'method': 'POST',
                                 'path': '/flags/acknowledge',
                                 'consequence': 'These flags are marked reviewed.',
                                 'body': {'flag_ids': ['flag-7', 'flag-6']}}],
                    'flag_ids': ['flag-7', 'flag-6']}]}
    patches = [
        {'route': '/flags',
         'path': [],
         'append': [{'id': 'flag-6',
                     'rule': 'keychain-access',
                     'severity': 2,
                     'ts': iso(120000),
                     'pid': 40844,
                     'agent': 'codex',
                     'session_id': 'sess-codex-9',
                     'title': 'Agent touched the keychain',
                     'evidence': [{'kind': 'keychain',
                                   'label': '/Users/dev/Library/Keychains/login.keychain-db',
                                   'sub': 'keychain access'}]},
                    {'id': 'flag-7',
                     'rule': 'keychain-access',
                     'severity': 2,
                     'ts': iso(60000),
                     'pid': 51364,
                     'agent': 'codex',
                     'session_id': 'sess-codex-9',
                     'title': 'Agent touched the keychain',
                     'evidence': [{'kind': 'keychain',
                                   'label': '/Users/dev/Library/Keychains/login.keychain-db',
                                   'sub': 'keychain access'}]}]},
    ]
    return {"now": now, "payloads": payloads, "patches": patches}


def large_keychain_pattern(now_ms=None):
    now, iso = _clock(now_ms)
    ids = [f"kc-{index}" for index in range(1, 62)]
    flags = [{'id': flag_id,
     'rule': 'keychain-access',
     'severity': 2,
     'ts': iso(60000),
     'pid': 40844,
     'agent': 'codex',
     'session_id': 'sess-codex-9',
     'title': 'Agent touched the keychain',
     'evidence': [{'kind': 'keychain',
                   'label': '/Users/dev/Library/Keychains/login.keychain-db',
                   'sub': 'keychain access'}]} for flag_id in ids]
    payloads = {'/patterns': [{'key': 'codex|keychain-access|/Users/dev/Library/Keychains/login.keychain-db',
                    'agent': 'codex',
                    'rule': 'keychain-access',
                    'title': 'Agent touched the keychain',
                    'subject': {'kind': 'keychain',
                                'label': '~/Library/Keychains/login.keychain-db',
                                'sub': 'keychain'},
                    'count': 61,
                    'unacked': 61,
                    'first': iso(540000),
                    'last': iso(60000),
                    'hourly': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61],
                    'pids': [40844],
                    'pid_count': 1,
                    'sessions': ['sess-codex-9'],
                    'session_count': 1,
                    'disposition': {'state': 'warning',
                                    'text': 'Needs a look',
                                    'why': 'Agent touched the keychain'},
                    'summary': 'codex touched the login keychain 61 times.',
                    'actions': [],
                    'flag_ids': ids}]}
    patches = [
        {'route': '/flags', 'path': [], 'append': flags},
    ]
    return {"now": now, "payloads": payloads, "patches": patches}


def github_reader_pattern(now_ms=None):
    now, iso = _clock(now_ms)
    payloads = {'/patterns': [{'key': 'claude|sensitive-read-then-connect|/Users/dev/.config/gh/hosts.yml',
                    'agent': 'claude',
                    'rule': 'sensitive-read-then-connect',
                    'title': 'Sensitive file read near an outside connection',
                    'count': 81,
                    'flags': 30,
                    'unacked': 1,
                    'first': iso(600000),
                    'last': iso(1000),
                    'hourly': [],
                    'flag_ids': ['gh-flag'],
                    'disposition': {'state': 'warning',
                                    'text': 'Needs a look',
                                    'why': 'Recorded evidence does not establish credential use.'},
                    'summary': 'gh read ~/.config/gh/hosts.yml near a GitHub connection.',
                    'actions': [{'id': 'expect',
                                 'label': 'Expected: gh → 140.82.114.6',
                                 'consequence': 'Approve only this reader, file, and endpoint. Other '
                                                'evidence stays open.',
                                 'method': 'POST',
                                 'path': '/expected',
                                 'body': {'flag_id': 'gh-flag',
                                          'path': '/Users/dev/.config/gh/hosts.yml',
                                          'host': '140.82.114.6'}},
                                {'id': 'review-local',
                                 'label': 'Send to local agent review',
                                 'body': {'flag_ids': ['gh-flag']}},
                                {'id': 'inspect-file',
                                 'label': 'Inspect file details',
                                 'body': {'path': '/Users/dev/.config/gh/hosts.yml'}},
                                {'id': 'dismiss-all',
                                 'label': 'Dismiss all 1 open',
                                 'method': 'POST',
                                 'path': '/flags/acknowledge',
                                 'body': {'flag_ids': ['gh-flag']}}]}]}
    patches = [
        {'route': '/flags',
         'path': [],
         'append': [{'id': 'gh-flag',
                     'rule': 'sensitive-read-then-connect',
                     'severity': 2,
                     'agent': 'claude',
                     'pid': 301,
                     'evidence': [{'kind': 'read',
                                   'label': '/Users/dev/.config/gh/hosts.yml',
                                   'exe': '/opt/homebrew/bin/gh'}]}]},
    ]
    return {"now": now, "payloads": payloads, "patches": patches}
