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
