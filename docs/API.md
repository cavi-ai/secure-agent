# secure-agent Unix Socket API Specification

The `secure-agentd` daemon exposes an HTTP API over a local Unix domain socket.

- **Default Socket Path**: `~/.config/secure-agent/daemon.sock`
- **File Permissions**: `0600` (Owner read/write only)

---

## 📡 Endpoints

### 1. `GET /status`

Returns daemon operational status, system uptime, and active tagged agent process count.

#### Request
```http
GET /status HTTP/1.1
Host: unix
```

#### Response
```json
{
  "running": true,
  "uptime": "1h24m05s",
  "active_agents": 2,
  "advisor_health": {
    "enabled": true,
    "circuit_open": false,
    "queue_depth": 0,
    "model": "qwen3:8b"
  }
}
```

`advisor_health` reports the local triage advisor's live state: `circuit_open`
means the model server has failed repeatedly and verdicts are paused
(`last_error` says why) — the UIs render this so advisor actions never look
like dead buttons. Absent on older daemons.

### Resource telemetry: `GET /resources`

Returns a point-in-time rollup of resources attributed to tagged agent process
families. Each session is anchored to the root PID and process start time, so
PID reuse cannot splice two runs together. Samples are taken every five
seconds and retained in memory for one hour; daemon restarts begin a new
history. The session totals remain agent-attributed; `host` provides the
whole-machine context needed to tell whether that usage is safe or is crowding
out the rest of the workstation.

```json
{
  "observed_at": "2026-09-15T20:00:00Z",
  "host": {
    "total_memory_bytes": 17179869184,
    "free_memory_bytes": 2147483648,
    "available_memory_bytes": 4294967296,
    "compressed_memory_bytes": 1073741824,
    "used_memory_bytes": 12884901888,
    "agent_memory_bytes": 5368709120,
    "non_agent_memory_bytes": 7516192768,
    "swap_total_bytes": 8589934592,
    "swap_used_bytes": 2147483648,
    "headroom_percent": 25,
    "agent_memory_percent": 31.3,
    "system_cpu_percent": 75,
    "agent_cpu_percent": 8.9,
    "non_agent_cpu_percent": 66.1,
    "logical_cpu_count": 16,
    "memory_pressure": "normal",
    "thermal_state": "nominal",
    "headroom_score": 25,
    "capacity": "constrained"
  },
  "rss_bytes": 5368709120,
  "cpu_percent": 142.5,
  "process_count": 3,
  "session_count": 1,
  "sessions": [{
    "key": "58210:1789502400000000000",
    "name": "claude",
    "workspace": "/Users/dev/project",
    "root_pid": 58210,
    "root_started_at": "2026-09-15T19:30:00Z",
    "rss_bytes": 5368709120,
    "cpu_percent": 142.5,
    "process_count": 3,
    "orphan_count": 0,
    "estimated_reclaim_bytes": 5368709120,
    "processes": [
      {"name": "claude", "pid": 58210, "ppid": 1, "rss_bytes": 1073741824, "cpu_percent": 22.5},
      {"name": "node", "pid": 58211, "ppid": 58210, "rss_bytes": 4294967296, "cpu_percent": 120}
    ],
    "samples": [{"at": "2026-09-15T20:00:00Z", "rss_bytes": 5368709120, "cpu_percent": 142.5}],
    "diagnoses": [{
      "code": "heavy-memory",
      "severity": "critical",
      "summary": "Session is using at least 4 GiB of resident memory.",
      "threshold": "RSS >= 4 GiB",
      "confidence": "high",
      "estimated_reclaim_bytes": 5368709120
    }]
  }]
}
```

Host CPU values are percentages of the machine's complete logical-CPU
capacity (0–100). Session and process CPU values continue to use 100% per
fully occupied core. `agent_cpu_percent` converts the attributed session total
to machine capacity; `non_agent_cpu_percent` is the saturating difference from
the measured system total. Memory attribution is likewise saturating, so a
racing process sample can never produce a negative non-agent value.

`headroom_score` is the most constrained available signal: available-memory
percentage, CPU idle percentage, unused-swap percentage, or the thermal cap.
Scores below 15 are `critical`, 15–49 are `constrained`, and 50–100 are
`ample`. Memory pressure is `critical` below 10% available memory or at 80%
swap use, `warning` below 20% available or at 50% swap use, and `normal`
otherwise. Fields that the operating system does not expose are omitted and
the corresponding state is `unknown`; secure-agent does not manufacture a
healthy reading. macOS and Linux use native kernel/proc metrics, with thermal
state collected best-effort. The first CPU sample has no delta and is omitted.

Diagnoses are deterministic and may include `heavy-memory` (RSS ≥ 4 GiB),
`heavy-cpu` (CPU ≥ 100%), `rapid-growth` (≥ 1 GiB and ≥ 25% over 15
minutes), `idle-heavy` (RSS ≥ 2 GiB after 15 minutes without attributed
activity), `runaway-child` (a child holds ≥ 1 GiB and ≥ 60% of family RSS),
and `orphan-drift` (an attributed process remains after its parent exits).
`estimated_reclaim_bytes` is an estimate of memory associated with the
diagnosed scope; it is not a promise that the operating system will reclaim
that exact amount immediately.

Resource budgets are configured in the private overlay and hot-reload within
one config-watch cycle:

```yaml
resource_control:
  mode: prompt              # observe | prompt | terminate
  max_rss_mb: 4096          # 0 disables this dimension
  max_cpu_percent: 200      # 0 disables; 100 is one full core
  sustain_seconds: 30       # continuous breach before action
  cooldown_seconds: 300     # suppress repeat prompts/failed retries
  interventions:            # optional ordered delays after sustain_seconds
    - action: notify
      after_seconds: 0
    - action: lower_priority
      after_seconds: 30
      nice: 10              # 1..19; larger values get less CPU priority
    - action: pause
      after_seconds: 60
    - action: terminate     # must be the final step
      after_seconds: 120
  workspace_overrides:
    - cwd_prefix: /Users/me/workspace/critical-service
      mode: terminate
      max_rss_mb: 8192
      max_cpu_percent: 300
      sustain_seconds: 60
      cooldown_seconds: 600
```

Workspace overrides cover the exact normalized path and its descendants. If
multiple prefixes match, the longest prefix wins. Every override is a complete
policy so its effective behavior does not depend on hidden field inheritance.
The Resource Mission Control editor writes the full policy document with
`PUT /resources/policy`; the daemon validates and atomically persists the YAML
before applying it. An unsuccessful write leaves the active policy unchanged.

The response also includes `episodes`, the newest 20 locally persisted
resource-pressure captures. An episode is recorded when a diagnosis first
appears, its diagnosis set changes, or resident memory rises another 25%.
Each capture contains whole-session totals, diagnostic evidence, effective
control state, the root plus at most 64 highest-RSS processes, and at most 120
five-second samples (a ten-minute prelude). It also includes the captured
`host` snapshot, so later review can distinguish a large but safe session from
one that exhausted machine headroom. The database retains the newest 500
episodes, and each `/resources` response returns the newest 20.

Episodes may also contain `activities` and `correlations`. The daemon selects
events only from PIDs in the captured process family and only between the
retained prelude and capture time, then rejects any event outside that exact
nanosecond window or before the captured process instance started. It converts
the survivors into short references such
as process starts, tool labels, file basenames, and network destinations;
payloads and secret values are never copied. At most 80 of the newest
references are retained. `correlations` identifies the largest positive
sample-to-sample RSS change and any recorded activity in that same interval:

```json
{
  "activities": [
    {"at":"2026-09-15T19:59:55Z","kind":"process-start","pid":58211,"process":"node","summary":"node started"}
  ],
  "correlations": [
    {"summary":"Memory rose 1.4 GiB in 5s while node started.","confidence":"observed-correlation","from":"2026-09-15T19:59:50Z","to":"2026-09-15T19:59:55Z","rss_delta_bytes":1503238554,"activity_count":1}
  ]
}
```

`observed-correlation` is deliberately not a causal verdict. The console says
so beside every explanation and preserves the underlying activity rows for
operator review. New episodes report `activity_status: "settling"` for 30
seconds. Reads re-enrich and persist that evidence so events which reached
SQLite slightly after the pressure capture are included; a successful refresh
after the settling window marks the episode `complete`.

`observe` only annotates sessions. With a configured ladder, `prompt` applies
`notify` automatically and adds an approval to `control.pending` for each
state-changing step. Resolve it with
`POST /resources/control {"id":"resource-1","decision":"apply|dismiss"}`.
Resume a paused family with
`POST /resources/control {"session_key":"…","decision":"resume"}`.
`terminate` mode executes every configured step automatically. Priority,
pause, resume, and termination always target the complete recognized session
family with a fresh process-start identity check immediately before action.
Failed steps stop escalation and enter cooldown; no later destructive step is
silently skipped to. Without an `interventions` list, the legacy behavior is
preserved: `prompt` requests termination approval and `terminate` invokes the
recognized-agent containment path automatically. Termination is never enabled
by default. Policy changes, operator decisions, automatic attempts, and
failures are recorded in `/audit`.

---

### 2. `GET /flags`

Retrieves recent security correlation flags.

#### Query Parameters
- `limit` *(optional, integer)*: Maximum number of flags to return (default: `50`).

#### Request
```http
GET /flags?limit=10 HTTP/1.1
Host: unix
```

#### Response
```json
[
  {
    "id": 42,
    "rule": "sensitive-read-then-connect",
    "severity": "high",
    "pid": 58210,
    "process_name": "fake-cursor",
    "details": "PID 58210 (fake-cursor) read sensitive file /Users/dev/project/.env and opened network connection to 192.168.1.50:443",
    "timestamp": "2026-08-12T19:42:00-04:00"
  }
]
```

#### Explanation stamping

`GET /flags` stamps `explain` (below) on the first **25 unacknowledged** flags of the response, without network lookups (endpoint identity comes from the CIDR/suffix tables and the reverse-DNS cache only). Acknowledged flags and rows past the cap stay raw. `/snapshot` stamps its `flags` the same way.

### 2a. `GET /flags/{id}/explain`

Returns one flag (with `title` and `advisor`) plus `explain`, the daemon's plain-language reading of it. Destinations may take one bounded reverse-DNS lookup. `404` for an unknown id or any other shape under `/flags/`; `405` for a non-GET. Console-admitted on the proxy listener in exactly this shape (non-empty id, not `.`/`..`). `POST /flags/acknowledge` is a separate exact route and is unaffected.

```json
{
  "id": "3f9c2a1b7d4e6f80",
  "rule": "sensitive-read-then-connect",
  "title": "Agent read a secret, then connected out",
  "explain": {
    "what": "Claude read a sensitive file in Claude skills (~/.claude/skills), then reached AWS 3 s later.",
    "subject": {"path": "/Users/me/.claude/skills/…/config", "display": "~/.claude/skills/…/config", "basename": "config",
                "category": "other_sensitive", "category_label": "sensitive file", "owner_label": "Claude skills (~/.claude/skills)"},
    "egress": [{"host": "2600:1f10:…:fd73", "port": 443, "org": "AWS", "kind": "ipv6", "allowlisted": false, "gap_seconds": 3}],
    "context": {"session_id": "…", "harness": "claude", "repo": "api", "branch": "main", "tool": "Read", "tool_status": "ok", "tool_at": "…", "model": "…"},
    "disposition": {"state": "benign-likely", "text": "Likely benign (advisor 93 %)", "why": "<advisor rationale, first sentence>"},
    "actions": [{"id": "allow-host", "label": "Allow 2600:1f10:…:fd73 (AWS) for claude", "consequence": "…",
                 "method": "POST", "path": "/allowlist", "body": {"agent": "claude", "host": "2600:1f10:…:fd73"}, "recommended": true}]
  }
}
```

| Field | Content |
|---|---|
| `what` | One sentence per rule; no pids; the destination's org over its address. |
| `subject` | The file from the first `read`/`keychain`/`transcript` item (or a `violation` carrying a path). `category`: `env_file`, `ssh_key`, `aws_credentials`, `keychain`, `keychain_system_trust`, `other_sensitive`, `transcript`. `owner_label`: `Claude skills (~/.claude/skills)`, `Claude Code config (~/.claude)`, `Cursor config`, `opencode config`, `repo <name>` (under the session workspace), `temp directory`, `home directory`, `system`. `display`: `~`-abbreviated, middle-truncated to 64 runes. |
| `egress` | Every `connect` item, deduped by host:port, in evidence order. `org`/`name`/`kind` from the endpoint identity table. `allowlisted`: the host is approved for the flag's agent (exact or dot-suffix match). `gap_seconds`: connect time − read time (negative when the connection came first; `0` without a read item). |
| `context` | The flag's session (harness, repo, branch, workspace), the same-session tool call nearest the read time within ±60 s (`tool`, `tool_status`, `tool_at`), and the nearest model call within ±60 s (`model`). Absent when the flag has no session. |
| `disposition` | One verdict, in precedence order: `acknowledged` ("Reviewed") → `benign-likely` (advisor `benign` with confidence ≥ 0.85; "Likely benign (advisor N %)", `why` = the rationale's first sentence) → `critical` (severity ≥ 3, "Act now") → `warning` ("Needs a look"). `why` is otherwise the rule title. |
| `actions` | In order, only those that apply: `allow-host` (per destination host not yet allowlisted), `allow-path` (env/ssh/cloud/keychain files; guard rules `env-files`, `ssh-keys`, `cloud-creds`, `keychain`), `mute-rule-host` (first destination `POST /mute` accepts — IPv6 literals are not), `mute-class` (keychain rules, `host: "*"`), `open-incident` (an incident holds the flag), `dismiss` (unacknowledged), `kill` (the pid is a live agent). Each carries the request (`method`, `path`, `body`) and a one-line `consequence`. `recommended` marks the action matching the advisor's `suggested_action` (`allow-host` → first `allow-host`; `mute-rule` → `mute-rule-host`, else `mute-class`; `kill-agent` → `kill`; `rotate-credentials` → `open-incident`). |

---

### 3. `GET /events`

Retrieves raw system telemetry events captured by the file watcher and network sampler.

#### Query Parameters
- `limit` *(optional, integer)*: Maximum number of events to return (default: `50`).

#### Request
```http
GET /events?limit=20 HTTP/1.1
Host: unix
```

#### Response
```json
[
  {
    "id": 105,
    "type": "file_read",
    "pid": 58210,
    "process_name": "fake-cursor",
    "path": "/Users/dev/project/.env",
    "timestamp": "2026-08-12T19:41:59-04:00"
  }
]
```

---

### 4. `POST /kill`

Terminates an active agent process tree by PID using `SIGKILL`.

#### Request
```http
POST /kill HTTP/1.1
Host: unix
Content-Type: application/json

{
  "pid": 58210
}
```

#### Response
```json
{
  "status": "ok",
  "pid": 58210
}
```

#### Error Response (400 / 500)
```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/plain; charset=utf-8

Kill failed: process not found
```

---

## 🛠️ Accessing via `curl`

To query the API from the command line:

```bash
# Check daemon status
curl --unix-socket ~/.config/secure-agent/daemon.sock http://unix/status

# Get recent security flags
curl --unix-socket ~/.config/secure-agent/daemon.sock http://unix/flags

# Terminate process 12345
curl -X POST --unix-socket ~/.config/secure-agent/daemon.sock \
  -H "Content-Type: application/json" \
  -d '{"pid": 12345}' \
  http://unix/kill
```

### 5. `GET /incidents`

Returns rotation-intel incident reports. `?id=ID` fetches one (`&format=markdown` renders the remediation checklist as markdown); without `id`, lists recent reports (`?limit=N`, default 50).

### 6. `GET /audit`

Returns the policy audit trail (rule promotions, fingerprint ingest, guard-rule changes). `?limit=N`, default 100.

### 7. `GET /fleet`

Returns this node's fleet-telemetry summary: hostname, OS/arch, build `version` (set via ldflags; `dev` on untagged builds), `node_id`, running state, active agents, recent flag count, proxy status.

### 8. `POST /firewall/mode`

Promotes or demotes a firewall rule at runtime and persists the override. Payload: `{"rule":"<id>","mode":"monitor|block"}`. Owner-role only.

### 9. `POST /firewall/fingerprints/reload`

Re-applies persisted secret fingerprints to the running engine.

### 10. `POST /firewall/fingerprints/ingest`

Scans configured ingest sources, registers HMAC fingerprints (never plaintext), applies them live, returns registered labels.

### 11. `GET|POST /firewall/sources`

Lists (GET) or edits (POST, `{"source":"<path>","op":"add|remove"}`) the fingerprint ingest sources. Config-defined sources are read-only; adds are validated against system paths.

### 12. `POST /guard/decision`

A hook's prompt-mode query. A cached (agent, rule) decision returns instantly (`reason:"cached"`); otherwise a pending prompt is enqueued and the request blocks until the menubar resolves it or the broker deadline elapses (fail-safe deny). Payload: `{"agent","tool","path","rule_id"}`; `agent`/`rule_id` must match `^[A-Za-z0-9_.-]+$`.

### 13. `GET /guard/pending`

Returns the queued guard prompts oldest-first. Each item carries a `scope_text` disclosing what "Allow Always" would approve.

### 14. `POST /guard/resolve`

Resolves a pending prompt: `{"id","verdict":"allow|deny","scope":"once|always"}`.

### 15. `GET|DELETE /guard/rules`

Lists stored guard decisions (GET); revokes one (DELETE `?agent=&rule_id=`), forcing a fresh prompt next time.

### 16. `GET /costs`

Model-call spend over a window, grouped by one dimension, across every traced harness.

```
GET /costs?since=24h&by=repo
```

| Param | Values | Default |
|---|---|---|
| `since` | lookback (`24h`, `90m`, `7d`) or RFC3339 timestamp | `24h` |
| `until` | RFC3339 timestamp | now |
| `by` | `repo`, `branch` (`repo@branch`), `harness`, `session`, `model` | `repo` |

A malformed `since`/`until` or an unknown `by` returns `400` with a one-line body.

```json
{
  "since": "2026-09-21T12:00:00Z",
  "until": "2026-09-22T12:00:00Z",
  "by": "repo",
  "total": {"key": "", "calls": 4, "sessions": 3, "tokens_in": 400, "tokens_out": 40,
            "cost_usd": 0.85, "unpriced_calls": 1, "unknown_model_calls": 0,
            "unpriced_model_calls": 1, "plan_calls": 0, "local_calls": 0},
  "rows": [
    {"key": "api-service", "harness": "claude", "calls": 2, "sessions": 1,
     "tokens_in": 200, "tokens_out": 20, "cost_usd": 0.75, "unpriced_calls": 0,
     "unknown_model_calls": 0, "unpriced_model_calls": 0, "plan_calls": 0, "local_calls": 0},
    {"key": "(no repo)", "harness": "codex", "calls": 1, "sessions": 1,
     "tokens_in": 100, "tokens_out": 10, "cost_usd": 0, "unpriced_calls": 1,
     "unknown_model_calls": 0, "unpriced_model_calls": 1, "plan_calls": 0, "local_calls": 0}
  ]
}
```

Rows are sorted by cost, then calls (at most 200); `rows` is `[]` when the window is empty. `harness` is the harness with the most calls in the group (omitted for `by=harness`). Missing repo, branch, harness or model values group as `(no repo)`, `(no branch)`, `(unknown)`. `unpriced_calls` counts calls with cost `0`; a cost is never estimated. Read-level. CLI: `secure-agent cost [--since 24h] [--by repo] [--json]`; the table view adds the class breakdown and one `add a price for <model> under pricing: in ~/.config/secure-agent/config.yaml` line per `unpriced-model` id.

Every row and the total split `unpriced_calls` by price class:

| Field | Class | Meaning |
|---|---|---|
| `unknown_model_calls` | `unknown-model` | the harness recorded no model id |
| `unpriced_model_calls` | `unpriced-model` | model id known, no price entry: add one under [`pricing`](CONFIGURATION.md) |
| `plan_calls` | `plan` | subscription provider (`kimi-for-coding`, `kimi-code-plan-global`) |
| `local_calls` | `local` | local runtime (`ollama`, `lmstudio`, `lm-studio`, `llama.cpp`, `mlx`, or a loopback provider) |

A zero-token call of a priced model is in `unpriced_calls` and in no class counter. A price entry wins over the provider: a priced model is `priced` whatever the provider. A vendor-prefixed id (`z-ai/glm-5.3-flash`) is looked up without its prefix when the full id has no entry. `by=model` rows also carry `provider` (the provider with the most calls for the model; omitted when none is recorded) and `class` (`priced` when every call carries a cost, else the model's class).

#### `GET /costs/unpriced`

The zero-cost calls by harness, provider and model with their class; `priced` groups are left out. Same `since`/`until` as `/costs`. Sorted by calls; `rows` is `[]` when nothing is unpriced. Read-level; console-allowed.

```json
{
  "since": "2026-09-22T06:30:00Z",
  "until": "2026-09-23T06:30:00Z",
  "rows": [
    {"harness": "opencode", "provider": "kimi-for-coding", "model": "k3", "class": "plan",
     "calls": 12, "tokens_in": 48000, "tokens_out": 2100},
    {"harness": "codex", "provider": "custom", "model": "gpt-5.6-sol", "class": "unpriced-model",
     "calls": 3, "tokens_in": 9000, "tokens_out": 400}
  ]
}
```

### 17. `GET /doctor`

The daemon's self-check: whether hooks, file telemetry, collectors and traces are producing data, and whether stored sessions and events are attributed, paired, priced and retained.

```
GET /doctor
```

Each check has a `state` of `pass`, `fail` or `skip`, a `detail`, and on `fail` a one-line `fix` (`bus` reports only and has none). `grace` is `true` while uptime is under 10 minutes; checks that need steady state then `skip` with detail `inside the 10-minute boot window`. `checks` is always an array, in this order:

| `id` | Fails when | Skips when |
|---|---|---|
| `hook-registered` | `~/.claude/settings.json` does not register the guard hook for `PreToolUse` and `PostToolUse` | home directory unknown |
| `hook-active` | agents are running and no hook event landed in 24h | no agents |
| `file-telemetry` | root ES service `not-loaded`, in a `spawn`/`exit` state, or `running` with agents active and the spool unwritten for over 10 min (past grace) | file telemetry is not spool-based |
| `collectors` | a collector is stopped or abandoned, or (with agents active) silent; passes with each polling collector's database, watermark and last poll | grace |
| `trace-coverage` | a harness has transcript- or hook-confidence sessions seen since boot (an ended one only with an event since boot) but no tool-call, turn or model-call rows; passes listing each traced harness with its session count | grace, or no such sessions since boot |
| `hermes` | a Hermes `state.db` could not be read (detail names the database and error); passes with each database's message watermark and the last poll time | no `state.db` under the Hermes root (`not installed`) |
| `session-identity` | under 80% of sessions carry a harness | no sessions |
| `session-repo` | under 50% of named sessions with a workspace since boot carry a repo, or named sessions since boot carry no workspace at all | grace, or no named sessions since boot |
| `session-rate` | sessions created in the last hour exceed 2 × agents + 10 | grace, or no agents |
| `tool-pairing` | any `(session_id, call_id)` pair is stored twice, or a tool-call row since boot has no call id | — |
| `pricing` | under 90% of `claude-*` model calls carry a cost (detail also reports unpriced calls over all models) | no Claude model calls |
| `retention` | an event kind is at its row budget and its oldest row is under 24h old | — |
| `egress-routing` | the proxy is on and endpoints were reached outside it (proxy off passes as `proxy off — egress not inspected`) | — |
| `bus` | subscribers dropped events on full buffers | — |

```json
{
  "generated_at": "2026-09-23T09:00:00Z",
  "version": "0.9.0",
  "uptime": "3h12m4s",
  "grace": false,
  "summary": {"pass": 11, "fail": 1, "skip": 1},
  "checks": [
    {"id": "hook-registered", "title": "Guard hook registered", "state": "pass",
     "detail": "registered for PreToolUse and PostToolUse"},
    {"id": "file-telemetry", "title": "File telemetry", "state": "fail",
     "detail": "root service state: spawn scheduled",
     "fix": "System Settings → Privacy & Security → Full Disk Access → Secure Agent, or the Setup card"},
    {"id": "pricing", "title": "Model-call pricing", "state": "skip", "detail": "no Claude model calls"}
  ]
}
```

(The example shows three of the thirteen checks.) Read-level. CLI: `secure-agent doctor [--json]` prints one `PASS`/`FAIL`/`SKIP` line per check, a `fix:` line under each failure and a summary line, and exits `1` when any check fails.

### 18. `GET /sessions/{id}/report`

What one session did — tools, models, spend, files, hosts, guard decisions, findings and secret-rule hits — as JSON or markdown. It carries tool names, model ids, paths, hosts, rule ids and counts; never content or matched text.

```
GET /sessions/{id}/report?format=json|md
```

`format` defaults to `json`; `md` returns `Content-Type: text/markdown; charset=utf-8`. An unknown session id, or any `/sessions/{id}/…` leaf other than `timeline` and `report`, returns `404`; another `format` returns `400`.

```json
{
  "session": {"id": "7f3a9c21-…", "harness": "claude", "repo": "api-service", "branch": "main",
              "started_at": "2026-09-23T09:00:00Z", "last_seen_at": "2026-09-23T09:42:10Z",
              "status": "active", "confidence": "hook"},
  "duration_s": 2530, "events": 214,
  "turns": 6, "tool_calls": 41, "model_calls": 19,
  "tokens_in": 812000, "tokens_out": 9100, "cost_usd": 3.12, "unpriced_calls": 0,
  "tools": [{"key": "Bash", "count": 22, "errors": 2, "duration_ms": 61000}],
  "models": [{"model": "claude-sonnet-4-5", "calls": 19, "tokens_in": 812000, "tokens_out": 9100,
              "cost_usd": 3.12, "unpriced_calls": 0}],
  "files": [{"key": "/work/api-service/go.mod", "count": 4}],
  "hosts": [{"key": "api.anthropic.com", "count": 19}],
  "guard": [{"ts": "2026-09-23T09:10:02Z", "kind": "guard-resolved", "label": "allow/session"}],
  "secret_hits": [{"ts": "2026-09-23T09:20:40Z", "kind": "transcript-hit", "label": "aws-key", "status": "typed"}],
  "flags": [],
  "timeline": [{"ts": "2026-09-23T09:00:04Z", "kind": "tool-call", "label": "Bash", "status": "ok", "duration_ms": 1500}]
}
```

- Events are read oldest-first, at most 20,000 per report; `events` is how many were read.
- `tools` are sorted by calls (`errors` counts `tool_status: "error"`, `duration_ms` is summed); `models` by cost; `files` (file open/write/delete) and `hosts` (connections) by count, at most 50 each.
- `secret_hits` are transcript hits: `label` is the rule id, `status` the detection layer.
- `flags` are the session's findings; `timeline` is the first 500 events, labelled by tool, model, path, host or detail.
- Every list is `[]` when empty, never `null`.

The markdown form:

```
# <harness> · <repo>@<branch, or the workspace> — <started, local> → <ended | live> (<duration>)
Session `<id>` · <status> · identity: <confidence>

## Summary
- Turns N · tool calls N (E errors) · model calls N · tokens N in / N out · cost $X (N unpriced)
- Files touched N · hosts contacted N · guard decisions N · findings N · secret hits N

## Models            table: model | calls | tokens in | tokens out | cost
## Tools             table: tool | calls | errors | time
## Files touched     - `path` × count (top 25)
## Network           - host × count
## Guard decisions   - HH:MM:SS kind label
## Findings          - severity N · rule · timestamp
## Secret hits       - rule · layer · HH:MM:SS
## Timeline          - HH:MM:SS kind label [status] [duration] (first 100, then "… N more")
```

Empty sections read `none`. Costs use the console's rule: two decimals, `<$0.01` under a cent. Read-level; admitted on the proxy listener with the console token. CLI: `secure-agent session <id-or-prefix> [--json]` prints the markdown (or the JSON); a unique id prefix of at least 6 characters resolves, an ambiguous one lists its candidates and exits `1`.

`GET /sessions` (the session list) narrows with exact-match `harness`, `repo` and `branch`, and `since` (`24h`, `7d` or RFC3339, as `/costs`; a session matches when it started or was last seen at or after it), alongside `status` (`active`, `idle`, `ended`; default: live sessions, then the 25 most recent ended ones) and `limit` (default 100). A malformed `since` returns `400`. CLI: `secure-agent sessions [--harness H] [--repo R] [--branch B] [--since D] [--status S] [--limit N] [--json]`.

---

## 🔐 Peer authentication & endpoint roles

Every connection is identified with macOS `LOCAL_PEEREPID` / `LOCAL_PEERCRED` (kernel-attested; not forgeable):

| Role | Who | Allowed |
|---|---|---|
| Owner | Same uid as the daemon (CLI, shells, ssh management) | All reads; `POST /guard/resolve`; `DELETE /guard/rules`; `POST /firewall/*`; `POST /kill` (agent pids only) |
| Agent | PIDs currently tagged as agent processes | Reads; `POST /guard/decision` |
| Foreign | Different uid | Nothing |

`POST /kill` additionally refuses any PID that is not currently a recognized agent process, so the control socket cannot be turned into an arbitrary-process killer.

`GET /debug/pprof/` (Go runtime profiles: `heap`, `goroutine`, `profile?seconds=N`, `trace`, …) is served on the unix socket only, to the Owner role (and the pinned menubar app); agents and foreign peers get 403, and the proxy listener never serves it.

## 🖥️ Web dashboard

The embedded console is served at both:

- `http://127.0.0.1:<proxy_port>/dashboard/` (when the proxy is enabled), and
- over the unix socket at `/dashboard/` (for `curl --unix-socket` or an SSH tunnel).

Both routes send `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.

---

## 🛰️ Fleet oversight

Downstream collectors consume events from many nodes three ways:

### 1. Webhook push (real-time)

Fastest path: `secure-agent fleet enroll <collector-url>` on the node — it reads the node id from the daemon, generates the secret, merges the webhook into `config.yaml` (backup first), and prints the one line the collector's secrets file needs. The daemon hot-reloads fleet config; no restart. The manual equivalent:

```yaml
fleet:
  hostname: "builder-01"              # display name collectors show (default: os.Hostname)
  labels: { env: prod, role: build-runner }  # grouping dimensions for multi-fleet views
  heartbeat_interval_sec: 60          # status-envelope cadence (default 60)
  webhooks:
    - url: https://collector.internal/hooks/secure-agent
      secret: "<shared-secret>"
      events: [flag, incident, guard]   # empty = all; add session, trace for the sessions view
```

Every flag, incident, and guard decision is POSTed as:

```json
{"node_id": "…", "kind": "flag", "ts": "…", "version": "…", "boot": "…", "seq": 42, "payload": {…}}
```

`session` envelopes carry a session upsert/lifecycle change (one per change, not per event) and `trace` envelopes carry one agent-semantic trace event (tool call, model call, turn) — both are opt-in per sink because a busy harness emits traces at a rate that would crowd the security events. Trace delivery is deliberately lossy: the publisher's in-flight cap drops trace overflow before it can starve flag/incident delivery, and the collector's gap detector keeps the loss honest. `GET /fleet/sessions` folds them into the cross-node sessions view.

`boot` identifies one daemon run; `seq` is a per-boot monotonic counter stamped on **every** envelope (heartbeats included). Collectors use them for gap detection: a delivery lost to the backlog cap, collector downtime, or a restart surfaces as a sequence gap with a 90s grace period for retries/reordering — loss is honest, never silent. A new `boot` resets the expectation (a restart is not a gap). Fleet config (`webhooks`, `hostname`, `labels`, `heartbeat_interval_sec`) is **hot-reloadable**: the daemon's config watcher swaps sinks and cadence within one poll cycle.

In addition, every node pushes a **`status` heartbeat** — once at boot, then
every `heartbeat_interval_sec`, and immediately whenever the posture state
changes (`all-clear → critical` must not wait out the interval). The status
kind is **not** filterable by `events:` — liveness that can be unsubscribed
is indistinguishable from a dead node. Payload:

```json
{"hostname": "builder-01", "os": "darwin", "arch": "arm64", "agents": 2,
 "uptime": "4h12m", "posture_state": "critical",
 "posture_summary": "Secret leaving in agent traffic — act now.",
 "needs_you": 2, "labels": {"env": "prod"}}
```

`posture_state`/`posture_summary`/`needs_you` are the node's own `/posture`
headline — collectors render the same answer the local UIs show instead of
re-deriving it from raw flags.

- Signature: `X-SecureAgent-Signature: sha256=<hex hmac-sha256(secret, body)>` — verify before trusting `payload`.
- Retries: 3 attempts (500ms/2s/5s backoff) on network errors, 5xx, and 429 only. Non-retryable failures land in `~/.local/state/secure-agent/webhook-deliveries.jsonl` (0600).
- Delivery is best-effort and asynchronous; a dead collector never slows the daemon.

### 2. Pull API

`GET /fleet` returns this node's status including stable `node_id` and build `version`; `GET /flags|events|incidents|audit|guard/*` are all available over SSH tunnels or Tailscale. Point the CLI at a tunneled socket with `SECURE_AGENT_SOCK=/path/to/tunneled.sock secure-agent status`.

### 3. Session identity

Hook-stamped `session_id` (env `CLAUDE_SESSION_ID`, or a per-run uuid) flows through `events`, `flags`, and incident evidence, so one agent run can be followed end-to-end even after PIDs recycle.

## 📁 Per-project guard policies

```yaml
directory_guard:
  cwd_overrides:
    - cwd_prefix: /Users/me/work/prod-api
      rules: { env-files: deny, ssh-keys: prompt }
```

Resolution per tool call: first entry whose `cwd_prefix` contains the agent's working directory wins for the rules it lists; unlisted rules fall back to the global `guard-modes.json` override, then to shipped defaults. This is how one repo gets pinned to `deny` while the machine stays `monitor`.

---

## 🧭 Operator UX endpoints

### `GET /posture`

The headline answer — *"do I need to look at this machine, and what first?"*:

```json
{
  "state": "attention",          // all-clear | attention | critical
  "needs_you": 2,
  "summary": "2 item(s) need you — first: Agent read a secret, then connected out.",
  "items": [
    {"kind": "flag", "id": "…", "title": "Agent read a secret, then connected out",
     "severity": 3, "detail": "…", "ts": "…"}
  ]
}
```

Flag items take their `severity` from the flag's disposition (`critical` 3, `warning` 2, `benign-likely` 1) and their `detail` starts with the disposition text (`"Likely benign (advisor 93 %) — …"`), so an advisor-confirmed benign flag yields `attention`, never `critical`. In `groups`, flag items carry `disposition`; a `benign-likely` flag has priority 1 and title "Finding, likely benign".

Item kinds: `flag` (recent ≤24h, severity ≥2, human-titled), `guard_pending` (unresolved prompts), `collector_down` (dead/abandoned monitors), `collector_silent`, `harness_uncovered` and `guard_hook_unregistered` (coverage gaps while agents run), `uninspected_egress` (connections that bypassed the firewall, one item per group that carries them), `incident` (unresolved critical/high, or open more than 72h), `resource_pressure` (a pending resource intervention). Derived live — never a second source of truth.

Invariant: every item in `items` appears in exactly one of `groups`, and the group item counts sum to `needs_you` (= `len(items)`). Groups are agent sessions (`session:<key>`), agent buckets (`agent:<name>`), and `machine` (`agent: ""`, `label: "This machine"`), which holds the agent-less items: dead or silent collectors, missing hooks, and the machine-wide uninspected item when no agent group carries egress. Group item priorities: guard 5, resource 4, incident 3 (aging below high risk 1), flag 2 (severity 2 or likely benign 1), machine 2 (1 below severity 2), egress 1.

### `GET /events/stream` (SSE)

Live feed of every bus event as `event: <kind>` / `data: <json>`, with a 15s heartbeat comment. Replaces polling for UIs that can hold a connection — **the menu bar app and the web console both consume this stream** (guard prompts surface at push latency), falling back to polling when the endpoint is unavailable. One bus subscription per connection, released on disconnect.

### Console access on the proxy port

The browser console at `http://127.0.0.1:<proxy_port>/dashboard/` fetches telemetry same-origin, i.e. from the proxy listener. That listener serves the API endpoints listed in `proxy.isConsoleAPIPath` (status/posture/flags/events/incidents/audit/fleet/firewall sources + guard pending/rules/resolve + kill + rollup + mute + allowlist(+suggestions) + `/egress/uninspected` + `/notify/rules` + advisor retriage + `/sessions/{id}/timeline` and `/sessions/{id}/report` + `/flags/{id}/explain` + this SSE stream) behind the **console token**. The whitelist is kept in lockstep with the console's fetches by `TestConsoleAPIPathsCoverWebApp` — a path the console fetches but the listener doesn't whitelist 407s and the panel dies silently, which is exactly the drift that test exists to catch:

- Header `X-SecureAgent-Console-Token: <token>` (fetch/XHR) or `?ct=<token>` (EventSource can't set headers).
- The token lives at `~/.config/secure-agent/console-token` (0600), distinct from the proxy token on purpose: agents routed through the proxy carry the proxy token in their environment and must not be able to read telemetry or resolve guard prompts with it.
- `/guard/decision` is **not** served on this listener at all — it stays on the peer-attested unix socket.

Besides telemetry kinds (`file-open`, `conn-open`, `proxy-hit`, …), the stream carries the guard lifecycle:

- `event: guard-prompt` — a directory-guard prompt was enqueued; refetch `/guard/pending` immediately.
- `event: guard-resolved` — a prompt was resolved; refetch pending + `/guard/rules`.

`data` for these carries only `{kind, ts, detail}` with `detail = "<agent>/<rule_id>"` — never paths.

### Incident workflow

- `GET /incidents` — list items now carry `workflow: {status, acknowledged_at, resolved_at, resolution_note}`.
- `GET /incidents?id=…` — returns `{incident, workflow}`.
- `POST /incidents/status` — `{"id","status":"open|acknowledged|resolved","note":"…"}`. Forward-only transitions; `acknowledged_at` stamps once; re-resolve replaces the note. Audited.

### `GET /egress/uninspected`

The drill-down behind the posture warning — the actual endpoints that
bypassed inspection, so the count is explainable and actionable:

```
GET /egress/uninspected?hours=24&limit=200
```

```json
[
  {"agent": "cursor", "host": "registry.npmjs.org", "count": 14,
   "last_seen": "2026-09-15T10:00:00Z",
   "assessment": "benign", "rationale": "npm registry is routine for JS projects"}
]
```

`hours` (1–168, default 24) windows the list by last-seen; out-of-range
values fall back to 24. Sorted most-frequent first; `assessment`/`rationale`
carry the advisor's host verdict when one exists. Read-level. Approve a row
with `POST /allowlist` to close that blind spot.

Related: `status.uninspected_egress` is a **rolling 24h** distinct-endpoint
count ("what is bypassing inspection now"), not a lifetime figure — pairs
silent for 7+ days are swept from the tracker entirely.

### `GET|POST /notify/rules`

Per-rule notification overrides, layered over the default policy
(**severity ≥ 3 notifies**; informational flags like routine keychain-db
opens are silent). Both UIs (menu bar app and web console) read this store,
so one choice silences both surfaces.

```json
GET /notify/rules
{"default_min_severity": 3, "overrides": {"keychain-access": false}}
```

```
POST /notify/rules   {"rule": "keychain-access", "notify": false}
POST /notify/rules   {"rule": "keychain-access", "notify": null}   // clear → default
```

`true` = always notify for the rule (even below the severity bar), `false` =
never, `null`/absent = back to default. Rule ids must match
`^[A-Za-z0-9_.-]+$`. Persisted at `~/.config/secure-agent/notify-rules.json`
(0600, atomic); sets and clears are audited (`notify-rule-set` /
`notify-rule-clear`).

### Muting flag classes (`host: "*"`)

`POST /mute` with `host: "*"` is the **rule-level disposition**: the whole
flag class stops raising flags (silenced fires are counted in
`status.muted_flags`), and every open flag of the rule is acknowledged so the
old rows leave the critical list. This is the recourse for noisy host-less
rules (`keychain-access`, `keychain-security-cli`) — the console and menu bar
expose it as "Dismiss this flag class". Reversible with `DELETE /mute`.

---

## 📥 Reference collector (`cmd/secure-agent-collector`)

Stdlib-only reference implementation of the consumer side. Run:

```bash
make collector
printf '<node-id>=<secret>\n' > secrets.txt
./bin/secure-agent-collector -addr 127.0.0.1:9445 -store <dir> -config secrets.txt
```

| Endpoint | Description |
|---|---|
| `POST /hooks/secure-agent` | Webhook receiver. Requires `X-SecureAgent-Node` (provisioned) and `X-SecureAgent-Signature` (HMAC over the raw body, constant-time compared). Envelope `node_id` must match the header. Accepted kinds: `flag`, `incident`, `guard`, `status`, `session`, `trace`. |
| `GET /fleet` | Merged multi-node rollup ordered by operator priority (critical → attention → stale → all-clear → legacy). Per node: `hostname`, `labels`, `version` (tracks the newest report), `last_seen` (liveness), `last_event` (security activity), lifetime counts, **rolling 24h counts** (`flags_24h`, `critical_flags_24h`, `incidents_24h`), guard `allow`/`deny` breakdown, `gaps` (sequence-gap loss count), `boot_id`, and the node's own posture (`posture_state`, `posture_summary`, `needs_you`, `agents`). |
| `GET /fleet/rules` | Cross-node rule aggregation: `{total_nodes, rules: [{rule, nodes, node_ids, flags_24h, critical_24h}]}` sorted by fleet spread — "is the same thing firing on N/M nodes?" |
| `GET /fleet/sessions` | Cross-node sessions: every node's latest record per session (`harness`, `workspace`, `repo`, `branch`, `status`, `confidence`, timestamps) with the node's `hostname` and `labels`. Live sessions first, ended ones below — the "who is working where" view. Fed by the opt-in `session`/`trace` envelope kinds. |
| `GET /nodes/<id>/events?kind=&limit=` | One node's stored envelopes, newest first. |
| `GET /` | HTML overview: a fleet headline ("2 critical · 1 stale · 12 all-clear"), the rules-across-fleet table, and per-node cards (hostname, posture chip, 24h counts, labels, delivery-gap warnings). Liveness: heartbeat nodes stale >3 min, gone >10 min; legacy event-only nodes >10 / >20 min. |
| `GET /healthz` | Liveness. |

Secrets come from a flat file (`node_id=secret` lines) or `-secrets n1=a,n2=b`. Store: append-only JSONL per node, `0600` in a `0700` directory, replayed into the rollup at startup behind a small `envelopeLog` interface — a SQLite backend can replace it without touching rollup semantics (the production-grade trajectory: retention, TLS, alerting).

The e2e smoke test provisions a collector, configures a node webhook, triggers a real flag, and asserts verified flag **and status-heartbeat** envelopes land in the store — the fleet contract cannot regress silently.
