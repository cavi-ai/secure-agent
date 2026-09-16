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
history. This is agent-attributed posture, not whole-machine memory or CPU.

```json
{
  "observed_at": "2026-09-15T20:00:00Z",
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

Diagnoses are deterministic and may include `heavy-memory` (RSS ≥ 4 GiB),
`heavy-cpu` (CPU ≥ 100%), `rapid-growth` (≥ 1 GiB and ≥ 25% over 15
minutes), `idle-heavy` (RSS ≥ 2 GiB after 15 minutes without attributed
activity), `runaway-child` (a child holds ≥ 1 GiB and ≥ 60% of family RSS),
and `orphan-drift` (an attributed process remains after its parent exits).
`estimated_reclaim_bytes` is an estimate of memory associated with the
diagnosed scope; it is not a promise that the operating system will reclaim
that exact amount immediately.

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

---

## 🔐 Peer authentication & endpoint roles

Every connection is identified with macOS `LOCAL_PEEREPID` / `LOCAL_PEERCRED` (kernel-attested; not forgeable):

| Role | Who | Allowed |
|---|---|---|
| Owner | Same uid as the daemon (CLI, shells, ssh management) | All reads; `POST /guard/resolve`; `DELETE /guard/rules`; `POST /firewall/*`; `POST /kill` (agent pids only) |
| Agent | PIDs currently tagged as agent processes | Reads; `POST /guard/decision` |
| Foreign | Different uid | Nothing |

`POST /kill` additionally refuses any PID that is not currently a recognized agent process, so the control socket cannot be turned into an arbitrary-process killer.

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
      events: [flag, incident, guard]   # empty = all
```

Every flag, incident, and guard decision is POSTed as:

```json
{"node_id": "…", "kind": "flag", "ts": "…", "version": "…", "boot": "…", "seq": 42, "payload": {…}}
```

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

Item kinds: `flag` (recent ≤24h, severity ≥2, human-titled), `guard_pending` (unresolved prompts), `collector_down` (dead/abandoned monitors), `uninspected_egress` (connections that bypassed the firewall). Derived live — never a second source of truth.

### `GET /events/stream` (SSE)

Live feed of every bus event as `event: <kind>` / `data: <json>`, with a 15s heartbeat comment. Replaces polling for UIs that can hold a connection — **the menu bar app and the web console both consume this stream** (guard prompts surface at push latency), falling back to polling when the endpoint is unavailable. One bus subscription per connection, released on disconnect.

### Console access on the proxy port

The browser console at `http://127.0.0.1:<proxy_port>/dashboard/` fetches telemetry same-origin, i.e. from the proxy listener. That listener serves the API endpoints listed in `proxy.isConsoleAPIPath` (status/posture/flags/events/incidents/audit/fleet/firewall sources + guard pending/rules/resolve + kill + rollup + mute + allowlist(+suggestions) + `/egress/uninspected` + `/notify/rules` + advisor retriage + this SSE stream) behind the **console token**. The whitelist is kept in lockstep with the console's fetches by `TestConsoleAPIPathsCoverWebApp` — a path the console fetches but the listener doesn't whitelist 407s and the panel dies silently, which is exactly the drift that test exists to catch:

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
| `POST /hooks/secure-agent` | Webhook receiver. Requires `X-SecureAgent-Node` (provisioned) and `X-SecureAgent-Signature` (HMAC over the raw body, constant-time compared). Envelope `node_id` must match the header. Accepted kinds: `flag`, `incident`, `guard`, `status`. |
| `GET /fleet` | Merged multi-node rollup ordered by operator priority (critical → attention → stale → all-clear → legacy). Per node: `hostname`, `labels`, `version` (tracks the newest report), `last_seen` (liveness), `last_event` (security activity), lifetime counts, **rolling 24h counts** (`flags_24h`, `critical_flags_24h`, `incidents_24h`), guard `allow`/`deny` breakdown, `gaps` (sequence-gap loss count), `boot_id`, and the node's own posture (`posture_state`, `posture_summary`, `needs_you`, `agents`). |
| `GET /fleet/rules` | Cross-node rule aggregation: `{total_nodes, rules: [{rule, nodes, node_ids, flags_24h, critical_24h}]}` sorted by fleet spread — "is the same thing firing on N/M nodes?" |
| `GET /nodes/<id>/events?kind=&limit=` | One node's stored envelopes, newest first. |
| `GET /` | HTML overview: a fleet headline ("2 critical · 1 stale · 12 all-clear"), the rules-across-fleet table, and per-node cards (hostname, posture chip, 24h counts, labels, delivery-gap warnings). Liveness: heartbeat nodes stale >3 min, gone >10 min; legacy event-only nodes >10 / >20 min. |
| `GET /healthz` | Liveness. |

Secrets come from a flat file (`node_id=secret` lines) or `-secrets n1=a,n2=b`. Store: append-only JSONL per node, `0600` in a `0700` directory, replayed into the rollup at startup behind a small `envelopeLog` interface — a SQLite backend can replace it without touching rollup semantics (the production-grade trajectory: retention, TLS, alerting).

The e2e smoke test provisions a collector, configures a node webhook, triggers a real flag, and asserts verified flag **and status-heartbeat** envelopes land in the store — the fleet contract cannot regress silently.
