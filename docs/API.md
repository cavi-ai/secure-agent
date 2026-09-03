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
  "active_agents": 2
}
```

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

```yaml
fleet:
  webhooks:
    - url: https://collector.internal/hooks/secure-agent
      secret: "<shared-secret>"
      events: [flag, incident, guard]   # empty = all
```

Every flag, incident, and guard decision is POSTed as:

```json
{"node_id": "…", "kind": "flag", "ts": "…", "version": "…", "payload": {…}}
```

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

Live feed of every bus event as `event: <kind>` / `data: <json>`, with a 15s heartbeat comment. Replaces polling for UIs that can hold a connection (the console's 2 s poll remains for fallback). One bus subscription per connection, released on disconnect.

### Incident workflow

- `GET /incidents` — list items now carry `workflow: {status, acknowledged_at, resolved_at, resolution_note}`.
- `GET /incidents?id=…` — returns `{incident, workflow}`.
- `POST /incidents/status` — `{"id","status":"open|acknowledged|resolved","note":"…"}`. Forward-only transitions; `acknowledged_at` stamps once; re-resolve replaces the note. Audited.

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
| `POST /hooks/secure-agent` | Webhook receiver. Requires `X-SecureAgent-Node` (provisioned) and `X-SecureAgent-Signature` (HMAC over the raw body, constant-time compared). Envelope `node_id` must match the header. |
| `GET /fleet` | Merged multi-node rollup, node-id ordered: version, last-seen, flag/incident/guard counts, latest incident summary. |
| `GET /nodes/<id>/events?kind=&limit=` | One node's stored envelopes, newest first. |
| `GET /` | HTML overview: per-node posture cards, staleness warnings (>10 min stale, >20 min gone quiet). |
| `GET /healthz` | Liveness. |

Secrets come from a flat file (`node_id=secret` lines) or `-secrets n1=a,n2=b`. Store: append-only JSONL per node, `0600` in a `0700` directory, replayed into the rollup at startup.

The e2e smoke test provisions a collector, configures a node webhook, triggers a real flag, and asserts a verified envelope lands in the store — the fleet contract cannot regress silently.
