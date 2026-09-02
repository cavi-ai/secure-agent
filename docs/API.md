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
