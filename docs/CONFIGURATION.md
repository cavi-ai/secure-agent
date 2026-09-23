# secure-agent Configuration Guide

`secure-agent` uses a flexible YAML configuration system. Default configuration rules are embedded into the Go daemon binary and can be customized by creating an overlay configuration file at `~/.config/secure-agent/config.yaml` or passing a `-config <path>` flag to `secure-agentd`.

---

## 📄 File Location

- **Default Overlay Path**: `~/.config/secure-agent/config.yaml`
- **CLI Flag Override**:
  ```bash
  secure-agentd -config /path/to/custom_config.yaml
  ```

---

## ⚙️ Configuration Schema

### `sensitive_globs` (List of Strings)
Glob patterns matching file paths considered sensitive. If an agent process accesses a file matching any of these patterns, a sensitive read event is recorded.

```yaml
sensitive_globs:
  - "**/.env"
  - "**/.env.*"
  - "~/.ssh/id_*"
  - "~/.ssh/*_rsa"
  - "~/.ssh/*_ed25519"
  - "~/.aws/credentials"
  - "~/.config/gh/hosts.yml"
```

---

### `sensitive_paths` (List of Strings)
Directory path prefixes considered sensitive. Any file access within these directory trees triggers a sensitive read event.

```yaml
sensitive_paths:
  - "~/.aws"
  - "~/.ssh"
```

---

### `keychain_markers` (List of Strings)
Path substrings identifying macOS Keychain database files.

```yaml
keychain_markers:
  - "library/keychains"
  - ".keychain-db"
  - "login.keychain"
```

---

### `agents` (List of Agent Objects)
Definitions used by the process tagger to identify AI agent process trees.

```yaml
agents:
  - name: claude
    match: ["claude"]
  - name: cursor
    match: ["Cursor Helper", "cursor"]
  - name: codex
    match: ["codex"]
```

- `name`: Identifier for the agent harness.
- `match`: List of process name substrings or binary name patterns to match against system processes.

---

### `vendor_allowlist` (Map of Agent Name to List of Domains)
Approved egress hostnames and domains per agent harness. Network connections established to domains outside this allowlist following a sensitive file read will trigger a security flag.

```yaml
vendor_allowlist:
  claude:
    - "anthropic.com"
    - "claude.ai"
  cursor:
    - "cursor.sh"
    - "cursor.com"
  codex:
    - "openai.com"
    - "api.openai.com"
```

---

### `net_sample_interval_ms` (Integer)
Frequency in milliseconds at which the socket sampler (`lsof`) lists active open network sockets for tagged agent processes (default: `2000` ms). Loopback endpoints are never recorded — local-only traffic is not egress.

```yaml
net_sample_interval_ms: 2000
```

---

### `retention` (Object)
Time-based event retention, per kind. Socket churn (`conn-open`/`conn-close`) ages out in hours so it cannot evict the security record; all other kinds keep days. A row-count cap remains as a backstop.

```yaml
retention:
  conn_event_hours: 24  # socket open/close churn
  event_days: 7         # file, exec, transcript, guard, proxy events
```

---

### File & Socket Paths

```yaml
socket_path: "~/.config/secure-agent/daemon.sock"
db_path: "~/.local/state/secure-agent/events.db"
jsonl_path: "~/.local/state/secure-agent/events.jsonl"  # flag mirror; rotates at 8 MiB
openclaw_home: "~/.openclaw"  # openclaw state directory holding lcm.db
hermes_home: "~/.hermes"      # Hermes Agent root holding state.db and profiles/*/state.db
```

`openclaw_home` is unset by default. Unset, the daemon uses the first of
`$OPENCLAW_STATE_DIR`, `$OPENCLAW_HOME/.openclaw`, `~/.openclaw`, and the
`.openclaw` directory of a running openclaw process's executable path that
holds `lcm.db`. Set, it is the only path read.

`hermes_home` is unset by default. Unset, the daemon uses `$HERMES_HOME`, else
`~/.hermes`. It reads `state.db` there and each `profiles/<name>/state.db`;
none present, the Hermes collector stays idle and `/doctor` reports `hermes`
as not installed.
A Hermes installed outside `~/.hermes` without a `hermes-agent` path needs an `agents:` override to be tagged.

Tilde (`~`) prefixes are automatically expanded to the user's home directory. Environment variables (e.g. `$HOME`) are also resolved automatically.

### `directory_guard` (Map)

Configures the interactive filesystem guard. The shipped defaults are all `monitor`; the onboarding **Guard My Secrets** opt-in promotes rules via `guard-modes.json`, not this file.

```yaml
directory_guard:
  prompt_deadline_ms: 45000   # how long a prompt-mode hook waits before failing safe to deny
  cwd_overrides:              # per-project policies (first matching prefix wins)
    - cwd_prefix: /Users/me/work/prod-api
      rules:
        env-files: deny
        ssh-keys: prompt
```

Each entry pins a directory subtree to specific rule modes; rules not listed fall back to the global override file, then shipped defaults.

### `fleet` (Map)

Downstream webhook delivery for fleet oversight:

```yaml
fleet:
  webhooks:
    - url: "https://collector.example.com/hooks/secure-agent"
      secret: "<shared-secret>"
      events: [flag, incident, guard]   # empty = all
```

Every payload is signed with `X-SecureAgent-Signature: sha256=HMAC(secret, body)`; delivery retries (500ms/2s/5s) on network errors and 5xx/429 only. Add `session` and `trace` to `events` to carry the session spine and agent-semantic trace events (the collector's `GET /fleet/sessions` view); trace delivery is deliberately lossy under load.

### `otlp` (Map)

OpenTelemetry trace export (opt-in). Sessions, tool calls, model calls and turns are exported as **OTLP/HTTP JSON** spans to any backend (Tempo, Jaeger, Honeycomb, an OTel Collector). Empty `endpoint` disables it. No secrets cross this wire — spans carry tool names, models, durations and token counts, never file contents or command text.

```yaml
otlp:
  endpoint: "http://127.0.0.1:4318/v1/traces"  # OTLP/HTTP JSON receiver
  service: "secure-agent"                       # resource service.name
  headers: { "x-api-key": "<token>" }           # hosted backends; optional
  labels: { env: prod, role: build-runner }     # extra resource attributes
```

One session maps to one OTLP trace; each tool/model call nests under it. Export is best-effort and bounded — a slow or dead endpoint never stalls the daemon's event drain, and dropped spans are counted rather than buffered without limit.

### `pricing` (Map)

Model-call cost uses a built-in table of Anthropic, OpenAI and Google list prices. `pricing` adds entries for models the daemon does not know, in USD per 1M tokens:

```yaml
pricing:
  gpt-5.6-sol:  { input: 1.25, output: 10 }   # USD per 1M tokens
  k3-256k:      { input: 0.60, output: 2.50 }
```

Each key is an exact model id or a prefix: an exact match wins, otherwise the longest prefix whose remainder is empty, `-latest`, a date (`-20260101`, `-2026-01-01`), or `@20260101` (`k3` prices `k3-20260101` but not `k3-256k`; a `-pro`/`-mini` variant or another version needs its own entry). An entry here wins over the built-in table. An entry with a missing, non-numeric, or non-positive price is ignored and logged; the rest still apply. Changes take effect live within one poll cycle. Unknown models cost 0 and show as unpriced in `/costs` and `secure-agent cost` — never a fabricated price. `GET /costs/unpriced` lists each unpriced model with its class (`unpriced-model` needs an entry here; `plan`, `local` and `unknown-model` do not), and `secure-agent cost` prints one `add a price for <model>` line per `unpriced-model` id.

### `worktrees` (Map)

The worktree hunter (`GET /worktrees`, `secure-agent worktrees`). Repositories are found from agent sessions, the worktree directories agent apps use, and the saved list; `roots` adds directories to search for repositories, three levels deep.

```yaml
worktrees:
  roots: ["~/code", "/Volumes/work"]   # absolute or ~-relative
  stale_days: 14                       # idle age that marks a worktree stale (1-365; 0 = 14)
```

Changes take effect live within one poll cycle.

### Proxy authentication

Default `proxy_enabled` is `false` (MITM inspection and the web console are opt-in). When the proxy is enabled, the daemon generates a per-install token at
`~/.config/secure-agent/proxy-token` (0600). The routing snippet
(`agent-env.sh`) carries it; the proxy rejects unauthenticated proxying with
`407`. The dashboard remains unauthenticated (loopback only).

### Runtime overrides (not in this file)

- `firewall-modes.json` — firewall rules promoted to block, persisted
- `guard-modes.json` — directory-guard mode overrides (onboarding writes this)
- `firewall-sources.json` — user-added fingerprint ingest sources
- `node-id` — stable per-install fleet identity
