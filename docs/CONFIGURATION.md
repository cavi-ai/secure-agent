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

## Reloading

The daemon re-reads the overlay every 2 seconds and applies `agents`, `disabled_agents`, `advisor`, `fleet`, `pricing`, `resource_control`, `system_agent` and `worktrees` live. Every other setting loads only at start; while the file holds a start-only setting the running daemon does not, Doctor's `config` check names its key until Secure Agent restarts.

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

### `not_secret_paths` (List of Strings)
Exact paths or directory prefixes that hold no secret, checked before the automatic `.env` rule, `sensitive_paths`, and `sensitive_globs`. SSH private keys, AWS credentials, and keychains retain their dedicated classification. Changes to this configuration require a daemon restart. For a live, reversible agent-scoped `.env` exception, use **Mark this .env as a test / non-secret file** on a finding and revoke it under Policy.

```yaml
not_secret_paths:
  - "~/.docker/completions"   # on zsh's fpath: read at every shell start
```

`.env` templates (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`) are never sensitive.

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

`disabled_agents` (list of agent names, case-insensitive) removes definitions from the tagger; Settings → Providers writes it. Changes to `agents` and `disabled_agents` apply within seconds, without a restart: processes of a disabled agent lose their tag, and processes of a re-enabled agent are tagged again.

```yaml
disabled_agents:
  - windsurf
```

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

### `credential_owners` (List of Objects)
The orgs each credential file, or every file under a directory, is meant for, spelled as the endpoint identity table names them (the `org` a flag explanation shows under `egress`). When the process that read the file, one of its ancestors or one of its descendants connects to one of them (git-remote-https running gh as its credential helper), the connection is counted in `status.credential_owner_uses` and not flagged. A process outside that tree, an agent tool read of the file, or any other destination still flags.

`programs` lists executable basename patterns (`filepath.Match`) of the programs that own the credential. A read of the file by a matching program is never a secret read, so it raises no finding whatever it connects to.

```yaml
credential_owners:
  - { path: "~/.config/gh/hosts.yml", orgs: ["GitHub"], programs: ["gh"] }
  - { path: "~/.aws",                 orgs: ["AWS", "AWS CloudFront"], programs: ["aws"] }
  - { path: "~/.azure",               orgs: ["Azure", "Microsoft"], programs: ["az"] }
  - { path: "~/.config/gcloud",       orgs: ["Google", "Google Cloud"], programs: ["gcloud"] }
  - { path: "~/.docker",              orgs: ["Docker Hub", "Docker", "GitHub Container Registry"], programs: ["docker", "docker-credential-*", "com.docker.*"] }
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

Each kind also has a row cap. `file-open`, `file-write`, `file-delete` and `exec` arrive faster than any fixed cap holds for a day under build load, so their cap keeps minutes to hours of rows. The security record (an event that raised a flag, or a file event that counts as a secret read) stays past the cap for the full retention, up to 20,000 rows per kind. A keychain file counts only when a byte-copy tool (`cp`, `cat`, `dd`, `tar`, `curl`, …) opened it; the system trust store never counts. At start, rows marked under an older rule lose the mark unless they are a stored flag's own event.

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
  prompt_deadline_ms: 45000   # a guard prompt is denied 3 s before this (at least 1 s; 0 = 45000)
  cwd_overrides:              # per-project policies (first matching prefix wins)
    - cwd_prefix: /Users/me/work/prod-api
      rules:
        env-files: deny
        ssh-keys: prompt
```

Each entry pins a directory subtree to specific rule modes; rules not listed fall back to the global override file, then shipped defaults.

The hook waits for a prompt decision for its own deadline, `SECURE_AGENT_PROMPT_DEADLINE_S` (default 45 s), and does not read this file. When the hook stops waiting first, the prompt is withdrawn: an answer given after that saves no rule.

The daemon writes these entries at every start to `guard-cwd-overrides.json` in the directory of `socket_path` (default `~/.config/secure-agent/guard-cwd-overrides.json`, the path the hook reads). A daemon run with a socket elsewhere writes its own copy beside that socket and leaves the default file untouched.

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

### `system_agent` (Map)

The system agent behind the console's Agent tab: a chat with a model on your local Ollama that proposes work for Claude Code, Codex, OpenClaw or Hermes Agent and dispatches it against the same Ollama. Off by default. See [SYSTEM_AGENT.md](SYSTEM_AGENT.md).

```yaml
system_agent:
  enabled: false
  endpoint: "http://127.0.0.1:11434"   # Ollama base URL (no /v1); must be loopback when enabled
  model: ""                            # chat model; "" = the first model Ollama lists
  harness_model: ""                    # model dispatched harnesses run; "" = model
  timeout_minutes: 30                  # bound on one headless dispatch (0-240; 0 = 30)
  auto_review: false                   # send new findings to the review queue on their own
  auto_review_min_severity: 2           # detector severity: 1 informational, 2 warning, 3 critical; 0 = 2
  auto_review_excluded_rules: []        # exact finding rule IDs to leave out of automatic review
```

`auto_review` (Settings → Secure Agent → Chat → Review new findings automatically) sends newly stored, unacknowledged findings that meet the severity cutoff and are not excluded to the local agent review queue. Settings exposes the cutoff and finding-type choices. These choices affect automatic review only; detection, protection and notification settings remain independent.

A “new” finding is a newly stored finding, not every observed event. Repeated activity folded into an existing finding does not queue it again, and enabling review does not scan the existing backlog. A batch waits two minutes after its first eligible finding, reviews go out at least ten minutes apart with at most ten findings each, and a busy agent retries later. The current policy is checked again before sending: acknowledged findings and findings that no longer qualify are skipped. Relaxing the policy applies to future findings; previously skipped findings can be sent manually.

Ollama receives a bounded, masked evidence summary and returns a recommendation linked to the findings. This toggle does not execute commands, dismiss findings or change protection. Local commands and harness dispatches require separate user confirmation. Published samples and placeholder credentials are evidence for review, not an automatic dismissal rule.

An enabled agent with a non-loopback endpoint is a validation error. Changes take effect live within one poll cycle.

### Proxy authentication

Default `proxy_enabled` is `false` (MITM inspection and the web console are opt-in). When the proxy is enabled, the daemon generates a per-install token at
`~/.config/secure-agent/proxy-token` (0600). Routed clients carry it as the
password in the proxy URL, `http://<mode>:<token>@127.0.0.1:<proxy_port>`; the
proxy rejects unauthenticated proxying with `407`. The dashboard remains
unauthenticated (loopback only).

### Routing modes

The user name in the proxy URL selects the mode for each connection:

- `inspect` — a CONNECT to a host in `proxy_inspect_hosts` (default
  `api.anthropic.com`) is decrypted with Secure Agent's CA and scanned; any
  other CONNECT is tunneled. For clients that trust the CA: Claude Code reads
  `NODE_EXTRA_CA_CERTS`.
- `tunnel` — every CONNECT passes through unopened: the destination is
  counted, the bytes are not read, and the client needs no CA.

The daemon writes the tunnel-mode snippet to `agent-env.sh` next to the CA
(`HTTP(S)_PROXY` in both cases, `NO_PROXY=localhost,127.0.0.1,::1`).
**Settings → Secure Agent → Traffic → Route Claude Code through Secure Agent**
writes the inspect-mode environment and the CA into the `env` block of
`~/.claude/settings.json`, and a SessionStart hook that appends the
tunnel-mode snippet to each session's Bash environment (`CLAUDE_ENV_FILE`). It
refuses when the file already sets one of those keys itself, records the keys
it added (`SECURE_AGENT_ROUTED_KEYS`), and removes only those when turned off
or when the app quits; the next launch writes them again. `/status` counts
`proxy_tunneled` and `proxy_decrypted` connections since start.

### Runtime overrides (not in this file)

- `firewall-modes.json` — firewall rules promoted to block, persisted
- `guard-modes.json` — directory-guard mode overrides (onboarding writes this)
- `firewall-sources.json` — user-added fingerprint ingest sources
- `node-id` — stable per-install fleet identity
