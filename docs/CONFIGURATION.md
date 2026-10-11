# secure-agent Configuration Guide

[Documentation](README.md) · [Project home](../README.md)

Defaults are embedded in the daemon and can be customized with a YAML overlay at `~/.config/secure-agent/config.yaml` or a `-config <path>` flag to `secure-agentd`. Start with the app's Settings when available; use this reference for manual configuration and headless nodes.

The embedded [defaults](../daemon/internal/config/defaults.yaml) and [configuration types](../daemon/internal/config/config.go) are the source of truth. Omitted fields retain their defaults, but a supplied list replaces that entire list: `agents`, `sensitive_globs`, `firewall.patterns` and similar lists are not merged by name or rule ID. Copy every entry you want to retain before customizing a list. Examples below show field shapes; review their scope before applying them.

- [Reload behavior](#reloading)
- [File and agent classification](#configuration-schema)
- [Guard policy](#directory_guard-map)
- [Firewall](#firewall-map)
- [Resource budgets](#resource_control-map)
- [Fleet](#fleet-map) and [trace export](#otlp-map)
- [Advisor](#advisor-map) and [local chat](#system_agent-map)
- [Proxy routing](#proxy-settings) and [runtime overrides](#runtime-overrides-not-in-this-file)

## Edit protection in Settings

In **Settings → File Guard** and **Settings → Egress Firewall**, use **Add**, **Edit**, or the trash button to manage guarded paths and secret-detection patterns. Saves validate the rule and persist it locally; failed saves retain the current protection. Firewall edits apply to new requests immediately. Guard path edits apply to the next hooked tool call; restart Secure Agent to update background file correlation. Mode controls choose Monitor/Prompt/Deny or Monitor/Block. See [Protection](PROTECTION.md) for the workflow and coverage limits.

---

## File Location

- **Default Overlay Path**: `~/.config/secure-agent/config.yaml`
- **CLI Flag Override**:
  ```bash
  secure-agentd -config /path/to/custom_config.yaml
  ```

---

## Reloading

The daemon re-reads the overlay every 2 seconds and applies `agents`, `disabled_agents`, `advisor`, `fleet`, `pricing`, `resource_control`, `system_agent` and `worktrees` live. Every other setting loads only at start; while the file holds a start-only setting the running daemon does not, Doctor's `config` check names its key until Secure Agent restarts.

---

## Configuration Schema

See the [generated default configuration](reference/DEFAULTS.md) for the complete embedded YAML in this checkout. The sections below explain its fields and behavior.

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
    match: ["cursor"]
  - name: codex
    match: ["codex"]
```

- `name`: Identifier for the agent harness.
- `match`: List of process name substrings or binary name patterns to match against system processes.

Definitions are checked in order: first match wins. `kind: infra` keeps shared infrastructure visible without counting it as an agent session or reclaimable agent memory. Defaults classify the Claude desktop app and Cursor IDE as infrastructure before matching their harness processes. Preserve that ordering when customizing matches. An `agents` overlay replaces the complete list; the example below demonstrates Cursor classification only, so copy other desired agents from the defaults too.

```yaml
agents:
  - name: cursor-ide
    match: ["Cursor.app", "Cursor Helper"]
    kind: infra
  - name: cursor
    match: ["cursor"]
```

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

Configures the interactive filesystem guard. Named path rules ship in `monitor`; **Guard My Secrets** under Optional capabilities promotes SSH keys, cloud credentials, keychain and harness configuration to `prompt` via `guard-modes.json`, not this file. Independent hard-deny checks still apply in monitor mode; see [Guard coverage](PROTECTION.md#directory-guard).

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

### `firewall` (Map)

Controls fingerprint and typed-pattern detection for inspected requests and tailed transcripts. The firewall defaults to `monitor`; request blocking requires explicit opt-in. The entropy backstop is monitor-only. See [Protection](PROTECTION.md#egress-secret-leak-firewall) for routing and [the threat model](FIREWALL_THREAT_MODEL.md) for inspection limits.

```yaml
firewall:
  mode: monitor
  registry:
    salt_ref: "~/.config/secure-agent/fw-salt"
    ingest_sources:
      - "~/.env"
      - "~/.aws/credentials"
    fingerprints: []   # populated by registration; never enter plaintext secrets
  patterns:
    - { id: aws-key, type: cloud-key, re: 'AKIA[0-9A-Z]{16}', mode: block }
  entropy:
    enabled: true
    min_len: 20
    min_bits: 4.0
    mode: monitor
  vendors:
    claude:
      hosts: ["api.anthropic.com", "claude.ai"]
      auth_header: authorization
  context:
    allow_own_vendor_auth: true
    treat_body_secret_as_leak: true
```

The `patterns` list above demonstrates a single AWS rule and replaces the shipped typed-pattern list if applied. To change only one existing rule's mode while retaining other patterns, use Settings or `secure-agent firewall mode aws-key block`. Specify each pattern's `mode` explicitly; the global mode is the fallback for hits without a per-rule mode, such as registered fingerprints. Registered fingerprints contain `id`, `type`, `len`, `label` and `hmac`, with the salt stored separately. Use **Scan & Register My Secrets** or `secure-agent fingerprint` to scan configured sources; do not paste secrets into the overlay.

Manual YAML firewall changes load at start. Mode controls and `secure-agent firewall mode <rule> <monitor|block>` write live runtime overrides in `firewall-modes.json`; these overrides take precedence over configured modes. Review them when diagnosing a policy that differs from the overlay. The Settings pattern editor persists the complete `firewall.patterns` list in `config.yaml` and replaces the running detector immediately after validation and a successful save.

### `resource_control` (Map)

Controls whole-session resource budgets. Zero disables a limit; shipped defaults use `observe` with both limits disabled. Changes apply live.

```yaml
resource_control:
  mode: observe
  max_rss_mb: 0
  max_cpu_percent: 0
  sustain_seconds: 30
  cooldown_seconds: 300
  workspace_overrides: []
```

| Mode | Behavior |
|---|---|
| `observe` | Reports budget breaches without changing processes |
| `prompt` | Notifies automatically; state-changing interventions need approval |
| `terminate` | Executes the configured intervention ladder automatically |

`interventions` optionally specifies ordered stages. Each stage uses `action` (`notify`, `lower_priority`, `pause`, `terminate`) and non-negative `after_seconds`. `lower_priority` accepts `nice` from 1 to 19. Actions cannot repeat, must follow that progression, and their delays cannot decrease. For example, a prompt-mode policy can notify first and offer a pause later:

```yaml
resource_control:
  mode: prompt
  max_rss_mb: 4096
  max_cpu_percent: 0
  sustain_seconds: 30
  cooldown_seconds: 300
  interventions:
    - { action: notify, after_seconds: 0 }
    - { action: pause, after_seconds: 60 }
  workspace_overrides: []
```

Each `workspace_overrides` entry is a complete policy with a `cwd_prefix` and its own mode, limits, timing and optional interventions; it does not inherit omitted policy fields from the machine default. Review a captured process family before approving an intervention. Pause may stop growth without freeing memory; lowering priority addresses contention; termination can lose unsaved work. The [usage guide](USAGE.md#manage-session-resources) explains receipts and later observations.

### `fleet` (Map)

Downstream webhook delivery for fleet oversight:

```yaml
fleet:
  hostname: "builder-01"             # defaults to the machine hostname
  labels: { env: prod, role: build-runner }
  heartbeat_interval_sec: 60
  webhooks:
    - url: "https://collector.example.com/hooks/secure-agent"
      secret: "<shared-secret>"
      events: [flag, incident, guard]   # empty = all
```

Every payload is signed with `X-SecureAgent-Signature: sha256=HMAC(secret, body)`; delivery retries (500ms/2s/5s) on network errors and 5xx/429 only. Add `session` and `trace` to `events` to carry the session spine and agent-semantic trace events (the collector's `GET /fleet/sessions` view); trace delivery is deliberately lossy under load.

Status heartbeats bypass the event filter and also fire on posture changes. See [Fleet](FLEET.md) for enrollment, collector provisioning, sequence gaps and read authentication.

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
  example-model: { input: 1.25, output: 10 }  # illustrative, not a quoted vendor price
  example-model-mini: { input: 0.60, output: 2.50 }
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

### `advisor` (Map)

Setup's **Local Advisor** optional capability and **Settings → Analysis → Advisor tools
and diagnostics** configure these fields. Saves apply live; changing the model
preserves the timeout, classifier and debug settings.

```yaml
advisor:
  enabled: false
  endpoint: "http://127.0.0.1:8080" # existing local server
  model: ""                       # the server's served chat model
  timeout_ms: 60000                # whole triage task, including tools and loading
  classifier_endpoint: ""         # optional running Kev service, e.g. http://127.0.0.1:8009
  classifier_model: "kev-latest"
  debug: false                    # request sizes, tool names and timings only
```

Endpoints must be loopback. The optional classifier uses `/v1/systemone`; its
hints do not change enforcement. The connection check verifies `/v1/models`,
not accuracy. Debug entries appear in `~/Library/Logs/secure-agent/daemon-err.log`,
which **Open daemon log** opens. Evidence, prompts and replies are excluded.
See [advisor boundaries](ADVISOR_THREAT_MODEL.md) for managed-model setup and
context/tool budgets.

### `system_agent` (Map)

The console's Agent tab chats directly with your local Ollama and can propose exact local commands for confirmation. Optional harness handoffs save separate plans for Claude Code, Codex, OpenClaw, Hermes Agent or Pi runner; Pi is terminal-only. Chat and harness dispatch remain separate. Off by default. See [SYSTEM_AGENT.md](SYSTEM_AGENT.md).

```yaml
system_agent:
  enabled: false
  debug: false                        # metadata-only request and read-tool logs
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

`debug` is also available in **Settings → Secure Agent → Chat → Tools and diagnostics**.
**Open daemon log** opens `~/Library/Logs/secure-agent/daemon-err.log`. Logging includes
request sizes, round numbers, read-tool names/counts and elapsed time; it excludes
prompts, tool arguments, evidence and model replies. Read tools are scoped to the
current reply, with fixed context, response and cache budgets described in
[SYSTEM_AGENT.md](SYSTEM_AGENT.md#read-tools-and-fresh-chat).

### Proxy settings

```yaml
proxy_enabled: false
proxy_port: 8443
proxy_ca_cert_path: "~/.config/secure-agent/ca.crt"
proxy_ca_key_path: "~/.config/secure-agent/ca.key"
proxy_inspect_hosts:
  - api.anthropic.com
```

These YAML fields require a daemon restart. Enabling the listener alone does not route a client or give it CA trust.

### Proxy authentication

Default `proxy_enabled` is `false` (MITM inspection and the web console are opt-in). When the proxy is enabled, the daemon generates a per-install token at
`~/.config/secure-agent/proxy-token` (0600). Routed clients carry it as the
password in the proxy URL, `http://<mode>:<token>@127.0.0.1:<proxy_port>`; the
proxy rejects unauthenticated proxying with `407`. Dashboard assets are served
on loopback, but console telemetry and admitted mutations require a separate
console token at `~/.config/secure-agent/console-token` (0600). **Open console**
passes it automatically. A proxy token cannot read telemetry or approve guard
requests. See [console authentication](API.md#console-access-on-the-proxy-port).

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
- `guard-rules.json` — user-edited guard paths
- `guard-cwd-overrides.json` — derived per-project policies written at daemon start
- `proxy-token`, `console-token` — separate private routing and console credentials
- `node-id` — stable per-install fleet identity
