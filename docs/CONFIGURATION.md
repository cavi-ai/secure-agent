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

For OpenClaw running under Node, matches apply to the program entry point or process title rather than Node's installation directory. Unrelated helpers using OpenClaw's bundled Node inherit their parent harness. Custom OpenClaw match strings should identify its program; a shared Node executable path alone does not establish OpenClaw identity. Arguments and environment values are not retained as program identity.

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

### `file_telemetry_enabled` (Optional Boolean)

The menu bar's File Telemetry Enable and Remove controls save this choice.
`false` pauses privileged file-feed ingestion, including reads from an old
spool. The Remove control also unregisters the helper. `true` permits ingestion;
the helper still needs macOS approval and Full Disk Access. Changes apply live.
When omitted, existing collector discovery is preserved.

Disabled monitoring and unconfigured optional hooks are neutral observations.
Active failures still require attention. Recovery clears the current fault
while retaining loss counters and historical gaps in Monitoring.

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

`hermes_home` is unset by default. An explicit setting is authoritative;
otherwise the daemon uses `$HERMES_STATE_DIR`, then `$HERMES_HOME`, from its
own environment or, when that has neither, as the user's login shell
(`$SHELL -l`) exports them, read once per daemon run. With neither set, it
looks for `state.db` under `~/.hermes`, then under the
`.hermes` directory or parent of `hermes-agent` in a tagged Hermes process's
executable path. It also reads each `profiles/<name>/state.db`. Discovery
retries each poll, so Hermes can start after the daemon. A missing database
leaves the collector idle; `/doctor` reports the searched root and settings.
A daemon started by the menu bar app or launchd inherits no shell variables,
so an export in a shell profile is enough; set `hermes_home` when no login
shell exports them and no running process reveals the state directory.
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

The hook waits for a prompt decision for its own deadline, `SECURE_AGENT_PROMPT_DEADLINE_S` (default 45 s), and every prompt of one hook run ends within `SECURE_AGENT_HOOK_BUDGET_S` (default 55 s, below the harness's 60 s hook timeout); it does not read this file. When the hook stops waiting first, the prompt is withdrawn: an answer given after that saves no rule.

The daemon writes these entries at every start to `guard-cwd-overrides.json` in the directory of `socket_path` (default `~/.config/secure-agent/guard-cwd-overrides.json`, the path the hook reads). A daemon run with a socket elsewhere writes its own copy beside that socket and leaves the default file untouched.

#### Optional shell risk observations

Shell review records local classifier hints for Bash calls without changing
permissions in `observe` mode. It is disabled by
default and requires a running loopback Kev-compatible `/v1/systemone` server:

```yaml
directory_guard:
  shell_review:
    enabled: true
    mode: observe
    endpoint: http://127.0.0.1:8009
    model: kev-latest
    timeout_ms: 1000
```

Restart the daemon after changing these settings. Install the updated guard
hook, then set `SECURE_AGENT_SHELL_REVIEW=1` in the environment of the Claude
Code or Cursor process invoking it. Both opt-ins are required. Unsetting the
environment variable stops submissions; setting `enabled: false` and
restarting stops the daemon worker. Other harnesses are not covered.

In observe mode, the hook spends at most approximately 100 ms attempting local delivery and
never waits for inference. The daemon uses one worker and 32 queue slots, with
a default one-second model deadline (maximum five seconds). Oversized commands
are refused rather than truncated. Missing delivery acknowledgments are
recorded without command text in the hook audit log. Queue drops, model
failures, and storage failures are reported separately.

Read observations from an operator terminal outside an agent process:

```sh
curl --unix-socket "$HOME/.config/secure-agent/daemon.sock" \
  'http://localhost/guard/shell-reviews?limit=1000'
```

`POST /guard/shell-review` accepts hook observations on the control socket;
it cannot approve a tool. `GET /guard/shell-reviews` returns health and recent
observations (100 by default; `limit` accepts 1–1000). The database retains at
most 1,000 observations; results older than seven days are excluded from reads
and removed on the next write. Commands and working directories are masked
before model calls and are never stored in this table. Results retain the
redacted command's digest, hook-reported session/call IDs, the existing guard
verdict, configured model name, policy version, latency, and validated scores.
These records do not prove that a command executed or that the reported
identity is authentic.

##### Optional shell blocking

`mode: block` makes `POST /guard/shell-check` available. To use it, set
`SECURE_AGENT_SHELL_REVIEW=block` in the Claude Code or Cursor harness
environment after restarting the daemon with that mode. Both settings are
required; a mode mismatch denies the checked command. Observe remains the
default. Blocking is experimental and can deny ordinary development commands.

The hook runs the existing guard first. Its hard denials never consult the
model and cannot be overridden. For an otherwise allowed Bash command, the
additional check permits continuation only when the model result is routine,
meets the probability floor below, has unredacted evidence, and has a stored
receipt. Review, unknown, model error, malformed input, queue pressure, missing
receipt storage, and unavailable transport deny the command. There is no
interactive approval or automatic retry, and no standing permission is saved.

The total daemon deadline covers queue wait, model inference, and receipt
storage; it is the configured model deadline plus 200 ms. The hook has a
six-second absolute transport deadline and validates each reply against the
submitted command and working directory. It never reuses an earlier reply.
Stored `proposed_verdict` is the decision before delivery, not proof that the
hook received it or executed a command. `request_digest` binds that proposal
to the submitted input without storing the command or working directory.

The history response reports `enforcement_configured`, the configured mode,
and check/denial counters. These do not establish coverage of every tool call.
Only supported hooks using the check endpoint are gated. An unrestricted
same-user process can bypass the hook or alter its environment; this feature
does not provide filesystem or network isolation. Model mistakes can still
pass the additional check. Existing hard rules and OS restrictions remain
necessary when operating with broad permissions.

The classifier returns `routine`, `review`, or `unknown`. These are uncalibrated
risk hints; `routine` is not permission or a safety guarantee. A routine answer
requires at least 0.9 reported probability; otherwise the observation is unknown
with reason `uncertain_classification`. That cutoff is an abstention policy,
not a measured accuracy rate. Uncertain routine answers preserve the original
`model_choice` and scores so an abstention cannot hide a model mistake. Health counts
abstentions separately from unavailable or invalid model responses.
Invalid or unavailable model output produces `unknown` with a reason. A routine
answer on redacted evidence is also downgraded to unknown. User authorization is not
assessed: no trusted user intent is supplied. Opaque scripts and unresolved
runtime behavior are explicitly presented to the classifier as unknowns.
Existing hook and OS-level coverage limits still apply.

The model sees the command and working directory. The hook-reported guard
verdict is recorded for comparison but is excluded from model input, so it
cannot bias the model toward trusting an earlier permission.

##### Customizing a local shell classifier

`packaging/classifier/customize.py` adapts an existing local Kev LoRA adapter
and decision head. It uses the daemon's embedded `shellreview/policy.json`,
including its option order and command/working-directory format. It requires
a Python environment containing Kev's dependencies and a local Kev source
checkout. Base weights must already be cached; tuning runs offline and never
executes dataset commands.

Supply a private JSON dataset with `version: 1` and a `rows` array. Each row
requires string fields `id`, `family`, `split`, `label`, `command`, and `cwd`.
Splits are `train`, `development`, and `test`; labels are `routine`, `review`,
and `unknown`. Each split must contain every label. Keep related command
templates in one family and one split. Duplicate commands, shared families
across splits, and oversized inputs are rejected. Use synthetic examples;
do not export private commands or credentials into training data.

Freeze the dataset and policy, then tune into a separate directory:

```sh
python3 packaging/classifier/customize.py freeze \
  --suite .remember/shell-suite.json --manifest .remember/shell-manifest.json
python3 packaging/classifier/customize.py tune \
  --suite .remember/shell-suite.json --manifest .remember/shell-manifest.json \
  --kev-source /path/to/kev --checkpoint /path/to/local/checkpoint \
  --out .remember/shell-run
```

The output contains a `candidate` checkpoint, input hashes, training settings,
development results, and `comparison.json`. Candidate selection uses only the
development split; the test split is scored after selection against both the
candidate and original checkpoint. Reports separate label accuracy, routine
coverage, abstention, and non-routine examples that would pass the gate's 0.9
reported-probability floor. Tuning exits with status 2 and records rejection
reasons if any non-routine test command would be allowed, label accuracy
regresses, or routine coverage regresses. Synthetic results do not establish a production
false-allow rate. Training does not change the running model or daemon settings;
evaluate the candidate through the actual hook before enabling it. Use a separate
endpoint for the shell candidate: adaptation can change decisions on other tasks.

An opt-in acceptance probe evaluates a small fixed set of synthetic shell
commands through the production classifier path. It never executes those
commands or changes the running daemon's configuration:

```sh
SECURE_AGENT_TEST_CLASSIFIER_ENDPOINT=http://127.0.0.1:8009 \
  go test ./daemon/internal/shellreview -run '^TestLocalShellReviewEvaluation$' -count=1 -v
```

The probe uses the supported five-second maximum deadline to separate decision
quality from cold-request timeouts. It reports a failed test when a classification
misses its expected category; ordinary unit tests do not run the live probe.

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
With Claude Code selected, **Settings → Secure Agent → Traffic → Route Claude Code through Secure Agent**
writes the inspect-mode environment and the CA into the `env` block of
`~/.claude/settings.json`, and a SessionStart hook that appends the
tunnel-mode snippet to each session's Bash environment (`CLAUDE_ENV_FILE`). It
refuses when the file already sets one of those keys itself, records the keys
it added (`SECURE_AGENT_ROUTED_KEYS`), and removes only those when turned off
or when the app quits. Quit Claude Desktop and exit Claude Code before changing
routing, then reopen them so the proxy and certificate settings load together.
Routing changes, including reapplication at app launch, are refused while Claude
is running. Close routed sessions before quitting Secure Agent; removing settings
does not clear the proxy from an existing process. `/status` counts
`proxy_tunneled` and `proxy_decrypted` connections since start.

For other agents, select **Set Up & Open** in Traffic to install supported hooks
and launch the agent with a process-scoped tunnel environment. GUI apps reopen
gracefully; CLIs open in Terminal. This does not change shell profiles or system
proxy settings. Only proxy-aware connections use the tunnel, and payloads are
not inspected. Start routed sessions through Traffic and keep Secure Agent running.

### Runtime overrides (not in this file)

- `firewall-modes.json` — firewall rules promoted to block, persisted
- `guard-modes.json` — directory-guard mode overrides (onboarding writes this), including `untrusted-egress` and `untrusted-egress-injected` ([Egress after untrusted input](PROTECTION.md#egress-after-untrusted-input))
- `guard-categories.json` — per-kind modes for sends after untrusted input (Settings → File Guard writes this; [Egress after untrusted input](PROTECTION.md#egress-after-untrusted-input))
- `firewall-sources.json` — user-added fingerprint ingest sources
- `guard-rules.json` — user-edited guard paths
- `guard-cwd-overrides.json` — derived per-project policies written at daemon start
- `proxy-token`, `console-token` — separate private routing and console credentials
- `node-id` — stable per-install fleet identity

### Local model resource controls

The system agent uses Ollama's native API with a 32K context request and a
two-minute idle expiry. Advisor endpoints on port 11434 use the same controls.
For Ollama on another port, set `advisor.protocol: ollama`; use
`advisor.protocol: openai` for other compatible servers. External servers
manage their own context allocation. MLX/Safetensors context metadata can
describe a dynamic maximum rather than allocated cache.

Daemon chat and advisor requests share a bounded queue and one inference slot.
Background review has a two-minute budget per fifteen-minute window.
Managed MLX models start on demand and stop after two idle minutes.
The Agent page provides current-work cancellation, a background pause and
provider-reported memory status.

Agent history requires macOS Keychain or Linux Secret Service
(`secret-tool`). When the keystore cannot be unlocked, history remains locked
and new agent messages are refused. Monitoring and deterministic protection
continue.
