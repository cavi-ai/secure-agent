# Changelog

All notable changes to `secure-agent` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [v0.9.0-rc.3] — 2026-09-08

Release candidate 3: the console UI overhaul (liveness, evidence chains,
menubar redesign), a console XSS fix, the local advisor (opt-in triage
and incident narratives), and a hardening pass on the daemon's wiring
and test infrastructure.

### Local advisor (opt-in)

- **Local triage advisor.** Flags and incidents are offered asynchronously
  to a locally served model (MLX or any OpenAI-compatible loopback
  endpoint) and the verdicts surface as advisory annotations: an
  `advisor: benign|suspicious|malicious` chip on flag cards, an
  "advisor: N of M look benign" line in the posture banner and menubar
  hero, and a plain-English narrative paragraph on incident cards.
  Loopback-only is enforced in config validation and again at client
  construction; verdicts can never flip enforcement; a down/slow model
  fails silent behind a circuit breaker. See
  `docs/ADVISOR_THREAT_MODEL.md`.
- **Advisor onboarding step.** The setup wizard detects a model server on
  the loopback endpoint and offers one-click enable/disable (atomic
  config.yaml flip, restart note included); `/status` carries
  `advisor_enabled` so UIs can distinguish "no verdicts" from "advisor
  off". The YAML flip helpers are unit-tested (append-when-absent,
  flip-only-enabled, block scoping, missing file).
- Guard coverage expansion: `Grep`/`Glob` scans rooted at protected
  directories (`~/.ssh`, `~/.aws`, `~/Library/Keychains`, …) are now
  gated by the governing rule's mode (monitor/prompt/deny); the
  `harness-config` rule covers harness settings & hook scripts (reads
  mode-governed, writes always denied — the self-removal class); grep/rg
  are classed as readers so `grep '' credentials` is the same deny as
  `cat`.
- DOM-level console test suite (24 assertions in CI) and an SSE
  subscription race fix (subscribe-before-greeting).
- **Allowlist suggestions.** Recurring uninspected egress endpoints
  (≥3 sightings, counted per agent+host in the correlator) now surface
  in the firewall panel with a one-click "Allow for \<agent\>" —
  persisted to `allowlist-overrides.json` (0600, atomic), consulted by
  the vendor-host check immediately, purged from the blind-spot count,
  and audited. Hosts are validated as bare hostnames so the allowlist
  can't be widened by smuggled structure; the endpoint is mutation-gated
  like firewall promotions.
- **Settings window.** A real tabbed Settings surface (⌘, from the
  menu bar, or the popover gear): General (login item, CLI, routing,
  uninstall), Guard (the full monitor/prompt/deny rule editor),
  Firewall (per-rule monitor/block with live counters), Advisor (server
  detection + enable toggle).
- **Activity trends.** The store keeps pre-aggregated hourly rollups
  (O(buckets) reads, 30-day retention) served at `/stats/rollup`; the
  console gains an Activity strip chart (24h/7d, events with rose flag
  markers), and the advisor's triage prompt now carries week-over-week
  trend context (rule frequency, host novelty) so "benign vs unusual"
  is judged against this machine's own history.
- **Posture language fix.** Dead collectors read as operator language
  ("File monitoring is off — usually missing Full Disk Access…")
  instead of process jargon ("Monitor eslogger is abandoned"), and the
  attention summary pluralizes properly.
- **Advisor managed mode.** `advisor.managed: true` makes the daemon
  download, spawn, and supervise the model server itself (supervised
  like every collector, killed with the app). Path B: `/advisor/discover`
  lists loopback OpenAI-compatible servers you already run (Ollama/MLX/
  llama.cpp) plus the curated managed list; the Settings Advisor pane
  renders both paths as radio + dropdowns — nobody types an endpoint.
  Reasoning models handled: thinking disabled per-request, think
  blocks stripped.
- **Injection second opinion.** Prompt-injection detections now carry a
  bounded, secret-scrubbed snippet of what matched (in the event
  detail → flag evidence), and `proxy-prompt-injection` flags get a
  dedicated second-opinion prompt tuned for the scanner's classic
  false positive (documentation ABOUT injection vs an attack).
- **Agent count precision.** `active_agents` counts tree roots, not
  processes (266 helpers ≠ 266 agents); new `tracked_processes` field
  carries the full count; the menubar lists roots only.
- **Triage completion loop.** The advisor backfills verdicts for
  severity-3 flags that fired while it was off (7-day window, bounded);
  advisor-benign flag rows offer a reversible **Mute rule+host**
  disposition (persisted to `muted.json`, suppressed at the correlator
  with a `muted_flags` counter, unmute from the flags panel); open
  incidents older than 72h surface in posture as aging items.
- **Informed suggestions + weekly digest.** Suggestion-threshold hosts
  get an advisor legitimacy pre-assessment shown inline on the Allow
  button; Monday 09:00 the menubar sends a one-line weekly digest from
  rollups ("3 flags · 1 blocked leak · 2 approvals · 0 open incidents").
- **In-app updates.** Settings → Updates: a Stable channel (latest
  GitHub release DMG, SHA-256 verified against the release's
  checksums.txt before mounting — mismatch or missing checksum is a
  loud refusal) and a Nightly channel (ff-only build from origin/main
  of a local checkout via `packaging/update_nightly.sh`).
  `make_dmg.sh` now emits `dist/checksums.txt` on every build.

### Security fixes

- **Console inline-handler XSS closed.** Every inline `onclick` handler
  interpolated values into single-quoted JS strings, but the HTML escaper
  never touched `'` or `\` — a value like `');alert(1);//` broke out and
  executed as script in the operator's console, which holds the console
  token in memory (telemetry reads and guard self-approval were the
  escalation). Reachable by a monitored agent via `session_id`/event detail
  through `activity.jsonl`. New `escapeJS` with correct layering
  (`escapeHTML(escapeJS(v))`) applied to all six interpolation sites;
  `removeSource` dropped `encodeURIComponent` (never escaped quotes either).
  Regression tests count unescaped quotes in the emitted attribute.
  Follow-up: all inline handlers were then replaced with `data-*`
  attributes + a single delegated click listener — the JS-string
  interpolation context no longer exists at all (`grep onclick`: 0 hits).

### Console (web UI)

- **Evidence-chain hero view.** Flags are now expandable cards that tell
  their causal story as a connected node chain (sensitive read → egress
  destination → verdict), parsed from the correlator's real evidence
  sentences with a raw-node fallback that never hides audit data. The most
  recent flag auto-expands; raw evidence remains visible below the chain.
- **Liveness pass.** Masthead event-rate sparkline (rolling 60s, SSE-fed
  with poll-fallback backfill), fresh timeline rows animate only for events
  unseen in the previous render (no polling flicker), KPI numbers tween
  with a directional flash, a proxy verdict pulses the firewall panel and
  flashes the rule row that intercepted, and the posture banner
  cross-fades between states. All motion honors `prefers-reduced-motion`.
- **Session drill-down.** "View session in timeline" on any flag card
  filters the event timeline to that harness session (chip with match
  count + one-click clear).
- **CSS regressions fixed.** Undefined `--rose`/`--text`/`--muted` tokens
  (the critical posture dot was invisible), a duplicate `@keyframes pulse`
  that broke the status-dot glow, and a `.status-chip` class collision
  that shrank the masthead chip. New `check_console_css.sh` guard (CI +
  `make test`) fails on undefined custom properties and duplicate
  keyframes.
- **Real version badge.** `/status` carries the link-time build version
  and the console renders it — the badge can't go stale. Timeline
  timestamps are now deterministic zero-padded `HH:MM:SS` (`fmtTime`),
  immune to locale quirks.

### Menu bar app

- **Popover redesign.** A 3-state hero (Protected / Attention / Action
  needed, plus Disconnected) now answers the three glance questions,
  mirroring the console's posture banner. The firewall section condenses
  to rules that have seen suspicious traffic; the guard policy editor
  moved behind a collapsed "Manage rules…" disclosure. A new severity-3
  flag briefly pulses the status-item title.

### Testing & engineering

- **`main.go` decomposed** (was the codebase's biggest untested hotspot,
  degree 172) into `wire.go`: setupFirewall, setupProxy, guardBrokerMS,
  transcriptTailTargets, startDrainLoop, buildStatusFn, watchParentExit —
  each with direct unit tests.
- **Console JS test harness.** DOM-free logic extracted to `lib.js`
  (escapeHTML, fmtTime, sparkline math, markdown, evidence-chain
  parser) and covered by a zero-dependency `node --test` suite wired
  into CI and `make test`. A DOM-level suite
  (`packaging/test/console_dom/`) renders the real console in headless
  Chrome against stubbed telemetry and asserts 24 behaviors: telemetry
  wiring, evidence chain, liveness classes, session drill-down, and the
  zero-inline-handlers guarantee.
- **Linux CI flake fixed.** `TestFullBusCorrelatorStorePipeline` now
  drains its consumer goroutine before closing the store on every path
  (was: `sql: database is closed` races on slow runners).
- **README screenshots regenerated** — they now show the posture banner,
  evidence chain, secret sources, policy audit, fleet, and the correct
  version badge.

## [v0.9.0-rc.2] — 2026-09-07

Release candidate 2: the full audit hardening pass (hooks, daemon,
menubar, CI/packaging), SSE push for both UIs, the console-auth
fix, session evidence chains, and the guard policy editor.

### Linux support

- The daemon is now platform-portable (pure Go, no cgo): `/proc`-based
  process source and socket lister, SO_PEERCRED peer credentials, eslogger
  gated behind an availability check (Endpoint Security is macOS-only —
  file telemetry degrades to the transcript scanner on Linux, everything
  else is identical). New `Linux build + vet + test` CI job on ubuntu-latest
  enforces it; darwin/linux factories (`NewProcSource`, `NewSocketLister`,
  `NewPeerChecker`) keep platform code in build-tagged files.

### Security fixes (hooks)

- **Shell `-c` bypass closed.** `sh`/`bash`/`zsh`/`dash`/`ksh` payloads are now
  recursively analyzed (depth-capped). Previously `zsh -c "security
  dump-keychain"` bypassed every check, including the keychain total-ban.
- **Executor bypasses closed.** `xargs` is no longer stripped as a wrapper
  (`echo ~/.zshrc | xargs rm` was allowed); `find -exec/-delete` over protected
  paths is denied; archivers (`tar`/`zip`/`ditto`/`7z`) over protected
  directories are denied as bulk exfiltration.
- **Case-folding on APFS.** Path classification is case-insensitive
  (`~/.ZSHRC` is `~/.zshrc` on a case-insensitive volume).
- **Wider credential surface.** Added `~/.netrc`, `~/.gnupg/**`,
  `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`,
  `~/.config/gh/hosts.yml`, and `*.pem`/`*.p12`/`*.pfx` to the never-print set.
  `.pub` public keys are now correctly *allowed* (they are meant to be shared).
- **Obfuscated inline writes denied.** Interpreter `-c` code combining a file
  write with runtime path composition (chr()/base64/env lookups) is denied as
  `interpreter-obfuscated-write`.
- **chflags fixed both ways.** Unlock detection now matches a known flag set
  (`nouchg`/`noschg`) instead of "starts with no" — so `chflags nodump` (a
  hardening flag) is allowed, while `chflags -R nouchg ~` is denied.
- **No secrets in the audit trail.** Denied commands are redacted (passwords,
  tokens, bearer strings, PEM headers) before hitting `secret-guard.jsonl` /
  `activity.jsonl`, and both logs are now `0600` in `0700` dirs.
- **Corrupt guard config fails closed.** A truncated `guard-modes.json` /
  `guard-cwd-overrides.json` now denies (and logs loudly) instead of silently
  reverting every rule to `monitor`.
- **Injection scanner robustness.** NFKC normalization, zero-width/format char
  stripping, and Cyrillic-homoglyph folding before matching; added
  `forget…`/`do not follow…`/`new goal:` pattern families; recursion is
  depth-bounded and a scanner crash now emits `{}` instead of dying with no
  JSON.

### Security fixes (daemon)

- **Guard broker data race fixed** (`Resolve` iterated a waiter's channel slice
  after dropping the lock while `Request` appended under it). New `-race`
  regression test.
- **Authorization wired correctly.** `authorize` now uses the role methods
  (`canRead`/`canDecide`/`canMutate`): tagged agents may read and ask
  `/guard/decision` (previously 403, which broke the prompt flow), but can
  never mutate.
- **CA key regeneration actually lands at 0600.** `os.WriteFile` preserves an
  existing file's mode, so a regenerated key inherited the old world-readable
  perms; all security-state files now write via temp+fsync+rename (atomic and
  crash-consistent).
- **Salt rotation is loud, never silent.** A truncated/unreadable salt file is
  an error with operator instructions instead of silently minting a new salt
  that orphans every registered fingerprint.
- **Fingerprint ingest refuses to purge.** A run that reads zero fingerprints
  while every source failed returns an error instead of an empty set that
  would silently wipe the registry; oversized lines no longer truncate scans.
- **Config overlay errors are visible** (log warnings on unreadable/malformed
  YAML), and `Load` validates values that would panic at runtime
  (`net_sample_interval_ms <= 0` panics `time.NewTicker`).
- **Store correctness.** `SetIncidentStatus` uses `RowsAffected` instead of
  `SELECT changes()` on a possibly-different pooled connection (spurious
  404s); incident IDs now include the flag ID (same-second same-pid flags no
  longer overwrite each other's evidence); `flags` table has a retention cap
  like the other tables; `QueryEvents` returns `session_id`; timestamps are
  stored UTC-normalized.
- **Proxy correctness.** Blocked CONNECT request bodies are drained before the
  next read (keep-alive tunnels no longer desync); the plain-HTTP path reuses
  one transport; token comparison is constant-time.
- **Resource bounds.** Fleet deliveries capped at 64 in flight (dropped and
  counted beyond that); the correlator's uninspected-egress set is capped;
  the tagger prunes dead pids (also fixes recycled-pid tag inheritance);
  transcript scanner prunes rotated files and caps line length; eslogger
  zombies reaped; reverse DNS is async with a deadline instead of blocking
  the sampler; the event bus refuses subscriptions after close; API POST
  bodies are size-limited; `/guard/resolve` validates method and id;
  `lsof` failures are logged.
- **Collector read auth.** `-read-token` (or
  `SECURE_AGENT_COLLECTOR_READ_TOKEN`) gates `/fleet`, `/nodes/*`, and `/`;
  binding a non-loopback address without one logs a loud warning.
- **`agent-env.sh` values are shell-quoted** — paths with spaces (e.g.
  `Application Support`) no longer break the snippet, and metacharacters
  can't inject into the sourcing shell.

### Menu bar app

- **Transport hardening.** The unix-socket client now has connect/send/recv
  timeouts (a wedged daemon no longer hangs the app or leaks blocked
  threads), parses the HTTP status line (non-2xx is an error, not JSON), and
  handles chunked transfer-encoding. Query parameters from daemon-supplied
  values are percent-encoded.
- **No more fail-open guard UI.** `/guard/pending` and `/guard/rules` decode
  strictly; a malformed response surfaces an error instead of silently
  showing "nothing to approve".
- **No first-launch notification storm.** The first fetch seeds the
  notification baseline; only genuinely new flags alert. Notification bodies
  no longer leak paths/hostnames to the lock screen.
- **Honest actions.** Kill asks for confirmation and reports refusal; a guard
  decision that fails to reach the daemon tells you it wasn't recorded;
  disconnect clears all daemon-derived state instead of showing stale data;
  a daemon that crashed past the restart limit gets an in-app "Restart"
  button instead of a silent permanent "Disconnected".
- **Incident remediation in the popover.** Tapping an incident opens the
  daemon-generated rotation checklist (previously only in the web console).
- Fetch loop is serialized (no overlapping out-of-order polls), the unused
  1 Hz `/events` fetch is gone, hook detection requires all three harnesses
  (`allSatisfy`), the hook self-test no longer pipe-deadlocks, and
  `guard-modes.json` writes are atomic.

### CI / packaging

- GitHub Actions are SHA-pinned with `permissions: contents: read`.
- `e2e_smoke.sh` kills all background processes on any exit (failures used to
  orphan the daemon/collector with their state dir deleted underneath).
- `make_dmg.sh` fails loudly when notarization was requested but fails.
- `make_app.sh` sanitizes git-derived strings before plist interpolation.
- `uninstall.sh` only removes hooks it actually installed and lists leftover
  state instead of claiming "completely uninstalled".
- `run_e2e_verbose.py` anchors at the repo root and always reaps the daemon.

### Menu bar: SSE push replaces 1 Hz polling

- The menu bar app now consumes the daemon's `/events/stream` SSE feed:
  guard prompts arrive at **push latency** instead of up-to-1s poll latency,
  and the idle poll drops to a 30s status cadence. Falls back to the 1 Hz
  poll when the endpoint is unavailable (503 from an older daemon) and
  reconnects with capped exponential backoff + jitter on transport failure.
  The stream's 15s heartbeat doubles as the liveness watchdog (45s idle =
  dead connection, reconnect).
- Daemon publishes two new bus event kinds for the guard lifecycle:
  `guard-prompt` (a prompt was enqueued) and `guard-resolved` (a prompt was
  resolved), letting every connected UI refetch immediately.
- Enforced by `e2e_smoke.sh`: the stream must carry both guard lifecycle
  events during the guard round-trip.

### Web console: actually works now, and live

- **Fixed a broken headline feature**: the dashboard at
  `http://localhost:8443/dashboard/` loaded, but every telemetry fetch hit the
  proxy listener's token challenge (407) — the console rendered a permanent
  offline banner with no data. The proxy port now serves the console's API
  endpoints behind a new per-install **console token**
  (`~/.config/secure-agent/console-token`, 0600) — deliberately distinct from
  the proxy token, which agents carry in their environment and could
  otherwise trade for telemetry reads and guard self-approval.
  `/guard/decision` stays off the HTTP listener entirely (peer-attested unix
  socket only).
- The console now consumes `/events/stream` (SSE) with a 2s polling fallback
  and a 30s slow refresh for status — guard prompts and flags appear at push
  latency.
- The menubar's **Open console** passes the console token automatically; the
  page strips it from the address bar after lifting it into memory.
- Enforced by `e2e_smoke.sh`: 403 without a token, 403 with the *proxy* token,
  200 with the console token; plus `TestConsoleAPIGate` in Go.

### Features & follow-ups

- **Session evidence chains survive the store.** The `flags` table now
  persists `session_id` (with an in-place migration for existing databases —
  no more `duplicate column` log noise on fresh starts), `/flags` returns it,
  and the menubar shows the session prefix on flag rows.
- **Guard policy editor in the popover.** Per-rule `monitor` / `prompt` /
  `deny` toggles write `guard-modes.json` atomically — Directory Guard policy
  is now editable without touching JSON by hand. A corrupt modes file is
  surfaced in the UI (the hook fails closed on it) instead of looking like
  "everything is monitor".
- **docs/GUARD_THREAT_MODEL.md** — the Directory Guard's closed bypass
  classes, known limits (symlinks, TOCTOU, static inline-code analysis), and
  the fail-open/fail-closed table, linked from the README.
- `go mod tidy`: dependency graph normalized (direct deps were all marked
  indirect).
- Swift model identities no longer collide (`EventModel.id` was
  `kind-pid-second`; `AgentSummaryModel.id` was bare pid).
- `AppState` is testable: the daemon client is injected behind a protocol and
  notifications go through a closure — new unit tests cover the notification
  baseline storm-guard, dedupe, low-severity filtering, disconnect state
  clearing, decode-vs-transport distinction, guard decode surfacing, and
  pause semantics.


## [v0.9.0-rc.1] — 2026-09-02

First release candidate. Everything below has CI enforcement: Go (vet, test,
`-race`), Swift package tests, 138 Python hook cases, an end-to-end smoke test
(flag → incident → guard round-trip through a live daemon), and secret
scanning of the repository itself.

> **RC disclaimer.** The DMG is ad-hoc signed: recipients must right-click →
> Open the first time. Notarized builds are planned for v1.0.

### Security hardening

- **Kernel-attested control socket.** Every unix-socket connection is
  identified with `LOCAL_PEEREPID` / `LOCAL_PEERCRED`; a role gate restricts
  reads (owner + agents), guard decisions (agents), and mutations
  (owner-level). Nothing can spoof the menubar or a hook.
- **`/kill` allowlist.** The daemon only kills PIDs it currently recognizes as
  agent processes — the control socket is no longer an arbitrary-process
  killer, and killing the daemon through its own API is impossible.
- **Guard broker bounds.** The pending-prompt queue caps at 32 with an explicit
  `deny("queue-full")` on overflow; identical in-flight requests share one
  waiter; prompts resolve oldest-first.
- **Informed consent.** Guard prompts disclose what "Allow Always" approves
  (`scope_text`): every path under the rule for that agent, not just the file.
- **Filesystem hygiene.** State directories `0700`; database, WAL, and JSONL
  logs `0600`.
- **Web console hardening.** CSP, `X-Frame-Options: DENY`, `nosniff`, and
  `Referrer-Policy` on both the proxy-port and unix-socket dashboard routes.
- **Honest telemetry.** `/fleet` reports a real ldflags-stamped version and a
  stable `node_id`; the fabricated `tailnet_ready` field and the dead
  "synchronous blocker" collector stub were removed.
- **Race fix.** `ProxyServer.port` data race (found by the new `-race` CI job)
  made atomic.

### Directory Guard

- Config-driven `monitor` / `prompt` / `deny` modes across file tools and Bash.
- **Per-project policies**: `directory_guard.cwd_overrides` pins one repo
  subtree to specific rule modes (deny `.env` in the production repo, monitor
  everywhere else) — resolution: cwd overlay → global override → default.
- Native menubar prompts (Allow Once / Allow Always / Deny, with **Deny as the
  safe default**), per-`(agent, rule)` caching, and rule revocation.
- Guard's own control plane is protected from agent writes and from direct
  socket forgery via network clients.

### Fleet oversight

- **Signed webhook delivery** of flags, incidents, and guard decisions:
  `X-SecureAgent-Signature: sha256=HMAC(secret, body)`, 3 retries with backoff
  (network/5xx/429 only), `0600` delivery log, never blocks the daemon.
- **Stable node identity**: 128-bit `node_id` per install, reported by
  `/fleet` and stamped on every webhook envelope.
- **Session identity**: hooks stamp `session_id` (Claude session env or per-run
  UUID) through events → flags → incidents, so evidence chains survive PID
  reuse.
- **CLI parity**: `secure-agent guard list|revoke`, `firewall mode|sources`,
  `events|audit`, plus `SECURE_AGENT_SOCK` for tunneled remote nodes.

### Operator UX

- **`GET /posture`** — the headline: all-clear / attention / critical, a
  `needs_you` count, and severity-ranked items (recent critical flags, pending
  guard prompts, dead collectors, uninspected egress).
- **Incident workflow** — forward-only `open → acknowledged → resolved` with
  audited transitions; reports stay immutable evidence.
- **`GET /events/stream`** — SSE live feed with heartbeat; replaces polling.
- **Console** — posture banner with drill-down links, incident ack/resolve
  buttons, status chips, resolution notes.
- **Onboarding hook self-test** — one click fires a synthetic tool call through
  the installed guard and verifies the round-trip.
- **Human-language guard prompts** — "claude wants to read a cloud credential
  file" with the stakes explained, not a raw path.

### New endpoints (unix-socket API)

`/posture` · `/events/stream` (SSE) · `/incidents/status` · `/guard/*` ·
`/firewall/*` · `/fleet` · `/dashboard/` — full reference in `docs/API.md`.

### Compatibility

- Existing `events.db` files are migrated in place (new columns are additive;
  nothing is rewritten or reinterpreted).
- Everything ships in monitor mode by default: no rule blocks until you
  promote it.

## Earlier

Development history lives in the git log; this changelog starts at the first
tagged release.