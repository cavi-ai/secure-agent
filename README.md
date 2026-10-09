# secure-agent

[![CI](https://github.com/cavi-ai/secure-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/cavi-ai/secure-agent/actions/workflows/ci.yml)
[![Go Reference](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Swift](https://img.shields.io/badge/Swift-6.0-FA7343?style=flat&logo=swift)](https://swift.org/)
[![macOS](https://img.shields.io/badge/macOS-14.0+-000000?style=flat&logo=apple)](https://apple.com/macos)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Egress inspection & secret-leak firewall for local AI agents.** See what your agents send, catch secrets before they leak, and stop rotating your keys three times a week.

<p align="center">
  <img src="assets/screenshots/console.png" alt="Secure Agent — live security console" width="920">
</p>

**`secure-agent`** is a lightweight, always-on AI-agent security monitor and harness guard designed for macOS.

> **Platform support.** macOS 14+ is the primary target (Endpoint Security telemetry, menubar app, DMG packaging). The Go daemon also builds and runs on **Linux** (`GOOS=linux go build ./...`), where Endpoint Security (`eslogger`) file telemetry degrades gracefully to the transcript scanner and network sampling runs on `/proc` — the guard hooks, egress firewall, fleet, and console all work identically. CI enforces the Linux build + tests on every push.

As AI coding agents (Claude Code, Cursor, Codex, Antigravity, Pi, Qwen Code, opencode, Copilot, etc.) gain increasing autonomy in local development environments, they gain execution privileges to read local sensitive files, mutate shell configurations, access credential stores, and initiate external network connections. `secure-agent` provides a non-intrusive, multi-layered defense system that enforces zero-trust boundaries around AI agent process trees without disrupting developer velocity.

---

## 🌟 Key Features

- 🛡️ **In-Harness Secret Guard (`PreToolUse` Gating)**  
  Synchronously intercepts agent tool calls to block unauthorized reads or mutations targeting Keychain files (`login.keychain-db`), shell configurations (`.zshrc`, `.zshenv`, `/etc/paths`), SSH keys, and cloud credentials. Supports Claude Code and Cursor hook protocols.

- 💉 **Prompt Injection Detection (`PostToolUse` Scanning)**  
  Scans tool output streams, web fetches, and agent transcripts in real time for indirect prompt injection vectors and credential leakage.

- ⚡ **Low-Overhead System Telemetry Daemon (`secure-agentd`)**  
  A pure Go daemon that consumes macOS Endpoint Security events (`eslogger`) and periodically samples per-process active network sockets (`lsof`). Current measured footprint: ~100 MB RSS resident, <2% CPU (the "<30 MB" target was written before the resource tracker, proxy, and advisor subsystems landed).

- 🧭 **Harness Trace Coverage**  
  Parses agent-semantic trace events (tool calls, model calls, turns) from Claude Code, Codex, Cursor, Antigravity (agy), and opencode transcripts — a metadata-only trace (names, durations, models, tokens; never content). opencode stores its trace in SQLite and is read by a read-only, watermarked poller. Coverage table in `docs/ARCHITECTURE.md`.
  - `/costs` and `secure-agent cost`: model-call spend by repo, branch, harness, session, model, provider, or local day at the `tz` / `--tz` offset, across every traced harness.
  - Session replay: `secure-agent session <id>` prints what an agent did — tools, models, cost, files, hosts, guard decisions, findings — as markdown for a PR body; the console's Export button copies the same.

- 🔗 **Sliding-Window Event Correlation Engine**  
  Correlates process file activity with network egress. Automatically raises security flags when an agent process reads a sensitive file (e.g. `~/.aws/credentials` or `.env`) followed by an outbound socket connection to a domain outside its pre-approved vendor allowlist.

- **Monitoring coverage and evidence health**
  Home lists a decision only when you must act: a pending guard prompt or resource intervention, an open high or critical incident, or a critical finding. Everything else stays in the Findings history log. Coverage shows each live session's supported paths and its own observations, joined by session identity and process start time. A sibling session's activity, a handshake, and an inspection failure cannot count as guard or inspection evidence. Payload inspection remains dependent on proxy routing and reliable attribution. Setup can check each installed Claude or Cursor hook's inert round trip to the daemon; that manual check does not prove a running agent invokes the hook or change guard policy. Configuration changes invalidate the result. Dropped event deliveries and failed core evidence writes appear in posture and Doctor. Successful writes clear the active storage fault for that operation, while the failure count remains for the daemon run: recovery cannot restore missing evidence. The native app keeps last-known data when an endpoint fails, marks it stale, and requires a successful refresh of that endpoint to clear the warning.

- 🚨 **Incident Remediation**
  Incident reports list suggested remediation steps and recorded control outcomes. Report individual steps completed or mark them pending in the console; these reports remain unverified and do not resolve the incident. Later evidence is shown beside earlier reports. Credential rotation and revocation are external work and are never performed automatically.

- 🌐 **Opt-In Local MITM Proxy & Payload Inspection (`127.0.0.1:8443`)**  
  Features an inline HTTP/HTTPS proxy server with dynamic TLS certificate generation (`CAManager`) that inspects request streams for outbound credential leaks (`redact.Detect`) and response streams for prompt injection attacks (`injection.Detect`).

- 🖥️ **Live Web Security Console (`http://localhost:8443/dashboard/`)**  
  Embedded dark-mode visual web console for real-time monitoring of active AI agent process trees, secret-exposure incident reports, sliding-window security flags, and proxy payload inspection streams. Its **Attention** view groups resource approvals, blocked guard requests, critical findings and incidents, and uninspected egress by complete session, with workspace, memory, CPU, process count, and scoped actions in one queue. Individual security flags open an evidence drawer with the local advisor's plan and actions. **Inspect file details** shows supported `.env` variable names without values. **Send to local agent review** routes the selected finding into the Agent recommendation queue. Expected-read exceptions cover an exact host; test/non-secret `.env` exceptions cover one exact file for the named agent and are reversible under Policy. Cloud/CDN identity is infrastructure context, not proof of secret transmission. On the **Agent** page, **Analyze activity** asks local Ollama to review stored flags and operator actions; its recommendation waits in a review queue for an explicit local-command confirmation or a saved harness plan. Updates are pushed over SSE (`/events/stream`) with a polling fallback. The console's telemetry endpoints on the proxy port are gated by a per-install **console token** (0600, `~/.config/secure-agent/console-token`) — a credential agents never receive, so a routed agent can't turn its proxy token into telemetry reads or guard self-approval. The menubar's **Open console** passes the token automatically.

- 📊 **Resource Mission Control**
  Resource actions reserve a durable intent before changing processes and record applied, partial, failed, or unknown results. Approvals bind to the captured family and budget context; changed identities require a new decision. Missing or partial results cannot silently replay the operation, including after restart. Results retain up to three existing resource samples within 15 seconds and show agent and host metrics separately. A successful process call is applied, not recovered; termination verification means the captured family was absent in a later sample. Pause may stop growth without freeing memory, priority changes address CPU contention, and termination can lose unsaved work. The console, native glance, and session export retain these limits. Configured budgets still apply on a healthy host; high use alone does not prove host damage.

  Attributes live resident memory and CPU to complete agent sessions—root process plus helpers—so one runaway child cannot hide behind a harmless-looking parent. Whole-machine context shows available and free memory, compression, swap, CPU split between agents and everything else, memory pressure, thermal state, and a conservative headroom score. The console ranks sessions by pressure, charts one hour of history, explains heavy memory, full-core CPU, rapid growth, idle retention, runaway children, and orphan drift, and opens the entire process family before any terminate action. The native menu bar shows machine headroom and family totals and adds an **Impact** sort for quick daily triage. A bounded local flight recorder keeps pressure episodes, their captured host conditions, process attribution, and the ten-minute lead-up available for post-mortem review after a session exits. Each episode correlates redacted process, tool call, model call, file, network, guard, and security activity with the steepest observed memory rise while clearly distinguishing temporal correlation from proven causation.

  Optional session budgets add a sustained-breach grace period, cooldown, and
  a graduated `notify → lower priority → pause → terminate` ladder. `observe`
  reports only, `prompt` notifies automatically and requires approval for
  state-changing steps, and `terminate` executes the configured ladder
  automatically. Paused session families can be resumed from the console. The
  default is `observe` with both limits disabled.

- 🛠️ **Native `secure-agent` CLI Tool**  
  Pure-Go terminal utility (`secure-agent status`, `flags`, `incidents`, `kill`, `fleet`, `service`) for inspecting security posture directly from terminal prompts. `secure-agent service install` runs the daemon headless under launchd for fleet/CI nodes with no GUI login.
  - `secure-agent telemetry repair` — asks the menu bar app to re-register its file-telemetry helper when launchd will not start it; exits 1 unless the helper runs within 60 s.
  - `secure-agent doctor` — hooks, file telemetry, collectors, trace coverage, sessions, pairing, pricing, retention, egress; repo attribution is measured only for sessions inside Git workspaces. Exits 1 on any failure.
  - `secure-agent worktrees` — every git worktree from agent sessions, agent worktree directories and a saved repo list, each marked remove, review, keep or prune with the reasons; `worktrees remove` and `worktrees prune` act only on those verdicts. The console's System tab shows them: Remove on a review or keep row moves the folder to the Trash while the Git branch, commits, and stashes stay (refused while an agent session is live, the worktree is locked, or a detached HEAD holds commits no branch keeps). “Ask <harness>” appears only for a live, resumable agent session; “Ask advisor” requests an advisory note; “Discuss” puts the question to the Agent tab. The tab also shows disk usage per project and what cleanups have reclaimed (`secure-agent cleanup log`).

- 🔌 **Local Control & Query API**  
  Exposes a secure HTTP API over a Unix domain socket (`~/.config/secure-agent/daemon.sock`) for querying status, events, flags, incidents, and initiating process termination.

- ⚙️ **Extensible YAML Rules & Allowlists**  
  Easily customize sensitive path patterns, agent binary matchers, vendor network allowlists (`anthropic.com`, `cursor.sh`, `openai.com`), and proxy settings.

- 🤖 **Secure Agent: Local Chat and Confirmed Actions (opt-in)**
  Turn on **Settings → Secure Agent → Chat → Enable chat**, then click **Ask Agent** in the menu bar popover. Chat goes directly to your own Ollama. For local work, the model proposes an exact shell command and folder; you review and confirm it before it runs, either headless or in Terminal for passphrases. Commands run with your account's file and network access. An optional **Harness handoff** section saves separate plans for Claude Code, Codex, OpenClaw, Hermes Agent, or Pi runner; it never changes where chat goes. Pi is terminal-only because it has no built-in sandbox. Messages and output are masked by the firewall; `/agent/*` routes refuse agent processes. See [`docs/SYSTEM_AGENT.md`](docs/SYSTEM_AGENT.md).

- 🔔 **Noise-Controlled Alerts, With Real Recourse**  
  Only **severity-3 criticals page you** by default (confirmed secret leaks, direct read-then-connect activity, TCC tampering, keychain CLI execs); warnings queue silently in the popover and console. A secret file read and later connection by unrelated sibling processes in one agent family remains a severity-2 finding for review, because timing alone does not show that the reader sent the bytes. Model-visible tool reads remain critical. Routine keychain-DB file opens are informational (severity 1) — legitimate tooling touches them constantly, so they never page unless you opt in. Every noisy class has a working **"Dismiss this flag class"** (rule-level mute, reversible from Settings → Exceptions), and Settings → Notifications / the console bell menu offer per-rule overrides, critical only by default, **Always** or **Never** (`/notify/rules`), shared by both UIs.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph Harness ["AI Agent Harness (Claude Code / Cursor)"]
        H1["PreToolUse Hook\n(Secret Guard)"] --> H2["Tool Execution"]
        H2 --> H3["PostToolUse Hook\n(Injection Scanner)"]
        H1 -->|JSONL Audit| LOG["~/.local/state/secure-agent/activity.jsonl"]
    end

    subgraph OS Telemetry ["macOS Subsystems"]
        ES["eslogger\n(open, exec, rename, unlink, tcc_modify)"]
        LP["lsof\n(Socket Sampler)"]
    end

    subgraph Daemon ["secure-agentd (Go Daemon)"]
        C1["File Watch Collector"]
        C2["Net Socket Sampler"]
        C3["Process Tagger"]
        C4["Transcript & Log Scanner"]

        ES --> C1
        LP --> C2
        LOG --> C4

        C1 --> BUS["Event Bus\n(Non-blocking Pub/Sub)"]
        C2 --> BUS
        C3 --> BUS
        C4 --> BUS

        BUS --> CORR["Sliding-Window\nCorrelation Engine"]
        CORR --> STORE["Store Engine\n(SQLite + JSONL)"]
        STORE --> API["Unix Socket API\n(~/.config/secure-agent/daemon.sock)"]
    end

    subgraph UI ["User Interface"]
        API --> MENUBAR["Swift Menu Bar App\n(Status, Flags & Kill Switch)"]
        API --> CLI["curl / CLI Tools"]
    end
```

---

## 🚀 Quick Start

### DMG Installation (recommended)

```bash
# Generate the app icon (one-time, or after changing artwork)
make icon

# Build universal binaries, assemble & sign "Secure Agent.app", package a DMG
make dmg
```

Open `dist/SecureAgent-<version>.dmg`, drag **Secure Agent.app** to **Applications**, and launch it.
First-use setup follows one selected agent path:

1. **Choose** — select a harness and see guarding, recorded activity, and payload inspection as separate capabilities. The bundled daemon starts and stops with the app.
2. **Enable** — explicitly install hooks for Claude Code or Cursor alone, preserving existing user hooks. Other harnesses can continue with their observation path.
3. **Result** — run an inert installed-hook check or view the result without a check. The check verifies the hook's daemon round trip; it does not establish that a running agent invokes the hook or that its traffic is inspected. Configuration changes and unavailable status require another check or refresh.

File telemetry, additional hook scripts, traffic routing, secret registration, guard rules, the local advisor, Open at Login, and CLI installation remain under **Optional capabilities** after the result and in Settings. New first-use setup leaves file-telemetry registration and permission panes deferred until you explicitly enable that capability.

Everything is also manageable later from the menu bar icon (**Setup & Permissions…**, **Settings…**, **Uninstall…**, **Open console**, **Ask Agent**). Secure Agent appears in the Dock, opens the setup flow on first use, and opens Settings on subsequent launches. Click the Dock icon to reopen Settings after closing its window; quit the app to stop its child daemon.

Session cards in the menu bar open that same session in the console. Finding and remediation links open the selected evidence or incident, with a return to its session when the daemon knows that identity. Missing records stay unavailable; links never substitute a new process with the same PID. The console retains record identifiers when removing the handoff credential from the address bar.

The UI has a separate menu bar identity in this update. Saved Secure Agent preferences and monitoring data remain in their existing locations. Allow **Secure Agent** in System Settings → Menu Bar; another application's menu bar setting should not be required. Review any macOS notification, Login Items or Full Disk Access prompt through the native Setup flow.

On macOS Tahoe, Control Center can incorrectly associate a status item with the application that launched it. If Secure Agent is allowed but its icon is missing, check **System Settings → Menu Bar → Allow in the Menu Bar** for the launcher as well. Enabling that launcher can restore the shield without restarting the monitor. Reinstalling the app or recreating its status item does not change the launcher's permission. Secure Agent keeps its Dock control available and limits recovery to one attempt for each observed loss of its AppKit item or window.

### In-app updates

The menu bar's **Settings… → Updates** tab offers two channels:

- **Stable** — the latest GitHub release. The app downloads the DMG, verifies
  it against the release's SHA-256 `checksums.txt` **before mounting** (a
  mismatch or a missing checksum is a loud refusal, never a silent install),
  replaces the app bundle in place, and relaunches (the daemon, a child of
  the app, comes down and back up with it).
- **Nightly** — builds from the current `origin/main` of a local checkout via
  `packaging/update_nightly.sh` (fetch → ff-only merge → `make install`).
  Developer-grade: it needs a git checkout and the repo toolchain; stable
  needs neither. The check refuses to move a tree with local-only commits.

#### Signing & notarization

`make install`, `make app`, and `make dmg` all resolve `CODESIGN_IDENTITY` the same way (`packaging/lib/sign_identity.sh`): the first "Apple Development" identity in your keychain, else the first "Developer ID Application" identity, else ad-hoc (`-`) as the fallback. Signing with a real identity — Apple Development or Developer ID — is what lets the ES helper's Full Disk Access and Login Items grants survive rebuilds; the first build under a new identity still needs one Login Items approval and one Full Disk Access grant. An ad-hoc build loses both grants on every rebuild.

Override the identity explicitly, e.g. for proper Gatekeeper distribution:

```bash
export CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
xcrun notarytool store-credentials secure-agent-notary --apple-id you@example.com --team-id TEAMID
export NOTARY_PROFILE=secure-agent-notary
make dmg   # signs, notarizes, and staples both the app and the DMG
```

### Developer Installation (from source)

Prerequisites: macOS 14+, Go 1.22+, Python 3.10+, and Xcode with the macOS 27.0 SDK and a Swift 6 toolchain. App packaging and local Swift builds/tests use `packaging/swift_macos.sh` to select `macosx27.0` for both compilation and linking; an unavailable SDK fails the build. Packaging also checks that both executable architectures record SDK 27.0 and minimum macOS 14.0.

```bash
git clone https://github.com/cavi-ai/secure-agent.git
cd secure-agent
make build      # daemon, menubar, CLI into bin/
make test       # full Go + Swift + Python + E2E suites
make install    # build "Secure Agent.app", install it to /Applications and launch it (no LaunchAgents)
```

`make install` replaces `/Applications/Secure Agent.app` (the previous copy goes to the Trash) and opens only that copy. The build output in `dist/` is never registered or opened: macOS binds the file-telemetry helper to the copy that registered it, so only the copy in `/Applications` registers, re-registers or repairs it. Any other copy shows "Secure Agent must run from /Applications to manage file telemetry".

### File telemetry

Endpoint Security telemetry via `eslogger` runs in a collector daemon that ships inside the app bundle and is registered with `SMAppService` — no admin password.

- **Enable:** new first-use setup waits for **Enable file telemetry** in Optional capabilities or Settings → Telemetry. After that choice, the app retains its automatic registration and repair path: registration once per launch and permission guidance once per build. Existing installations retain their telemetry choices.
- **Your two switches:** **Secure Agent** in **System Settings → General → Login Items & Extensions**, then **Secure Agent** in **Privacy & Security → Full Disk Access**; the File Telemetry card in **Settings → Telemetry** turns green on its own.
- **Doctor:** **Run Doctor…** in the menu bar menu, or **Run Doctor** on the card, checks signing, the service in the bundle, registration, Login Items, the launchd job, Full Disk Access, spool health, an old helper under `/Library`, and the daemon's `/doctor`.
- **Fixes:** each failing check has a Fix button; **Fix all** runs them in check order and waits up to 5 minutes on each System Settings switch.
- **Off:** Remove on the card keeps file telemetry off until Enable.
- **Old helper:** a collector installed by an earlier version under `/Library` is removed from the same card (one admin prompt).

### Plugin Hook Installation

To link the Python hook scripts into Claude Code and Cursor harness directories manually:

```bash
./plugin/install.sh
```

This creates symbolic links from `plugin/hooks/` to:
- `~/.claude/hooks/`
- `~/.cursor/hooks/`

---

## 🛡️ Egress Secret-Leak Firewall

Inspects what your agents send to their APIs and catches secrets leaving where they shouldn't — the class of mistake that forces constant key rotation.

<p align="center">
  <img src="assets/screenshots/firewall.png" alt="Egress firewall — per-rule stats and promote-to-block" width="720">
</p>

**Detection layers** (`daemon/internal/firewall/`):
- **Known-secret fingerprints** — your real secrets, stored only as a salted HMAC (never plaintext), matched even through base64 / url / gzip / JSON encodings.
- **Typed patterns** — Anthropic, OpenAI (incl. project keys), GitHub (classic + fine-grained), GitLab, AWS, Google, Stripe (secret/restricted/webhook), Slack, Twilio, SendGrid, npm, PyPI, DigitalOcean, Doppler, JWT, bearer tokens, private keys, and database connection strings with embedded credentials.
- **Entropy** — a high-entropy backstop (monitor-only).
- **Transcript scanning** — the fingerprint and pattern layers also run over tailed harness transcripts; a hit raises `secret-in-transcript` (severity 3 for a registered secret, 2 for a typed pattern) carrying the rule id, path, and session — never the matched text.

**Precision, not noise.** A credential in the expected auth header to its own vendor host is *legitimate*, not a leak. A secret is flagged only when it goes to a non-vendor host, or lands in a request body / query / non-auth header. This is what makes blocking safe.

**See the control result.** New payload findings distinguish registered fingerprints from typed pattern matches and show the resolved request outcome: **Blocked before forwarding** or **Observed only; delivery unknown**. A monitor-only match can share a request that another rule blocked. Incident reports preserve mixed outcomes as counts of recorded findings, and session exports retain review state, control results, and evidence limits. Older findings retain an unknown outcome. Acknowledgment or reported resolution does not prove credential revocation, repair earlier exposure, or establish remote delivery.

**Export recorded session history.** Session reports include the latest saved review decisions, the evidence revisions they apply to, residual risk, and intervention/remediation results. Missing source history and export limits are explicit. Copying a partial report shows a warning; an export does not establish task completion or current permission.

**See decisions and results in the session.** The Results view keeps saved reviews, process-control receipts, and reported incident actions together. Applied controls, later observations, and unverified external actions remain distinct. Source failures retain the last known receipts with a retry message; bounded and expired history stay visible as limits.

**Monitor by default; earn enforcement.** Every rule runs in `monitor` mode: leaks are reported, nothing is blocked. Promote a rule to blocking once you trust it, in `~/.config/secure-agent/config.yaml`:

```yaml
firewall:
  mode: monitor              # global default
  patterns:
    - { id: aws-key, type: cloud-key, re: 'AKIA[0-9A-Z]{16}', mode: block }  # this rule now blocks
```

**Route Claude Code through the proxy** with **Settings → Secure Agent → Traffic → Route Claude Code through Secure Agent** (opt-in; no keychain or system-trust changes). The app writes the proxy and Secure Agent's CA (`NODE_EXTRA_CA_CERTS`) into the `env` block of `~/.claude/settings.json`, plus a SessionStart hook that gives each session's Bash commands the tunnel-mode snippet. API requests to the hosts in `proxy_inspect_hosts` (default `api.anthropic.com`) are decrypted and scanned; every other connection passes through unopened, so tools that do not trust Secure Agent's CA (gh, git, curl) keep working. Quitting the app takes the routing back out; while routing is on, start Secure Agent before Claude Code.

**Route other agents** by sourcing the tunnel-mode snippet the daemon writes to `~/.config/secure-agent/agent-env.sh` where you launch them (scoped to that shell; every connection passes through unopened):

```bash
source ~/.config/secure-agent/agent-env.sh
```

The snippet carries a per-install proxy token, so the loopback listener is not a free open proxy for other local processes — only routed agents can use it.

Traffic that bypasses the proxy (pinned or unrouted) is counted as `uninspected_egress` in the status — a **rolling 24h** distinct-endpoint count, so the number reflects the current blind spot instead of growing forever. Clicking the warning (console or posture banner) opens the drill-down: every endpoint with per-agent counts, last-seen, the advisor's verdict, and a one-click **Allow** that closes the blind spot (`GET /egress/uninspected` for the raw list).

See [docs/FIREWALL_THREAT_MODEL.md](docs/FIREWALL_THREAT_MODEL.md) for exactly what the firewall defends against, what it does not, and how it handles secret material.

---

## 🔒 Directory Guard

The second pillar: interactive allow/deny for sensitive file access — Little Snitch for agents, instead of for your network.

When an agent tool call touches a guarded path (SSH keys, cloud credentials, the keychain, `.env` files, shell rc files), the hook checks the rule's mode:

| Mode | Behavior |
|---|---|
| `monitor` (default) | Logged only. Nothing is blocked, nothing is asked. |
| `prompt` | The hook holds the tool call while the menu bar raises a native **Allow Once / Allow Always / Deny** prompt. Your answer is remembered per `(agent, rule)` — "Allow Always" is cached, so the same agent hitting the same rule again is resolved instantly with no further prompt. |
| `deny` | Blocked outright, no prompt. |

**Quiet by default.** Every rule ships `monitor` — nothing is blocked out of the box. The onboarding **"Guard My Secrets"** step is the explicit opt-in that promotes SSH keys, cloud credentials, and the keychain to `prompt`, written to `~/.config/secure-agent/guard-modes.json`.

**Honest coverage.** The `PreToolUse` hook enforces at the tool-call boundary — it can actually block a `prompt`/`deny` rule before the tool runs. The daemon's `eslogger` telemetry observes a broader slice of file activity (including access outside the hook's reach) but is observe-only there: it can log and correlate, not block.

| Surface | Coverage |
|---|---|
| Claude file tools (`Read`/`Write`/`Edit`/`NotebookEdit`) | Mode-enforced: `monitor` / `prompt` / `deny`, per rule. Writes to harness settings & hook scripts (`~/.claude/`, `~/.cursor/`, `~/.config/opencode/`) are always denied — that's the guard's own enforcement plane. |
| Claude `Grep`/`Glob` | Mode-enforced when the search root is a protected directory (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/Library/Keychains`) — a scan reaches every protected file inside, so the governing rule's mode gates the scan. Broad roots (e.g. `~`) stay ungated; file-level matches inside results are still enforced per call. |
| Claude `Bash` | `deny`-mode rules enforced (protected-directory targets like `cp -r ~/.ssh` included); key material (SSH keys, cloud credential files) always denied via `cat` **or any reader alias** (`grep`/`rg` included — `grep '' credentials` is the same leak). `prompt`-mode paths are also denied — there is no interactive prompt mid-Bash, so a `prompt` rule fails safe to `deny` there instead of asking. |
| Cursor | `Bash` commands only. Cursor's shell-exec payload doesn't carry a `tool_name`, which the file-tool guard needs to tell a `Write` from a `Read`. |

A sixth guard rule, `harness-config`, covers the harnesses' own settings and hook scripts. It ships `monitor` (reads logged); **Guard My Secrets** promotes it to `prompt` alongside SSH keys, cloud credentials, and the keychain. Writes are always denied regardless of mode — editing the hook or `settings.json` is how an agent removes the guard watching it.

Writes to `~/.claude/settings.json` and the hook scripts are now denied outright, so the obvious self-removal path is closed — but a determined agent can still probe paths outside the covered harness directories, and the harness's decision to invoke the hook at all can't be enforced from inside the hook. This layer raises the bar; it is not a complete seal.

See [docs/GUARD_THREAT_MODEL.md](docs/GUARD_THREAT_MODEL.md) for the full list of closed bypass classes, the known limits (symlinks, TOCTOU, static inline-code analysis), and exactly which failures fail closed vs. open.

---

## ⚙️ Configuration

In **Settings → File Guard** and **Settings → Egress Firewall**, use **Add**, **Edit**, or the trash button to manage guarded paths and secret-detection patterns. Saves validate the rule and persist it locally; failed saves retain the current protection. Firewall edits apply to new requests immediately. Guard path edits apply to the next hooked tool call; restart Secure Agent to update background file correlation. The mode controls continue to choose Monitor/Prompt/Deny or Monitor/Block.

`secure-agent` loads default configuration rules and applies user overlays from `~/.config/secure-agent/config.yaml`.

```yaml
# Sensitive file path patterns to monitor
sensitive_globs:
  - "**/.env"
  - "**/.env.*"
  - "~/.ssh/id_*"
  - "~/.aws/credentials"
  - "~/.config/gh/hosts.yml"

sensitive_paths:
  - "~/.aws"
  - "~/.ssh"

keychain_markers:
  - "library/keychains"
  - ".keychain-db"
  - "login.keychain"

# Agent binary matching rules
agents:
  - name: claude
    match: ["claude"]
  - name: cursor
    match: ["Cursor Helper", "cursor"]
  - name: codex
    match: ["codex"]

# Pre-approved egress domains per agent
vendor_allowlist:
  claude: ["anthropic.com", "claude.ai"]
  cursor: ["cursor.sh", "cursor.com"]
  codex: ["openai.com", "api.openai.com"]

# Network sampling frequency
net_sample_interval_ms: 2000

# Socket & storage locations
socket_path: "~/.config/secure-agent/daemon.sock"
db_path: "~/.local/state/secure-agent/events.db"
jsonl_path: "~/.local/state/secure-agent/events.jsonl"

# Opt-in local proxy configuration (MITM + web console hitchhike)
proxy_enabled: false
proxy_port: 8443
proxy_ca_cert_path: "~/.config/secure-agent/ca.crt"
proxy_ca_key_path: "~/.config/secure-agent/ca.key"
proxy_inspect_hosts:          # decrypted for inspect-mode clients; every other routed connection is tunneled
  - api.anthropic.com

# Opt-in local advisor: a locally served model (MLX, llama.cpp, Ollama —
# any OpenAI-compatible chat endpoint) triages flags and writes incident
# narratives. Loopback-only, enforced in code; advisory verdicts can never
# change enforcement. See docs/ADVISOR_THREAT_MODEL.md.
advisor:
  enabled: false                     # flip to true once a local model is serving
  endpoint: "http://127.0.0.1:8080"  # must be loopback
  model: ""                          # e.g. "qwen3-4b-instruct"
  timeout_ms: 60000                  # whole triage task; requested plans/notes get at least 5 minutes
  classifier_endpoint: ""           # optional local Kev service, e.g. http://127.0.0.1:8009
  classifier_model: "kev-latest"
  debug: false                       # metadata-only task/tool logs, applied live
```

### 🤖 Secure Agent chat

```yaml
# Opt-in: Settings → Secure Agent. Chat and confirmed local commands use
# Ollama directly; optional harness handoff is separate. See docs/SYSTEM_AGENT.md.
system_agent:
  enabled: false
  endpoint: "http://127.0.0.1:11434"
  model: ""                   # first chat-capable installed model, or pin a model name
  harness_model: ""           # defaults to the chat model; pin a tool-calling model for dispatches
  auto_review: false          # queue local recommendations; commands still require confirmation
  auto_review_min_severity: 2 # minimum detector severity (1 informational, 2 warning, 3 critical)
  auto_review_excluded_rules: [] # finding rule IDs excluded from automatic review
```

Each local command proposal shows its exact shell text, folder and mode before
you confirm it. Terminal mode lets `ssh-keygen` prompt for a passphrase without
putting it in chat. Harness handoff has its own form, plans and dispatch
confirmation. Pi runner is terminal-only with its shell tool disabled.

### 🧠 Local advisor

With a local model serving the endpoint above, every flag gets an advisory
triage verdict (`advisor: benign / suspicious / malicious` chip on the flag
card, with the rationale as its tooltip), the posture banner and menubar hero
summarize how many critical flags look benign, and each incident card gains a
plain-English narrative. On request, it also writes a one-line note on a
worktree from the console's System tab or `secure-agent worktrees advise`,
and a short cleanup plan for a project's worktrees and clutter from the same tab
or `secure-agent cleanup advise`; neither changes a verdict or an action. The advisor is async and fails silent:
if the model is down, nothing changes except the absence of verdicts.

Each advisor task starts with fresh context and can call read-only tools for
its evidence, its finding's session activity, and similar operator judgments.
An optional local classifier helps choose which context to inspect; its output
cannot clear findings or change enforcement. The Agent page reports the active
task, evidence tool, elapsed time, queue depth and retry state. See
[advisor boundaries](docs/ADVISOR_THREAT_MODEL.md) for context and cache limits.

---

## 🔌 Unix Socket Control API

The Go daemon listens on a local Unix domain socket (`~/.config/secure-agent/daemon.sock`).

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/status` | `GET` | Returns daemon running state, uptime, active agent count, and proxy status. |
| `/resources` | `GET` | Returns attributed session-family RSS, CPU, process topology, history, diagnoses, and reclaim estimates. |
| `/resources/control` | `POST` | Applies or dismisses a pending resource action, or resumes a paused session family. |
| `/flags` | `GET` | Returns recent security correlation flags (accepts optional `?limit=N`). |
| `/events` | `GET` | Returns recent raw system events (accepts optional `?limit=N`). |
| `/incidents` | `GET` | Returns rotation intel postmortem reports & checklists (`?id=ID`, `?format=markdown`). |
| `/incidents/remediation` | `POST` | Records reported/pending remediation steps against the viewed incident evidence and revision. |
| `/kill` | `POST` | Terminate an agent process tree by PID (`{"pid": 12345}`). |
| `/worktrees` | `GET` | Every git worktree found, with a remove/review/keep/prune verdict and its reasons (`?refresh=1` rescans). |
| `/worktrees/repos` | `POST` | Add a repository to the worktree hunter's saved list, or hide it (`{"path": "...", "hidden": true}`). |
| `/worktrees/remove` | `POST` | Remove a worktree whose fresh verdict is `remove` (`{"path": "..."}`), or prune missing ones (`{"repo": "...", "prune": true}`). |
| `/worktrees/review-trash` | `POST` | Move a `keep` or `review` row's folder to Trash and unregister it; fresh facts must still match, and a live session, lock, loose commits, conflicts or partly staged files refuse it. |
| `/worktrees/advise` | `POST` | Ask the local advisor for a note on one worktree (`{"path": "..."}`); advisory only. |
| `/worktrees/reveal`, `/worktrees/reconnect`, `/worktrees/trash` | `POST` | For a folder whose repository moved or was deleted: open it in Finder, link it again with `git worktree repair`, or move it to the Trash. |
| `/cleanup/ledger` | `GET` | What cleanups removed and the bytes each gave back, with all-time and 30-day totals. |
| `/cleanup` | `GET` | `.tmp` and `.quarantine` folders, build output, tool and app caches: size, last touched, project, how to clear. |
| `/cleanup/trash`, `/cleanup/clean` | `POST` | Move one item to the Trash, or run a tool cache's own clean command. |
| `/cleanup/advise` | `POST` | Ask the local advisor for a cleanup plan for one project (`{"project": "<repo path or machine>"}`); advisory only. |
| `/worktrees/ask` | `POST` | Ask a currently active, identified agent in a keep/review worktree to open a PR for its work or say the worktree can go (`GET /worktrees/asks` lists answers). |
| `/agent/status`, `/agent/skills`, `/agent/runs` | `GET` | The system agent's model and harness readiness, its skills, and its dispatches. |
| `/agent/chat` | `GET`, `POST`, `DELETE` | Direct Ollama conversation; `POST {"message","workdir"}` sends one (the reply lands asynchronously). A harness field is rejected. |
| `/agent/analyze` | `POST` | Build a bounded, masked local summary from stored flags, evidence, and operator actions and ask Ollama for an advisory recommendation. No command runs. |
| `/agent/worktree` | `POST` | Ask the chat about one worktree (`{"path"}`): the question carries the checker's facts and the repository data as untrusted evidence; follow-ups keep it in context. |
| `/agent/recommendations` | `GET`, `POST` | Review queued analysis replies; `POST {"message_id","state":"dismissed"}` dismisses a pending item. |
| `/agent/actions` | `POST` | Start the exact local command stored on an assistant message: `{"message_id":123}`. The caller cannot supply command text. |
| `/agent/plans` | `GET`, `POST`, `DELETE` | Plans with whether each can run now; save a reply's proposal (`{"message_id"}`) or write one. |
| `/agent/dispatch` | `POST` | Run a plan's harness on the local Ollama: `{"plan_id","mode":"headless|terminal"}`. |

### Example Query

```bash
curl --unix-socket ~/.config/secure-agent/daemon.sock http://unix/status
```

```json
{
  "running": true,
  "uptime": "2h45m12s",
  "active_agents": 2
}
```

```bash
curl --unix-socket ~/.config/secure-agent/daemon.sock http://unix/flags?limit=10
```

---

## 🛰️ Connect a Fleet

The fleet contract is two sides: each node pushes signed webhooks, and a collector rolls them up.

**Node side** — one command enrolls this machine into a collector:

```bash
secure-agent fleet enroll https://collector.internal:9445
```

Enroll reads the node id from the running daemon, generates the shared secret, merges the webhook into `~/.config/secure-agent/config.yaml` (backup written first), and prints the single line to append to the collector's secrets file. The daemon hot-reloads fleet config — deliveries begin within seconds, **no daemon restart**. (Manual setup still works; the equivalent `config.yaml` block is below.)

```yaml
fleet:
  hostname: "builder-01"                      # display name (default: os.Hostname)
  labels: { env: prod, role: build-runner }   # grouping dimensions for fleet views
  heartbeat_interval_sec: 60                  # status cadence (default 60)
  webhooks:
    - url: "https://collector.internal:9445/hooks/secure-agent"
      secret: "<shared-secret>"
      events: [flag, incident, guard]   # empty = all
```

Every flag, incident, and guard decision is POSTed as an envelope:

```json
{"node_id": "…32-hex…", "kind": "flag", "ts": "…", "version": "v0.9.0-rc.1", "boot": "…", "seq": 42, "payload": {…}}
```

with `X-SecureAgent-Signature: sha256=<hex hmac-sha256(secret, body)>` and `X-SecureAgent-Node: <node_id>` headers. `boot` + `seq` are the node's gap-detection coordinates: every delivery is numbered per daemon run, so a dropped delivery (backlog cap, collector downtime, restart) surfaces at the collector as a **sequence gap** — best-effort delivery, but never *silent* loss.

Nodes also push a **`status` heartbeat** — at boot, on the interval, and immediately on posture-state changes — carrying the node's own `/posture` headline (`posture_state`, `posture_summary`, `needs_you`) plus hostname, labels, and agent count. The heartbeat bypasses the `events:` filter on purpose: liveness you can unsubscribe from is indistinguishable from a dead node. This is what lets the collector answer the two fleet questions that matter — *"is anything critical anywhere?"* and *"is every node alive?"*

**Collector side** — the reference collector in this repo (`cmd/secure-agent-collector`, stdlib-only):

```bash
make collector
# provision one secret per node, then run (loopback by default):
printf '%s
' "<node-id-1>=<secret-1>" > secrets.txt
./bin/secure-agent-collector -addr 127.0.0.1:9445 -store ~/.local/state/secure-agent-collector -config secrets.txt
```

- `GET /fleet` — merged multi-node rollup ordered by operator priority (critical → attention → stale → all-clear): version (tracks the newest report), liveness vs. last-activity timestamps, **rolling 24h counts** (`flags_24h`, `critical_flags_24h`, `incidents_24h`), guard allow/deny breakdown, sequence-gap count, and each node's posture headline
- `GET /fleet/rules` — **cross-node rule aggregation**: which flag rules are firing, on how many of the fleet's nodes ("`sensitive-read-then-connect` — 5/12 nodes, 3 critical in 24h"). One node is an incident; five is a bad release.
- `GET /nodes/<id>/events?kind=flag&limit=50` — one node's stored envelopes
- `GET /` — dark overview page: fleet headline (*"2 critical · 1 stale · 12 all-clear"*), the rules-across-fleet table, and per-node cards titled by hostname with posture chips, label chips, and delivery-gap warnings
- `GET /healthz` — liveness

Liveness is heartbeat-aware: nodes sending `status` are stale after 3 missed minutes and "gone quiet" after 10; legacy event-only nodes keep the lenient 10/20-minute thresholds.

Signatures are verified constant-time; unsigned, tampered, wrong-node, and unknown-node traffic is rejected. Deliveries retry (500ms/2s/5s) on network errors and 5xx/429 only; failures land in the node's `webhook-deliveries.jsonl`.

The whole chain — node → signed webhook → verified envelope (flag **and** heartbeat) with contiguous sequence numbers → posture-aware rollup — plus the `fleet enroll` CLI flow, is enforced by `packaging/test/e2e_smoke.sh` on every CI run.

---

## 🧪 Testing & Verification

The repository includes test suites across Go, Python, Swift, and end-to-end shell smoke testing.

```bash
# 1. Run Go daemon unit & integration tests
go test ./...

# 2. Run Python plugin hook test suites
python3 plugin/hooks/test_secret_guard.py
python3 plugin/hooks/test_injection_scan.py
python3 plugin/hooks/test_activity_log.py

# 3. Run Swift menu bar package tests
bash packaging/swift_macos.sh test --package-path menubar

# 4. Run console JS unit tests + DOM tests + asset lint
node --test 'packaging/test/console/*.test.mjs'
python3 packaging/test/console_dom/run_dom_tests.py
./packaging/test/check_console_css.sh

# 5. Run end-to-end smoke test script
./packaging/test/e2e_smoke.sh

# 6. Check the built app bundle layout (after make app)
./packaging/test/check_bundle_layout.sh
```

---

## 📂 Repository Layout

```
secure-agent/
├── daemon/               # Go telemetry daemon (secure-agentd)
│   ├── cmd/              # Main executable entrypoint
│   └── internal/         # Collectors, bus, correlator, store, API, config
│   │       └── api/web_dist/  # Embedded web console assets (canonical source)
├── plugin/               # Harness plugin hooks (Claude Code / Cursor / opencode)
│   ├── hooks/            # secret_guard.py, injection_scan.py, activity_log.py
│   └── install.sh        # Symlink installer script (dev flow)
├── menubar/              # Native Swift menu bar app ("Secure Agent.app")
│   ├── Package.swift     # SwiftPM manifest
│   └── Sources/          # AppKit / SwiftUI NSStatusItem interface + setup wizard
├── packaging/            # Distribution & deployment
│   ├── make_app.sh       # Universal build → signed Secure Agent.app
│   ├── make_dmg.sh       # Notarize (optional) → distributable DMG
│   ├── make_icon.sh      # Generates AppIcon.icns
│   ├── install.sh        # Dev helper: build Secure Agent.app and launch it
│   ├── uninstall.sh      # Remove legacy LaunchAgents/binaries/hooks from older installs
│   └── test/             # E2E smoke testing harness
├── CONTRIBUTING.md       # Open-source contribution guidelines
└── SECURITY.md           # Security disclosure policy
```

---

## 🤝 Contributing

We welcome community contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) guide for details on development workflows, coding standards, and submitting pull requests.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
