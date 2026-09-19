# secure-agent Architecture Specification

This document provides a detailed overview of the internal architecture of `secure-agent`, including daemon telemetry collection, event bus pub/sub, sliding-window correlation, harness plugin gating, and the native Swift menu bar interface.

---

## 🏛️ System Overview

`secure-agent` consists of three core components:

```
+-----------------------------------------------------------------------+
|                             Harness Hooks                             |
|     (plugin/hooks/secret_guard.py, injection_scan.py, activity_log.py)|
|    - Synchronous PreToolUse mutation & read gating (directory guard)  |
|    - Synchronous PostToolUse prompt injection scanning                |
|    - Writes session audit JSONL                                       |
+-----------------------------------+-----------------------------------+
                                    |
                                    v (Audit JSONL Tail)
+-----------------------------------+-----------------------------------+
|                           secure-agentd                               |
|                            (Go Daemon)                                |
|  +--------------------+  +-------------------+  +------------------+  |
|  | File Watcher       |  | Socket Sampler    |  | Process Tagger   |  |
|  | (eslogger spool)   |  | (lsof)            |  | (sysctl/proc)    |  |
|  +---------+----------+  +---------+---------+  +--------+---------+  |
|            |                       |                     |            |
|            +-----------------------+---------------------+            |
|                                    |                                  |
|                                    v                                  |
|                     Event Bus (Non-blocking Pub/Sub)                  |
|                                    |                                  |
|         +--------------------------+--------------------------+         |
|         v                          v                          v         |
|  Sliding-Window            Egress Proxy + Secret       Resource Tracker |
|  Correlation Engine        Leak Firewall               + Control Ladder |
|  (correlate.go)            (proxy/, firewall/)         (resource/)      |
|         |                          |                          |         |
|         +--------------------------+--------------------------+         |
|                                    v                                  |
|                 SQLite Store & Unix Domain Socket API                 |
|                       (+ SSE stream, posture endpoint)                |
+--------+--------------------------+--------------------------+--------+
         |                          |                          |
         v (Unix Socket API)        v (Loopback HTTP)          v (Webhooks)
+-------------------+  +---------------------------+  +-------------------+
| secure-agent-     |  | Web Console (dashboard)   |  | Fleet Collector   |
| menubar (SwiftUI) |  | served by the daemon      |  | (secure-agent-    |
| - posture hero &  |  | behind console token:     |  |  collector):      |
|   guard prompts   |  | posture, sessions,        |  | flags, incidents  |
| - one-click kill  |  | egress, attention         |  | and posture per   |
| - local advisor   |  | - CSP + nosniff           |  |  node, rollup     |
|   triage surface  |  |                           |  |                   |
+-------------------+  +---------------------------+  +-------------------+
```

---

## 1. Go Telemetry Daemon (`daemon/`)

By default the daemon (`secure-agentd`) runs as a child process of the menu bar app: it starts when Secure Agent launches and stops when the app quits (the daemon also self-terminates if it is orphaned). For a headless node — a fleet or CI machine with no GUI login — `secure-agent service install` writes a plain launchd LaunchAgent (`RunAtLoad`, **no** `KeepAlive`; the daemon's own supervisor restarts collectors, and launchd respawning the whole process would fight the menubar over the socket), giving it a GUI-independent lifetime. Run either the app or the service, not both. It collects OS system telemetry without kernel extensions using modern macOS APIs.

### Collectors

1. **File Watch Collector (`daemon/internal/collect/eslogger.go`)**:
   - Subprocesses macOS Endpoint Security (`eslogger`) streaming events for `open`, `exec`, `rename`, `unlink`, and `tcc_modify`.
   - Parses the JSON stream in real-time and filters target paths against sensitive path rules (`sensitive_globs`, `sensitive_paths`, `keychain_markers`).

2. **Network Socket Sampler (`daemon/internal/collect/netsample.go`)**:
   - Periodically lists established TCP sockets via `lsof` (platform-abstracted: `netsample_darwin.go`, `netsample_linux.go`) and keeps only sockets owned by tagged agent process trees. Loopback endpoints are filtered out — local-only traffic is not egress.
   - Diffs consecutive socket states to detect newly opened outbound socket connections.

3. **Agent Process Tagger (`daemon/internal/agents/tagger.go`)**:
   - Monitors the system process table to identify known AI agent executables (`claude`, `cursor`, `codex`, `copilot`) and child interpreter subprocesses (`node`, `python`, `bash`).
   - Tags events with agent identity, working directory (`cwd`), session ID, and parent PID chain.

4. **Transcript & Trace Scanner (`daemon/internal/collect/transcript.go`, `*_trace.go`)**:
   - Tails harness session logs and `activity.jsonl` files emitted by the plugin hooks.
   - Runs Layer-5 credential redaction patterns to strip secrets (JWTs, API tokens, private keys) before event persistence.
   - **Trace parsing** turns harness transcripts into agent-semantic events (tool calls, model calls, turns) — see the coverage table below. No transcript content ever crosses into an event: only tool names, durations, model ids and token counts.
   - **opencode** keeps no JSONL; its trace lives in a SQLite database and is read by a separate **read-only, watermarked poller** (`opencode_trace.go`) — never writes, never locks the app out, bounded rows per poll.

   **Trace coverage** (what the daemon can actually see, by harness):

   | Harness | Source | Trace events |
   |---|---|---|
   | Claude Code | `~/.claude/projects/**/*.jsonl` | tool calls (with durations), model calls (tokens + cost), turns |
   | Codex | `~/.codex/sessions/**/rollout-*.jsonl` | tool calls (with durations), model calls (tokens; model/cost unknown) |
   | Cursor | `~/.cursor/projects/*/agent-transcripts/*/*.jsonl` | tool calls, turns (no timestamps/results/usage in the format) |
   | Antigravity (agy) | `~/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript_full.jsonl` | tool calls (status, no duration), turns |
   | opencode | `~/.local/share/opencode/opencode.db` (SQLite) | tool calls (with durations), model calls (tokens + cost) |

   Uncovered-by-trace harnesses (any other agent CLI) still get process, network and resource visibility, and every tailed log is redaction-scanned for secrets.

### Event Bus & Storage

- **Pub/Sub Channel Bus (`daemon/internal/bus/bus.go`)**: Centralized Go channel event bus with non-blocking fan-out subscribers. Guarantees that slow database disk IO never blocks real-time file or process event capture.
- **Store Engine (`daemon/internal/store/store.go`)**: Dual-persists events and correlation flags to SQLite (`events.db`) and structured JSONL logs (`events.jsonl`). Implements automatic retention pruning.

### Correlation Engine (`daemon/internal/correlate/correlate.go`)

The correlator evaluates incoming event streams against a sliding time window (default 30 seconds):

- **Rule: `sensitive-read-then-connect`**: When a tagged agent process reads a file matching sensitive path criteria, and within the time window opens a network connection to a host outside that agent's `vendor_allowlist`, a high-severity security flag is raised.
- **Rule: `keychain-access`**: Detects direct access attempts targeting macOS Keychain files or `security` CLI invocations.

---

## 2. Harness Plugin Hooks (`plugin/`)

The plugin layer operates synchronously inside AI agent CLI/IDE harnesses (Claude Code, Cursor).

- **`secret_guard.py` (`PreToolUse`)**: Intercepts tool execution requests (e.g. `Bash`, `Write`) to enforce strict safety constraints:
  - Blocks execution of Keychain manipulation CLI subcommands (`security delete-generic-password`, `security dump-keychain`, etc.).
  - Blocks modification of shell initialization files (`.zshrc`, `.zshenv`, `/etc/paths`).
  - Blocks reads or writes targeting private key paths and credential vaults.
  - Returns dual-protocol JSON responses for Claude Code (`decision`, `reason`) and Cursor (`permission`, `user_message`).
- **`injection_scan.py`**: Prompt-injection detector imported by `secret_guard.py` on `PostToolUse` (same python3 as the guard; not a separate hook spawn). Still appends a redacted activity record via `activity_log.log_payload`.
- **`activity_log.py`**: Shared writer for `~/.local/state/secure-agent/activity.jsonl`; not a separate hook process.

---

## 3. Swift Menu Bar UI (`menubar/`)

Built using Swift 6, AppKit, and SwiftUI, `secure-agent-menubar` is a lightweight macOS status bar application.

- **Asynchronous Daemon Client (`DaemonClient.swift`)**: Talks to the daemon over its Unix domain socket API (`/status`, `/flags`, `/events`, `/snapshot`, …). Live updates arrive over the SSE stream (`EventStream`); a fallback poll keeps state fresh when the stream drops.
- **User Interface (`ConsoleView.swift` popover + the daemon-served web console)**: The popover shows the posture hero, session families, pending guard prompts and one-click actions; the full console (posture, sessions, egress, attention) is served by the daemon behind the console token.
- **Process Termination**: Sends POST requests to `/kill` to issue `SIGKILL` signals to compromised or rogue agent process trees.
