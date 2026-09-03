# secure-agent Architecture Specification

This document provides a detailed overview of the internal architecture of `secure-agent`, including daemon telemetry collection, event bus pub/sub, sliding-window correlation, harness plugin gating, and the native Swift menu bar interface.

---

## 🏛️ System Overview

`secure-agent` consists of three core components:

```
+-----------------------------------------------------------------------+
|                             Harness Hooks                             |
|           (plugin/hooks/secret_guard.py & injection_scan.py)          |
|    - Synchronous PreToolUse mutation & read gating                    |
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
|  | (eslogger)         |  | (libproc)         |  | (sysctl/proc)    |  |
|  +---------+----------+  +---------+---------+  +--------+---------+  |
|            |                       |                     |            |
|            +-----------------------+---------------------+            |
|                                    |                                  |
|                                    v                                  |
|                     Event Bus (Non-blocking Pub/Sub)                  |
|                                    |                                  |
|                                    v                                  |
|                 Sliding-Window Correlation Engine                     |
|                                    |                                  |
|                                    v                                  |
|                 SQLite Store & Unix Domain Socket API                 |
+-----------------------------------+-----------------------------------+
                                    |
                                    v (Unix Socket API)
+-----------------------------------+-----------------------------------+
|                       secure-agent-menubar                            |
|                            (Swift UI)                                 |
|    - NSStatusItem menu bar view & desktop notifications               |
|    - Active agent list & evidence chain view                          |
|    - One-click process kill switch                                    |
+-----------------------------------------------------------------------+
```

---

## 1. Go Telemetry Daemon (`daemon/`)

The daemon (`secure-agentd`) runs as a child process of the menu bar app: it starts when Secure Agent launches and stops when the app quits (the daemon also self-terminates if it is orphaned). There is no `launchd` service and nothing runs in the background. It collects OS system telemetry without kernel extensions using modern macOS APIs.

### Collectors

1. **File Watch Collector (`daemon/internal/collect/eslogger.go`)**:
   - Subprocesses macOS Endpoint Security (`eslogger`) streaming events for `open`, `exec`, `rename`, `unlink`, and `tcc_modify`.
   - Parses the JSON stream in real-time and filters target paths against sensitive path rules (`sensitive_globs`, `sensitive_paths`, `keychain_markers`).

2. **Network Socket Sampler (`daemon/internal/collect/netsample.go`)**:
   - Periodically queries open TCP/UDP sockets for tagged agent process PIDs using `libproc` socket APIs.
   - Differs consecutive socket states to detect newly opened outbound socket connections.

3. **Agent Process Tagger (`daemon/internal/agents/tagger.go`)**:
   - Monitors the system process table to identify known AI agent executables (`claude`, `cursor`, `codex`, `copilot`) and child interpreter subprocesses (`node`, `python`, `bash`).
   - Tags events with agent identity, working directory (`cwd`), session ID, and parent PID chain.

4. **Transcript Scanner (`daemon/internal/collect/transcript.go`)**:
   - Tails harness session logs and `activity.jsonl` files emitted by the plugin hooks.
   - Runs Layer-5 credential redaction patterns to strip secrets (JWTs, API tokens, private keys) before event persistence.

### Event Bus & Storage

- **Pub/Sub Channel Bus (`daemon/internal/bus/bus.go`)**: Centralized Go channel event bus with non-blocking fan-out subscribers. Guarantees that slow database disk IO never blocks real-time file or process event capture.
- **Store Engine (`daemon/internal/store/store.go`)**: Dual-persists events and correlation flags to SQLite (`events.db`) and structured JSONL logs (`events.jsonl`). Implements automatic retention pruning.

### Correlation Engine (`daemon/internal/correlate/correlator.go`)

The correlator evaluates incoming event streams against a sliding time window (default 30 seconds):

- **Rule: `sensitive-read-then-connect`**: When a tagged agent process reads a file matching sensitive path criteria, and within the time window opens a network connection to a host outside that agent's `vendor_allowlist`, a high-severity security flag is raised.
- **Rule: `keychain-access`**: Detects direct access attempts targeting macOS Keychain files or `security` CLI invocations.

---

## 2. Harness Plugin Hooks (`plugin/`)

The plugin layer operates synchronously inside AI agent CLI/IDE harnesses (Claude Code, Cursor, OpenClaw).

- **`secret_guard.py` (`PreToolUse`)**: Intercepts tool execution requests (e.g. `Bash`, `Write`) to enforce strict safety constraints:
  - Blocks execution of Keychain manipulation CLI subcommands (`security delete-generic-password`, `security dump-keychain`, etc.).
  - Blocks modification of shell initialization files (`.zshrc`, `.zshenv`, `/etc/paths`).
  - Blocks reads or writes targeting private key paths and credential vaults.
  - Returns dual-protocol JSON responses for Claude Code (`decision`, `reason`) and Cursor (`permission`, `user_message`).
- **`injection_scan.py` (`PostToolUse`)**: Scans tool outputs for prompt injection markers and dangerous indirect instruction patterns.
- **`activity_log.py`**: Logs structured tool event records into `~/.local/state/secure-agent/activity.jsonl`.

---

## 3. Swift Menu Bar UI (`menubar/`)

Built using Swift 6, AppKit, and SwiftUI, `secure-agent-menubar` is a lightweight macOS status bar application.

- **Asynchronous Daemon Client (`DaemonClient.swift`)**: Polls the daemon Unix domain socket API (`/status`, `/flags`, `/events`) over an asynchronous timer.
- **User Interface (`MenuBuilder.swift`)**: Displays active agent count badge, quick action buttons, live process list, and security flag details with complete evidence chains (process PID, executable path, file accessed, remote IP/domain).
- **Process Termination**: Sends POST requests to `/kill` to issue `SIGKILL` signals to compromised or rogue agent process trees.
