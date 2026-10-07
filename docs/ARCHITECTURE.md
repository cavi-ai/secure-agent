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

By default the daemon (`secure-agentd`) runs as a child process of the macOS app: it starts when Secure Agent launches and stops when the app quits (the daemon also self-terminates if it is orphaned). The app creates its status item before setup work and claims a per-user instance lock before starting the daemon. It also keeps a Dock icon and opens Settings on launch, so the user has a visible way to access and quit the app if macOS hides its menu bar item; a status item's accessibility coordinates alone cannot prove it is visible. If another app copy is running, the new copy offers an explicit replacement choice instead of starting a second daemon against the same socket and console port. For a headless node — a fleet or CI machine with no GUI login — `secure-agent service install` writes a plain launchd LaunchAgent (`RunAtLoad`, **no** `KeepAlive`; the daemon's own supervisor restarts collectors, and launchd respawning the whole process would fight the app over the socket), giving it a GUI-independent lifetime. Run either the app or the service, not both: each daemon holds an exclusive lock on `<db_path>.lock` for its lifetime, and a second daemon on the same store waits, without binding the socket or starting collectors, until the holder exits, a signal arrives, or its parent exits. It collects OS system telemetry without kernel extensions using modern macOS APIs.

The app bundle has one identity, `com.cavi-ai.secure-agent`, for Launch Services, its standard preferences domain and the instance guard. Background Task Management records the file-telemetry helper registered with `SMAppService.daemon` under that identity, so only an app carrying it can register or unregister the helper; `packaging/test/check_bundle_layout.sh` and the Swift tests pin it. The collector, daemon and CLI retain their existing signing identities. macOS privacy and Login Items approvals remain managed through the native Setup flow.

### Collectors

1. **File Watch Collector (`daemon/internal/collect/eslogger.go`)**:
   - Subprocesses macOS Endpoint Security (`eslogger`) streaming events for `open`, `exec`, `rename`, `unlink`, and `tcc_modify`.
   - Parses the JSON stream in real-time and filters target paths against sensitive path rules (`sensitive_globs`, `sensitive_paths`, `keychain_markers`).

   On macOS `eslogger` requires root, so it runs in a collector daemon that ships inside the app bundle: the daemon binary again as `Contents/MacOS/secure-agent-esd` (that name selects collector mode) with its LaunchDaemon plist at `Contents/Library/LaunchDaemons/com.cavi-ai.secure-agent-esd.plist`. The app registers it with `SMAppService.daemon`; the user approves Secure Agent once in Login Items and once in Full Disk Access, with no admin password. The collector refuses to start when its own code signature does not verify, then appends eslogger's JSON to `/var/db/secure-agent/es-spool.jsonl`, which the unprivileged daemon tails (`daemon/internal/collect/spool.go`).

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
   - **openclaw** keeps its conversations in `lcm.db` (SQLite) in its state directory, read by the same kind of read-only, watermarked poller (`openclaw_trace.go`); the watermark persists beside the store, and with none the first poll starts at the last 24 h. Each conversation is a session (`openclaw:<agent>` workspace label), ended when openclaw marks it inactive or archived.
   - **Hermes Agent** keeps its sessions in `state.db` (SQLite) under its root (`hermes_home`, else `$HERMES_HOME`, else `~/.hermes`) and one `state.db` per profile under `profiles/<name>/`; each is read by the same kind of read-only poller (`hermes_trace.go`), watermarked per database on `messages.id`, the watermarks persisted beside the store; a database with none (a first run, a new profile) starts at the last 24 h. Each session carries its cwd (else a `hermes:<source>` label), the repo and branch Hermes records, and its parent session; it ends at Hermes's `ended_at`. Tool-call arguments and message content are never selected.

   **Trace coverage** (what the daemon can actually see, by harness):

   | Harness | Source | Trace events |
   |---|---|---|
   | Claude Code | `~/.claude/projects/**/*.jsonl` | tool calls (with durations), model calls (tokens + cost), turns |
   | Codex | `~/.codex/sessions/**/rollout-*.jsonl` | tool calls (with durations), model calls (tokens; model/cost unknown) |
   | Cursor | `~/.cursor/projects/*/agent-transcripts/*/*.jsonl` | tool calls, turns (no timestamps/results/usage in the format) |
   | Antigravity (agy) | `~/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript_full.jsonl` | tool calls (status, no duration), turns |
   | opencode | `~/.local/share/opencode/opencode.db` (SQLite) | tool calls (with durations), model calls (tokens + cost) |
   | openclaw | `<openclaw_home>/lcm.db` (SQLite) | tool calls (status; durations in whole seconds), turns, model calls (tokens + cost, when openclaw records step tokens) |
   | Hermes Agent | `<hermes_home>/state.db`, `<hermes_home>/profiles/*/state.db` (SQLite) | tool calls (with durations; error only when `finish_reason` says so), turns, model calls (per model per session from `session_model_usage` when present, else per assistant message with `token_count`; cost recorded or priced from the model id) |

   A codex process holds its rollout open for append. Every 30 s the daemon lists the rollouts open in live codex processes (`lsof -p … -Fn` on macOS, `/proc/<pid>/fd` on Linux; `openfiles.go`) and joins each rollout's session to the process tree holding it: that tree's process-tree session is merged into it and the tree's later events resolve to it.

   Uncovered-by-trace harnesses (any other agent CLI) still get process, network and resource visibility, and every tailed log is redaction-scanned for secrets.

### Event Bus & Storage

- **Pub/Sub Channel Bus (`daemon/internal/bus/bus.go`)**: Centralized Go channel event bus with non-blocking fan-out subscribers. Guarantees that slow database disk IO never blocks real-time file or process event capture.
- **Store Engine (`daemon/internal/store/store.go`)**: Persists events and correlation flags to SQLite (`events.db`) and mirrors flags only to a forensic JSONL log (`jsonl_path`, default `events.jsonl`). Implements automatic retention pruning. The store depends on no detection engine; endpoint naming comes from `daemon/internal/hostid`.
- **Endpoint identity (`daemon/internal/hostid`)**: Names a host or IP by owning org, class, and CDN/cloud infrastructure, and holds the one host match rule for vendor and user-approved hosts. Standard library only; shared by the correlator, store, and API.

Core evidence writes (events, flags, incidents, guard decisions, sessions,
resource episodes, episode enrichment, operator audit, and the flag JSONL mirror)
report fixed operation labels to an in-memory health tracker with a mutex
independent of database IO. Status,
posture, and Doctor consume the same snapshot. Active faults clear on a
successful write of the same operation; cumulative failures and bus delivery
loss remain coverage gaps for that daemon run because the missing evidence
cannot be reconstructed. The mirror retries opening on the next flag after
a failure, without a retry loop or blocking collectors.
The native Telemetry Doctor displays the daemon's recovery guidance and opens
hook setup for failed registration or activity checks. Lost bus deliveries
remain an evidence gap for that run; restarting cannot recover them.
The ES spool reader offers events without blocking and retains rejected lines
for the next poll, including the tail of the retained rotated spool. Valid
bursts past the parse budget remain on disk for later polls. If rotation
overwrites unread bytes, or the garbage budget skips a tail, status reports a
cumulative lower bound in `es_service.bytes_lost`; Doctor and posture keep that
gap visible for the run. Spool retention is bounded, so sustained overload can
still lose evidence.
The transcript scanner retains one parsed line per blocked file and retries
its undelivered events without replaying stateful trace parsers. Hook activity,
trace events, and secret findings share a checkpoint that advances only after
the bus accepts every event from the line. Pending delivery continues even if
discovery no longer lists the source. A restart can replay an accepted prefix
from an uncommitted line; the source must remain available for that recovery.
Bus acceptance does not guarantee a successful storage write. Other collectors
retain their best-effort bus delivery.
Failed transcript checkpoint writes retain their retry state, including while
sources are idle, and retry on the existing save cadence. Storage health reports
the fixed `transcript checkpoints` operation for write or rename failures;
successful replacement clears that active fault while the cumulative failure
count remains visible in Doctor and posture for the daemon run.
Hook setup merges Cursor native `preToolUse` and `postToolUse` registrations
into `~/.cursor/hooks.json`, preserving existing entries and a backup. Copied
scripts alone do not satisfy setup. Cursor payloads retain their conversation
id and harness identity; only observed activity proves that a hook ran.
Rotation keeps the previous archive if renaming the active file fails.
Resource episode inserts and enrichment updates recover independently; an
unchanged enrichment payload or a concurrent update does not clear a write fault.
Incident aggregation reports a separate write fault and emits an updated report
only after persistence succeeds. Malformed saved evidence is left unchanged;
missing rows and updates that change no row do not clear an active fault.
New incidents enter the live feed, fleet delivery, and advisor queue only after
their insertion succeeds. Insertion and serialization failures still refresh
posture through the evidence-health tracker while flag collection continues.
Advisor verdicts track persistence failures independently and publish a flag
refresh only after the verdict is saved. Every verdict write refreshes posture;
storage failures do not count as provider failures or trip its circuit breaker.
Advisor plan saves have a separate write-health label and refresh posture on
failure and recovery. Failed saves retain the previous plan and release the
pending subject so it can be retried; storage faults do not trip the provider
circuit breaker.
Session ending commits the lifecycle transition and closure of running tool
calls in one transaction. Failed endings have a separate write-health label;
the resolver retains tracking and emits no ending transition until persistence
succeeds. Missing-session no-ops and unrelated upserts do not clear that fault.
Idle transitions commit as a complete batch before returning changed session
IDs. Idling and activity writes report independent faults, and failed activity
writes do not advance the resolver's throttle clock. No-op transitions leave
existing faults active; successful writes retain cumulative failure history.
Deferred session promotion retains its retry state and throttle clock when
an upsert fails, and publishes the stored identity only after a successful
write. Initial process-tree creation uses this same path: failed writes retain
attribution in memory and retry on later activity instead of publishing an
unsaved session. A recent transcript touch does not delay root attachment.
Promotion records the current activity time. Session upserts return read/write
errors and reject writes that save no row; an empty-ID no-op does
not clear an active session write fault.
Hook handshakes, transcript sightings, stamped events, and transcript root
attachments publish only after their metadata upsert succeeds. Failed metadata
saves skip follow-up activity writes; the next input retries the upsert.
Observed hook and transcript sightings remain recorded even when storage fails.

Per-harness coverage joins recent hook and trace events to their persisted
session IDs. It lists only active, non-infrastructure harnesses and separates
adapter support from observed activity in the last 24 hours; activity from
one harness cannot clear another's missing-hook signal. Supported guard hooks
are Claude Code and Cursor; Claude registration checks apply only while Claude
is active. These observations do not establish coverage of every current
session, or payload inspection, which depends on proxy routing.

Native endpoint refresh failures retain last-known values and mark the failed
section stale. Polling and SSE refreshes clear a section only on success.
Stale sections keep the icon in attention and surface a warning; a stale
all-clear posture cannot produce a reassuring hero.

### Correlation Engine (`daemon/internal/correlate/correlate.go`)

The correlator evaluates incoming event streams against a sliding time window (default 30 seconds):

- **Rule: `sensitive-read-then-connect`**: A secret read and connection in the same process tree, or a model-visible agent tool read followed by a family connection, raises a severity-3 flag. A file read and later connection in unrelated sibling processes of the same agent family remains a severity-2 finding: useful for review, but weaker evidence of transfer. The owner-use and operator-expected-pattern checks still apply before a flag is raised.
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
- **`activity_log.py`**: Shared writer for `~/.local/state/secure-agent/activity.jsonl`; not a separate hook process. Its `redact_str` is the one redaction rule set for the activity log and the guard audit trail. The daemon's `daemon/internal/redact` applies the same rules; both satisfy `daemon/internal/redact/testdata/cases.json`. One difference: after a private-key BEGIN marker with no END, the daemon withholds the rest of the text, while the hook masks the marker alone so the logged command keeps the paths the daemon classifies.

---

## 3. Swift Menu Bar UI (`menubar/`)

Built using Swift 6, AppKit, and SwiftUI, `secure-agent-menubar` is a lightweight macOS status bar application.

- **Asynchronous Daemon Client (`DaemonClient.swift`)**: Talks to the daemon over its Unix domain socket API (`/status`, `/flags`, `/events`, `/snapshot`, …). Live updates arrive over the SSE stream (`EventStream`); a fallback poll keeps state fresh when the stream drops.
- **User Interface (`ConsoleView.swift` popover + the daemon-served web console)**: The popover shows the posture hero, session families, pending guard prompts and one-click actions; the full console (posture, sessions, egress, attention) is served by the daemon behind the console token.
- **Process Termination**: Sends POST requests to `/kill` to issue `SIGKILL` signals to compromised or rogue agent process trees.
