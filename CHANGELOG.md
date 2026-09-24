# Changelog

All notable changes to `secure-agent` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Spend: Codex calls on a ChatGPT plan record provider `chatgpt` (class `plan`); `GET /costs/plans` serves each Codex home's plan headroom (windows, percent used, reset time); `/costs` `unpriced_calls` excludes plan and local calls; `secure-agent cost` prints the plan/local/unpriced split; the console Spend card shows a line and bar per plan, the stat strip counts calls on plans, and an all-plan row reads "plan".
- `POST /cleanup/advise`: queues a project (a repository, or `machine` for caches outside any repository) for a local-advisor cleanup plan built from its worktrees and clutter: a summary and at most 5 steps; paths, branch names and reasons go to the model inside `<evidence>`.
- `GET /cleanup` `advice`: the stored plan per project; plans never change a verdict or what an action accepts.
- `secure-agent cleanup advise <repo|machine>`; `secure-agent cleanup` prints each project's plan under it.
- Console Clutter panel: Ask advisor on every project header; the plan shows under the header.
- `POST /worktrees/ask`: resumes the Claude Code or Codex session that worked in a keep or review worktree with a fixed request — open a pull request for work worth keeping, or say the worktree can go; `--fork-session`, $1.00 cap (Claude Code), 15-minute bound, own process group, one at a time.
- Agent answers (`pr`, `removable`, `keep`) are recorded in `agent_asks`, the audit trail and the cleanup ledger; `GET /worktrees/asks`; `/worktrees` carries each worktree's newest ask.
- `secure-agent worktrees ask <path>`; console Ask the agent on keep and review rows, with the answer under the row.
- Tool clean commands and agent asks run in their own process group: a timeout stops everything they started.
- `GET /cleanup`: `.tmp` and `.quarantine` directories in and around repositories, build output inside repositories, developer tool caches and per-app caches, each with size, last touched, project and how to clear it.
- `POST /cleanup/trash` moves one inventory item to the Trash on its volume; `POST /cleanup/clean` runs a tool cache's own clean command; both re-check the inventory and skip places with a live agent session.
- Items inside a repository are offered for the Trash only when git ignores them and they hold no tracked files.
- Cleanup ledger books `trash:<kind>` and `clean:<tool>` rows; totals count Trash moves apart as `trashed_bytes`.
- `secure-agent cleanup [--kind] [--project] [--refresh] [--json]`, `cleanup trash <path>`, `cleanup clean <tool>`.
- Console Sessions › Cleanup sub-view (was Worktrees): a Clutter panel grouped by project (8 rows until Show more) with kind filters, Move to Trash and Run <clean command>.
- `POST /mute` takes an optional `agent` that scopes the mute to that agent only.
- `GET /mute`, `/snapshot` `mutes` and `DELETE /mute` carry the mute's `agent`.
- Flag explanations and patterns serve `mute-class` / `mute-rule-host` with the agent in `body` and a label naming it ("Mute keychain access for codex").
- Console Muted list shows the agent of a scoped mute.
- Console Policy: muted flag classes show the mute's agent, or "all agents".
- `GET /mute` rows carry `title`, the rule's human title.
- Menu bar: the top unacted finding shows under the hero with its served title, explanation and disposition.
- Menu bar: the finding's recommended allow host, allow path, mute or dismiss action runs from the popover.
- Menu bar: an allow host or allow path from the popover also dismisses the finding.
- Menu bar: a popover action runs only when its method, path and body keys match its action id.
- Console: four tabs (Home, Sessions, Egress, Policy) replace nine.
- Console: old tab links, menu bar deep links and saved views open the matching tab or sub-view.
- Console Home: Needs your attention first, then Spend, then collapsed Findings history and Trends.
- Console Sessions: Sessions, Processes, Resources, Worktrees and Events sub-views.
- Console Policy: notification rules, guard decisions, file exceptions, muted flag classes and the policy audit.
- Console: a load without a console token, or a revoked token, shows only "Console session ended."
- Console: a new `#ct=` in the address bar reloads the page with that token.
- `GET /worktrees` sizes: `size_bytes` per worktree and per repository (allocated bytes, measured in the background and cached for an hour; `sizing` while pending), `summary.size_bytes`, `summary.removable_bytes`, `volumes` (mount, total, free) and `reclaimed` totals.
- Cleanup ledger: every worktree removal books the bytes it gave back, every prune a row; `GET /cleanup/ledger` and `secure-agent cleanup log`.
- `POST /worktrees/remove` answers the bytes reclaimed.
- `secure-agent worktrees` lists the biggest projects first with sizes, disk free per volume, worktree and removable totals and reclaimed so far.
- Console Worktrees tab: disk card (volume bar, worktree, removable and reclaimed totals), sizes per project and worktree, biggest projects first; a removal updates the totals in place; while sizes are measured the tab re-reads the cached report every 5 s (up to 5 minutes).
- `POST /worktrees/advise`: queues a worktree for a local-advisor note (`remove`, `review` or `keep` with a rationale); branch names, paths and commit subjects go to the model inside `<evidence>`.
- `GET /worktrees` `advice`: the stored note per worktree path at its current HEAD; notes never change the state or what `POST /worktrees/remove` accepts.
- `secure-agent worktrees advise <path>`; the list view prints the note under its row.
- Console Worktrees tab: Ask advisor on review and keep rows; the note shows under the row.
- Operator labels: allow, mute, path allow and guard answers record ok or not ok for the case (rule, agent, path or host); `POST /labels` takes Mark as routine / Mark as not ok and kills from a finding.
- Flag explanations count the operator's labels on the same case; `/advisor/plan` shows the 5 most similar and, after 3 consistent labels, suggests the offered allow (or kill); triage and plan prompts carry the similar labels.
- Console: Mark as routine / not ok on finding cards and in the What to do drawer, with your history and the suggestion.
- Playbooks: every rule has a fixed response — why it fires, what to do now, how to prevent it (guard rules, settings, secret handling, agent instructions, workflow), which actions apply.
- `GET/POST /advisor/plan`: the playbook always; on request the local advisor writes a plan from this machine's context (explanation, session, masked file excerpt, history, local policy) — why, prevention, behavior changes, remediation, recommended actions; stale when new evidence arrives.
- Console: a What to do drawer on every finding, and the playbook and plan in the incident and file drawers with Ask the advisor and the recommended actions as buttons.
- `GET /costs?by=provider`: recorded provider, else the vendor whose price table resolves the model, else `(unknown)`.
- `GET /costs?by=day&tz=<minutes>`: spend per local calendar day, oldest first.
- `GET /costs`: `tz` outside `-840..840` returns `400`.
- `secure-agent cost --by provider|day` and `--tz <minutes>` (default: this machine's offset).
- Claude Code model calls record provider `anthropic`.
- Console Spend card: dimension (repo, provider, model, day) and window (24h, 7d, 30d) controls, kept per tab.
- Console Spend card: day view as bars.
- `GET /files/detail`: facts, findings, agent-session accesses, transcript hits and a masked excerpt for a file stored evidence names.
- `POST /files/reveal` and `POST /files/open`: Finder selects the file or the default text editor opens it; audited.
- NoAgent route class: refused for agent processes on the socket (live family check) and on the console listener (the TCP client's process).
- Firewall `Engine.Mask`: fingerprint and pattern hits replaced by `[REDACTED:<rule>]`, with a rescan that reports anything left.
- Transcript secret hits and their flag evidence carry the byte offset of the line.
- Console: evidence paths (incident Accessed Files, a finding's File) open a file drawer with Reveal in Finder and Open in editor; `#file=<path>` deep link.
- Menubar: an incident's files reveal in Finder or open their console file drawer.
- `/advisor/discover` returns `machine` (chip, RAM, free disk) and `recommendations`: installed chat models and a verified catalog (Qwen3.5 4B/9B, Qwen3.6 35B-A3B, Qwen3.8 27B 4-/8-bit) ranked by fit for this machine; Ollama discovery reports model sizes.
- Menubar: Settings → Advisor lists the models recommended for this Mac with a Use button; onboarding step 9 offers the recommendation with Use recommended.
- `GET /worktrees`: every git worktree found from session workspaces, agent worktree directories, `worktrees.roots` and a saved repo list, each with state `remove`, `review`, `keep`, `prune` or `main`, reasons, `stale` and last activity.
- Worktree merge detection by ancestry or a zero-context patch-id match for squash merges; local git only.
- Worktree rows list precious ignored files (`.env*`, `*.pem`, `*.key`, `.tmp/`, `.claude/`, `.remember/`) with file count and size.
- Worktree directories git no longer lists are reported as orphans.
- `POST /worktrees/repos` adds or hides a repository on the saved list.
- `secure-agent worktrees [--state] [--repo] [--stale] [--refresh] [--json]` and `secure-agent worktrees add|hide <path>`.
- `worktrees.roots` and `worktrees.stale_days` settings, applied live.
- `POST /worktrees/remove`: removes a worktree only when a fresh inspection says `remove` (`git worktree remove`, never `--force`; the branch stays), or prunes missing ones; 409 carries the fresh verdict.
- `secure-agent worktrees remove <path>` and `secure-agent worktrees prune <repo>`.
- `worktree-remove` and `worktree-prune` audit rows.
- A missing worktree that is locked reads `keep` (git does not prune it).
- A worktree active in the last 24 hours is never `remove`.
- `secure-agent worktrees` explains a 403: while the menu bar app runs, changes go through its console.
- Console Worktrees tab: rows grouped by repository with state, stale, idle days, branch, path and reasons; state and stale filters; Remove, Prune, Hide repo, Add repository and Rescan.
- `GET /patterns`: repeating flags grouped by agent, rule and subject, with cadence, pids, sessions, disposition, summary and actions.
- `/snapshot` `patterns`.
- `/posture` `pattern` items in place of the flag items a pattern covers.
- `POST /flags/acknowledge` accepts `flag_ids` (up to 500) in one transaction.
- Console pattern card on Attention and Flags: count, window, summary, 24-bar cadence strip, open count, served actions, individual flags.
- Console tab bar stays at the top while the page scrolls.
- Console tab bar shows a posture pill once stuck.
- Console posture pill scrolls the page back to the top.
- Console scope bar under the tabs names the session or process family Events, Flags and Incidents are narrowed to, with a Clear button.
- Console drawers opened from inside another drawer show a Back button that reopens the previous drawer.
- `/posture` `machine` group for collector, hook and machine-wide egress items.
- `/egress/uninspected` rows carry `identity`, `first_seen` and `session_id`.
- `identity.class` (`vendor`, `telemetry`, `cloud`) on `/egress/uninspected`, `/egress/endpoint` and `/snapshot` suggestions.
- Egress drill-down groups vendor-class endpoints (no `infra`) into one row per agent and vendor with Allow all and Evidence.
- Egress drill-down keeps cloud and telemetry hosts in the unknown list with the org shown after the host.
- `/snapshot` suggestions carry `identity`.
- `/snapshot` suggestions skip vendor-class hosts.
- Advisor host prompt carries the host's identity, reverse name and the agents it is already allowed for.
- Hermes Agent process matcher (`hermes-agent`, `/.hermes/`).
- Hermes Agent sessions from `state.db` and each profile's `state.db`: turns, tool calls and model calls; `hermes_home` setting.
- Hermes sessions carry the repo, branch and parent session Hermes records.
- `/doctor` `hermes` check: databases read, watermarks and last poll, or not installed.
- openclaw conversations from `lcm.db`: sessions, turns, tool calls and model calls; `openclaw_home` setting.
- `/doctor` trace coverage names the traced harnesses.
- `/doctor` collectors check prints the openclaw, opencode and hermes database, watermark and last poll.
- `/costs` rows and total split `unpriced_calls` into `unknown_model_calls`, `unpriced_model_calls`, `plan_calls` and `local_calls`.
- `/costs?by=model` rows carry `provider` and `class`.
- `GET /costs/unpriced`: zero-cost calls by harness, provider and model with their class.
- `secure-agent cost` prints the class breakdown and one pricing hint per unpriced model id.
- opencode and codex model calls record the provider.
- Owner-only `GET /debug/pprof/` on the control socket: Go runtime profiles
  for the owner uid and the pinned menubar app; refused for agent and
  foreign peers, never admitted by the console token, not served on the
  proxy listener.
- `GET /flags/{id}/explain`: one plain sentence per rule, no pids.
- Explain carries the file's category and owner, each destination's org, allowlist state and read→connect gap, the session with the nearest tool call and model.
- Explain carries one disposition (`acknowledged` → `benign-likely` at advisor confidence ≥ 0.85 → `warning` → `critical`).
- Explain lists the applicable actions with the exact request each performs; the advisor's suggestion is marked recommended.
- `/flags` and `/snapshot` stamp `explain` on the first 25 unacknowledged flags without network lookups.
- Session report: `GET /sessions/{id}/report?format=json|md` aggregates one
  session's tools, models, cost, files, hosts, guard decisions, findings,
  secret-rule hits and opening timeline (names, paths, hosts, model and rule
  ids, counts — never content); `secure-agent session <id-or-prefix>` prints
  it as markdown, `secure-agent sessions` lists sessions, `GET /sessions`
  filters by `harness`, `repo`, `branch` and `since`, and the console's
  session head gains an Export button that copies the markdown.
- `secret-in-transcript` flag: tailed harness transcript lines are scanned with
  the firewall's known-secret fingerprints and typed patterns; a hit carries
  the rule id, transcript path, and session id (never the matched text), is
  severity 3 for a registered secret and 2 for a typed pattern, and repeats
  per (path, rule) are collapsed.

### Changed
- A stored advisor verdict publishes its flag as a stream delta.
- The served allow-host label for an IPv6 address names the address owner instead of the literal.
- Menu bar hero: state, color and subtitle come from `/posture`.
- Menu bar: flags refetch only on `flag`, `posture`, `guard-prompt` and `guard-resolved` stream frames.
- Menu bar: an identical flags refetch leaves the popover unchanged.
- Menu bar: notification and mute-list titles come from the daemon.
- The console token admits a method other than GET or HEAD only when the route lists it in `MutatingMethods` or `ConsoleMethods`.
- `/guard/path-allow` is console-admitted on the proxy listener.
- `POST /guard/path-allow` is a pinned-UI mutation.
- Console finding cards offer the served allow-path action.
- Menu bar Open console loads the fresh console link into the existing console tab before focusing it.
- Console notification preferences moved from the header to the Policy tab.
- `/worktrees*` routes are NoAgent: agent processes cannot read or change the machine's worktrees.
- Console Overview: Memory by session is Memory by family — one bar per live process family, its RSS counted once, `N sessions` in the label.
- Console Overview: the Memory by family badge counts agent families, not infra.
- Events carry a `(session_id, kind, id)` index; the event store writes planner statistics (`PRAGMA optimize`, `analysis_limit` 1000) at open and after each prune.
- Untagged keychain flags name the agent the match strings give the exe.
- Untagged keychain flags with a version-number exe name carry the directory that names it (`untagged:claude 2.1.280`).
- Console Flags list hides flags a pattern covers.
- `/posture` `items` and `groups` come from one pass.
- `/posture` puts every item in exactly one group.
- `/posture` group items sum to `needs_you`.
- `/posture` `groups` include unacknowledged severity-2 flags with priority 1, rule title and disposition.
- `/posture` `groups` include pending resource decisions as `resource` items.
- `/posture` `items` include pending resource decisions as `resource_pressure` items.
- `/posture` `items` carry one `uninspected_egress` item per group with uninspected egress to unknown endpoints.
- `/posture` egress items and their counts exclude known CDN/cloud carriers.
- `/posture` `items` carry open critical incidents at severity 3.
- `/posture` `state` is `critical` while a critical incident is open.
- `/posture` `items` carry open high incidents at severity 2.
- `/posture` `items` carry other incidents open more than 72h at severity 1.
- Console Attention badge shows `posture.needs_you`.
- File opens, writes and deletes from processes outside every agent family are not stored unless they raise a flag.
- Event pruning seeks a `(kind, id)` index: kinds by index skip-scan, each kind's budget cut at its budget-th newest id.
- Insert-driven pruning runs at most once per 30 s.
- The event store opens WAL with `synchronous=NORMAL`.
- Posture and attention: a flag the advisor judged benign at confidence ≥ 0.85 is severity 1 (`attention`, "Finding, likely benign"), never `critical`.
- Console: an explained flag's card and Attention item show who, what and the one verdict with the served actions as buttons; raw evidence, pid and timestamps sit behind Details.
- Console Resources: a one-row machine strip (headroom, memory, CPU, swap; pressure and thermal chips) replaces the host block.
- Console Resources: families with a diagnosis lead as at most five needs-attention cards.
- Console Resources: families group by harness, sorted by memory, with orchestrated children nested under their parent and infrastructure in one trailing, uncounted group.
- Console Resources: families are named harness · repo@branch or harness · folder, never by pid; the Overview memory chart uses the same names.
- Console Resources: View family opens a drawer with usage, processes, recent activity, findings and terminate actions instead of switching tabs.
- Console Resources: the board fits a 375px phone at any font metrics; family rows and long labels wrap instead of overflowing.
- Console: the Events tab lists the newest 50 rows, the family process table 12 and an Agents group 8 instances, each with Show more.
- Console: pid-scoped event filtering opens the Events tab.
- Console: "View session in timeline" opens the session in the Sessions tab with its trace, keeping Events scoped to it.
- Console: the drawer's Copy button stays hidden outside incident reports.
- Advisor host pre-assessment skips vendor-class hosts as well as CDN carriers.
- Advisor host pre-assessment still covers cloud, telemetry and unknown hosts.

### Removed
- Menu bar: the unused flag action, incident detail and process detail sheets.

### Fixed
- A daemon writes `guard-cwd-overrides.json` beside its own socket.
- A second daemon with a socket elsewhere no longer rewrites the default `guard-cwd-overrides.json` the hook reads.
- Keychain flags from the last hour stamped `untagged:<exe>` are relabeled to the agent when the tagger tags that pid.
- The console receives each relabeled keychain flag as a flag delta.
- Menu bar: a lost daemon connection also clears posture and the pending guard prompt.
- Menu bar: the Sessions header count matches the "more" overflow count.
- The console token no longer reaches the owner-level `DELETE /guard/rules`.
- Flag sentences and attention labels keep agent ids such as `untagged:node` as written.
- Posture and `/doctor` report "File monitoring writer is flooding" only while the spool is still being written (within 2 min); garbage left by a removed writer no longer masks the service state. A spool whose service is not loaded shows "File monitoring is off" with the steps to enable it.
- Secret patterns count only where the match starts a token (not after a base64 or base64url character, except a JSON `\n`, `\t` or `\r` escape): vendor-key shapes inside encrypted reasoning items and other encoded blobs no longer raise secret-in-transcript or proxy findings.
- Endpoint detail lists an allowance whose approved parent domain covers the host.
- Endpoint drawer resolves sessions by id, so sessions beyond the newest 1,000 are attributed.
- A second process in the same working directory gets its own session, never another root's.
- A codex rollout session joins the process holding the rollout open: root pid set, that tree's process-tree session merged in.
- `/doctor` trace coverage counts transcript and hook sessions seen since boot, not only those started since boot.
- A session upsert stores a new parent and never clears a stored one.
- Every event from a pid already resolved carries its session id, not only the first.
- A hook-stamped session carries its process tree's root pid and absorbs that tree's process-tree session.
- Sessions first seen through a trace event record `transcript` confidence, not `hook`.
- Codex model calls name the model from `turn_context` when the rollout has no `thread_settings_applied` line.
- A codex rollout resumed from a saved offset keeps its session and model.
- Claude `<synthetic>` records no longer count as model calls.
- A vendor-prefixed model id is priced by its unprefixed entry.
- Spool tailer: lines under 16 bytes or not starting with `{` are rejected
  before JSON parsing; a per-tick 4 MiB drain budget skips the rest of a
  flooded tail in bulk instead of scanning it, and posture/doctor report a
  flooding writer (unparsed share, MB skipped) instead of parsing garbage.
- Console: live-stream frames mark only the panels that read the changed data.
- Console: only the active tab's panels, the header and the tab badges render, at most every 250 ms per panel; hidden panels render on tab switch.
- Console: list panels (findings, attention, incidents, audit, sessions rail, agents, firewall, events) patch rows by key, so focus, open disclosures and a click during a render survive.
- Console: a panel waits while the pointer is down in it or one of its controls has focus (up to 3 s).
- Console: allow, mute, unmute, promote/demote, incident status, guard and resource decisions, source add/remove, allowlist remove and dismiss change the card before the request, revert on failure and leave a 4 s inline note on success.
- Verified by DOM checks on a 300-event burst (hidden-tab render counts, an open rail group, a focused button, a mid-burst Dismiss click) and on allow success and failure.
- Sessions: a tagged child process (a shell under a harness) joins its harness
  family's session instead of minting its own — the tagger now reports the
  family root on every tag, not only in the process listing.
- Sessions: a session is ended only when its root process is confirmed gone,
  not when one process-table sample happened to miss it.
- Sessions: orchestrated runs are nested under their orchestrator's session —
  the parent lookup walks the OS ancestry past the child's own harness match
  instead of a chain that stopped at the first match.
- Model pricing: explicit entries for every current Anthropic model (Fable
  5.x, Opus 5.5/5/4.8/4.7/4.6/4.5, Sonnet 5/4.6/4.5, Haiku 4.5) at list
  price; a family prefix only absorbs a date or `-latest` suffix, so a newer
  version or a `-pro`/`-mini` variant is never billed at another model's
  price — it is unpriced until an entry exists.
- Sensitive-path classifier: globs with a directory component
  (`~/.kube/config`, `~/.claude/settings.json`, the merged guard-rule paths)
  match the full path only; previously the file name alone matched, so any
  `config`, `settings.json`, `hosts.yml`, `credentials`, or shell rc file
  anywhere classified as sensitive and seeded `sensitive-read-then-connect`.
- Flag evidence `read` items carry `rule` (which classifier rule or glob
  matched); ES file events from the daemon's own pid are dropped at ingest.
- Event retention: every event kind has its own row budget; the shared
  10,000-row cap over all non-trace kinds let a file-open burst evict
  hook-activity, connection, and transcript-hit rows, which made the posture
  hook item and the acceptance gate report a firing hook as silent.
- ES grant flow: the Full Disk Access entry is the helper binary
  `com.cavi-ai.secure-agent-esd`, not `eslogger` — the setup card now names
  it exactly, and the retry-interval copy matches the real 60s backoff.
- ES service probe parses the FIRST top-level `state =` from `launchctl print`
  (nested sections repeat the key and previously overwrote the real service
  state); the last-exit-code annotation is kept.
- Posture emits at most one item per collector: the spool-based ES probe
  supersedes the tailer heartbeat when it reports a failure, so a crash-looping
  root service no longer double-counts under the `eslogger` id.
- Session repo identity walks up to the enclosing git root (workspaces are
  often subdirectories of a checkout), reports empty when no repo encloses the
  workspace instead of inventing one from the basename, and the memoized
  resolution expires after 10 minutes instead of living for the process
  lifetime.
- Codex rollout discovery reads `CODEX_HOME` off live codex processes (same
  mechanism as `ps eww`), so orchestrators that relocate the rollout store no
  longer blind codex tracing until a daemon restart.
- opencode model attribution reads the current schema (`message.data.modelID`
  top-level) with the older nested `model.modelID` as fallback — model calls
  carry their model id again instead of landing unpriced with an empty model.
- Privileged ES collector: the integrity hash moved from the console-user-owned
  spool directory to root-owned `/Library/Application Support/secure-agent`,
  the binary self-check now refuses non-root-owned executables in addition to
  writable ones, and the expected pre-grant eslogger permission failure retries
  inside the process (60s backoff) instead of respawn-churning through launchd.
- Acceptance gate: the ES service check no longer parses JSON through
  quote-broken shell interpolation (every probe read as absent), treats
  `not-loaded` as a failure when spool-based, asserts guard hook ACTIVITY
  (events in the last hour) instead of settings.json registration, and scopes
  the repo-coverage and turn-ratio assertions to the current daemon's boot
  window — rows and transcript records from before boot cannot be fixed
  retroactively and previously made the ratio assertions measure old binaries.
- Acceptance gate: time-window queries wrap stored RFC3339 timestamps in
  `datetime()` before comparing — the raw string compare against sqlite's
  space-separated format made every row from the same day read as "in the
  last hour", which hid session floods and inflated hook-activity counts.
- Transcript tailer no longer skips new content: a boot re-seed only applies
  to files the tailer was already following (tracked files keep their saved
  offsets), and a transcript discovered for the first time under an already-
  tracked target is read from the start instead of from its current end —
  session one in a workspace and lines written while the daemon was down are
  ingested again.
- Daemon startup repairs rows written by older resolvers: sessions whose repo
  carries the old basename heuristic's signature are re-resolved against the
  enclosing git root, and tool-call rows stranded at "running" past ten
  minutes (lost completion lines) are closed as error.
- Process-discovered sessions stamp `started_at` with the process's real
  start time instead of the discovery time — a daemon restart no longer makes
  every live agent look like a session created in the last hour.
- Guard hook: read-only socket reads against the agent daemon are allow-listed
  by RESOLVED target (a `$SOCK` variable or `http://unix/<path>` URL now
  matches the socket path, not the literal token), covering GETs to /status,
  /resources, /healthz and /posture; any write verb or /guard path against the
  socket is still denied, and loopback /guard requests are denied regardless.
- Privileged ES collector exits 0 on failures launchd cannot fix (not root,
  binary-integrity failure, eslogger missing) so the service stops
  crash-looping; genuine startup failures still exit non-zero.
- ES collector integrity check trims the recorded hash — the installer wrote
  it via `awk '{print $1}' > file`, leaving a trailing newline that made every
  start read as tampered; the installer now writes it without one.
- Flag evidence is structured (`kind`/`label`/`sub`/`ts`) instead of display
  strings every client re-parsed with its own regexes; the console evidence
  chain and the menubar action sheet render the served fields, and rows
  written by older daemons still decode as plain-text items.
- Flag rule titles are served by the daemon (`flag.title`) instead of being
  copied into the console's `RULE_TITLES`, the menubar notification switch,
  and the posture copy — one table, every surface agrees; the client tables
  remain only as fallbacks for older daemons.

### Changed
- Transcript discovery by harness shape: Claude, Cursor, Codex and
  Antigravity transcripts are found by per-harness globs re-resolved every
  15 s instead of recursive walks of their trees; files modified in the last
  two minutes are tailed every second; tail offsets are saved at most every
  30 s and on shutdown; the ES spool tail skips a spool whose size and mtime
  are unchanged.
- The Endpoint Security collector ships inside the app bundle
  (`Contents/MacOS/secure-agent-esd` plus
  `Contents/Library/LaunchDaemons/com.cavi-ai.secure-agent-esd.plist`) and is
  registered with `SMAppService.daemon`: the user approves Secure Agent in
  Login Items and Full Disk Access, with no admin password. The collector
  verifies its code signature instead of an install-time hash, the setup card
  names Secure Agent instead of the launchd label, and a collector installed
  by an earlier version under `/Library` is removed from the card (one admin
  prompt) or by `packaging/uninstall.sh`.
- API HTTP handlers for resources, kill, firewall, and guard live in their own files (`api.go` 1662→940). Same package, no behavior change.
- The daemon composition root is split into named stages (`buildResourceStack`,
  `buildFleetAndOTLP`, `runResourceLoop`, `wireEgressOverrides`,
  `buildAdvisorHooks`, `buildResourcePolicyUpdater`, `makeResourceExecutor`,
  `startCollectors`) — `Build` 477→197 lines of sequencing. Same wiring, no
  behavior change.

### Added
- **Codex model attribution.** Codex model calls carry the model id from the
  rollout's thread settings and are priced from the price tables; a model the
  tables do not know costs 0 and counts as unpriced — never a fabricated price.
- **User price table.** `pricing` in `config.yaml` sets USD per 1M input and
  output tokens by exact model id or prefix, wins over the built-in table, and
  applies live on change. Built-in prices now cover OpenAI and Google model
  families alongside Anthropic.
- **Self-check.** `GET /doctor` and `secure-agent doctor` report pass, fail
  or skip for guard-hook registration and activity, file telemetry,
  collectors, per-harness trace coverage, session identity, repo attribution
  and creation rate, tool-call pairing, Claude model-call pricing, per-kind
  retention, egress routing and bus drops, each failure with a one-line fix;
  the CLI exits 1 on any failure.
- **Model-call spend.** `GET /costs` and `secure-agent cost` sum model calls
  by repo, branch, harness, session or model over a window (`since`,
  `until`), with tokens, distinct sessions and the dominant harness per
  group. Calls from models outside the pricing table are counted as
  `unpriced_calls` and never assigned a cost. The console Overview shows a
  24h spend tile and a top-5 spend-by-repo card.
- **Unified Attention Center.** The console now groups resource approvals,
  blocked guard requests, critical findings and incidents, and uninspected
  egress by complete agent session. Each group shows its workspace, process
  count, memory, CPU, and the reason it needs review, with existing scoped
  actions available directly from the queue. Signals that cannot be safely
  attributed to one live session remain in an explicit agent-level group.
  The grouping is computed once, daemon-side (`/posture` → `groups`): the
  console renders it as served and the menubar's attention predicate reads
  the posture state instead of re-deriving it from flags and incidents, so
  the icon, hero, badge, and console queue can never disagree.
- **Resource Mission Control for local agent fleets.** The daemon now samples
  live RSS and CPU for attributed processes, groups them into stable session
  families, retains one hour of five-second history, and diagnoses heavy
  memory, full-core CPU, rapid growth, idle retention, runaway children, and
  orphan drift. `GET /resources` exposes process topology, trends, evidence,
  thresholds, confidence, and reclaim estimates. The web console ranks and
  charts whole sessions with click-through family detail; the native menu bar
  shows family CPU/memory and supports Impact sorting. A local Resource Flight
  Recorder preserves bounded pressure episodes when diagnoses appear, change,
  or memory escalates another 25%, retaining whole-session totals, the root,
  the 64 highest-impact processes, and a ten-minute prelude after exit. Each
  episode adds up to 80 redacted activity references from the captured process
  family, marks them on the trend chart, and identifies the activity observed
  during the steepest sample-to-sample memory rise without claiming that
  temporal proximity proves causation. Exact nanosecond and per-process
  lifetime checks prevent recycled PIDs from importing unrelated activity;
  a bounded settling window re-enriches episodes from events persisted just
  after the initial capture.
- **Opt-in session resource budgets and containment.** A hot-reloadable
  `resource_control` policy supports observe-only reporting, approval-required
  containment, or explicit automatic whole-family termination after a
  sustained RSS/CPU breach. Grace periods, cooldowns, PID start-time checks,
  retryable failed approvals, console controls, and durable audit entries keep
  the destructive path bounded and explainable. The console now includes a
  visual policy editor with complete per-workspace overrides, longest-path
  selection, atomic YAML persistence, and an explicit confirmation before
  automatic termination can be saved.
- CI: cancel stale runs, job timeouts, credential-free checkout, cgo-free Linux gate, go mod tidy, govulncheck, Dependabot, Go test shuffle. Proxy token and CA permission contracts now have unit tests (the old 0600 check was asserting a different temp path). Go toolchain 1.26.6.

### Changed
- Overview shows a 3-row session strip (project folder, RSS, last seen, needs-you) that opens the Sessions tab. The full board stays on Sessions.
- Menubar sessions are grouped by harness family again (collapsed headers with session/memory/activity aggregates, small families expanded), capped at 6 groups with a "+N more — open the console" link. The flat 50-row list is gone.
- Every hero count is clickable: "N flags to review" opens the top unacted flag's action sheet; uninspected/would-block opens the console egress drill-down (tab deep-links now survive the token handoff).

### Changed
- The session board is its own console tab (Overview / Sessions / Agents / Egress / Findings) instead of filling the main dashboard. Overview keeps the activity trend and event timeline.

### Changed
- Uninspected-egress headline now counts only unknown endpoints. Known CDN/cloud infrastructure (Cloudflare, Google, AWS, GitHub, Akamai, Fastly, Azure — by suffix, CIDR, and cached PTR for bare IPs) is collapsed into a separate `uninspected_infra` figure and one collapsible group in the drill-down, excluded from the hero, posture, allowlist suggestions, and advisor pre-assessment.

### Added
- Firewall rules can be demoted back to monitor from the console (block was a one-way ratchet in the UI).
- `GET /allowlist` lists user-approved endpoints; `DELETE /allowlist` removes one. The console renders them with working Remove buttons.

### Changed
- Console SSE only refetches `/snapshot` on exec, guard, and proxy-hit; file/conn events update the sparkline only.
- Process tagger walks every 3s while agents are tagged (idle stays 5s).
- `PostToolUse` is one `secret_guard.py` spawn (injection scan + activity log); `injection_scan.py` is no longer a second process.

### Fixed
- List endpoints (`/events`, `/flags`, `/incidents`, `/audit`, `/stats/rollup`) returned `null` instead of `[]` when empty — crashed strict clients (process transcript sheet).
- Daemon shutdown during instance overlap could unlink the successor's live unix socket (running but unreachable).
- Menubar: decodes `null` list bodies as empty; transcript sheet gains Retry.

### Fixed
- **Hero "N flags to review" counted reviewed flags.** The popover hero's
  Attention branch counted every severity≥2 flag in the fetch window —
  including acknowledged ones — so it read "20 flags to review" over a list
  the operator had fully dealt with. It now uses the same unacted filter as
  the attention section (`unactedFlags`), and `heroModel` is pinned by
  regression tests (reviewed flags never demand review; uninspected-egress
  alone still earns Attention).
- **"Open console" was a greyed-out dead end when the inspection proxy was
  off.** The footer button is now the way OUT of the off state: it offers a
  one-click "Turn on & open" flow — writes `proxy_enabled: true` into
  config.yaml (narrow line-based edit, every other byte preserved), bounces
  the daemon (waiting for the old one to release the socket so the new one
  wins the bind race), waits for the port, and opens the console. The button
  shows an "Enabling…" state and fails loudly if the port never comes up.
- **Duplicate console tabs.** "Open console" now focuses an already-open
  console tab in Safari or Chrome (AppleScript, with plain-open fallback for
  other browsers and for Automation-consent denial) instead of spawning a
  fresh dead-end tab on every click.
- **Menubar build warnings cleared** (dead `try?`/`await`/variables,
  optional-interpolation, implicit-strong-capture) — the package builds
  warning-free.
- **Notification Center no longer piles up handled alerts.** The menubar now
  reconciles delivered banners on every poll: banners whose flag was acted
  on (dismissed in either UI, muted, retro-acknowledged daemon-side — all
  converge to `acknowledged`) are withdrawn, and anything older than 7 days
  is pruned. Previously nothing ever withdrew a delivered notification, so
  the Center accumulated greyed-out history for alerts the operator had
  already dealt with. (The reconciliation path also skips
  `getDeliveredNotifications` outside a real .app bundle — it throws in the
  xctest host.)
- **Malformed-overlay log storm.** A bad `config.yaml` logged a WARNING on
  every load — and the hot-reload watcher loads every 2s, producing ~1,600
  lines/hour (`cannot unmarshal !!seq into config.rawConfig`). The loader is
  now silent; boot-time `Load` logs the warning exactly once, and the
  watcher keeps its own once-per-state line. Regression test pins the
  contract.

### Added
- **One-command fleet enrollment (`secure-agent fleet enroll <collector-url>`).**
  Reads the node id from the running daemon, generates the webhook secret,
  merges `fleet.webhooks` into `config.yaml` (comment-preserving, backup
  written first; re-enrolling the same URL rotates the secret in place), and
  prints the single line the collector's secrets file needs. The old flow —
  hunt the node id, invent a secret, edit two files, restart the daemon — is
  gone.
- **Fleet config is hot-reloadable.** The daemon's config watcher (previously
  advisor-only) now swaps fleet sinks, heartbeat cadence, labels, and
  hostname live within one poll cycle — enroll takes effect in seconds, and
  enrolling a node that had no webhooks at boot activates heartbeats without
  a restart. `fleet_configured` follows the webhook set so the console's
  fleet panel appears/disappears live.
- **Sequence numbers + gap detection (`boot`/`seq` on every envelope).** The
  Publisher stamps each envelope with a per-boot monotonic sequence; the
  collector tracks holes with a 90s grace for retries/reordering and surfaces
  confirmed loss per node (`gaps` in `/fleet`, "N deliveries lost" warnings
  in the overview). Delivery stays best-effort — but backlog-cap drops and
  collector downtime are now *visible* instead of silent. A new boot (daemon
  restart) resets the expectation; legacy unsequenced envelopes skip
  tracking.
- **Cross-node rule aggregation (`GET /fleet/rules`).** Rolling-24h per-rule
  fleet footprint: which rules are firing, on how many of the fleet's nodes,
  with how much critical mass — "one node is an incident; five is a bad
  release." Rendered as a "Rules across the fleet" table in the collector
  overview, sorted by node spread.
- **Fleet posture heartbeats (`status` envelope kind).** Every fleeted node
  now pushes a status envelope — at boot, every `fleet.heartbeat_interval_sec`
  (default 60s), and immediately on posture-state transitions — carrying the
  node's own `/posture` headline (`posture_state`, `posture_summary`,
  `needs_you`), hostname, agent count, and operator-defined `fleet.labels`
  (env/role/team grouping). Heartbeats bypass per-sink `events:` filters on
  purpose: liveness that can be unsubscribed is indistinguishable from a dead
  node. Posture computation was extracted (`computePosture`) so the collector
  renders the exact headline the console and menubar show.
- **Posture-aware collector rollup.** The reference collector now harvests
  what it used to discard: flag `severity` and incident `risk` feed rolling
  **24h counts** (`flags_24h`, `critical_flags_24h`, `incidents_24h`,
  recomputed at snapshot time so they decay on quiet nodes); guard decisions
  break down into allow/deny; `last_event` (security activity) is tracked
  separately from `last_seen` (liveness). The overview page leads with a
  fleet headline ("2 critical · 1 stale · 12 all-clear") over cards titled
  by hostname with posture chips and label chips, sorted critical-first.
  Heartbeat nodes are stale after 3 min and "gone quiet" after 10 (was:
  indistinguishable from idle after 10 min); legacy event-only nodes keep
  the lenient 10/20-min thresholds.
- **Node identity config.** `fleet.hostname` (display-name override) and
  `fleet.labels` in `config.yaml`, carried in every status envelope.

### Fixed
- **Collector version was sticky.** The first version a node ever reported
  was frozen in the rollup forever; upgrades were invisible. Version now
  tracks the newest report.
- **Empty fleet panel was permanent noise.** The console's Fleet nodes panel
  now hides entirely when the node has no collector webhooks configured
  (`/fleet` reports `fleet_configured`), instead of a forever-empty
  "No remote fleet nodes registered" placeholder on single-machine installs.
- **`secure-agent fleet` help text** claimed remote node telemetry; it shows
  this node's fleet identity (remote rollups live at the collector).

### Changed
- **Collector storage sits behind a seam.** Persistence is now a small
  `envelopeLog` interface (append/replay/query) with the JSONL backend as the
  reference implementation — the swap point for a production-grade SQLite
  store (retention, TLS, alerting on the roadmap).

### Fixed
- **Console whitelist drift (the "everything runs but the console says it
  can't reach the daemon" bug).** The proxy listener's console-token
  whitelist (`isConsoleAPIPath`) had fallen behind the console's fetches:
  `/stats/rollup`, `/mute`, `/allowlist(+suggestions)` and others answered
  **407** in the browser, silently blanking the Activity chart, the muted
  list, and the egress suggestions. The whitelist now covers every endpoint
  the console fetches, and `TestConsoleAPIPathsCoverWebApp` parses
  `web_dist/app.js` and fails CI on any future drift.
- **Console session no longer dies on reload.** The console token was kept
  in memory only after stripping `#ct=` from the URL, so a single reload
  produced a permanent wall of 403s rendered as "can't reach the daemon".
  The token now persists for the life of the tab (sessionStorage), and the
  offline state is honest: **auth-expired** ("reopen the console from the
  menu bar") is no longer conflated with **unreachable**. Every fetch also
  carries a 5s timeout so a hung endpoint can't wedge the refresh cycle.
- **Uninspected-egress warning was a dead end.** Clicking it scrolled to a
  panel that showed the same number and nothing else. There is now a real
  drill-down (`GET /egress/uninspected`): every endpoint with agent, counts,
  last-seen, the advisor's verdict, and a one-click **Allow**.
- **Keychain alert storm had no recourse.** `keychain-access` (file-open of
  keychain DBs) fired a severity-2 notification per (pid, path) every 15
  minutes, the mute system was never consulted in the keychain code paths,
  and the menu bar's action sheet offered only "Kill agent" (dismiss actions
  required host evidence, which keychain flags don't have).

### Added
- **Rolling 24h blind-spot counter.** `status.uninspected_egress` now counts
  distinct endpoints seen in the last 24 hours instead of growing
  monotonically for the daemon's lifetime (it had inflated to ~1000); pairs
  silent for 7+ days are swept from the tracker.
- **Rule-level mutes (`host: "*"`).** `POST /mute` with `host: "*"`
  suppresses an entire flag class (counted in `status.muted_flags`, all open
  flags of the rule acknowledged). Exposed as "Dismiss this flag class" in
  both UIs — including, finally, keychain flags.
- **Per-rule notification overrides (`/notify/rules`).** Default policy is
  now **severity ≥ 3 notifies** (was ≥ 2); per-rule Default / Always / Never
  overrides persist at `~/.config/secure-agent/notify-rules.json` and apply
  to the menu bar and the web console alike (console bell menu, Settings →
  Notifications section). Sets/clears are audited.
- **Daemon-restart signal in the console.** An uptime that moves backwards
  is reported as "Daemon restarted — reconnected" instead of silently
  pretending continuous state.

### Changed
- **`keychain-access` demoted to severity 1 (informational).** Legitimate
  tooling opens keychain DBs for TLS trust evaluation and credential helpers
  — it never justifies a page. The `security(1)` CLI exec rule
  (`keychain-security-cli`) stays severity 3.
- **Console layout is now tabbed** (Overview / Agents / Egress / Findings)
  instead of one endless page — organized by the question each view answers,
  with per-tab badges ("2" on Egress = uninspected endpoints waiting),
  deep-linkable tabs (`#findings`), and posture items that jump to the right
  tab. Posture banner + KPIs stay always-visible on top.

### Added
- **Per-flag dismiss in both UIs.** Every flag card/sheet now has "Dismiss"
  (reviewed-and-done) alongside "Dismiss this flag class" and "Kill" —
  the missing middle recourse. Posture excludes acknowledged flags, so a
  reviewed flag stops demanding attention everywhere.
- **Advisor actions have a feedback loop.** `/status` now carries
  `advisor_health` (circuit-breaker state, last error, queue depth); re-run
  requests show a pending spinner, the fresh verdict lands with a notice,
  timeouts say so honestly after 90s, and a paused advisor renders "Advisor
  offline — verdicts paused" instead of a clickable dead button (in the web
  console AND the menu bar sheet).
- **Human-readable process labels.** The console event timeline and incident
  cards show agent names (not bare PIDs); menu bar session rows show the
  project folder next to the PID; keychain flags carry a "this is usually
  routine" context note.
- **Regression coverage for every "nothing happens" bug class.** The DOM
  harness is now stateful: Allow removes the suggestion, Dismiss removes the
  card, re-triage shows pending then the landed verdict, advisor-offline
  renders the disabled state, tabs hide/show panels. Connection states are
  pinned too: 403 → "Session expired — reopen from the menu bar" (never
  "daemon down"), network failure → retry banner, token persists across
  reloads via sessionStorage with no `#ct` fragment. Go + Swift suites cover
  the server/client halves (posture unacted filter, retriage lifecycle,
  dismiss echo, peer-gate disposition policy for `/mute`,
  `/flags/acknowledge`, `/allowlist`, `/notify/rules`, `DaemonClientError`
  human descriptions, `advisor_health` decoding, `NotifyRulesResponse`
  decoding).

### Fixed
- **THE dashboard-killer: `/fleet` returns a node-status OBJECT, but the
  console did `fleet.map` on it** — throwing inside `renderFleet` on every
  poll and silently killing every panel after it in `renderAll` (flags,
  incidents, audit, sources, events, activity chart). The live console
  rendered only agents/firewall/KPIs; the rest was permanently dead.
  `renderFleet` now accepts both shapes (object → local node card), and
  `renderAll` is crash-isolated per panel so no single bad payload can ever
  blank half the page again. The DOM harness's `/fleet` fixture lied (array)
  — it now matches the real endpoint, with a regression check that panels
  after fleet render.
- **Menu bar quick-dismiss errored on keychain groups** ("no connection
  target to mute") — hostless rules now fall back to the rule-level mute
  (`host: "*"`), so every flag group has a working one-gesture dismiss.
- **Informational flags no longer demand attention in the popover.**
  `unactedFlags` is severity ≥ 2 — routine keychain-db opens queue silently
  in the console's Findings tab instead of occupying the menu bar's
  needs-a-decision list.
- **Dashboard assets send `Cache-Control: no-cache`** (both the unix-socket
  and proxy-port handlers) so an upgrade can never pair stale cached assets
  with a new daemon.
- **Dismiss failures are now diagnosable.** The peer gate logs every denial
  with the kernel-attested peer (pid/uid/role, endpoint) to daemon-err.log,
  and `DaemonClientError` conforms to `LocalizedError` — the menu bar says
  "daemon refused the change (HTTP 403)…" instead of "The operation could
  not be completed. (…error 1.)".
- **Menu bar harness accordion was dead for single-session groups.** The
  outer (harness) header of a one-session harness looked clickable but could
  never collapse; expansion state is now an explicit override that works in
  both directions for every group.
- **"Re-run the advisor" acknowledged the flag.** The old flow marked the
  flag acted-upon after an *informational* action, closing the loop the
  operator hadn't closed; only true dispositions acknowledge now.

## [v1.1.0] — 2026-09-11

Released: https://github.com/cavi-ai/secure-agent/releases/tag/v1.1.0
Signed with an Apple Development certificate (stable TCC grants across
updates); notarization is the follow-up for public distribution.

A substantial feature + hardening release one day after v1.0.0 — in
retrospect, 1.0.0 was effectively the last release candidate; everything
below is the delta that earns the "stable" label.

### Added
- **Actionable criticals** — every flag is a decision point: click it for the
  evidence chain, the advisor verdict, and one-click dispositions (allow
  host / dismiss this flag class / kill agent / open incident report).
- **Little-Snitch-style dispositions** — allowlist a host for an agent, mute
  a rule+host pair, or **allow one exact file** (per-path guard exceptions,
  exact-match + descendants, fully revocable from Settings → Decisions).
- **Agent session trees** — the popover groups harness → sessions →
  subagents with per-harness brand icons, family memory, and last-activity
  staleness; collapsed by default, expandable per level.
- **Process transcripts** — click any process for its live event transcript
  (reads / writes / spawns / connections with per-line timestamps) and kill
  with confirmation.
- **Privileged ES collector** — file telemetry (eslogger) via a root
  LaunchDaemon running the daemon in `--es-collector` mode writing to a
  spool; one-click install from onboarding step 3 or Settings → Telemetry.
- **Popover quit button** — power icon + ⌘Q in the footer (joins the
  right-click menu entry).
- **Advisor config hot-reload** — the daemon watches config.yaml and swaps
  the advisor stack live; enabling/disabling/switching the model takes
  effect within seconds, no daemon restart required. The Settings advisor
  tab restores the persisted mode/endpoint/model on open (it previously
  reset to "managed local model" every launch, making the config look
  unpersisted).

### Fixed
- **"Disconnected" flapping on a healthy daemon** — `/status` last-seen join
  was a `MAX(ts) GROUP BY pid` SQL scan (2–11s at ~400 pids, past the 3s
  socket timeout). Replaced with an O(1) in-memory last-seen map; socket
  timeout relaxed to 10s; two-strike rule before declaring disconnection.
- **SSE reconnect crash-loop** — Go chunk-encodes the event stream over unix
  sockets; the client's SSE parser never dechunked, corrupting every frame
  into an eternal reconnect. Added an incremental chunked-body decoder.
- **Pause semantics** — resume re-seeds the notification baseline (no banner
  storm of accumulated flags); guard consent prompts still flow while
  paused (agents no longer hang silently); paused state is now visible in
  the hero, status icon, and copy.
- **Update installs no longer freeze the UI** — hdiutil/ditto/git run
  off-main with concurrent pipe draining (was main-thread + pipe-deadlock
  risk); DMG downloads stream to disk while hashing instead of buffering
  whole in RAM; relaunch after terminate (socket-bind race removed); version
  comparison zero-pads segments ("v1.0" == "v1.0.0").
- **Console token off the wire** — dashboard handoff moved from `?ct=` query
  (logged in browser history/server logs) to a `#ct=` fragment (never sent).
- **Open at Login is now a two-way toggle** (was enable-only forever).
- **Guard prompt copy** — disconnected hero no longer says "monitoring
  paused" (collided with the real Pause feature).
- **Supervisor abandons deterministic failures immediately** — eslogger's
  NOT_PRIVILEGED used to retry 14× over 3 minutes; permanent errors now
  abandon on the first attempt with the actionable stderr in the health
  record. Abandoned collectors surface in the popover with a Retry affordance.
- **Silent failure paths made visible** — firewall promote, guard-rule
  revoke, and guard-decision resolution failures surface in the popover
  error banner instead of being swallowed.
- **"Open console" is disabled with a reason** when the daemon/proxy is
  down (was a silent no-op).

### Changed
- **Settings reorganized by function** — Protection (guard modes +
  firewall), Providers, Telemetry (ES collector + collector health),
  Decisions (per-path allows ledger), App, Advisor, Updates.
- **Provider support out of the box** — 12 harnesses matched by default
  (claude, cursor, codex, opencode, antigravity, windsurf, aider, gemini,
  codeium, copilot) plus local model infrastructure (ollama, lm-studio,
  tracked but their loopback traffic never flagged), each with vendor
  allowlists. New **Providers tab** toggles monitoring per harness
  (`disabled_agents` in config.yaml).
- **Popover reads in priority order** — needs-a-decision (incidents,
  criticals) → what's running (agent sessions) → what's enforcing
  (firewall, guard).
- **Incident sheet redesigned** — human summary + structured evidence +
  dispositions first; the raw markdown remediation report demoted behind a
  disclosure with one-click copy.
- **Agent identity** — brand-colored drawn glyphs for claude / cursor /
  codex / opencode (and a hashed-hue monogram for unknown harnesses).

### Security
- **TCC grant stability** — the app must be signed with a stable identity
  (Developer ID); ad-hoc signing changes the designated requirement's
  cdhash every build, silently invalidating every Full Disk Access grant
  on each update. Noted for the release pipeline.

## [v1.0.0] — 2026-09-10
## [v1.0.0] — 2026-09-10

The first stable release. rc.3 was folded into 1.0 rather than published
separately — everything below ships in v1.0.0:

- **Console UI overhaul** — evidence chains, liveness, session drill-down,
  activity trends, posture banner, menubar redesign.
- **Security hardening** — inline-handler XSS closed and structurally
  eliminated, harness self-protection, Grep/Glob directory-scan gating,
  Linux build enforced in CI.
- **The local advisor** — opt-in triage and incident narratives from a
  locally served model (loopback-only, advisory-only), with managed-mode
  provisioning, existing-server discovery, triage backfill, mute
  dispositions, and injection second opinions.
- **Learning loop** — allowlist suggestions with advisor assessments,
  weekly digest.
- **Self-updating** — verified stable channel + nightly channel.
- **Daemon hardening** — `main()` decomposition into tested wiring,
  both CI flakes root-caused and fixed.

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
- **v1.0 polish.** The collector-down posture item deep-links one click
  into System Settings → Full Disk Access (`POST /ui/open-fda`); the
  onboarding wizard deep-links into the Settings window ("More options
  in Settings…") so Settings is the single owner of ongoing config.

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
