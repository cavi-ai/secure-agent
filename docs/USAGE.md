# Use the console and CLI

[Documentation](README.md) · [Project home](../README.md)

Start with [installation and setup](GETTING_STARTED.md). Keep Secure Agent running while using an agent, then open **Open console** from the menu bar. The console is available when the local proxy listener is enabled; the menu bar passes its separate console credential automatically.

- [Review findings](#review-findings-and-incidents)
- [Inspect session history](#inspect-session-history)
- [Manage resources](#manage-session-resources)
- [Manage worktrees and disk space](#manage-worktrees-and-disk-space)
- [Use local analysis](#use-local-analysis)
- [Use the CLI](#use-the-cli)

## Review findings and incidents

Home shows decisions that need your attention. Open the selected finding's evidence before deciding whether to acknowledge it, change policy or report remediation. History remains available in Findings even when an item does not page you.

The web console shows active AI agent process trees, secret-exposure incident reports, correlated security flags, and proxy payload inspection streams. Its **Attention** view groups resource approvals, blocked guard requests, critical findings and incidents, and uninspected egress by complete session, with workspace, memory, CPU, process count, and scoped actions in one queue.

Individual security flags open an evidence drawer with the local advisor's plan and actions. **Inspect file details** shows supported `.env` variable names without values. **Send to local agent review** routes the selected finding into the Agent recommendation queue. Expected-read exceptions cover an exact host; test/non-secret `.env` exceptions cover one exact file for the named agent and are reversible under Policy. Cloud/CDN identity is infrastructure context, not proof of secret transmission.

On the **Agent** page, **Analyze activity** asks local Ollama to review stored flags and operator actions; its recommendation waits in a review queue for an explicit local-command confirmation or a saved harness plan.

Updates are pushed over SSE (`/events/stream`) with a polling fallback. The console's telemetry endpoints on the proxy port are gated by a per-install **console token** (0600, `~/.config/secure-agent/console-token`) — a credential agents never receive, so a routed agent can't turn its proxy token into telemetry reads or guard self-approval. The menubar's **Open console** passes the token automatically.

The correlation engine joins process file activity with network egress. It raises security flags when an agent process reads a sensitive file (e.g. `~/.aws/credentials` or `.env`) followed by an outbound socket connection to a domain outside its pre-approved vendor allowlist.

Incident reports list suggested remediation steps and recorded control outcomes. Report individual steps completed or mark them pending in the console; these reports remain unverified and do not resolve the incident. Later evidence is shown beside earlier reports. Credential rotation and revocation are external work and are never performed automatically.

### Notifications and exceptions

Only **severity-3 criticals page you** by default (confirmed secret leaks, direct read-then-connect activity, TCC tampering, keychain CLI execs); warnings queue silently in the popover and console.

A secret file read and later connection by unrelated sibling processes in one agent family remains a severity-2 finding for review, because timing alone does not show that the reader sent the bytes. Model-visible tool reads remain critical. Routine keychain-DB file opens are informational (severity 1) — legitimate tooling touches them constantly, so they never page unless you opt in.

Use **Dismiss this flag class** for a rule-level mute, reversible from Settings → Exceptions. Settings → Notifications and the console bell menu offer per-rule overrides: critical-only by default, **Always** or **Never** (`/notify/rules`), shared by both UIs.

### Coverage and evidence health

Home lists a decision only when you must act: a pending guard prompt or resource intervention, an open high or critical incident, or a critical finding. Everything else stays in the Findings history log.

Coverage shows each live session's supported paths and its own observations, joined by session identity and process start time. A sibling session's activity, a handshake, and an inspection failure cannot count as guard or inspection evidence. Payload inspection remains dependent on proxy routing and reliable attribution.

Setup can check each installed Claude or Cursor hook's inert round trip to the daemon; that manual check does not prove a running agent invokes the hook or change guard policy. Configuration changes invalidate the result.

Dropped event deliveries and failed core evidence writes appear in posture and Doctor. Successful writes clear the active storage fault for that operation, while the failure count remains for the daemon run: recovery cannot restore missing evidence.

The native app keeps last-known data when an endpoint fails, marks it stale, and requires a successful refresh of that endpoint to clear the warning.

Session cards in the menu bar open that same session in the console. Finding and remediation links open the selected evidence or incident, with a return to its session when the daemon knows that identity. Missing records stay unavailable; links never substitute a new process with the same PID. The console retains record identifiers when removing the handoff credential from the address bar.

For installation checks and missing telemetry, use [Troubleshooting](GETTING_STARTED.md#troubleshooting). Guard and firewall enforcement limits are in [Protection](PROTECTION.md).

## Inspect session history

Secure Agent parses agent-semantic trace events (tool calls, model calls, turns) from Claude Code, Codex, Cursor, Antigravity (agy), opencode, OpenClaw, and Hermes Agent records. The semantic trace contains metadata only (names, durations, models, tokens; never message or tool-call content). opencode stores its trace in SQLite and is read by a read-only, watermarked poller. See the [per-harness coverage table](ARCHITECTURE.md#collectors).

- `/costs` and `secure-agent cost`: model-call spend by repo, branch, harness, session, model, provider, or local day at the `tz` / `--tz` offset, across every traced harness.
- Session export: `secure-agent session <id>` prints what an agent did — tools, models, cost, files, hosts, guard decisions, findings — as a Markdown report; the console's Export button copies the same.

**Export recorded session history.** Session reports include the latest saved review decisions, the evidence revisions they apply to, residual risk, and intervention/remediation results. Missing source history and export limits are explicit. Copying a partial report shows a warning; an export does not establish task completion or current permission.

**See decisions and results in the session.** The Results view keeps saved reviews, process-control receipts, and reported incident actions together. Applied controls, later observations, and unverified external actions remain distinct. Source failures retain the last known receipts with a retry message; bounded and expired history stay visible as limits.

**Inspect the permissions from a decision.** View permissions in Results opens only the scope IDs saved with that decision, with their exact resources, recipients, expiry, and revocation records. Missing records have unknown status; failed refreshes retain labeled last-known data and disable revocation. Revocation requires confirmation and a matching saved response. It does not undo past access or remaining exposure, and other permissions or legacy policies may still allow access. Back returns to the same session result.

**Return to the session after investigating.** Session evidence and resource drawers keep a session Back link. Findings history and resource Events preserve the originating view, reading position, and evidence filters through Back to session and browser Back/Forward. Clearing evidence filters retains the return path; changing sessions or credentials discards the old context.

Finding and incident titles in session Memory open their retained evidence or report directly. Back returns to the same Memory view, reading position, and title. Missing sources are labeled unavailable; a retained summary does not reconstruct expired evidence.

**Inspect recorded session activity.** View session events reads matching retained events for that session in pages of up to 200 records, including ended sessions without a live process family. Use the paging controls to inspect earlier records and return to a newer page. Event and time filters query retained records directly; changing filters starts a new page history. A failed page request retains the current page so you can retry the same control. The end of retained records does not establish complete coverage; older activity may have expired. Back restores the originating session view and event filters. See the [paged event API](API.md#paged-session-events).

## Manage session resources

Open a session's resource view to inspect its complete process family and host conditions before selecting an action.

Resource actions reserve a durable intent before changing processes and record applied, partial, failed, or unknown results.

Approvals bind to the captured family and budget context; changed identities require a new decision. Missing or partial results cannot silently replay the operation, including after restart.

Results retain up to three existing resource samples within 15 seconds and show agent and host metrics separately. A successful process call is applied, not recovered; termination verification means the captured family was absent in a later sample.

Pause may stop growth without freeing memory, priority changes address CPU contention, and termination can lose unsaved work. The console, native glance, and session export retain these limits. Configured budgets still apply on a healthy host; high use alone does not prove host damage.

Resource tracking attributes live resident memory and CPU to complete agent sessions—root process plus helpers—so one runaway child cannot hide behind a harmless-looking parent.

Whole-machine context shows available and free memory, compression, swap, CPU split between agents and everything else, memory pressure, thermal state, and a conservative headroom score.

The console ranks sessions by pressure, charts one hour of history, explains heavy memory, full-core CPU, rapid growth, idle retention, runaway children, and orphan drift, and opens the entire process family before any terminate action. The native menu bar shows machine headroom and family totals and adds an **Impact** sort for quick daily triage.

A bounded local flight recorder keeps pressure episodes, their captured host conditions, process attribution, and the ten-minute lead-up available for post-mortem review after a session exits. Each episode correlates redacted process, tool call, model call, file, network, guard, and security activity with the steepest observed memory rise while clearly distinguishing temporal correlation from proven causation.

Optional session budgets add a sustained-breach grace period, cooldown, and
a graduated `notify → lower priority → pause → terminate` ladder. `observe`
reports only, `prompt` notifies automatically and requires approval for
state-changing steps, and `terminate` executes the configured ladder
automatically. Paused session families can be resumed from the console. The
default is `observe` with both limits disabled.

See [resource policy configuration](CONFIGURATION.md#resource_control-map) for budgets, intervention stages and workspace overrides.

## Manage worktrees and disk space

`secure-agent worktrees` lists every Git worktree found through agent sessions, agent worktree directories and a saved repo list, each marked remove, review, keep or prune with the reasons. The console's System tab shows these worktrees and disk usage per project, including what cleanups have reclaimed (`secure-agent cleanup log`).

“Ask <harness>” appears only for a live, resumable agent session; “Ask advisor” requests an advisory note; “Discuss” puts the question to the Agent tab. Removing a reviewed worktree moves its folder to Trash while keeping the Git branch, commits and stashes. It refuses an active session, a locked worktree, or a detached HEAD holding commits no branch keeps, as well as conflicts and partly staged files.

Start with the inventory before removing anything:

```bash
secure-agent worktrees --refresh
secure-agent cleanup
secure-agent cleanup log
```

`secure-agent worktrees add <repository>` saves a repository for discovery; `hide` hides it from reports. `remove <path>` acts only on a fresh `remove` verdict without `--force`, leaving the branch intact. `prune <repository>` removes Git records for missing worktree directories. The console's reviewed removal uses Trash and refuses live sessions, locks, loose commits, conflicts and partly staged files.

`secure-agent cleanup trash <path>` moves one inventoried item to Trash; `cleanup clean <tool>` uses the tool's own cache-clean command. `cleanup advise <repository|machine>` requests a local advisory plan before action. See [worktree configuration](CONFIGURATION.md#worktrees-map) and the [API contracts](API.md).

## Use local analysis

### Local chat and confirmed commands

Turn on **Settings → Secure Agent → Chat → Enable chat**, then click **Ask Agent** in the menu bar popover. Chat goes directly to your own Ollama. For local work, the model proposes an exact shell command and folder; you review and confirm it before it runs, either headless or in Terminal for passphrases. Commands run with your account's file and network access.

An optional **Harness handoff** section saves separate plans for Claude Code, Codex, OpenClaw, Hermes Agent, or Pi runner; it never changes where chat goes. Pi is terminal-only because it has no built-in sandbox.

Messages and output are masked by the firewall; `/agent/*` routes refuse agent processes. See [`docs/SYSTEM_AGENT.md`](SYSTEM_AGENT.md).

### Local advisor

With a local model serving the endpoint above, every flag gets an advisory
triage verdict (`advisor: benign / suspicious / malicious` chip on the flag
card, with the rationale as its tooltip). The posture banner and menubar hero
summarize how many critical flags look benign, and each incident card gains a
plain-English narrative. On request, it also writes a one-line note on a
worktree from the console's System tab or `secure-agent worktrees advise`,
and a short cleanup plan for a project's worktrees and clutter from the same tab
or `secure-agent cleanup advise`; neither changes a verdict or an action. The advisor runs asynchronously. If the model is unavailable, detection and enforcement continue independently; advisor health and retry state show why recommendations are unavailable.

Each advisor task starts with fresh context and can call read-only tools for
its evidence, its finding's session activity, and similar operator judgments.
An optional local classifier helps choose which context to inspect; its output
cannot clear findings or change enforcement. The Agent page reports the active
task, evidence tool, elapsed time, queue depth and retry state. See
[advisor boundaries](ADVISOR_THREAT_MODEL.md) for context and cache limits.

## Use the CLI

See the [generated CLI command reference](reference/CLI.md) for the full help from this checkout.

Install the CLI from Setup's Optional capabilities. A source build places it at `bin/secure-agent`; use that path if it is not on your `PATH`. Commands query `~/.config/secure-agent/daemon.sock`; set `SECURE_AGENT_SOCK` to query another socket.

| Task | Command |
|---|---|
| See command help | `secure-agent help` |
| Check daemon and coverage | `secure-agent status`, `secure-agent doctor` |
| Review findings and incidents | `secure-agent flags`, `secure-agent incidents` |
| Read raw events or policy audit | `secure-agent events --limit 20`, `secure-agent audit --limit 20` |
| List sessions | `secure-agent sessions` |
| Export one retained session | `secure-agent session <id-or-prefix>` |
| Review model-call spend | `secure-agent cost --by repo`, `secure-agent cost --by day --tz 0` |
| Inspect worktrees or cleanup history | `secure-agent worktrees`, `secure-agent cleanup log` |
| Inspect remembered guard decisions | `secure-agent guard list` |
| Inspect fingerprint sources | `secure-agent firewall sources` |
| Show this node's fleet identity | `secure-agent fleet` |
| Inspect the macOS headless service | `secure-agent service status` |

`secure-agent kill <PID>` terminates an agent process tree and can lose unsaved work. Inspect the family first. The [protection guide](PROTECTION.md) covers `fingerprint`, firewall modes and guard revocation; [Fleet](FLEET.md) covers enrollment; [Getting started](GETTING_STARTED.md) covers telemetry repair and service installation.

For automation, see the [Unix socket API](API.md). Its peer roles and mutation restrictions also apply to CLI requests.
