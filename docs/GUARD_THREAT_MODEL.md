# Directory Guard — Threat Model & Known Limits

[Documentation](README.md) · [Project home](../README.md)

The Directory Guard (PreToolUse hook + daemon prompt broker) is a
**bar-raising** layer, not a complete seal. This document is the honest
accounting of what it stops, what it structurally cannot, and which failure
modes fail closed vs. open. The firewall's equivalent lives in
[FIREWALL_THREAT_MODEL.md](FIREWALL_THREAT_MODEL.md).

## What it defends against

An AI agent process (or a prompt-injected tool call within one) attempting to:

- Read or mutate shell rc files (`~/.zshrc`, `/etc/paths`, …), SSH private
  keys, cloud credential files, keychain files, `.env` files.
- Run the macOS `security(1)` CLI in any capacity.
- Edit the guard's own control plane (`~/.config/secure-agent/`,
  `daemon.sock`, `/guard/*` endpoints) **or the harnesses' own enforcement
  plane** (`~/.claude/settings.json`, hook scripts under `~/.claude/hooks/`,
  `~/.cursor/hooks/`, `~/.config/opencode/hooks/`) — the self-removal class.
- Scan a protected directory (`Grep`/`Glob` rooted at `~/.ssh`, `~/.aws`,
  the keychain dir, or Bash `cp -r`/`tar` over them) — a scan reaches every
  protected file inside, so the governing rule's mode gates the scan itself.
- Exfiltrate protected directories wholesale (`tar`/`zip`/`ditto`, recursive
  `find -exec`, `xargs` fed from a pipe).
- Send data out after reading untrusted content (`untrusted-egress`). Once a
  session has read a web page, a search result, an MCP result, an image, or
  fetched output, later network commands, `git push`, `gh` writes,
  data-carrying URLs and MCP send tools in that session follow the rule's
  mode. The rule does not look for injected instructions, so a payload hidden
  in an image, a response header or a page does not need to be recognized.

Enforcement points, honestly labeled:

| Surface | Coverage |
|---|---|
| Claude file tools (`Read`/`Write`/`Edit`/`NotebookEdit`) | Mode-enforced per rule: `monitor` / `prompt` / `deny`. Writes to harness settings/hook scripts are **always denied** (like guard-control writes). |
| Claude `Grep`/`Glob` | Mode-enforced via the governing rule when the search root is a protected directory (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/Library/Keychains`) or matches a file rule directly. |
| Claude `Bash` | `deny`-mode rules enforced (including protected-directory targets); key material always denied — via `cat` **or any reader alias** (`grep`/`rg` included); `prompt` fails safe to `deny` (no interactive prompt mid-Bash). |
| Cursor | `Bash` commands only (Cursor's payload lacks `tool_name`). |
| Untrusted-input egress | Claude Code: every tool the `PreToolUse` hook sees, mode-enforced (`monitor` / `prompt` / `deny`). Cursor: shell commands, tainted only by events that carry a tool name. Routed agents in `deny`: every new proxy connection from a tainted session, except the model API hosts the proxy decrypts and loopback. |

## Bypass classes that are CLOSED (with regression tests)

- `sh -c "…"` / `bash -c` / `zsh -c` payloads — recursively analyzed
  (depth-capped at 3).
- `echo ~/.zshrc | xargs rm` — executors whose target arrives via stdin.
- `find ~/.ssh -exec cat {} +` / `-delete` over protected trees.
- `grep '' ~/.aws/credentials` / `rg . ~/.ssh/id_ed25519` — reader aliases
  for `cat` on secret files (closed by classing grep-family as readers).
- `Grep`/`Glob` rooted at `~/.ssh` or `~/.aws` — directory scans gated by
  the governing rule's mode; `cp -r ~/.ssh /tmp/x` gated the same way in Bash.
- `Write`/`Edit` of `~/.claude/settings.json` or hook scripts — always denied
  (`harness-config-write-tool`); Bash `cp`/`mv`/`sed`/redirects into them
  denied as `harness-config-mutation` / `harness-config-redirect`.
- Case variants (`~/.ZSHRC`) on case-insensitive APFS.
- Inline interpreter writes naming a protected path (`python3 -c
  "open('~/.zshrc','a')…"`), including runtime path composition
  (`chr()`/base64/env lookups) — the latter denied as
  `interpreter-obfuscated-write`.
- `chflags nouchg/noschg` (unlock), including `chflags -R … ~`.
- Redirects into protected paths (`>> ~/.zshrc`), subshells (`$(…)`),
  `sudo`/wrapper prefixes.

## Known limits (accepted, documented)

1. **The agent can attack the guard itself.** Writes to harness settings and
   hook scripts are denied (`harness-config-write-tool`) and reads are
   mode-governed by the `harness-config` rule — but a sufficiently capable
   agent can still try paths outside the covered harness directories (e.g.
   `~/.claude.json`, harness-internal state dirs), and the harness's decision
   to invoke the hook at all is not enforceable from inside the hook. This is
   why the daemon's eslogger/correlator layer exists: it observes file access
   *outside* the hook's reach and flags `sensitive-read-then-connect` after
   the fact. The bar is raised; it is not a seal.
2. **Path classification is string-based.** A pre-existing symlink at an
   unguarded path pointing at a protected file defeats the check (the hook
   must not `realpath` arbitrary user input — that races the filesystem
   anyway). TOCTOU between check and tool execution is inherent to a
   pre-execution gate.
3. **Inline code analysis is static and heuristic.** Sufficiently layered
   runtime composition (encrypted blobs, multi-stage eval) can hide a target
   path. The obfuscation heuristic trades a small false-positive rate for
   coverage of the common dodges; when in doubt it denies with an explanation.
4. **Hooks spawn per tool call**, so cross-call correlation (rate limiting,
   "three reads then a connect") lives in the daemon, not the hook.
5. **Directory-scan gating is prefix-based.** A scan rooted at a directory
   that merely *contains* a protected subdir (e.g. `Grep` over `~`) is not
   gated — gating broad roots would make normal project searches unusable.
   The governing rule's file-level matches inside the results are still
   enforced per call, and eslogger observes what the scan reads.
6. **Untrusted-egress sinks are recognized by name and shape.** Command
   words, `git`/`gh` subcommands, URL shape and MCP tool verbs decide what is
   a sink. A program the agent writes and then runs, a repository script, or
   a short secret in a plain URL path is not recognized; for a routed agent
   in `deny`, the proxy refuses their connections, but a connection opened
   before the taint keeps running, a client the proxy cannot tie to one live
   session passes, and `prompt` leaves the proxy idle. Sessions without a
   harness session id carry no taint. A person committing and pushing what
   the agent wrote is outside the hook. An `always` answer covers every
   untrusted-egress sink for that agent.
7. **Input origins are what the machine recorded.** An image's origin is its
   last commit (author name and email are whatever the committer set) and the
   macOS download attributes, which a copy or an archive can drop. Git is
   read with plumbing commands only, with `core.fsmonitor` and signature
   checks off, so the repository's configuration runs nothing; the hook
   spends at most 2 s on git, once per new image.

## Failure posture

### Shell classifier observations

The optional shell review worker is independent of the advisor. Observe mode
records risk hints asynchronously. Opt-in block mode adds a synchronous check
after the existing guard permits a Bash command. Hard denials never consult
the model and cannot become allows. Neither mode writes guard rules, resolves
prompts, or covers unhooked harnesses.

The block check permits continuation only for an unredacted routine result
with a stored receipt. Review, unknown, invalid input or output, queue overflow,
deadline expiry, and storage or transport failure deny. Its deadline includes
queue wait. Replies bind to the submitted command and working directory, and
no reply or receipt authorizes a subsequent call. A stored proposed verdict
does not prove the hook received the reply or that a command executed.

This is an optional extra restriction, not an OS security boundary. A fully
privileged same-user process can bypass hooks, change their environment, or
forge observations. Classifier mistakes can permit actions the existing guard
does not deny. Enabling the daemon's block mode does not establish that a live
harness invokes the check; per-session coverage still needs direct evidence.

The classifier receives masked command and working-directory text as
untrusted evidence, with no trusted user authorization. Hook-reported permission
decisions are excluded from that input. It has no tools or
filesystem access. Transport is loopback-only, ignores proxy environment
variables, and refuses redirects. Model errors and invalid probability
distributions produce unknown results. Routine answers below 0.9 reported
probability become unknown observations, while the original model choice and
scores remain inspectable. This cutoff is not a validated error bound; model
confidence is not calibrated security confidence. Submitted identities and verdicts are hook-reported,
not authenticated action receipts. A same-user process can forge observations.

Inference, queue size, input size, response size, and stored history are
bounded. Queue drops and write failures are visible in the observation API;
unconfirmed hook delivery is recorded in the hook audit log. Missing records
must not be interpreted as safe actions or complete coverage. See
[shell review configuration](CONFIGURATION.md#optional-shell-risk-observations).

### Guard failures

| Failure | Behavior |
|---|---|
| Malformed hook payload (can't parse stdin) | **Fail closed** when shell block mode is selected; otherwise **fail open**, retaining the observation-only hook's behavior. |
| Daemon unreachable in `prompt` mode | Claude: harness `ask`. Cursor: **fail closed** (deny). |
| Daemon hangs in `prompt` mode | **Fail closed** after `SECURE_AGENT_PROMPT_DEADLINE_S` (default 45s). |
| Corrupt `guard-modes.json` / cwd overrides | **Fail closed** (deny) + loud audit record. Never silently reverts to `monitor`. |
| Malformed daemon decision response | **Fail closed** (deny). |
| Guard prompt queue full (32 waiters) | Explicit `deny("queue-full")` — never an unbounded pile of dialogs. |

## Audit trail

Every verdict (allow-with-touch, deny, ask) is written to
`~/.agents/logs/secret-guard.jsonl` and mirrored to the daemon-tailed
`activity.jsonl`. Denied commands are **redacted** before logging (passwords,
tokens, bearer strings, PEM headers) — the guard's own logs must never become
a secret store. Both files are `0600` in `0700` directories.
