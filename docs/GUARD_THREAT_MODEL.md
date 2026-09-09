# Directory Guard — Threat Model & Known Limits

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

Enforcement points, honestly labeled:

| Surface | Coverage |
|---|---|
| Claude file tools (`Read`/`Write`/`Edit`/`NotebookEdit`) | Mode-enforced per rule: `monitor` / `prompt` / `deny`. Writes to harness settings/hook scripts are **always denied** (like guard-control writes). |
| Claude `Grep`/`Glob` | Mode-enforced via the governing rule when the search root is a protected directory (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/Library/Keychains`) or matches a file rule directly. |
| Claude `Bash` | `deny`-mode rules enforced (including protected-directory targets); key material always denied — via `cat` **or any reader alias** (`grep`/`rg` included); `prompt` fails safe to `deny` (no interactive prompt mid-Bash). |
| Cursor | `Bash` commands only (Cursor's payload lacks `tool_name`). |

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

## Failure posture

| Failure | Behavior |
|---|---|
| Malformed hook payload (can't parse stdin) | **Fail open** (allow) — a crashed hook must not brick every tool call; harnesses failClosed covers hook crashes. |
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
