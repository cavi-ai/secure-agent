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
  `daemon.sock`, `/guard/*` endpoints).
- Exfiltrate protected directories wholesale (`tar`/`zip`/`ditto`, recursive
  `find -exec`, `xargs` fed from a pipe).

Enforcement points, honestly labeled:

| Surface | Coverage |
|---|---|
| Claude file tools (`Read`/`Write`/`Edit`/`NotebookEdit`) | Mode-enforced per rule: `monitor` / `prompt` / `deny`. |
| Claude `Bash` | `deny`-mode rules enforced; key material always denied; `prompt` fails safe to `deny` (no interactive prompt mid-Bash). |
| Cursor | `Bash` commands only (Cursor's payload lacks `tool_name`). |
| `Grep`/`Glob` directory scans | Observe-only (eslogger backstop). |

## Bypass classes that are CLOSED (with regression tests)

- `sh -c "…"` / `bash -c` / `zsh -c` payloads — recursively analyzed
  (depth-capped at 3).
- `echo ~/.zshrc | xargs rm` — executors whose target arrives via stdin.
- `find ~/.ssh -exec cat {} +` / `-delete` over protected trees.
- Case variants (`~/.ZSHRC`) on case-insensitive APFS.
- Inline interpreter writes naming a protected path (`python3 -c
  "open('~/.zshrc','a')…"`), including runtime path composition
  (`chr()`/base64/env lookups) — the latter denied as
  `interpreter-obfuscated-write`.
- `chflags nouchg/noschg` (unlock), including `chflags -R … ~`.
- Redirects into protected paths (`>> ~/.zshrc`), subshells (`$(…)`),
  `sudo`/wrapper prefixes.

## Known limits (accepted, documented)

1. **The agent can attack the guard itself.** An agent that can edit
   `~/.claude/settings.json`, the hook source, or its own harness config can
   remove the hook from the loop. The guard's own files are protected, but the
   harness's decision to invoke the hook is not enforceable from inside the
   hook. This is why the daemon's eslogger/correlator layer exists: it
   observes file access *outside* the hook's reach and flags
   `sensitive-read-then-connect` after the fact.
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
