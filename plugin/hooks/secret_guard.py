#!/usr/bin/env python3
"""Deny agent mutation of the keychain and shell config; keep secrets out of agent reach.

Shared single copy. Symlinked into ~/.cursor/hooks/ and ~/.claude/hooks/.

Speaks both hook protocols at once by emitting every key each runtime reads:
Claude Code reads `decision`/`reason`, Cursor reads `permission`/`user_message`/
`agent_message`, and each ignores the other's keys.

Policy:
  - Agents get no `security` access at all. Apps reach their own Safe Storage
    natively, not through a shell, so no carve-out is needed.
  - Credentials an agent needs are proposed to the user, never read directly
    by the agent.
  - Shell rc files are read-only to agents.

Design rule that the hook this replaces got wrong: match on argv[0], never on a
substring. `gh api /repos/x/y/security` is not a keychain command. Default is
allow; a denial requires a positive match on a parsed command word.

Known limit, deliberate: only the top-level command is inspected. A repo script
that calls `security` internally (code signing, app-store-connect uploads, etc.)
is not gated — the user's own trusted scripts are out of scope for this generic
check, only ad-hoc agent commands are.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import socket as _socket
import sys
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
AUDIT_LOG = os.path.join(HOME, ".agents", "logs", "secret-guard.jsonl")

# --- protected surfaces -----------------------------------------------------

SHELL_RC_NAMES = {
    ".zshenv", ".zshrc", ".zprofile", ".zlogin", ".zlogout",
    ".profile", ".bashrc", ".bash_profile", ".bash_login",
}
SYSTEM_RC_PREFIXES = (
    "/etc/zshenv", "/etc/zprofile", "/etc/zshrc", "/etc/zlogin",
    "/etc/profile", "/etc/bashrc", "/etc/paths", "/etc/paths.d",
)

KEYCHAIN_MARKERS = ("library/keychains", ".keychain-db", "login.keychain")

PRIVATE_KEY_RE = re.compile(r"/\.ssh/(id_[a-z0-9]+|.*_(rsa|dsa|ecdsa|ed25519))(\.pub)?$", re.I)

# Commands that write to whatever path they are handed.
MUTATORS = {
    "tee", "sed", "perl", "awk", "chmod", "chflags", "chown", "cp", "mv", "ln",
    "install", "truncate", "dd", "patch", "ed", "ex", "sponge", "rsync", "shred",
    "rm", "unlink", "touch", "mkfile",
}
# Commands that emit file contents to stdout — the leak path for secret files.
READERS = {
    "cat", "head", "tail", "less", "more", "bat", "strings", "base64", "xxd",
    "od", "hexdump", "nl", "cut", "cp", "scp", "rsync", "curl", "tee", "open",
}
# Wrappers to strip before reading the real command word.
WRAPPERS = {
    "sudo", "env", "command", "nohup", "time", "nice", "xargs", "builtin",
    "exec", "doas", "stdbuf", "caffeinate", "script",
}

INTERPRETERS = {
    "python", "python3", "perl", "ruby", "node", "deno", "bun", "osascript",
    "php", "lua", "tclsh",
}
WRITE_VERB_RE = re.compile(
    r"""(?ix)
    (
      open\s*\([^)]*['"][aw]\+?['"]        # open(path, 'w'|'a')
      | \.write\b | \.writelines\b | writeFileSync | appendFileSync
      | writeFile\b | \bunlink\b | os\.remove | shutil\.(copy|move)
      | \bchflags\b | \bchmod\b | Path\([^)]*\)\.write
      | >>? \s*['"]?[^\s'"]*(\.zsh|\.profile|\.bash|keychain)
      | do\s+shell\s+script
    )
    """
)

SEGMENT_SPLIT = re.compile(r"\|\||&&|[|;\n]|&(?!&)")
SUBSHELL_RE = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
REDIRECT_RE = re.compile(r"(?:\d?>>?|\d?<)\s*([^\s;|&()]+)")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- output -----------------------------------------------------------------

def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def audit(verdict: str, rule: str, command: str, event: str) -> None:
    """Never allowed to fail the hook."""
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": now(),
                "verdict": verdict,
                "rule": rule,
                "event": event,
                "command": command[:2000],
                "runtime": os.environ.get("CLAUDE_CODE_ENTRYPOINT") or os.environ.get("CURSOR_TRACE_ID") or "unknown",
            }) + "\n")
    except Exception:
        pass


def allow(rule: str = "", command: str = "", event: str = "") -> None:
    if rule:
        audit("allow", rule, command, event)
    emit({"permission": "allow"})
    sys.exit(0)


def deny(rule: str, user_msg: str, agent_msg: str, command: str, event: str) -> None:
    audit("deny", rule, command, event)
    emit({
        "permission": "deny",
        "decision": "block",
        "reason": agent_msg,
        "user_message": user_msg,
        "agent_message": agent_msg,
    })
    sys.exit(0)


# --- path classification ----------------------------------------------------

def norm(token: str) -> str:
    t = token.strip().strip("'\"")
    t = t.replace("$HOME", HOME).replace("${HOME}", HOME)
    # Expand any other env var the hook inherited, so a reference like
    # `$XDG_CONFIG_HOME/gcloud/...` classifies as the path it names.
    t = os.path.expandvars(t)
    if t.startswith("~"):
        t = HOME + t[1:]
    return os.path.normpath(t) if t else t


def is_shell_rc(token: str) -> bool:
    p = norm(token)
    if any(p.startswith(pre) for pre in SYSTEM_RC_PREFIXES):
        return True
    return os.path.basename(p) in SHELL_RC_NAMES


def is_keychain_path(token: str) -> bool:
    p = norm(token).lower()
    return any(m in p for m in KEYCHAIN_MARKERS)


# Default credential paths, beyond SSH private keys, that a bare `cat`/`base64`/
# etc. must never be allowed to print. Mirrors DEFAULT_GUARD_RULES' cloud-creds.
CREDENTIALS_GLOBS = ("~/.aws/credentials", "~/.config/gcloud/**")


def is_secret_file(token: str) -> bool:
    p = norm(token)
    if PRIVATE_KEY_RE.search(p):
        return True
    for g in CREDENTIALS_GLOBS:
        gg = norm(g)
        if fnmatch.fnmatch(p, gg) or fnmatch.fnmatch(p, gg + "/*"):
            return True
    return False


# --- directory guard: config-driven mode classification ---------------------

# Shipped default guard rules. Mirrors daemon defaults.yaml directory_guard.
# All ship monitor; the mode-override file is the user's opt-in to prompt/deny.
DEFAULT_GUARD_RULES = [
    {"id": "ssh-keys",    "paths": ["~/.ssh/id_*", "~/.ssh/*_rsa", "~/.ssh/*_ed25519"], "mode": "monitor"},
    {"id": "cloud-creds", "paths": ["~/.aws/credentials", "~/.config/gcloud/**", "~/.azure/**"], "mode": "monitor"},
    {"id": "keychain",    "paths": ["**/*.keychain-db", "**/login.keychain*"], "mode": "monitor"},
    {"id": "env-files",   "paths": ["**/.env", "**/.env.*"], "mode": "monitor"},
    {"id": "shell-rc",    "paths": ["~/.zshrc", "~/.zshenv", "~/.bashrc", "~/.profile"], "mode": "monitor"},
]


def _mode_overrides() -> dict:
    path = os.environ.get("SECURE_AGENT_GUARD_MODES") or os.path.join(HOME, ".config", "secure-agent", "guard-modes.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {str(k): str(v) for k, v in data.items()}
    except Exception:
        return {}


def match_rule(path: str, rules=DEFAULT_GUARD_RULES):
    """Return (rule_id, effective_mode) for the first rule whose globs match, else (None, None).
    Effective mode = override file value if present, else the rule's shipped mode."""
    p = norm(path)
    overrides = _mode_overrides()
    for rule in rules:
        for g in rule["paths"]:
            gg = norm(g)
            if fnmatch.fnmatch(p, gg) or fnmatch.fnmatch(p, gg + "/*"):
                return rule["id"], overrides.get(rule["id"], rule["mode"])
    return None, None


# --- directory guard: prompt-mode daemon resolution --------------------------

SOCK_PATH = os.environ.get("SECURE_AGENT_SOCK") or os.path.join(HOME, ".config", "secure-agent", "daemon.sock")
PROMPT_DEADLINE_S = 45.0


def _guard_query(agent, tool, path, rule_id, deadline_s):
    """POST /guard/decision over the unix socket; return the decision dict or
    None if the daemon is unreachable. Own deadline < harness timeout."""
    body = json.dumps({"agent": agent, "tool": tool, "path": path, "rule_id": rule_id})
    req = ("POST /guard/decision HTTP/1.1\r\nHost: localhost\r\n"
           "Content-Type: application/json\r\nConnection: close\r\n"
           f"Content-Length: {len(body)}\r\n\r\n{body}")
    s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    s.settimeout(deadline_s)
    try:
        s.connect(SOCK_PATH)
    except OSError:
        return None  # daemon down
    try:
        s.sendall(req.encode())
        chunks = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
    except (OSError, _socket.timeout):
        return {"verdict": "deny", "scope": "once", "reason": "timeout"}
    finally:
        s.close()
    raw = b"".join(chunks)
    i = raw.find(b"\r\n\r\n")
    if i < 0:
        return {"verdict": "deny", "scope": "once", "reason": "timeout"}
    try:
        return json.loads(raw[i + 4:].decode())
    except ValueError:
        return {"verdict": "deny", "scope": "once", "reason": "timeout"}


def runtime() -> str:
    if os.environ.get("CLAUDE_CODE_ENTRYPOINT"):
        return "claude"
    if os.environ.get("CURSOR_TRACE_ID"):
        return "cursor"
    return "unknown"


def resolve_prompt(agent, tool, path, rule_id, command, event):
    """Prompt-mode resolution. Daemon decides (cached or via the native prompt).
    Daemon-down degrades to the harness's own ask on Claude; on Cursor (whose ask
    support is unverified) it fails safe to deny. Timeout/deny always block."""
    d = _guard_query(agent, tool, path, rule_id, PROMPT_DEADLINE_S)
    deny_msg = (f"DENIED by Directory Guard ({rule_id}). Approve it in the Secure Agent prompt, "
                "or add an allow-always rule, then retry.")
    if d is None:  # daemon unreachable
        if runtime() == "claude":
            emit_ask(f"Secure Agent: allow {agent} to access {os.path.basename(path)}?", command, event)
        deny("guard-deny:" + rule_id, f"Blocked: access to {norm(path)} needs approval (monitor offline).",
             deny_msg, command, event)
    if d.get("verdict") == "allow":
        allow("guard-allow:" + rule_id, command, event)
    deny("guard-deny:" + rule_id, f"Blocked: access to {norm(path)} was denied.", deny_msg, command, event)


def emit_ask(reason, command, event):
    audit("ask", "guard-ask", command, event)
    emit({
        "hookSpecificOutput": {"hookEventName": "PreToolUse",
                               "permissionDecision": "ask",
                               "permissionDecisionReason": reason},
    })
    sys.exit(0)


# --- command parsing --------------------------------------------------------

def segments(command: str):
    """Yield (argv, raw_segment) for every shell segment, including subshells."""
    raw_parts = list(SEGMENT_SPLIT.split(command))
    for m in SUBSHELL_RE.finditer(command):
        raw_parts.extend(p for p in (m.group(1), m.group(2)) if p)

    for raw in raw_parts:
        raw = raw.strip()
        if not raw:
            continue
        try:
            argv = shlex.split(raw, comments=True)
        except ValueError:
            # Unbalanced quotes: fall back to whitespace tokens rather than
            # denying. The old hook's fail-everything behavior is the bug.
            argv = raw.split()
        # strip leading env assignments and wrappers
        i = 0
        while i < len(argv):
            head = argv[i]
            if "=" in head and not head.startswith("-") and "/" not in head.split("=")[0]:
                i += 1
            elif os.path.basename(head) in WRAPPERS:
                i += 1
            else:
                break
        argv = argv[i:]
        if argv:
            yield argv, raw


def cmd_name(argv: list) -> str:
    return os.path.basename(argv[0]) if argv else ""


# --- main -------------------------------------------------------------------

def check_command(command: str, event: str) -> list:
    """Returns the protected surfaces this command touched and was allowed to.

    Denials exit inside this function. What survives to the return value is the
    permitted traffic that still touched a guarded surface — reading an rc file,
    listing the keychain dir. Logging only denials would make the log answer
    "what did I stop" when the question after an incident is "who went near this".
    """
    touched = []
    for argv, raw in segments(command):
        name = cmd_name(argv)

        # 1. security(1) — total ban from agent shells.
        if name == "security":
            deny(
                "keychain-security-cli",
                "Blocked: an agent tried to run the macOS `security` tool.",
                "DENIED: agents have no keychain access, read or write. If you need a "
                "credential, say what you need and why; propose it to the user instead "
                "of reaching for the keychain, another client, or a subagent.",
                command, event,
            )

        # 2. Anything pointed at the keychain files.
        if name in MUTATORS or name in READERS:
            for tok in argv[1:]:
                if is_keychain_path(tok):
                    deny(
                        "keychain-file-op",
                        "Blocked: an agent tried to touch a keychain file directly.",
                        "DENIED: keychain files are off limits — copying, moving, "
                        "chmod/chflags, deleting or reading them. This is the exact class of "
                        "action that can corrupt or lock a user out of their keyring.",
                        command, event,
                    )

        # 3. Shell rc mutation (reads stay allowed).
        #    chflags is asymmetric: setting the immutable flag only hardens the
        #    file, so it is allowed; clearing it is the first move of anyone
        #    about to edit the file, so it is denied.
        if name == "chflags" and any(is_shell_rc(t) for t in argv[1:]):
            unlocking = any(
                a.lower().lstrip("-").startswith("no")
                for a in argv[1:]
                if not a.startswith("/") and "~" not in a and "." not in a.split("/")[-1][:1]
            )
            if not unlocking:
                touched.append("shell-rc-lock")
                continue
            deny(
                "shell-rc-unlock",
                f"Blocked: an agent tried to clear the immutable flag on a shell rc file.",
                "DENIED: clearing uchg/schg on shell config is how an agent gets write access "
                "to it. Setting the flag is allowed; removing it is the user's call alone.",
                command, event,
            )

        if name in MUTATORS:
            for tok in argv[1:]:
                if is_shell_rc(tok):
                    deny(
                        "shell-rc-mutation",
                        f"Blocked: an agent tried to modify {norm(tok)}.",
                        "DENIED: shell config is read-only to agents. `.zshenv` derives every "
                        "root and PATH for the whole shell; a silent edit there can break every "
                        "session at once. Read it, propose the diff to the user, let them apply it.",
                        command, event,
                    )

        # 4. Redirects into rc files or keychain paths, whatever the command is.
        for m in REDIRECT_RE.finditer(raw):
            tgt = m.group(1)
            if is_shell_rc(tgt):
                deny(
                    "shell-rc-redirect",
                    f"Blocked: an agent tried to redirect output into {norm(tgt)}.",
                    "DENIED: shell config is read-only to agents. Propose the diff to the user.",
                    command, event,
                )
            if is_keychain_path(tgt):
                deny(
                    "keychain-redirect",
                    "Blocked: an agent tried to redirect output into a keychain path.",
                    "DENIED: keychain files are off limits.",
                    command, event,
                )

        # 5. Inline interpreter code is the obvious way around an argv check:
        #    `python3 -c "open('~/.zshrc','a').write(...)"` has argv[0] == python3
        #    and the path buried in a string. Scan inline source for a protected
        #    path paired with a write verb. Reading stays allowed.
        if name in INTERPRETERS:
            for tok in argv[1:]:
                if not (is_shell_rc(tok) or is_keychain_path(tok) or is_secret_file(tok)):
                    # the path is usually inside the -c payload, not its own arg
                    # case-folded: KEYCHAIN_MARKERS are lowercase but the real
                    # path is `~/Library/Keychains`, so a literal compare misses it
                    low = tok.lower()
                    if not any(
                        marker.lower() in low
                        for marker in list(SHELL_RC_NAMES) + list(KEYCHAIN_MARKERS) + ["credentials/"]
                    ):
                        continue
                if WRITE_VERB_RE.search(tok):
                    deny(
                        "interpreter-write-bypass",
                        "Blocked: an agent tried to write protected config through an interpreter.",
                        "DENIED: routing a write to shell config, the keychain or a credential "
                        "file through python/perl/node does not make it allowed. Propose the "
                        "diff to the user.",
                        command, event,
                    )

        # 6. Printing raw credential files / private keys.
        if name in READERS:
            for tok in argv[1:]:
                if is_secret_file(tok):
                    deny(
                        "secret-file-read",
                        "Blocked: an agent tried to print a credential file.",
                        "DENIED: credential files reach a process through `source`, never "
                        "through stdout. Printing one puts the secret in a transcript. "
                        "Ask the user for the value you actually need instead.",
                        command, event,
                    )

        # 7. Permitted traffic that still went near a guarded surface.
        for tok in argv[1:]:
            if is_shell_rc(tok):
                touched.append("shell-rc-read")
            elif is_keychain_path(tok):
                touched.append("keychain-read")
            elif is_secret_file(tok):
                touched.append("secret-file-touch")

    return sorted(set(touched))


def check_file_write(path: str, command: str, event: str) -> None:
    if is_shell_rc(path):
        deny(
            "shell-rc-write-tool",
            f"Blocked: an agent tried to edit {norm(path)}.",
            "DENIED: shell config is read-only to agents. `.zshenv` derives every root and "
            "PATH for the shell. Propose the diff to the user instead of writing it.",
            command, event,
        )
    if is_keychain_path(path) or is_secret_file(path):
        deny(
            "protected-write-tool",
            f"Blocked: an agent tried to write {norm(path)}.",
            "DENIED: keychain and credential files are not agent-writable.",
            command, event,
        )


def main() -> int:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        # Malformed payload is not evidence of wrongdoing. Cursor's `failClosed`
        # covers a hook that actually crashes; denying real work here is the bug
        # that got the previous hook disabled.
        allow()
        return 0

    event = str(data.get("hook_event_name") or data.get("event") or "")
    tool = str(data.get("tool_name") or "")
    tool_input = data.get("tool_input") or {}

    command = str(data.get("command") or tool_input.get("command") or "")
    file_path = str(
        data.get("file_path")
        or tool_input.get("file_path")
        or tool_input.get("path")
        or data.get("path")
        or ""
    )

    if file_path and tool in {"Read", "Grep", "Glob", "Write", "Edit", "MultiEdit", "NotebookEdit"}:
        rule_id, mode = match_rule(file_path)
        if mode == "deny":
            deny_msg = (f"DENIED by Directory Guard ({rule_id}). Propose the change to the user, "
                        "or ask them to add an allow rule, then retry.")
            deny(
                "guard-deny:" + rule_id,
                f"Blocked: access to {norm(file_path)} is denied by Directory Guard ({rule_id}).",
                deny_msg,
                command or file_path, event,
            )
        elif mode == "monitor":
            audit("allow", "guard-monitor:" + rule_id, command or file_path, event)
        elif mode == "prompt":
            resolve_prompt(runtime(), tool, file_path, rule_id, command or file_path, event)

    touched = check_command(command, event) if command else []
    if file_path and tool in {"Write", "Edit", "MultiEdit", "NotebookEdit"}:
        check_file_write(file_path, command or file_path, event)

    allow(",".join(touched), command or file_path, event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
