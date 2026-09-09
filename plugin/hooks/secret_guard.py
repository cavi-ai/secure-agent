#!/usr/bin/env python3
"""Deny agent mutation of the keychain and shell config; keep secrets out of agent reach.

Shared single copy. Symlinked into ~/.cursor/hooks/ and ~/.claude/hooks/.

Speaks both hook protocols at once by emitting every key each runtime reads:
Claude Code reads `hookSpecificOutput.permissionDecision`/`permissionDecisionReason`,
Cursor reads `permission`/`user_message`/`agent_message`, and each ignores the
other's keys.

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
check, only ad-hoc agent commands are. Shell `sh -c "..."` payloads ARE expanded
recursively (depth-capped); beyond that, path classification is string-based —
a pre-existing symlink pointing at a protected path defeats it, and inline
interpreter code can hide a path behind enough layers of runtime composition.
This layer raises the bar; it is not a complete seal.
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
# Mirror of every verdict into the daemon-tailed activity stream, so guard
# decisions are visible in the security console, not just in this local file.
ACTIVITY_LOG = os.environ.get("SECURE_AGENT_ACTIVITY_LOG") or os.path.join(
    HOME, ".local", "state", "secure-agent", "activity.jsonl")

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

# Public keys (`.pub`) are designed to be shared — denying them was a false
# positive that got the predecessor hook disabled.
PRIVATE_KEY_RE = re.compile(r"/\.ssh/(id_[a-z0-9]+|.*_(rsa|dsa|ecdsa|ed25519))$", re.I)

# Commands that write to whatever path they are handed.
MUTATORS = {
    "tee", "sed", "perl", "awk", "chmod", "chflags", "chown", "cp", "mv", "ln",
    "install", "truncate", "dd", "patch", "ed", "ex", "sponge", "rsync", "shred",
    "rm", "unlink", "touch", "mkfile",
}
# Commands that emit file contents to stdout — the leak path for secret files.
# grep/rg are readers too: `grep "" ~/.aws/credentials` prints the file just
# like cat does — the most obvious alias around a cat-only check.
READERS = {
    "cat", "head", "tail", "less", "more", "bat", "strings", "base64", "xxd",
    "od", "hexdump", "nl", "cut", "cp", "scp", "rsync", "curl", "tee", "open",
    "grep", "egrep", "fgrep", "rg",
}
# Wrappers to strip before reading the real command word.
# NOTE: xargs is deliberately NOT here — it is an executor whose target arrives
# via stdin (`echo ~/.zshrc | xargs rm`); stripping it would hide the bypass.
# It gets explicit handling in check_command.
WRAPPERS = {
    "sudo", "env", "command", "nohup", "time", "nice", "builtin",
    "exec", "doas", "stdbuf", "caffeinate", "script",
}

# Network clients that can drive an HTTP-over-unix-socket call. Paired with a
# token naming the guard's own socket or HTTP surface, this is an agent
# forging its own allow decision instead of going through the tool calls the
# guard actually mediates.
NETWORK_CLIENTS = {"curl", "nc", "ncat", "socat", "wget", "http", "httpie"}

INTERPRETERS = {
    "python", "python3", "perl", "ruby", "node", "deno", "bun", "osascript",
    "php", "lua", "tclsh",
}

# Shells whose `-c "..."` payload is a whole new command line. Without
# recursing into it, `zsh -c "security dump-keychain"` bypasses every check
# above, including the keychain total-ban. Expanded in segments(), depth-capped.
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash"}

# Inline-code obfuscation tells: a write verb plus any of these means the
# target path is being composed at runtime (chr()/base64/env lookups) precisely
# to defeat the literal-path scan. Deny rather than pretend we checked.
OBFUSCATION_RE = re.compile(
    r"chr\s*\(|b64decode|base64|os\.environ|getenv\s*\(|\\x[0-9a-fA-F]{2}"
    r"|getattr\s*\(|__import__|eval\s*\(|exec\s*\("
)

# Archivers/exfil tools: `tar cf - ~/.ssh | ...` reads everything without any
# single-file read ever hitting READERS.
ARCHIVERS = {"tar", "zip", "ditto", "7z", "7zz"}
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


def split_segments(command: str) -> list:
    """Split a command line on shell operators (|, ;, &&, ||, &, newline) —
    but NOT inside quotes. A naive regex split on ';' breaks `python3 -c
    "import os; ..."` mid-payload, hiding the payload from every later check."""
    parts, buf = [], []
    quote = None
    i = 0
    while i < len(command):
        c = command[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if command.startswith("&&", i) or command.startswith("||", i):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        if c in "|;\n&":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- output -----------------------------------------------------------------

def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def session_id() -> str:
    """Mirrors activity_log.session_id — same env priority, same fallback."""
    for var in ("CLAUDE_SESSION_ID", "SECURE_AGENT_SESSION_ID"):
        v = os.environ.get(var)
        if v:
            return v[:64]
    global _SESSION_ID
    if _SESSION_ID:
        return _SESSION_ID
    import uuid
    _SESSION_ID = uuid.uuid4().hex
    return _SESSION_ID

_SESSION_ID = ""


# Denied commands can themselves contain secrets (`security add-generic-password
# -w hunter2`, `export AWS_SECRET_ACCESS_KEY=...`). Persisting them verbatim into
# the audit trail would make the guard a secret *collector*. Redact first.
_AUDIT_REDACT = [
    (re.compile(r"(?i)(\s-w|\s--?password(?:-phrase)?)\s+('[^']*'|\"[^\"]*\"|\S+)"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|aws_secret_access_key)"
                r"\w*\s*[:=]\s*('[^']*'|\"[^\"]*\"|\S+)"), r"\1=[REDACTED]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), "Bearer [REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"), "[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9\-_]{16,}\b"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"), "[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED-KEY]"),
]


def redact_secrets(s: str) -> str:
    for pat, repl in _AUDIT_REDACT:
        s = pat.sub(repl, s)
    return s


def _secure_append(path: str, line: str) -> None:
    """Append one JSONL record, keeping the log 0600 and its dir 0700. These
    files are a forensic trail; world-readable defaults would leak it."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def audit(verdict: str, rule: str, command: str, event: str) -> None:
    """Never allowed to fail the hook."""
    safe_command = redact_secrets(command)
    rec = {
        "ts": now(),
        "verdict": verdict,
        "rule": rule,
        "event": event,
        "command": safe_command[:2000],
        "runtime": os.environ.get("CLAUDE_CODE_ENTRYPOINT") or os.environ.get("CURSOR_TRACE_ID") or "unknown",
    }
    try:
        _secure_append(AUDIT_LOG, json.dumps(rec) + "\n")
    except Exception:
        pass
    # Second copy in the daemon-tailed stream. Schema matches what
    # TranscriptScanner.ScanLine parses (tool/pid/ts/command/file_path): the
    # guard verdict travels in `tool`, the guard rule in `file_path`.
    try:
        _secure_append(ACTIVITY_LOG, json.dumps({
            "ts": rec["ts"],
            "tool": f"secret-guard:{verdict}",
            "pid": os.getppid() or os.getpid(),
            "session_id": session_id(),
            "file_path": rule,
            "command": safe_command[:500],
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
        "user_message": user_msg,
        "agent_message": agent_msg,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": agent_msg,
        },
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
    # Case-folded: default macOS APFS is case-insensitive, so `~/.ZSHRC` IS
    # `~/.zshrc` on disk. A case-sensitive check is a write-through bypass.
    return os.path.basename(p).lower() in SHELL_RC_NAMES


def is_keychain_path(token: str) -> bool:
    p = norm(token).lower()
    return any(m in p for m in KEYCHAIN_MARKERS)


# The guard's own control plane: its mode-override file, its onboarding/CA
# state, and the socket the hook talks to the daemon over. An agent that can
# write here, or drive it directly over the socket, can turn the guard off.
GUARD_CONTROL_DIR = os.path.join(HOME, ".config", "secure-agent")


def is_guard_control_path(token: str) -> bool:
    p = norm(token)
    return p == GUARD_CONTROL_DIR or p.startswith(GUARD_CONTROL_DIR + os.sep)


# The harnesses' own enforcement plane: their hook configs and the hook
# scripts themselves. Editing these is how an agent removes or neuters the
# guard watching it — the self-removal bypass called out in the threat model.
# Reads stay allowed (and mode-governed via the harness-config rule below);
# writes are denied outright, like guard-control writes.
HARNESS_CONFIG_PATHS = (
    "~/.claude/settings.json", "~/.claude/settings.local.json",
    "~/.claude/hooks", "~/.cursor/hooks", "~/.cursor/hooks.json",
    "~/.config/opencode/hooks",
)


def is_harness_config_path(token: str) -> bool:
    p = norm(token)
    for h in HARNESS_CONFIG_PATHS:
        nh = norm(h)
        if p == nh or p.startswith(nh + os.sep):
            return True
    return False


# Default credential paths, beyond SSH private keys, that a bare `cat`/`base64`/
# etc. must never be allowed to print. Mirrors DEFAULT_GUARD_RULES' cloud-creds.
CREDENTIALS_GLOBS = (
    "~/.aws/credentials", "~/.config/gcloud/**", "~/.azure/**",
    "~/.netrc", "~/.gnupg/**", "~/.kube/config", "~/.docker/config.json",
    "~/.npmrc", "~/.pypirc", "~/.config/gh/hosts.yml",
)
# Bare-key/cert material by extension, anywhere on disk.
SECRET_FILE_EXTS = (".pem", ".p12", ".pfx")


def is_secret_file(token: str) -> bool:
    p = norm(token)
    if PRIVATE_KEY_RE.search(p):
        return True
    if os.path.basename(p).lower().endswith(SECRET_FILE_EXTS):
        return True
    pl = p.lower()
    for g in CREDENTIALS_GLOBS:
        gg = norm(g).lower()
        if fnmatch.fnmatch(pl, gg) or fnmatch.fnmatch(pl, gg + "/*"):
            return True
    return False


# Directory prefixes whose *entire subtree* is protected — used by executor
# checks (find/xargs/tar) where the target is a directory, not a single file.
PROTECTED_DIR_BASES = (
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.azure", "~/.config/gcloud",
    "~/.kube", "~/Library/Keychains", "~/.docker",
)


def is_protected_dir(token: str) -> bool:
    p = norm(token)
    pl = p.lower()
    for b in PROTECTED_DIR_BASES:
        nb = norm(b).lower()
        if pl == nb or pl.startswith(nb + os.sep):
            return True
    return is_keychain_path(p) or is_guard_control_path(p)


def command_references_protected(command: str) -> bool:
    """True if any token anywhere in the full command line (including the
    pipeline's left side) names a protected path. Used for executor commands
    (xargs/find/tar) whose dangerous target arrives outside their own argv."""
    try:
        tokens = shlex.split(command, comments=True)
    except ValueError:
        tokens = command.split()
    for tok in tokens:
        if (is_shell_rc(tok) or is_keychain_path(tok) or is_secret_file(tok)
                or is_guard_control_path(tok) or is_protected_dir(tok)):
            return True
    return False


# --- directory guard: config-driven mode classification ---------------------

# Shipped default guard rules. Mirrors daemon defaults.yaml directory_guard.
# All ship monitor; the mode-override file is the user's opt-in to prompt/deny.
DEFAULT_GUARD_RULES = [
    {"id": "ssh-keys",    "paths": ["~/.ssh/id_*", "~/.ssh/*_rsa", "~/.ssh/*_ed25519"], "mode": "monitor"},
    {"id": "cloud-creds", "paths": ["~/.aws/credentials", "~/.config/gcloud/**", "~/.azure/**",
                                    "~/.netrc", "~/.kube/config", "~/.docker/config.json",
                                    "~/.config/gh/hosts.yml"], "mode": "monitor"},
    {"id": "keychain",    "paths": ["**/*.keychain-db", "**/login.keychain*"], "mode": "monitor"},
    {"id": "env-files",   "paths": ["**/.env", "**/.env.*"], "mode": "monitor"},
    {"id": "shell-rc",    "paths": ["~/.zshrc", "~/.zshenv", "~/.bashrc", "~/.profile"], "mode": "monitor"},
    {"id": "harness-config", "paths": ["~/.claude/settings.json", "~/.claude/settings.local.json",
                                       "~/.claude/hooks/**", "~/.cursor/hooks/**", "~/.cursor/hooks.json",
                                       "~/.config/opencode/hooks/**"], "mode": "monitor"},
]


# Directory prefixes whose *scan* is itself a guarded act: a Grep/Glob rooted
# at ~/.ssh is reaching for the keys inside even though no single file path
# matches the rules above. Maps the prefix to the rule whose mode governs it.
DIR_SCAN_RULES = (
    ("~/.ssh", "ssh-keys"),
    ("~/.aws", "cloud-creds"),
    ("~/.config/gcloud", "cloud-creds"),
    ("~/.azure", "cloud-creds"),
    ("~/.kube", "cloud-creds"),
    ("~/.docker", "cloud-creds"),
    ("~/.gnupg", "cloud-creds"),
    ("~/Library/Keychains", "keychain"),
)


def match_dir_scan(path: str):
    """Rule id when a Grep/Glob search root is (or sits inside) a protected
    directory subtree, else None."""
    p = norm(path)
    pl = p.lower()
    for base, rid in DIR_SCAN_RULES:
        nb = norm(base).lower()
        if pl == nb or pl.startswith(nb + os.sep):
            return rid
    return None


def _load_json_file(path: str, sentinel):
    """Load a guard config file. Missing file is normal (returns None);
    a file that EXISTS but won't parse is a security signal: return the
    fail-closed sentinel and log it, never silently revert to shipped
    monitor defaults."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except Exception:
        try:
            audit("deny", "guard-config-corrupt", path, "config")
        except Exception:
            pass
        return sentinel


def _mode_overrides() -> dict:
    path = os.environ.get("SECURE_AGENT_GUARD_MODES") or os.path.join(HOME, ".config", "secure-agent", "guard-modes.json")
    data = _load_json_file(path, {"*": "deny"})
    if data is None:
        return {}
    if not isinstance(data, dict):
        try:
            audit("deny", "guard-config-corrupt", path, "config")
        except Exception:
            pass
        return {"*": "deny"}
    return {str(k): str(v) for k, v in data.items()}


def _cwd_overrides() -> list:
    """Per-project policy overlays, newest daemon-written file:
    [{"cwd_prefix": "/Users/me/work/api", "rules": {"env-files": "deny"}}, ...]
    First matching prefix wins; rule modes from a matched entry replace the
    global override for that entry only."""
    path = os.environ.get("SECURE_AGENT_GUARD_CWD_OVERRIDES") or os.path.join(
        HOME, ".config", "secure-agent", "guard-cwd-overrides.json")
    data = _load_json_file(path, [{"cwd_prefix": os.sep, "rules": {"*": "deny"}}])
    if data is None:
        return []
    if not isinstance(data, list):
        try:
            audit("deny", "guard-config-corrupt", path, "config")
        except Exception:
            pass
        return [{"cwd_prefix": os.sep, "rules": {"*": "deny"}}]
    return data


def _cwd_for_request() -> str:
    """The agent's working directory for this tool call: the harness exposes it
    in the payload's cwd; fall back to the hook process's cwd."""
    v = os.environ.get("SECURE_AGENT_CWD") or os.environ.get("CLAUDE_CWD") or ""
    return os.path.normpath(v) if v else os.getcwd()


def _resolve_mode(rid: str, shipped: str, cwd_modes: dict, overrides: dict) -> str:
    """The mode-resolution chain shared by file-glob rules and directory-scan
    rules: per-cwd overlay > global override file > shipped default. A "*"
    entry means a corrupt config — fail closed with it verbatim."""
    if "*" in cwd_modes:
        return cwd_modes["*"]
    if rid in cwd_modes:
        return cwd_modes[rid]
    if "*" in overrides:
        return overrides["*"]
    return overrides.get(rid, shipped)


def _cwd_mode_map() -> dict:
    """First per-cwd overlay whose prefix contains the request cwd ({} if none)."""
    cwd = _cwd_for_request()
    for entry in _cwd_overrides():
        prefix = norm(str(entry.get("cwd_prefix", "")))
        if prefix and (cwd == prefix or cwd.startswith(prefix + os.sep)):
            rules_map = entry.get("rules") or {}
            if isinstance(rules_map, dict):
                return {str(k): str(v) for k, v in rules_map.items()}
            break
    return {}


def match_rule(path: str, rules=DEFAULT_GUARD_RULES):
    """Return (rule_id, effective_mode) for the first rule whose globs match, else (None, None).

    Effective mode resolution order: per-cwd overlay (first entry whose
    cwd_prefix contains the request cwd) > global override file > shipped mode.
    This is how a fleet operator pins one repo to deny while the rest of the
    machine stays monitor."""
    p = norm(path).lower()  # case-insensitive APFS: fold before glob matching
    cwd_modes = _cwd_mode_map()
    overrides = _mode_overrides()
    for rule in rules:
        for g in rule["paths"]:
            gg = norm(g).lower()
            if fnmatch.fnmatch(p, gg) or fnmatch.fnmatch(p, gg + "/*"):
                return rule["id"], _resolve_mode(rule["id"], rule["mode"], cwd_modes, overrides)
    return None, None


def mode_for_dir_scan(rid: str) -> str:
    """Effective mode for a directory-scan rule id (same override chain as
    match_rule; shipped mode looked up from DEFAULT_GUARD_RULES)."""
    shipped = next((r["mode"] for r in DEFAULT_GUARD_RULES if r["id"] == rid), "monitor")
    return _resolve_mode(rid, shipped, _cwd_mode_map(), _mode_overrides())


# --- directory guard: prompt-mode daemon resolution --------------------------

SOCK_PATH = os.environ.get("SECURE_AGENT_SOCK") or os.path.join(HOME, ".config", "secure-agent", "daemon.sock")
try:
    PROMPT_DEADLINE_S = float(os.environ.get("SECURE_AGENT_PROMPT_DEADLINE_S", "45"))
except ValueError:
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
    path = norm(path)
    d = _guard_query(agent, tool, path, rule_id, PROMPT_DEADLINE_S)
    deny_msg = (f"DENIED by Directory Guard ({rule_id}). Approve it in the Secure Agent prompt, "
                "or add an allow-always rule, then retry.")
    if d is None:  # daemon unreachable
        if runtime() == "claude":
            emit_ask(f"Secure Agent: allow {agent} to access {os.path.basename(path)}?", command, event)
            # emit_ask exits; fall through only for runtimes without ask support
        deny("guard-deny:" + rule_id, f"Blocked: access to {path} needs approval (monitor offline).",
             deny_msg, command, event)
    if isinstance(d, dict) and d.get("verdict") == "allow":
        allow("guard-allow:" + rule_id, command, event)
    deny("guard-deny:" + rule_id, f"Blocked: access to {path} was denied.", deny_msg, command, event)


def emit_ask(reason, command, event):
    audit("ask", "guard-ask", command, event)
    emit({
        "hookSpecificOutput": {"hookEventName": "PreToolUse",
                               "permissionDecision": "ask",
                               "permissionDecisionReason": reason},
    })
    sys.exit(0)


# --- command parsing --------------------------------------------------------

def segments(command: str, _depth: int = 0):
    """Yield (argv, raw_segment) for every shell segment, including subshells
    and shell `-c` payloads. `bash -c "rm ~/.zshrc"` is argv == [bash, -c, ...]
    at the top level — the real command lives inside the payload string, so
    recurse into it (depth-capped against `bash -c 'bash -c ...'` chains)."""
    raw_parts = list(split_segments(command))
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
            if _depth < 3 and os.path.basename(argv[0]) in SHELLS:
                for flag in ("-c", "-ic", "-lc"):
                    if flag in argv[1:]:
                        payload = argv[argv.index(flag) + 1] if argv.index(flag) + 1 < len(argv) else ""
                        if payload:
                            yield from segments(payload, _depth + 1)
                        break


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

        # 1a. Network clients driving the guard's own control socket / HTTP
        #     surface directly — forging /guard/resolve or /guard/decision is
        #     the same class of attack as editing guard-modes.json by hand.
        if name in NETWORK_CLIENTS:
            for tok in argv[1:]:
                if "daemon.sock" in tok or "/guard/" in tok:
                    deny(
                        "guard-control-network",
                        "Blocked: an agent tried to drive the guard's own control socket.",
                        "DENIED: talking to the Directory Guard's control socket directly "
                        "(curl/nc/wget/etc against daemon.sock or /guard/*) is how an agent "
                        "would forge its own allow decision. Use the tool calls the guard "
                        "already mediates instead.",
                        command, event,
                    )

        # 1b. Executors whose dangerous target arrives outside their own argv:
        #     `echo ~/.zshrc | xargs rm` (target via stdin), `find ~/.ssh
        #     -exec cat {} +`, `tar cf - ~/.aws`. argv alone looks harmless, so
        #     check the WHOLE command line for protected references.
        if name == "xargs":
            subcmds = [t for t in argv[1:] if not t.startswith("-")]
            if any(os.path.basename(t) in MUTATORS | READERS for t in subcmds):
                if command_references_protected(command):
                    deny(
                        "executor-bypass",
                        "Blocked: an agent piped a protected path into xargs.",
                        "DENIED: `xargs` with a mutator/reader fed from a protected path "
                        "is the same action as running that command on the path directly. "
                        "Ask the user to run it themselves.",
                        command, event,
                    )
        if name == "find" and any(f in argv for f in ("-exec", "-ok", "-delete", "-execdir")):
            if command_references_protected(command):
                deny(
                    "executor-bypass",
                    "Blocked: an agent used find -exec/-delete against a protected path.",
                    "DENIED: `find` with -exec/-delete over a protected directory reads or "
                    "mutates everything beneath it without any single-file check. Ask the "
                    "user to run it themselves.",
                    command, event,
                )
        if name in ARCHIVERS and command_references_protected(command):
            deny(
                "secret-archive",
                "Blocked: an agent tried to archive a protected directory.",
                "DENIED: archiving/copying a protected directory (ssh keys, cloud creds, "
                "keychain) is bulk exfiltration, whatever the stated purpose.",
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
        #    about to edit the file, so it is denied. The flag match is against
        #    a known unset-flags set — the old `startswith("no")` heuristic both
        #    missed `-R ~` recursion and false-denied hardening flags like
        #    `nodump`.
        CHFLAGS_UNSET = ("nouchg", "noschg")
        targets_rc = any(is_shell_rc(t) for t in argv[1:])
        recursive_home = any(a.startswith("-") and "R" in a for a in argv[1:]) and any(
            norm(t) == HOME for t in argv[1:] if not t.startswith("-")
        )
        if name == "chflags" and (targets_rc or (recursive_home and any(
                a.lower().lstrip("-") in CHFLAGS_UNSET for a in argv[1:]))):
            unlocking = any(
                a.lower().lstrip("-") in CHFLAGS_UNSET
                for a in argv[1:]
                if not a.startswith("/") and "~" not in a
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
                if is_guard_control_path(tok):
                    deny(
                        "guard-control-mutation",
                        f"Blocked: an agent tried to modify {norm(tok)}.",
                        "DENIED: the guard's own config and socket directory "
                        "(~/.config/secure-agent/) is not agent-writable. Editing "
                        "guard-modes.json or touching daemon.sock is how an agent would "
                        "disable the guard that is watching it.",
                        command, event,
                    )
                if is_harness_config_path(tok):
                    deny(
                        "harness-config-mutation",
                        f"Blocked: an agent tried to modify {norm(tok)}.",
                        "DENIED: harness settings and hook scripts are the guard's "
                        "enforcement plane — modifying them is how an agent removes or "
                        "neuters the guard watching it. Propose the change to the user.",
                        command, event,
                    )

        # 4. Redirects into rc files, keychain paths, or the guard's own
        #    control plane, whatever the command is.
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
            if is_guard_control_path(tgt):
                deny(
                    "guard-control-redirect",
                    f"Blocked: an agent tried to redirect output into {norm(tgt)}.",
                    "DENIED: the guard's own config and socket directory is not "
                    "agent-writable — this is how an agent would disable the guard "
                    "that is watching it.",
                    command, event,
                )
            if is_harness_config_path(tgt):
                deny(
                    "harness-config-redirect",
                    f"Blocked: an agent tried to redirect output into {norm(tgt)}.",
                    "DENIED: harness settings and hook scripts are the guard's "
                    "enforcement plane — this is how an agent would disable the "
                    "guard that is watching it.",
                    command, event,
                )

        # 5. Inline interpreter code is the obvious way around an argv check:
        #    `python3 -c "open('~/.zshrc','a').write(...)"` has argv[0] == python3
        #    and the path buried in a string. Scan inline source for a protected
        #    path paired with a write verb. Reading stays allowed.
        #    A write verb paired with runtime path *composition* (chr(), base64,
        #    env lookups) is denied too — that pattern exists to defeat exactly
        #    this literal-substring scan, so its absence proves nothing.
        if name in INTERPRETERS:
            for tok in argv[1:]:
                if not WRITE_VERB_RE.search(tok):
                    continue
                # the path is usually inside the -c payload, not its own arg
                # case-folded: KEYCHAIN_MARKERS are lowercase but the real
                # path is `~/Library/Keychains`, so a literal compare misses it
                low = tok.lower()
                names_protected = (
                    is_shell_rc(tok) or is_keychain_path(tok) or is_secret_file(tok)
                    or any(
                        marker.lower() in low
                        for marker in list(SHELL_RC_NAMES) + list(KEYCHAIN_MARKERS) + ["credentials/"]
                    )
                )
                if names_protected:
                    deny(
                        "interpreter-write-bypass",
                        "Blocked: an agent tried to write protected config through an interpreter.",
                        "DENIED: routing a write to shell config, the keychain or a credential "
                        "file through python/perl/node does not make it allowed. Propose the "
                        "diff to the user.",
                        command, event,
                    )
                if OBFUSCATION_RE.search(tok):
                    deny(
                        "interpreter-obfuscated-write",
                        "Blocked: an agent hid a file write behind runtime path composition.",
                        "DENIED: this inline code combines a file write with dynamic string "
                        "construction (chr/base64/env lookups) — the signature of hiding the "
                        "target path from static inspection. Write it as a plain script with "
                        "literal paths, or ask the user to run it.",
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

        # 6a. Directory Guard modes apply to Bash reads/mutations too, not
        #     just file tools — `cat ~/.aws/credentials` must not skip the
        #     same policy a Read tool call would hit (match_rule runs only
        #     for file tools otherwise). The hard secret-file-read deny above
        #     always wins for key material; this is the general case.
        #     Bounded rule: Bash never gets the interactive prompt the
        #     file-tool path uses — it can touch many paths at once, and a
        #     printed secret is unrecoverable — so a prompt-mode path here
        #     resolves straight to deny, never an ask.
        if name in READERS or name in MUTATORS:
            for tok in argv[1:]:
                rule_id, mode = match_rule(tok)
                if not rule_id:
                    # A directory target (cp -r ~/.ssh, tar cf - ~/.aws) is a
                    # scan of every protected file inside it — same gate as
                    # the Grep/Glob tool path.
                    scan_rid = match_dir_scan(tok)
                    if scan_rid:
                        rule_id, mode = scan_rid, mode_for_dir_scan(scan_rid)
                if mode in ("deny", "prompt"):
                    deny(
                        "guard-deny:" + rule_id,
                        f"Blocked: access to {norm(tok)} is denied by Directory Guard ({rule_id}).",
                        f"DENIED by Directory Guard ({rule_id}). Propose the change to the "
                        "user, or ask them to add an allow rule, then retry.",
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
    if is_guard_control_path(path):
        deny(
            "guard-control-write-tool",
            f"Blocked: an agent tried to write {norm(path)}.",
            "DENIED: the guard's own config directory (~/.config/secure-agent/) is not "
            "agent-writable — this is how an agent would disable the guard watching it. "
            "Reads stay allowed; propose the change to the user instead.",
            command, event,
        )
    if is_harness_config_path(path):
        deny(
            "harness-config-write-tool",
            f"Blocked: an agent tried to write {norm(path)}.",
            "DENIED: harness settings and hook scripts (~/.claude/, ~/.cursor/, "
            "~/.config/opencode/) are the guard's enforcement plane — editing them is "
            "how an agent removes or neuters the guard watching it. Reads stay allowed; "
            "propose the change to the user instead.",
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
        or tool_input.get("notebook_path")
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

    # Grep/Glob directory scans: the file-glob rules above match single files,
    # but a scan ROOTED at a protected directory (~/.ssh, ~/.aws, the
    # keychain dir) reaches for everything inside it. Gate the scan with the
    # governing rule's mode. The search root is the tool's path, defaulting to
    # the request cwd (a Grep with no path searches cwd).
    if tool in {"Grep", "Glob"}:
        search_root = file_path or _cwd_for_request()
        scan_rid = match_dir_scan(search_root)
        if scan_rid and not match_rule(search_root)[0]:
            scan_mode = mode_for_dir_scan(scan_rid)
            scan_target = norm(search_root)
            if scan_mode == "deny":
                deny(
                    "guard-deny:" + scan_rid,
                    f"Blocked: a directory scan of {scan_target} is denied by Directory Guard ({scan_rid}).",
                    f"DENIED by Directory Guard ({scan_rid}): scanning {scan_target} reaches "
                    "the protected files inside it. Ask the user for the specific value you "
                    "need instead of scanning the directory.",
                    command or search_root, event,
                )
            elif scan_mode == "monitor":
                audit("allow", "guard-monitor:" + scan_rid, command or search_root, event)
            elif scan_mode == "prompt":
                resolve_prompt(runtime(), tool, search_root, scan_rid, command or search_root, event)

    touched = check_command(command, event) if command else []
    if file_path and tool in {"Write", "Edit", "MultiEdit", "NotebookEdit"}:
        check_file_write(file_path, command or file_path, event)

    allow(",".join(touched), command or file_path, event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
