#!/usr/bin/env python3
"""PostToolUse hook: logs agent tool activity to activity.jsonl for the daemon to tail."""

from __future__ import annotations

import datetime
import json
import os
import re
import sys

# The one redaction rule set for every hook log; daemon/internal/redact holds
# the daemon's copy and daemon/internal/redact/testdata/cases.json is the
# contract both satisfy. Patterns are ASCII-only, as in Go. Order: private-key
# blocks, then credential shapes, then context rules, so a value the token
# rules already masked stays masked. Unlike the daemon, a BEGIN marker with no
# END masks the marker alone, keeping the command's paths for the daemon's
# classifier.
_A = re.ASCII

# An existing mask, such as the firewall's [REDACTED:<pattern id>], optionally
# quoted and followed only by punctuation ('"}' in JSON). A context rule keeps
# it and its label.
_MASK = re.compile(r"['\"]?\[REDACTED(?::[^\]\s]*)?\][^A-Za-z0-9]*", _A)
_PORT_PATH = re.compile(r"[0-9]+/", _A)


def _is_mask(v: str) -> bool:
    return _MASK.fullmatch(v) is not None


def _is_mask_or_port_path(v: str) -> bool:
    return _is_mask(v) or _PORT_PATH.match(v) is not None


# (pattern, replacement, keep): keep(value of the last group) leaves a match
# unmasked.
REDACT_RULES = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", _A | re.S),
     "[REDACTED:private-key]", None),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", _A), "[REDACTED:private-key]", None),
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*", _A), "Bearer [REDACTED]", None),
    (re.compile(r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b", _A), "[REDACTED]", None),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b", _A), "[REDACTED]", None),
    (re.compile(r"\bsk-[A-Za-z0-9\-_]{16,}\b", _A), "[REDACTED]", None),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b", _A), "[REDACTED]", None),
    (re.compile(r"\bglpat-[A-Za-z0-9\-_]{16,}\b", _A), "[REDACTED]", None),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", _A), "[REDACTED]", None),
    (re.compile(r"(\bsecurity\s+[a-z-]*password\b[^|;&\n]*?\s-w)\s+('[^']*'|\"[^\"]*\"|[^\s-]\S*)", _A),
     r"\1 [REDACTED]", _is_mask),
    (re.compile(r"(?i)(\s--?password(?:-phrase)?)\s+('[^']*'|\"[^\"]*\"|[^\s-]\S*)", _A),
     r"\1 [REDACTED]", _is_mask),
    (re.compile(r"(?i)\b((?:[a-z0-9]+_)*(?:password|passwd|secret|token|api[_-]?key|aws_secret_access_key)"
                r"\w*\s*[:=]\s*)('[^']*'|\"[^\"]*\"|\S+)", _A), r"\1[REDACTED]", _is_mask),
    (re.compile(r"://[^/\s:@]+:([^@\s]+)@", _A), "://[REDACTED]@", _is_mask_or_port_path),
]

# Cap logged command length — multi-MB heredocs would grow the daemon-tailed
# log without bound.
MAX_CMD_CHARS = 2000

def redact_str(s: str) -> str:
    res = s
    for pat, repl, keep in REDACT_RULES:
        if keep is None:
            res = pat.sub(repl, res)
        else:
            res = pat.sub(lambda m: m.group(0) if keep(m.group(m.re.groups)) else m.expand(repl), res)
    return res

def session_id(payload: dict | None = None) -> str:
    """Stable id for this harness session.

    Claude Code passes the session id in the hook JSON payload as
    ``session_id`` (and exposes ``CLAUDE_SESSION_ID`` only to the agent's own
    environment, NOT to hook subprocesses). Reading it from the payload is what
    makes the handshake id match the transcript's ``sessionId`` — the join the
    session resolver depends on. The env vars are kept as a legacy fallback.

    The sentinel file is keyed on this id, so a stable id means exactly one
    handshake per session (hooks spawn once per tool call). Without a stable
    id the fallback is a fresh per-invocation uuid, which cannot group a run.
    """
    if payload:
        v = payload.get("conversation_id") or payload.get("session_id") or payload.get("sessionId")
        if v:
            return str(v)[:64]
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

# Harness name by the payload's ``transcript_path`` or the agent's env. The
# transcript path is the reliable signal: Claude Code writes
# ~/.claude/projects/<slug>/<session>.jsonl, so its presence names the harness
# even when no env var survives into the hook subprocess.
def detect_harness(payload: dict | None = None) -> str:
    env_harness = os.environ.get("SECURE_AGENT_HARNESS", "")
    if env_harness:
        return env_harness
    if payload:
        if payload.get("cursor_version") or payload.get("conversation_id"):
            return "cursor"
        tp = payload.get("transcript_path") or ""
        if ".claude/projects" in tp or payload.get("session_id"):
            return "claude"
    return "claude" if os.environ.get("CLAUDE_SESSION_ID") else ""


def _git_field(workspace: str, *args: str) -> str:
    """Best-effort git probe with a hard timeout; never fails the hook."""
    import subprocess
    try:
        out = subprocess.run(
            ["git", "-C", workspace, *args],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            return out.stdout.strip()[:256]
    except Exception:
        pass
    return ""


def maybe_handshake(payload: dict, sid: str, log_path: str) -> None:
    """Emit one session_start line per session so the daemon can register the
    authoritative session record (harness, workspace, repo, branch, harness
    pid). Sentinel files make hooks — spawned once per tool call — cheap.
    """
    home = os.path.expanduser("~")
    seen_dir = os.path.join(home, ".local", "state", "secure-agent", "sessions_seen")
    sentinel = os.path.join(seen_dir, re.sub(r"[^A-Za-z0-9._-]", "_", sid))
    if os.path.exists(sentinel):
        return
    workspace = payload.get("cwd") or os.getcwd()
    harness = detect_harness(payload)
    repo = _git_field(workspace, "rev-parse", "--show-toplevel")
    branch = _git_field(workspace, "rev-parse", "--abbrev-ref", "HEAD") if repo else ""
    rec = {
        "type": "session_start",
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "session_id": sid,
        "harness": harness,
        "workspace": workspace,
        "repo": os.path.basename(repo) if repo else "",
        "branch": branch,
        "pid": os.getppid() or 0,
    }
    try:
        os.makedirs(seen_dir, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        with open(sentinel, "w") as f:
            f.write("")
    except Exception as e:
        sys.stderr.write(f"activity_log handshake error: {e}\n")


def log_payload(payload: dict) -> None:
    tool = payload.get("tool_name") or payload.get("tool") or "unknown"
    pid = payload.get("pid") or os.getppid() or os.getpid()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cmd = ""
    tool_input = payload.get("tool_input") or {}
    if isinstance(tool_input, dict):
        cmd = tool_input.get("command") or tool_input.get("file_path") or ""

    if cmd:
        cmd = redact_str(str(cmd))[:MAX_CMD_CHARS]

    sid = session_id(payload)
    rec = {
        "ts": ts,
        "tool": tool,
        "pid": pid,
        "session_id": sid,
        "command": cmd,
    }

    target_path = os.environ.get("SECURE_AGENT_ACTIVITY_LOG")
    if not target_path:
        home = os.path.expanduser("~")
        target_path = os.path.join(home, ".local", "state", "secure-agent", "activity.jsonl")

    try:
        logdir = os.path.dirname(target_path)
        os.makedirs(logdir, exist_ok=True)
        try:
            os.chmod(logdir, 0o700)
        except OSError:
            pass
        maybe_handshake(payload, sid, target_path)
        with open(target_path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        try:
            os.chmod(target_path, 0o600)
        except OSError:
            pass
    except Exception as e:
        sys.stderr.write(f"activity_log error: {e}\n")


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        payload = json.loads(raw)
    except Exception:
        return

    log_payload(payload)

if __name__ == "__main__":
    main()
