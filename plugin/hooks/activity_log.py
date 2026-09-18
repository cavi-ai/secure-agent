#!/usr/bin/env python3
"""PostToolUse hook: logs agent tool activity to activity.jsonl for the daemon to tail."""

from __future__ import annotations

import datetime
import json
import os
import re
import sys

REDACT_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Bare provider tokens (no Bearer prefix required)
    re.compile(r"\bsk-[A-Za-z0-9\-_]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9\-_]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    # key=value / key: value assignments of credential-shaped variables
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|aws_secret_access_key)"
               r"\w*\s*[:=]\s*('[^']*'|\"[^\"]*\"|\S+)"),
    # credentials embedded in URLs (https://user:ghp_xxx@github.com/...)
    re.compile(r"://[^/\s:]+:[^@\s]+@"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]

# Cap logged command length — multi-MB heredocs would grow the daemon-tailed
# log without bound.
MAX_CMD_CHARS = 2000

def redact_str(s: str) -> str:
    res = s
    for pat in REDACT_PATTERNS:
        res = pat.sub("[REDACTED]", res)
    return res

def session_id() -> str:
    """Stable id for this harness session.

    Claude Code exposes CLAUDE_SESSION_ID. When no session env exists, hooks
    spawn one process per tool call, so the fallback is a fresh per-invocation
    uuid — it cannot group a whole harness run (the daemon's correlation
    window is what links those calls). PID alone is not enough — PIDs are
    recycled, and fleet consumers must be able to tell sessions apart.
    """
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
    harness = "claude" if os.environ.get("CLAUDE_SESSION_ID") else os.environ.get("SECURE_AGENT_HARNESS", "")
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

    sid = session_id()
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
