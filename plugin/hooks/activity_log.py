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
        v = payload.get("session_id") or payload.get("sessionId")
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
