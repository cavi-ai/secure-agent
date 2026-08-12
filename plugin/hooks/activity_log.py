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
]

def redact_str(s: str) -> str:
    res = s
    for pat in REDACT_PATTERNS:
        res = pat.sub("[REDACTED]", res)
    return res

def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        payload = json.loads(raw)
    except Exception:
        return

    tool = payload.get("tool_name") or payload.get("tool") or "unknown"
    pid = payload.get("pid") or os.getppid() or os.getpid()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cmd = ""
    tool_input = payload.get("tool_input") or {}
    if isinstance(tool_input, dict):
        cmd = tool_input.get("command") or tool_input.get("file_path") or ""

    if cmd:
        cmd = redact_str(str(cmd))

    rec = {
        "ts": ts,
        "tool": tool,
        "pid": pid,
        "command": cmd,
    }

    target_path = os.environ.get("SECURE_AGENT_ACTIVITY_LOG")
    if not target_path:
        home = os.path.expanduser("~")
        target_path = os.path.join(home, ".local", "state", "secure-agent", "activity.jsonl")

    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception as e:
        sys.stderr.write(f"activity_log error: {e}\n")

if __name__ == "__main__":
    main()
