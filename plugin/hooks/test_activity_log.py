#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "activity_log.py")

def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        logfile = os.path.join(tmpdir, "activity.jsonl")
        env = os.environ.copy()
        env["SECURE_AGENT_ACTIVITY_LOG"] = logfile

        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo Bearer sk-12345"},
            "pid": 4321,
        }

        p = subprocess.run(
            [sys.executable, HOOK],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=5,
        )
        if p.returncode != 0:
            raise AssertionError(f"hook exited {p.returncode}: {p.stderr}")

        if not os.path.exists(logfile):
            raise AssertionError("activity log file was not created!")

        with open(logfile, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        if len(lines) != 1:
            raise AssertionError(f"expected 1 line in activity log, got {len(lines)}")

        rec = json.loads(lines[0])
        if rec.get("tool") != "Bash" or rec.get("pid") != 4321:
            raise AssertionError(f"record mismatch: {rec}")

        # Assert secret token was redacted from command text
        if "sk-12345" in lines[0]:
            raise AssertionError("secret token leaked into activity log!")

    print("PASS (test_activity_log)")

if __name__ == "__main__":
    main()
