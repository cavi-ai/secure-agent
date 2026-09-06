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

        # Bare provider tokens (no Bearer prefix) and key=value secrets must
        # also be redacted before they hit the log.
        for i, cmd in enumerate([
            "echo sk-proj-abcdef1234567890abcdef",
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCY",
            "git clone https://user:ghp_abcdef1234567890abcdef@github.com/x/y",
        ]):
            p = subprocess.run(
                [sys.executable, HOOK],
                input=json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                                  "tool_input": {"command": cmd}, "pid": 5000 + i}),
                capture_output=True, text=True, env=env, timeout=5,
            )
            if p.returncode != 0:
                raise AssertionError(f"hook exited {p.returncode}: {p.stderr}")

        content = open(logfile).read()
        for leaked in ("sk-proj-abcdef1234567890abcdef", "wJalrXUtnFEMIK7MDENGbPxRfiCY",
                       "ghp_abcdef1234567890abcdef"):
            if leaked in content:
                raise AssertionError(f"secret leaked into activity log: {leaked[:12]}...")

        # Log must not be world-readable.
        import stat
        mode = stat.S_IMODE(os.stat(logfile).st_mode)
        if mode & 0o077:
            raise AssertionError(f"activity log is {oct(mode)}, expected 0600")

    print("PASS (test_activity_log)")

if __name__ == "__main__":
    main()
