"""Native Codex and OpenClaw calls use the shared guard and session identity."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class HarnessGuardTests(unittest.TestCase):
    def test_native_calls_deny_secrets_and_preserve_session(self):
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, "HOME": home, "SECURE_AGENT_ACTIVITY_LOG": home + "/activity.jsonl"}
            modes = Path(home, "modes.json")
            modes.write_text(json.dumps({"ssh-keys": "deny"}))
            env["SECURE_AGENT_GUARD_MODES"] = str(modes)
            for harness in ("codex", "openclaw"):
                for tool, args in [
                    ("Bash", {"command": "cat ~/.ssh/id_rsa"}),
                    ("read", {"path": home + "/.ssh/id_rsa"}),
                    ("apply_patch", {"command": "*** Begin Patch\n*** Add File: " + home + "/.zshrc\n+bad\n*** End Patch"}),
                ]:
                    payload = {"hook_event_name": "PreToolUse", "tool_name": tool,
                               "tool_input": args, "cwd": home, "session_id": harness + "-session"}
                    result = subprocess.run([sys.executable, str(Path(__file__).with_name("harness_guard.py")), harness],
                                            input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
            rows = [json.loads(line) for line in Path(home, "activity.jsonl").read_text().splitlines()]
            self.assertTrue(any(row.get("session_id") == "codex-session" for row in rows))
            self.assertTrue(any(row.get("session_id") == "openclaw-session" for row in rows))
            self.assertTrue(all(row.get("pid") == os.getpid() for row in rows if row.get("pid")),
                            "The adapter must preserve its native parent's process identity")


if __name__ == "__main__":
    unittest.main()
