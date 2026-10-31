"""Native Codex and OpenClaw calls use the shared guard and session identity."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class HarnessGuardTests(unittest.TestCase):
    def test_antigravity_cli_path_cannot_bypass_file_guard(self):
        with tempfile.TemporaryDirectory() as home:
            modes = Path(home, "modes.json")
            modes.write_text(json.dumps({"ssh-keys": "deny"}))
            env = {**os.environ, "HOME": home, "SECURE_AGENT_GUARD_MODES": str(modes),
                   "SECURE_AGENT_ACTIVITY_LOG": home + "/activity.jsonl"}
            for tool, args in [
                ("read_file", {"Path": home + "/.ssh/id_rsa"}),
                ("read_file", {"Path": ".ssh/id_rsa"}),
                ("read_file", {"Path": home + "/.ssh/id_rsa", "AbsolutePath": home + "/README.md"}),
                ("view_file", {"AbsolutePath": home + "/.ssh/id_rsa", "Path": home + "/README.md"}),
            ]:
                with self.subTest(tool=tool, args=args):
                    payload = {"toolCall": {"name": tool, "args": args},
                               "conversationId": "antigravity-cli-session", "workspacePaths": [home]}
                    result = subprocess.run([sys.executable, str(Path(__file__).with_name("harness_guard.py")),
                                             "antigravity", "PreToolUse"], input=json.dumps(payload),
                                            text=True, capture_output=True, env=env, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout).get("decision"), "deny")

    def test_native_calls_deny_secrets_and_preserve_session(self):
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, "HOME": home, "SECURE_AGENT_ACTIVITY_LOG": home + "/activity.jsonl"}
            modes = Path(home, "modes.json")
            modes.write_text(json.dumps({"ssh-keys": "deny"}))
            env["SECURE_AGENT_GUARD_MODES"] = str(modes)
            for harness in ("codex", "openclaw", "hermes", "opencode", "antigravity"):
                for tool, args in [
                    ("Bash", {"command": "cat ~/.ssh/id_rsa"}),
                    ("read", {"path": home + "/.ssh/id_rsa"}),
                    ("apply_patch", {"command": "*** Begin Patch\n*** Add File: " + home + "/.zshrc\n+bad\n*** End Patch"}),
                ]:
                    payload = {"hook_event_name": "PreToolUse", "tool_name": tool,
                               "tool_input": args, "cwd": home, "session_id": harness + "-session"}
                    if harness == "antigravity":
                        names = {"Bash": "run_command", "read": "view_file", "apply_patch": "write_to_file"}
                        native_args = {"CommandLine": args["command"]} if tool == "Bash" else {
                            "AbsolutePath" if tool == "read" else "TargetFile": home + ("/.ssh/id_rsa" if tool == "read" else "/.zshrc")}
                        payload = {"toolCall": {"name": names[tool], "args": native_args},
                                   "conversationId": harness + "-session", "workspacePaths": [home]}
                    result = subprocess.run([sys.executable, str(Path(__file__).with_name("harness_guard.py")), harness, "PreToolUse"],
                                            input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    response = json.loads(result.stdout)
                    self.assertEqual(response.get("decision") if harness == "antigravity" else response["hookSpecificOutput"]["permissionDecision"], "deny")
                allowed = ({"toolCall": {"name": "run_command", "args": {"CommandLine": "echo hello", "Cwd": home}},
                            "conversationId": harness + "-session", "workspacePaths": [home]} if harness == "antigravity" else
                           {"hook_event_name": "PreToolUse", "tool_name": "terminal" if harness == "hermes" else "bash",
                            "tool_input": {"command": "echo hello"}, "cwd": home, "session_id": harness + "-session"})
                result = subprocess.run([sys.executable, str(Path(__file__).with_name("harness_guard.py")), harness, "PreToolUse"],
                                        input=json.dumps(allowed), text=True, capture_output=True, env=env, timeout=10)
                response = json.loads(result.stdout)
                self.assertEqual(response.get("decision") if harness == "antigravity" else response.get("permission"), "allow")
            rows = [json.loads(line) for line in Path(home, "activity.jsonl").read_text().splitlines()]
            self.assertTrue(any(row.get("session_id") == "codex-session" for row in rows))
            self.assertTrue(any(row.get("session_id") == "openclaw-session" for row in rows))
            self.assertTrue(all(row.get("pid") == os.getpid() for row in rows if row.get("pid")),
                            "The adapter must preserve its native parent's process identity")


if __name__ == "__main__":
    unittest.main()
