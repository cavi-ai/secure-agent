"""Exercise the real guard process and its optional observation transport."""
import json
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

HOOK = Path(__file__).with_name("secret_guard.py")


class ShellReviewTests(unittest.TestCase):
    def run_hook(self, home, command, enabled=True, event="PreToolUse", tool="Bash"):
        base = {k: v for k, v in os.environ.items() if not k.startswith("SECURE_AGENT_")}
        env = {**base, "HOME": home, "SECURE_AGENT_SOCK": home + "/d.sock",
               "SECURE_AGENT_SHELL_REVIEW": enabled if isinstance(enabled, str) else ("1" if enabled else "0"),
               "SECURE_AGENT_ACTIVITY_LOG": home + "/activity.jsonl"}
        payload = {"hook_event_name": event, "tool_name": tool,
                   "tool_use_id": "call-1", "session_id": "session-1",
                   "cwd": home, "tool_input": {"command": command}}
        if tool == "Read":
            payload["tool_input"] = {"file_path": command}
        p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                           text=True, capture_output=True, timeout=8, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_observation_cannot_override_guard_denial(self):
        with tempfile.TemporaryDirectory(prefix="sr-") as home:
            received = []
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(home + "/d.sock")
                server.listen()
                # Wait as long as run_hook lets the hook run: a cold start
                # under load connects well after a second.
                server.settimeout(8)
                def serve():
                    try:
                        conn, _ = server.accept()
                    except OSError:
                        return
                    with conn:
                        data = b""
                        while b"\r\n\r\n" not in data:
                            data += conn.recv(4096)
                        headers, body = data.split(b"\r\n\r\n", 1)
                        length = int(next(line.split(b":", 1)[1] for line in headers.split(b"\r\n")
                                          if line.lower().startswith(b"content-length:")))
                        while len(body) < length:
                            body += conn.recv(4096)
                        received.append(json.loads(body))
                        conn.sendall(b'HTTP/1.1 202 Accepted\r\nContent-Length: 22\r\n\r\n{"permission":"allow"}')
                thread = threading.Thread(target=serve)
                thread.start()
                output = self.run_hook(home, "security dump-keychain")
                thread.join(2)
            self.assertEqual(output["permission"], "deny")
            self.assertEqual(len(received), 1, "Bash observation was not submitted")
            self.assertEqual(received[0]["guard_verdict"], "deny")
            self.assertEqual(received[0]["call_id"], "call-1")

    def test_offline_observer_preserves_both_verdicts(self):
        with tempfile.TemporaryDirectory(prefix="sr-") as home:
            self.assertEqual(self.run_hook(home, "echo hello")["permission"], "allow")
            self.assertEqual(self.run_hook(home, "security dump-keychain")["permission"], "deny")

    def test_offline_block_mode_denies(self):
        with tempfile.TemporaryDirectory(prefix="sr-") as home:
            self.assertEqual(self.run_hook(home, "echo hello", enabled="block")["permission"], "deny")

    def test_block_mode_preserves_cursor_file_tools(self):
        with tempfile.TemporaryDirectory(prefix="sr-") as home:
            result = self.run_hook(home, home + "/README.md", enabled="block", event="preToolUse", tool="Read")
            self.assertEqual(result["permission"], "allow")

    def test_hard_denial_never_consults_blocking_model(self):
        with tempfile.TemporaryDirectory(prefix="sr-") as home:
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(home + "/d.sock")
                server.listen()
                server.settimeout(0.05)
                self.assertEqual(self.run_hook(home, "security dump-keychain", enabled="block")["permission"], "deny")
                with self.assertRaises(TimeoutError):
                    server.accept()

    def test_block_mode_rejects_malformed_payload(self):
        with tempfile.TemporaryDirectory(prefix="sr-") as home:
            env = {k: v for k, v in os.environ.items() if not k.startswith("SECURE_AGENT_")}
            env.update(HOME=home, SECURE_AGENT_SHELL_REVIEW="block", SECURE_AGENT_ACTIVITY_LOG=home + "/activity.jsonl")
            p = subprocess.run([sys.executable, str(HOOK)], input="{broken", text=True,
                               capture_output=True, timeout=3, env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout)["permission"], "deny")

    def test_block_response_must_match_request_and_receipt(self):
        for change, want in [("valid", "allow"), ("digest", "deny"), ("receipt", "deny"),
                             ("mode", "deny"), ("denied", "deny"), ("oversized", "deny")]:
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix="sr-") as home:
                failures = []
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(home + "/d.sock")
                    server.listen()
                    server.settimeout(2)
                    def serve():
                        try:
                            conn, _ = server.accept()
                            with conn:
                                conn.settimeout(2)
                                data = b""
                                while b"\r\n\r\n" not in data:
                                    chunk = conn.recv(4096)
                                    if not chunk:
                                        raise AssertionError("incomplete request")
                                    data += chunk
                                headers, body = data.split(b"\r\n\r\n", 1)
                                self.assertTrue(headers.startswith(b"POST /guard/shell-check "))
                                length = int(next(line.split(b":", 1)[1] for line in headers.split(b"\r\n")
                                                  if line.lower().startswith(b"content-length:")))
                                while len(body) < length:
                                    body += conn.recv(4096)
                                request = json.loads(body)
                                digest = hashlib.sha256((request["command"] + "\x00" + request["cwd"]).encode()).hexdigest()
                                reply = {"mode": "block", "verdict": "allow", "request_digest": digest,
                                         "observation_id": "a" * 32}
                                if change == "digest": reply["request_digest"] = "0" * 64
                                if change == "receipt": reply.pop("observation_id")
                                if change == "mode": reply["mode"] = "observe"
                                if change == "denied": reply.update(verdict="deny", reason="model_review")
                                if change == "oversized": reply["padding"] = "x" * 9000
                                body = json.dumps(reply).encode()
                                conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
                        except Exception as exc:
                            failures.append(exc)
                    thread = threading.Thread(target=serve)
                    thread.start()
                    result = self.run_hook(home, "printf '%s\\n' café", enabled="block")
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
                    self.assertFalse(failures, failures)
                    self.assertEqual(result["permission"], want)

    def test_disabled_post_tool_and_oversized_calls_are_not_submitted(self):
        for enabled, event, command in [(False, "PreToolUse", "echo hello"),
                                        (True, "PostToolUse", "echo hello"),
                                        (True, "PreToolUse", "echo " + "x" * 8192)]:
            with self.subTest(enabled=enabled, event=event, oversized=len(command) > 8192):
                with tempfile.TemporaryDirectory(prefix="sr-") as home:
                    with socket.socket(socket.AF_UNIX) as server:
                        server.bind(home + "/d.sock")
                        server.listen()
                        server.settimeout(0.05)
                        self.run_hook(home, command, enabled=enabled, event=event)
                        with self.assertRaises(TimeoutError):
                            server.accept()


if __name__ == "__main__":
    unittest.main()
