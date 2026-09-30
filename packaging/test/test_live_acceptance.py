#!/usr/bin/env python3
"""Exercise live acceptance against isolated mixed-harness telemetry."""
import datetime
import http.server
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import subprocess
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).with_name("live_acceptance.sh")


class AcceptanceTest(unittest.TestCase):
    def run_gate(self, claude_turns, cursor_turns, uptime="30m0s", historical_prompts=0):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            now = datetime.datetime.now(datetime.timezone.utc)
            timestamp = (now - datetime.timedelta(minutes=10)).isoformat()
            projects = home / ".claude" / "projects" / "fixture"
            projects.mkdir(parents=True)
            transcript = projects / "claude-session.jsonl"
            older = (now - datetime.timedelta(hours=20)).isoformat()
            transcript.write_text("".join(json.dumps({
                "type": "user", "timestamp": older,
                "message": {"content": "synthetic older prompt"},
            }) + "\n" for _ in range(historical_prompts)) + "".join(json.dumps({
                "type": "user", "timestamp": timestamp,
                "message": {"content": "synthetic prompt"},
            }) + "\n" for _ in range(3)))
            settled = (now - datetime.timedelta(minutes=5)).timestamp()
            os.utime(transcript, (settled, settled))
            (home / ".claude" / "settings.json").write_text(json.dumps({
                "hooks": {"PreToolUse": [{"hooks": [{"command": "secret_guard.py"}]}]},
            }))
            db_path = home / "events.db"
            with sqlite3.connect(db_path) as db:
                db.executescript("""
                    CREATE TABLE sessions (id TEXT, harness TEXT, workspace TEXT,
                        repo TEXT, started_at TEXT);
                    CREATE TABLE events (session_id TEXT, kind INT, ts TEXT,
                        call_id TEXT, model TEXT, cost_usd REAL);
                """)
                for harness in ("claude", "cursor"):
                    session = harness + "-session"
                    db.execute("INSERT INTO sessions VALUES (?,?,?,?,?)",
                               (session, harness, str(home / "repo"), "fixture", timestamp))
                    count = claude_turns if harness == "claude" else cursor_turns
                    db.executemany("INSERT INTO events VALUES (?,13,?,NULL,NULL,NULL)",
                                   [(session, timestamp)] * count)
                db.execute("INSERT INTO events VALUES ('claude-session',8,?,NULL,NULL,NULL)",
                           (timestamp,))

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    body = json.dumps({"active_agents": 2, "infra_count": 0,
                                       "uptime": uptime} if self.path == "/status" else {}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *_):
                    pass

            sock = str(home / "daemon.sock")
            with socketserver.UnixStreamServer(sock, Handler) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    return subprocess.run(["bash", str(SCRIPT)], timeout=15,
                        capture_output=True, text=True, env={**os.environ,
                        "HOME": folder, "SECURE_AGENT_SOCK": sock,
                        "SECURE_AGENT_DB": str(db_path),
                        "SECURE_AGENT_WORKSPACE_ROOT": folder})
                finally:
                    server.shutdown()
                    thread.join()

    def test_other_harness_turns_do_not_inflate_claude_ratio(self):
        result = self.run_gate(3, 8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("turn ratio (3 turns vs 3 prompts)", result.stdout)

    def test_duplicate_claude_turns_still_fail(self):
        result = self.run_gate(8, 4)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("8 turns vs 3 human prompts", result.stdout)

    def test_other_harnesses_cannot_hide_missing_claude_turns(self):
        result = self.run_gate(1, 8)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 turns vs 3 human prompts", result.stdout)

    def test_prompt_window_matches_capped_turn_window(self):
        result = self.run_gate(3, 0, uptime="48h0m0s", historical_prompts=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("turn ratio (3 turns vs 3 prompts)", result.stdout)


if __name__ == "__main__":
    unittest.main()
