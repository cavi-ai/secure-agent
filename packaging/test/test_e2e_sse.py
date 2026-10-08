#!/usr/bin/env python3
"""Exercise the smoke gate's SSE assertion with small and noisy streams."""
import pathlib
import subprocess
import tempfile
import unittest


class SSEAssertionTests(unittest.TestCase):
    def check_stream(self, body, expected):
        source = pathlib.Path(__file__).with_name("e2e_smoke.sh").read_text()
        assertion = "SSE_PASSED=false\n" + source.split("SSE_PASSED=false\n", 1)[1].split(
            "\n# ---------------------------------------------------------------------------\n# Console auth:", 1
        )[0]
        with tempfile.TemporaryDirectory() as directory:
            stream = pathlib.Path(directory) / "stream.txt"
            stream.write_text(body)
            result = subprocess.run(
                ["bash", "-c", "set -euo pipefail\nSSE_OUT=$1\nSSE_CURL_PID=''\n"
                 + assertion + '\n[ "$SSE_PASSED" = "$2" ]',
                 "sse-test", str(stream), str(expected).lower()],
                capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_guard_lifecycle(self):
        self.check_stream(": secure-agent event stream\nevent: guard-prompt\nevent: guard-resolved\n", True)

    def test_large_stream_after_guard_events(self):
        self.check_stream(": secure-agent event stream\nevent: guard-prompt\nevent: guard-resolved\n"
                          + "event: event\ndata: {}\n\n" * 50000, True)

    def test_missing_resolution_fails(self):
        self.check_stream(": secure-agent event stream\nevent: guard-prompt\n", False)

    def test_missing_greeting_fails(self):
        self.check_stream("event: guard-prompt\nevent: guard-resolved\n", False)


if __name__ == "__main__":
    unittest.main()
