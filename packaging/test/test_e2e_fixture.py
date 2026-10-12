#!/usr/bin/env python3
"""Exercise fixture failure reporting without starting the daemon."""
import pathlib
import contextlib
import io
import json
import runpy
import select
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.request


class FixtureLivenessTests(unittest.TestCase):
    def check_fixture(self, command, exited=True):
        source = pathlib.Path(__file__).with_name("e2e_smoke.sh").read_text()
        function = "check_fixture_alive() {" + source.split(
            "check_fixture_alive() {", 1
        )[1].split('\n\necho "Waiting for flag', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            script = ('set -euo pipefail\ntmp=$1\n'
                      + command + ' > "$tmp/fake-agent.log" 2>&1 &\n'
                      + 'AGENT_PID=$!\ntrap \'kill "$AGENT_PID" 2>/dev/null || true\' EXIT\n'
                      + ('wait "$AGENT_PID" || true\n' if exited else '')
                      + function + '\ncheck_fixture_alive\n')
            return subprocess.run(
                ["bash", "-c", script, "fixture-test", directory],
                capture_output=True, text=True, timeout=5,
            )

    def test_running_fixture_continues(self):
        result = self.check_fixture("sleep 3", exited=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_fixture_preserves_error_and_status(self):
        result = self.check_fixture("bash -c 'echo probe-failed >&2; exit 7'")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exit 7", result.stderr)
        self.assertIn("probe-failed", result.stderr)

    def test_premature_successful_exit_still_fails(self):
        result = self.check_fixture("true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exit 0", result.stderr)


class AdvisorFixtureTests(unittest.TestCase):
    def test_startup_does_not_require_hostname_resolution(self):
        with mock.patch("socket.getfqdn", side_effect=AssertionError("DNS unavailable")), \
                mock.patch("http.server.HTTPServer.serve_forever"), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            runpy.run_path(str(pathlib.Path(__file__).with_name("advisor_stub.py")), run_name="__main__")
        self.assertTrue(output.getvalue().strip().startswith("http://127.0.0.1:"))

    def start_from_smoke(self, script_dir):
        source = pathlib.Path(__file__).with_name("e2e_smoke.sh").read_text()
        startup = 'mkfifo "$tmp/advisor-ready"' + source.split(
            'mkfifo "$tmp/advisor-ready"', 1
        )[1].split('\n# Create a test overlay', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run(
                ["bash", "-c", 'set -euo pipefail\ntmp=$1\nSCRIPT_DIR=$2\n'
                 + 'ADVISOR_STUB_PID=""\ntrap \'kill "$ADVISOR_STUB_PID" 2>/dev/null || true\' EXIT\n'
                 + startup + '\nprintf "%s\\n" "$ADVISOR_ENDPOINT"\n',
                 "advisor-test", directory, str(script_dir)],
                capture_output=True, text=True, timeout=15,
            )

    def test_smoke_waits_for_bound_listener(self):
        result = self.start_from_smoke(pathlib.Path(__file__).resolve().parents[2])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip().startswith("http://127.0.0.1:"))

    def test_smoke_reports_startup_failure(self):
        with tempfile.TemporaryDirectory() as missing:
            result = self.start_from_smoke(missing)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Advisor stub failed to start", result.stderr)
        self.assertIn("advisor_stub.py", result.stderr)

    def test_ready_stubs_use_distinct_ports_and_return_verdicts(self):
        processes = []
        self.addCleanup(lambda: self.stop(processes))
        endpoints = []
        for _ in range(2):
            process = subprocess.Popen(
                [sys.executable, str(pathlib.Path(__file__).with_name("advisor_stub.py"))],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            processes.append(process)
            readable, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(readable, "advisor fixture did not signal readiness")
            endpoint = process.stdout.readline().strip()
            self.assertTrue(endpoint.startswith("http://127.0.0.1:"), endpoint)
            endpoints.append(endpoint)
            request = urllib.request.Request(
                endpoint + "/v1/chat/completions",
                data=json.dumps({"model": "e2e-stub-4b", "messages": []}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                choices = json.load(response)["choices"]
            self.assertEqual(len(choices), 1)
            verdict = json.loads(choices[0]["message"]["content"])
            self.assertEqual(verdict["assessment"], "benign")
            self.assertEqual(verdict["rationale"], "routine workflow")
        self.assertNotEqual(*endpoints)

    @staticmethod
    def stop(processes):
        for process in processes:
            process.terminate()
            process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
