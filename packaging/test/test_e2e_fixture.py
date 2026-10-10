#!/usr/bin/env python3
"""Exercise fixture failure reporting without starting the daemon."""
import pathlib
import subprocess
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
