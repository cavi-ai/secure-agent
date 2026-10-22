#!/usr/bin/env python3
"""Build and run the smoke agent against a real local non-loopback socket."""
import ipaddress
import os
import pathlib
import re
import select
import subprocess
import tempfile
import time
import unittest


class NetworkFixtureTests(unittest.TestCase):
    def test_smoke_agent_establishes_non_loopback_connection(self):
        source = pathlib.Path(__file__).with_name("e2e_smoke.sh").read_text()
        agent_source = source.split('cat > "$tmp/fake_cursor_main.go" <<EOF\n', 1)[1].split('\nEOF', 1)[0]
        build = re.search(r'^go build -o "\$tmp/([^"/]+)" "\$tmp/fake_cursor_main.go"$', source, re.M)
        self.assertIsNotNone(build, "smoke fixture build command not found")
        binary_name = build.group(1)
        match = re.search(r'name: cursor, match: \["([^"]+)"\]', source)
        self.assertIsNotNone(match, "smoke fixture process matcher not found")
        self.assertEqual(binary_name, match.group(1))
        self.assertIn(f'"$tmp/{binary_name}" "$tmp" > "$tmp/fake-agent.log"', source)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "fake_cursor_main.go").write_text(agent_source)
            subprocess.run(
                ["bash", "-c", 'tmp=$1\n' + build.group(0), "network-fixture", directory],
                check=True, capture_output=True, text=True, timeout=60,
            )
            process = subprocess.Popen(
                [str(root / binary_name), directory],
                env={**os.environ, "HOME": directory},
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            output = b""
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    readable, _, _ = select.select([process.stderr], [], [], max(0, deadline - time.monotonic()))
                    if not readable:
                        break
                    chunk = os.read(process.stderr.fileno(), 8192)
                    if not chunk:
                        break
                    output += chunk
                    if b"network fixture connected to " in output:
                        break
                self.assertIn(b"network fixture connected to ", output, output.decode())
                endpoint = output.decode().split("network fixture connected to ", 1)[1].splitlines()[0]
                host = ipaddress.ip_address(endpoint.rsplit(":", 1)[0])
                self.assertFalse(host.is_loopback, endpoint)
                self.assertFalse(host.is_unspecified, endpoint)
                self.assertIsNone(process.poll(), output.decode())
            finally:
                if process.poll() is None:
                    process.terminate()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
