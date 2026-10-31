"""Exercise release credential handling without contacting Apple services."""
import base64
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "ci_release.sh"
SECRETS = {
    "MACOS_CERTIFICATE_P12_BASE64": base64.b64encode(b"certificate").decode(),
    "MACOS_CERTIFICATE_PASSWORD": "fixture-password",
    "MACOS_CODESIGN_IDENTITY": "Developer ID Application: Fixture (FIXTURE)",
    "MACOS_NOTARY_KEY_P8_BASE64": base64.b64encode(b"private-key").decode(),
    "MACOS_NOTARY_KEY_ID": "FIXTUREKEY",
    "MACOS_NOTARY_ISSUER_ID": "fixture-issuer",
}


class CIReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls"
        for command in ("security", "xcrun", "make"):
            tool = self.bin / command
            tool.write_text('''#!/bin/bash
set -eu
name="$(basename "$0")"
echo "$name ${1:-} ${2:-}" >> "$CALLS"
case "$name ${1:-}" in
  "security default-keychain"|"security list-keychains")
    if [[ "$*" != *" -s "* ]]; then echo '    "/fixture/login.keychain-db"'; fi ;;
  "make -C")
    [[ "$CODESIGN_IDENTITY" == "Developer ID Application: Fixture (FIXTURE)" ]]
    [[ -n "$NOTARY_PROFILE" ]]
    [[ -z "${DEVELOPER_TEAM:-}" ]]
    keys=("$RUNNER_TEMP"/secure-agent-signing.*/AuthKey.p8)
    [[ -f "${keys[0]}" ]]
    [[ "$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "${keys[0]}")" == 0o600 ]]
    ;;
esac
if [[ "$name" == "${FAIL_COMMAND:-}" ]]; then exit 7; fi
''')
            tool.chmod(0o755)
        self.env = {**os.environ, **SECRETS, "PATH": str(self.bin) + os.pathsep + os.defpath,
                    "RUNNER_TEMP": str(self.root), "CALLS": str(self.calls),
                    "DEVELOPER_TEAM": "must-not-be-used"}

    def run_script(self, mode="build", **settings):
        return subprocess.run(["bash", str(SCRIPT), mode, str(self.root / "source"), "v1.5.0"],
                              env={**self.env, **settings}, capture_output=True, text=True, timeout=15)

    def test_missing_secrets_fail_before_using_credentials(self):
        for secret in SECRETS:
            with self.subTest(secret=secret):
                result = self.run_script(**{secret: ""})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(secret, result.stderr)
                self.assertFalse(self.calls.exists())

    def test_check_does_not_use_credentials(self):
        result = self.run_script("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.calls.exists())

    def test_build_and_failure_clean_up_credentials(self):
        for failure in ("", "make", "xcrun"):
            with self.subTest(failure=failure):
                result = self.run_script(FAIL_COMMAND=failure)
                self.assertEqual(result.returncode, 7 if failure else 0, result.stderr)
                calls = self.calls.read_text()
                self.assertIn("security delete-keychain", calls)
                self.assertIn("security default-keychain -d", calls)
                self.assertEqual(list(self.root.glob("secure-agent-signing.*")), [])
                self.assertNotIn(SECRETS["MACOS_CERTIFICATE_PASSWORD"], result.stdout + result.stderr)
                self.calls.unlink()

    def test_rejects_non_distribution_identity(self):
        result = self.run_script(MACOS_CODESIGN_IDENTITY="-")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
