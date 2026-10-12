"""Run DMG packaging in an isolated fixture; Apple services are substituted."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]


class ReleasePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        packaging = self.root / "packaging"
        packaging.mkdir()
        shutil.copyfile(REPO / "packaging/make_dmg.sh", packaging / "make_dmg.sh")
        shutil.copytree(REPO / "packaging/lib", packaging / "lib")
        self.write_script(packaging / "make_app.sh", '''#!/bin/bash
set -eu
mkdir -p 'dist/Secure Agent.app'
touch dist/built
''')
        self.bin = self.root / "tools"
        self.bin.mkdir()
        self.write_script(self.bin / "hdiutil", '''#!/bin/bash
set -eu
printf '%s' "$DMG_CONTENT" > "${@: -1}"
''')
        self.write_script(self.bin / "ditto", '''#!/bin/bash
set -eu
touch "${@: -1}"
''')
        for command in ("codesign", "xcrun", "spctl"):
            self.write_script(self.bin / command, '''#!/bin/bash
set -eu
if [[ "$(basename "$0")" == "${FAIL_COMMAND:-}" ]]; then exit 1; fi
''')
        self.write_script(self.bin / "git", '''#!/bin/bash
set -eu
if [[ "${DIRTY_TREE:-0}" == 1 ]]; then exit 1; fi
''')
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.defpath,
                    "VERSION": "v1.3.0", "DMG_CONTENT": "first"}
        for key in ("CODESIGN_IDENTITY", "NOTARY_PROFILE", "RELEASE_BUILD", "FAIL_COMMAND", "DIRTY_TREE"):
            self.env.pop(key, None)

    def write_script(self, path, body):
        path.write_text(body)
        path.chmod(0o755)

    def run_build(self, **settings):
        return subprocess.run(["bash", "packaging/make_dmg.sh"], cwd=self.root,
                              env={**self.env, **settings}, capture_output=True, text=True, timeout=15)

    def test_rebuild_replaces_checksum_and_preserves_other_assets(self):
        dist = self.root / "dist"
        dist.mkdir()
        other = "a" * 64 + "  other.zip\n"
        (dist / "checksums.txt").write_text(other)
        first = self.run_build()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = self.run_build(DMG_CONTENT="second")
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual((dist / "checksums.txt").read_text(),
                         other + hashlib.sha256(b"second").hexdigest() + "  dist/SecureAgent-v1.3.0.dmg\n")

    def test_release_rejects_missing_notarization_before_build(self):
        result = self.run_build(RELEASE_BUILD="1", CODESIGN_IDENTITY="Developer ID Application: Fixture (FIXTURE)")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "dist/built").exists())

    def test_checksum_failure_retains_existing_entries(self):
        checksums = self.root / "checksums.txt"
        original = "a" * 64 + "  previous.dmg\n"
        checksums.write_text(original)
        result = subprocess.run(["bash", "-c", 'source "$1"; write_artifact_checksum "$2" "$3" "$4"',
                                 "checksum-test", str(REPO / "packaging/lib/checksum.sh"),
                                 str(self.root / "missing.dmg"), str(checksums), "missing.dmg"],
                                env=self.env, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(checksums.read_text(), original)

    def test_release_rejects_development_signing_before_build(self):
        for identity in ("", "-", "Apple Development: Fixture (FIXTURE)"):
            with self.subTest(identity=identity):
                result = self.run_build(RELEASE_BUILD="1", NOTARY_PROFILE="fixture-notary", CODESIGN_IDENTITY=identity)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "dist/built").exists())

    def test_release_rejects_nonrelease_version_before_build(self):
        result = self.run_build(RELEASE_BUILD="1", NOTARY_PROFILE="fixture-notary",
                                CODESIGN_IDENTITY="Developer ID Application: Fixture (FIXTURE)", VERSION="v1.3.0-2-gabc-dirty")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "dist/built").exists())

    def test_release_rejects_dirty_tree_before_build(self):
        result = self.run_build(RELEASE_BUILD="1", NOTARY_PROFILE="fixture-notary",
                                CODESIGN_IDENTITY="Developer ID Application: Fixture (FIXTURE)", DIRTY_TREE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "dist/built").exists())

    def test_failed_distribution_assessment_does_not_write_checksum(self):
        result = self.run_build(RELEASE_BUILD="1", NOTARY_PROFILE="fixture-notary",
                                CODESIGN_IDENTITY="Developer ID Application: Fixture (FIXTURE)", FAIL_COMMAND="spctl")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "dist/checksums.txt").exists())

    def test_failed_rebuild_preserves_previous_artifact_and_checksum(self):
        settings = {"RELEASE_BUILD": "1", "NOTARY_PROFILE": "fixture-notary",
                    "CODESIGN_IDENTITY": "Developer ID Application: Fixture (FIXTURE)"}
        first = self.run_build(**settings)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        checksum = (self.root / "dist/checksums.txt").read_bytes()
        second = self.run_build(**settings, DMG_CONTENT="second", FAIL_COMMAND="spctl")
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual((self.root / "dist/SecureAgent-v1.3.0.dmg").read_bytes(), b"first")
        self.assertEqual((self.root / "dist/checksums.txt").read_bytes(), checksum)

    def test_valid_release_settings_build_artifact(self):
        result = self.run_build(RELEASE_BUILD="1", NOTARY_PROFILE="fixture-notary",
                                CODESIGN_IDENTITY="Developer ID Application: Fixture (FIXTURE)")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "dist/SecureAgent-v1.3.0.dmg").read_bytes(), b"first")


if __name__ == "__main__":
    unittest.main()
