"""Owner setup must fail before compiling or signing without supplied profiles."""
import os
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("model_filter_entitlements", REPO / "packaging/lib/model_filter_entitlements.py")
PROFILES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILES)


class ModelFilterPackagingTests(unittest.TestCase):
    def test_profiles_bind_entitlements_to_authorized_bundle_and_team(self):
        team, bundle = "ABCDEFGHIJ", "com.cavi-ai.secure-agent"
        template = {PROFILES.CAPABILITY: ["content-filter-provider-systemextension"]}
        profile = {
            "TeamIdentifier": [team], "ApplicationIdentifierPrefix": ["LEGACYPREF"],
            "ExpirationDate": datetime.now(timezone.utc) + timedelta(days=1),
            "Entitlements": {PROFILES.TEAM_ID: team, PROFILES.APP_ID: "LEGACYPREF." + bundle,
                             PROFILES.CAPABILITY: template[PROFILES.CAPABILITY]},
        }
        prepared = PROFILES.entitlements(profile, template, team, bundle)
        self.assertEqual(prepared[PROFILES.APP_ID], "LEGACYPREF." + bundle)
        self.assertEqual(prepared[PROFILES.TEAM_ID], team)
        for field, value in (("TeamIdentifier", ["OTHERTEAM0"]),
                             ("ExpirationDate", datetime(2000, 1, 1)),
                             ("ApplicationIdentifierPrefix", ["OTHER"])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                PROFILES.entitlements({**profile, field: value}, template, team, bundle)
        with self.assertRaises(ValueError):
            PROFILES.entitlements(profile, template, team, bundle + ".model-filter")
        with self.assertRaises(ValueError):
            PROFILES.entitlements({**profile, "Entitlements": {**profile["Entitlements"], PROFILES.CAPABILITY: []}},
                                 template, team, bundle)

    def test_non_ad_hoc_filter_build_requires_owner_profiles_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "build-called"
            for name in ("go", "xcrun", "codesign", "security"):
                tool = root / name
                tool.write_text('#!/bin/sh\ntouch "$MODEL_FILTER_TEST_MARKER"\nexit 43\n')
                tool.chmod(0o700)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.defpath,
                   "MODEL_FILTER_BUILD": "1", "CODESIGN_IDENTITY": "Developer ID Application: Fixture",
                   "MODEL_FILTER_TEAM_ID": "", "MODEL_FILTER_APP_PROFILE": "",
                   "MODEL_FILTER_EXTENSION_PROFILE": "", "MODEL_FILTER_TEST_MARKER": str(marker)}
            result = subprocess.run(["bash", "packaging/make_app.sh"], cwd=REPO, env=env,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("owner-provided", result.stderr)
            self.assertFalse(marker.exists(), "build or signing started without provisioning inputs")


if __name__ == "__main__":
    unittest.main()
